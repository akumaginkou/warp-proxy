# warp-proxy — design & protocol notes

A clean-room, portable **Cloudflare WARP over MASQUE** proxy in Rust: register
free WARP accounts, run one MASQUE (CONNECT-IP / HTTP-3) tunnel per account,
front them with a SOCKS5 load-balancer, and drive it all from a local control
API. Usable as a Rust library or as a standalone daemon.

## Provenance / clean-room statement

The WARP registration and MASQUE protocols are **not officially documented** by
Cloudflare. The concrete values below (API version, headers, the non-standard
`cf-connect-ip` protocol token, endpoints, framing) were determined by reading
the **public behaviour and open-source clients** (`Diniboy1123/usque`,
`ViRb3/wgcf`) and the relevant **RFCs**. This project **does not copy** their
source — it re-derives an independent Rust implementation from the protocol
facts recorded here. Officially documented facts are tagged `[DOC]`; values
reverse-engineered from public clients are `[RE]` and may change with WARP app
releases (keep them as constants).

## Registration (REST) — implemented

Host `https://api.cloudflareclient.com`, version segment `v0a4471` `[RE]`.
Common headers on every call `[RE]`:

- `User-Agent: WARP for Android`
- `CF-Client-Version: a-6.35-4471`  (`a-<appver>-<build>`)
- `Content-Type: application/json; charset=UTF-8`
- `Connection: Keep-Alive`
- authed calls add `Authorization: Bearer <token>`; ZeroTrust adds
  `CF-Access-Jwt-Assertion: <jwt>` on register.

Two steps, mimicking the Android app:

1. `POST /v0a4471/reg` with a throwaway base64 32-byte "WireGuard" key
   (`key_type=curve25519`, `tunnel_type=wireguard`) + random android serial +
   `tos` timestamp `YYYY-MM-DDTHH:MM:SS.mmm±HH:MM`. Response yields device `id`
   and a bearer `token` (token present only on this call).
2. `PATCH /v0a4471/reg/{id}` (Bearer) with the real key:
   `{ key: base64(SPKI DER of P-256 pubkey), key_type: "secp256r1",
      tunnel_type: "masque", name? }`. Response `config` carries
   `peers[0].endpoint.{v4,v6}` (`host:port`, port is `:0`),
   `peers[0].public_key` (PEM), and `interface.addresses.{v4,v6}` (our assigned
   tunnel IPs; IPv4 is a CGNAT `172.16.x.x` — observed against the live API,
   2026-07).

**Identity `[RE]`:** ECDSA **P-256 (secp256r1)**. Persist private key as
base64(SEC1 DER); enroll public key as base64(SPKI DER). No server-issued client
cert and no CSR — the tunnel later uses a locally self-signed cert (below).

`config.json` fields: `private_key, endpoint_v4, endpoint_v6, endpoint_h2_v4,
endpoint_h2_v6, endpoint_pub_key (PEM), id, access_token, ipv4, ipv6`.

## MASQUE tunnel — next (Phase 0 core)

Transport `[RE]`/`[DOC]`:

- **HTTP/3**: QUIC/UDP to `endpoint_v4|v6:443`, ALPN `h3`. QUIC connection-id
  length **20** (avoids intermittent PROTOCOL_VIOLATION). HTTP/3 with datagrams
  enabled + additional setting `0x276=1` (legacy `SETTINGS_H3_DATAGRAM_00`).
- **Auth = mTLS, self-signed:** present a 24h self-signed X.509 wrapping the
  device P-256 key; `InsecureSkipVerify`-style (no PKI) but **pin** the server
  cert's public key to `endpoint_pub_key`. SNI `consumer-masque.cloudflareclient.com`
  (does not match the endpoint IP — hence the pin).
- **Extended CONNECT** with `:protocol = cf-connect-ip` (Cloudflare's
  **non-standard** value — the single most important deviation `[RE]`), target
  `https://cloudflareaccess.com`, empty `User-Agent`, capsule protocol on;
  proceed even without peer `ENABLE_CONNECT_PROTOCOL`. Success = HTTP 200.
- **Datagrams (RFC 9297/9484 `[DOC]`):** each QUIC DATAGRAM =
  `varint(quarter_stream_id) || varint(context_id=0) || <full IP packet>`.
  Only context id 0 (full uncompressed packet) is used.
- **HTTP/2 fallback (`--http2`):** TCP+TLS ALPN `h2` to `162.159.198.2:443`,
  same mTLS; Extended CONNECT (RFC 8441) `:protocol=cf-connect-ip` + headers
  `cf-connect-proto: cf-connect-ip`, `pq-enabled: false`; datagrams via the
  Capsule Protocol as DATAGRAM capsules (type `0x00`) carrying
  `varint(context_id=0) || IP`.
- **Addressing:** static from registration (`ipv4`/`ipv6`, e.g. `172.16.x.x`);
  **no ADDRESS_ASSIGN capsule**. MTU **1280**.

The CONNECT-IP capsule/datagram layer (the "forked connect-ip" behaviour) is
re-implemented in Rust here; this is the crux of Phase 0.

**Verified (2026-07, live endpoint):** QUIC dial with the self-signed mTLS
identity + endpoint pubkey pinning succeeds (ALPN `h3`), and the Extended CONNECT
with `:protocol=cf-connect-ip` to `https://cloudflareaccess.com` returns **HTTP
200** — the MASQUE session opens. Stack: `quinn` + `h3` (with a one-variant
vendored patch adding the `cf-connect-ip` protocol token, see
`vendor/h3/PATCH.md`) + `rustls`/`ring`.

**IP forwarding verified (Phase 1 core):** IP packets are exchanged as raw QUIC
DATAGRAMs framed `varint(quarter_stream_id) || varint(context_id=0) || IP`
(`Tunnel::send_ip`/`recv_ip`, bypassing `h3-datagram` — h3-quinn's datagram
support is a disabled feature, so quinn's native datagrams are used directly).
A hand-crafted DNS query (source = the WARP-assigned `172.16.x.x`) to
`whoami.cloudflare` round-trips through the tunnel and returns a Cloudflare **WARP
egress IP** (e.g. `104.28.x.x`). Note h3 closes the connection when the last
`SendRequest` is dropped, so the tunnel keeps it (and the request stream) alive.
**End-to-end proxy verified (Phase 1 done):** a `smoltcp` guest netstack
(`netstack.rs`) runs on its own thread as an actor — it owns the interface (our
assigned addresses + default routes), a channel-backed `phy::Device` bridged to
`TunnelIo`, and TCP + DNS sockets — and exposes an async `NetHandle`. A minimal
SOCKS5 server (`socks.rs`) routes CONNECT through it with **remote DNS** (via the
smoltcp DNS socket to 1.1.1.1 through the tunnel). Live check:
`curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace`
returns `warp=on` at a WARP egress IP (`104.28.x.x`, colo NRT). MTU is clamped to
the QUIC datagram budget (~1223).

**Phase 2 (partial):**
- **DoH-bypass registration** (`doh.rs`, `RegistrationClient::with_doh_bypass` /
  `register_auto`): resolve `api.cloudflareclient.com` via DoH over 1.1.1.1
  (reached by IP, SNI `cloudflare-dns.com`) + baked-in fallback IPs, pin the
  address while keeping the real TLS SNI. Verified: registration succeeds through
  the pinned path.
- **IP rotation**: re-registration (`register_auto`) provisions a fresh account /
  egress; live per-slot rotation arrives with the pool (Phase 3).
- **HTTP/2 fallback** (`h2tunnel.rs`, `Transport::Http2`): TCP+TLS (ALPN `h2`),
  same mTLS + pinning. Cloudflare's H2 endpoint does not advertise RFC 8441
  extended CONNECT, so it uses a plain CONNECT + `cf-connect-proto: cf-connect-ip`
  header (→ HTTP 200). IP packets travel as DATAGRAM capsules (type `0x00`) whose
  value is the **bare IP packet** — Cloudflare omits the connect-ip context id
  (non-RFC; matched to the `connect-ip-go` fork). Live-verified end to end:
  `proxy --http2` → `curl --socks5-hostname … /cdn-cgi/trace` = `warp=on`.

**Phase 3 (done):** `pool.rs` runs N accounts, each its own tunnel + netstack
(one egress IP); every worker's netstack is swappable so it can reconnect / rotate
/ switch transport live. `socks.rs::serve_pool` fronts them as a load-balancer
(round-robin over ready workers, or pinned; WARP off and loopback go direct).
`control.rs` is a compact token-guarded HTTP/1.1 control API
(`/api/status|toggle|select|rotate|reconnect|http2|trace|account/add|remove`).
`trace.rs` fetches `cdn-cgi/trace` over TLS through a worker to report its egress
IP / colo / warp state. Live-verified: two egress IPs round-robin, pin sticks,
WARP-off goes direct (real IP), rotate yields a fresh egress, trace reports
`warp=on`.

Remaining: library-API polish + the daemon CLI (handshake JSON) and packaging.

## Netstack, pool, control (later phases)

- A userspace TCP/IP stack (`smoltcp`) terminates the tunneled IP packets so a
  local SOCKS5 server (`fast-socks5`, remote DNS) can bridge app connections.
- An account pool runs one tunnel per account; a front SOCKS5 LB round-robins /
  pins across them (WARP off = direct; loopback always direct).
- A token-guarded local HTTP control API exposes status/toggle/select/rotate/
  http2/reconnect/interval/trace/account add·remove.
- DoH-bypass registration: on DNS-filtered networks, resolve
  `api.cloudflareclient.com` via DoH-over-1.1.1.1 (+ pinned fallback IPs) and
  connect by IP with the correct SNI.

## References

RFCs `[DOC]`: 9484 (CONNECT-IP), 9297 (HTTP Datagrams / Capsule Protocol),
9298 (CONNECT-UDP, for contrast), 8441 (H2 Extended CONNECT), 9220 (H3 Extended
CONNECT). Public clients `[RE]`: github.com/Diniboy1123/usque,
github.com/ViRb3/wgcf. Cloudflare docs/blog: WARP with MASQUE (HTTP/3,
default since 2024-12).
