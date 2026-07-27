# warp-proxy

A clean-room, portable **Cloudflare WARP over MASQUE** proxy in Rust.

It registers free WARP accounts, runs one MASQUE (CONNECT-IP / HTTP-3) tunnel
per account, fronts the pool with a local SOCKS5 load-balancer, and exposes a
small control API to switch/rotate egress IPs live — no external `usque` binary,
no system VPN, no admin rights. Usable as a **Rust library** or a **standalone
daemon** any project can launch as a subprocess.

> Independent reimplementation of the WARP MASQUE engine. Protocol behaviour is
> referenced from public clients and RFCs; no third-party source is copied. See
> [`DESIGN.md`](DESIGN.md).

## Status

Built bottom-up (see the repo plan). Current state:

- [x] Device identity (P-256) and `config.json` schema
- [x] Two-step device registration + key enroll (`warp-masque`)
- [x] QUIC dial with self-signed mTLS + endpoint pubkey pinning (live-verified)
- [x] HTTP/3 Extended CONNECT `:protocol=cf-connect-ip` → **HTTP 200** (live-verified)
- [x] IP-packet ⇄ HTTP-datagram forwarding (`Tunnel::send_ip`/`recv_ip`)
- [x] userspace netstack (`smoltcp`) + local **SOCKS5 proxy with remote DNS** —
      `curl --socks5-hostname … /cdn-cgi/trace` reports **`warp=on`** at a WARP
      egress IP (live-verified via the `proxy` example)
- [ ] HTTP/2 fallback, DoH-bypass registration, IP rotation
- [ ] account pool + front SOCKS5 LB + control API
- [ ] library API polish + daemon CLI

The CONNECT-IP handshake uses a one-variant vendored patch to `h3` (see
[`vendor/h3/PATCH.md`](vendor/h3/PATCH.md)) so `:protocol` can carry Cloudflare's
non-standard `cf-connect-ip` token.

### Try the tunnel handshake

```sh
cargo run -p warp-masque --example register     -- ./warp-config.json
cargo run -p warp-masque --example tunnel_poc   -- ./warp-config.json  # handshake -> HTTP 200
cargo run -p warp-masque --example egress_probe -- ./warp-config.json  # DNS through the tunnel -> WARP egress IP
```

### Run the SOCKS5 proxy

```sh
cargo run -p warp-masque --example proxy -- ./warp-config.json 127.0.0.1:1080
# in another shell:
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace   # -> warp=on
```

## Try registration

```sh
cargo run -p warp-masque --example register -- ./warp-config.json
```

This creates a free throwaway WARP account and writes `warp-config.json`
(compatible with the reference client's schema). Requires network access to
`api.cloudflareclient.com`.

## Layout

```
crates/warp-masque/   # MASQUE client: keys, registration, config, tunnel (wip)
DESIGN.md             # protocol spec + clean-room provenance
```

## License

MIT — see [`LICENSE`](LICENSE).
