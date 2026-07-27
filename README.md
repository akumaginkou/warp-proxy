# warp-proxy

[![CI](https://github.com/akumaginkou/warp-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/akumaginkou/warp-proxy/actions/workflows/ci.yml)

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
- [x] DoH-bypass registration (pin `api.cloudflareclient.com` via DoH over
      1.1.1.1 for DNS-filtered networks) — `register_auto` / `--doh`
- [x] IP rotation via re-registration (`register_auto` yields a fresh account;
      live per-slot rotation lands with the pool)
- [x] HTTP/2 fallback (`--http2`) for QUIC-blocked networks: plain CONNECT +
      `cf-connect-proto` → 200, DATAGRAM capsules with Cloudflare's bare-IP quirk.
      Live-verified: `proxy --http2` → `warp=on`
- [x] multi-account pool (N tunnels = N egress IPs) + front SOCKS5
      load-balancer (round-robin / pin, WARP off = direct) + token-guarded
      control HTTP API + egress trace — live-verified (`pool` example)
- [x] `warp-proxy` daemon (handshake JSON on stdout, account persistence,
      graceful SIGINT/SIGTERM) — usable from any language as a subprocess
- [x] per-worker supervisor (auto-reconnect with exponential backoff on tunnel
      death), auto-rotate timer (`/api/interval`), and GitHub Actions CI
      (fmt · clippy · build · test on Linux + Windows)

The CONNECT-IP handshake uses a one-variant vendored patch to `h3` (see
[`vendor/h3/PATCH.md`](vendor/h3/PATCH.md)) so `:protocol` can carry Cloudflare's
non-standard `cf-connect-ip` token.

## Quick start — the daemon

```sh
cargo run -p warp-proxy -- --accounts 2 --socks 127.0.0.1:1080 --control 127.0.0.1:47100
```

It registers (or, with `--state-dir DIR`, loads) N accounts, starts the SOCKS5
load-balancer + control API, and prints one JSON line to **stdout** so a parent
process can wire itself up:

```json
{"socksPort":1080,"controlUrl":"http://127.0.0.1:47100","controlToken":"…"}
```

Then point any app at `socks5h://127.0.0.1:1080` and drive egress over the
control API. Flags: `--accounts N`, `--socks ADDR`, `--control ADDR`,
`--state-dir DIR` (persist accounts across restarts), `--http2`. Ports may be
`:0` to auto-assign (read the real port from the handshake). Stops on
SIGINT/SIGTERM.

**As a Rust library:** `use warp_masque::{Pool, RegistrationClient, socks, control};`
— register configs, `Pool::new(configs, http2).await`, then `socks::serve_pool`
and `control::serve`.

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

### Run a multi-account pool + control API

```sh
cargo run -p warp-masque --example pool -- 2 127.0.0.1:1080 127.0.0.1:47100
# round-robins across 2 egress IPs; drive it live (token printed on start):
curl -H "X-Warp-Token: <token>" http://127.0.0.1:47100/api/status
curl -H "X-Warp-Token: <token>" "http://127.0.0.1:47100/api/select?slot=1"   # pin account 1
curl -H "X-Warp-Token: <token>" "http://127.0.0.1:47100/api/rotate?slot=1"   # new egress IP
```

Control endpoints (loopback, JSON, `X-Warp-Token` required): `/api/status`,
`/api/toggle`, `/api/select`, `/api/rotate`, `/api/reconnect`, `/api/http2`,
`/api/interval` (auto-rotate seconds), `/api/trace`, `/api/account/add`,
`/api/account/remove`.

## Layout

```
crates/warp-masque/   # library: keys · registration · tunnel (H3 + H2) · netstack
                      #          · SOCKS5 · pool · control API · DoH · trace
crates/warp-proxy/    # the `warp-proxy` daemon binary
vendor/h3/            # h3 0.0.8 + one-variant cf-connect-ip patch (see PATCH.md)
DESIGN.md             # protocol spec + clean-room provenance
```

## Build

```sh
cargo build --release          # -> target/release/warp-proxy
cargo test                     # OS-independent unit tests
```

Pure Rust on the `ring` crypto provider — no C toolchain needed for a native
Linux/macOS build. Cross-building to Windows works too, but `ring` needs a
Windows C compiler for that target (e.g. `x86_64-w64-mingw32-gcc`):

```sh
rustup target add x86_64-pc-windows-gnu
CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc cargo build --release --target x86_64-pc-windows-gnu
```

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this project by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

Bundles a patched copy of [`h3`](vendor/h3) (Apache-2.0 OR MIT); see
[`vendor/h3/PATCH.md`](vendor/h3/PATCH.md).
