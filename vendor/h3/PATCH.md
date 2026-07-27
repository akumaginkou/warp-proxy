# Vendored `h3` 0.0.8 — warp-proxy patch

This is an unmodified copy of the upstream [`h3`](https://crates.io/crates/h3)
crate v0.0.8 (Apache-2.0 / MIT, see `LICENSE`) with **one** change:

- `src/ext.rs`: add `Protocol::CF_CONNECT_IP` (and its `as_str` / `FromStr`
  mappings) so the Extended-CONNECT `:protocol` pseudo-header can carry
  Cloudflare's non-standard `cf-connect-ip` token. Upstream only ships
  `webtransport` and `connect-udp`.

It is wired in via `[patch.crates-io]` in the workspace `Cargo.toml`. This
mirrors how the reference Go client forks `connect-ip-go` for the same reason.
No other files are modified.
