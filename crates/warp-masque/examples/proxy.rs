//! Run a local SOCKS5 proxy whose traffic egresses through Cloudflare WARP.
//!
//! Usage:
//!   cargo run -p warp-masque --example proxy -- [CONFIG_PATH] [BIND_ADDR]
//!
//! Defaults: CONFIG_PATH=./warp-config.json, BIND_ADDR=127.0.0.1:1080. Then:
//!   curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
//! should report `warp=on` and a WARP egress IP.

use warp_masque::netstack;
use warp_masque::socks;
use warp_masque::tunnel::Tunnel;
use warp_masque::{DeviceKeypair, WarpConfig};

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let cfg_path = args.next().unwrap_or_else(|| "warp-config.json".into());
    let bind = args.next().unwrap_or_else(|| "127.0.0.1:1080".into());

    let cfg = WarpConfig::load(&cfg_path)?;
    let kp = DeviceKeypair::from_private_b64(&cfg.private_key)?;

    eprintln!("Establishing MASQUE tunnel…");
    let tunnel = Tunnel::connect(&cfg, &kp).await?;
    anyhow::ensure!(tunnel.status().is_success(), "tunnel not up: {}", tunnel.status());
    eprintln!("Tunnel up. Assigned {} / {:?}", tunnel.assigned_v4(), tunnel.assigned_v6());

    let net = netstack::spawn(tunnel.io(), tunnel.assigned_v4(), tunnel.assigned_v6());

    let listener = TcpListener::bind(&bind).await?;
    eprintln!("SOCKS5 proxy on {bind} — traffic egresses via WARP.");
    eprintln!("Try: curl --socks5-hostname {bind} https://www.cloudflare.com/cdn-cgi/trace");

    // Keep `tunnel` alive for the process lifetime (it owns the QUIC resources).
    let _tunnel = tunnel;
    socks::serve(listener, net).await;
    Ok(())
}
