//! Dial the MASQUE endpoint over QUIC and report whether the mTLS handshake
//! (client-cert auth + endpoint pinning) succeeds.
//!
//! Usage:
//!   cargo run -p warp-masque --example tunnel_poc -- [CONFIG_PATH]
//!
//! CONFIG_PATH defaults to `./warp-config.json` (produced by the `register`
//! example). Requires network access to the WARP MASQUE endpoint.

use warp_masque::tunnel::Tunnel;
use warp_masque::{DeviceKeypair, WarpConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "warp-config.json".into());
    let cfg = WarpConfig::load(&path)?;
    let kp = DeviceKeypair::from_private_b64(&cfg.private_key)?;

    eprintln!("Establishing MASQUE tunnel to {} (cf-connect-ip)…", cfg.endpoint_v4);
    let tunnel = Tunnel::connect(&cfg, &kp).await?;
    eprintln!("CONNECT-IP response status: {}", tunnel.status());
    if tunnel.status().is_success() {
        eprintln!("✅ MASQUE tunnel established (HTTP {}).", tunnel.status().as_u16());
        eprintln!("  assigned v4 : {}", tunnel.assigned_v4());
        eprintln!("  assigned v6 : {:?}", tunnel.assigned_v6());
        eprintln!("  max IP pkt  : {} bytes", tunnel.max_ip_packet());
    } else {
        eprintln!("⚠️  endpoint refused the CONNECT-IP session (HTTP {}).", tunnel.status().as_u16());
    }
    Ok(())
}
