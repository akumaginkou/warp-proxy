//! Register a fresh WARP MASQUE device and write its config.json.
//!
//! Usage:
//!   cargo run -p warp-masque --example register -- [OUT_PATH] [--name NAME]
//!
//! Registering creates a free, throwaway Cloudflare WARP account. OUT_PATH
//! defaults to `./warp-config.json`. Requires network access to
//! api.cloudflareclient.com.

use warp_masque::{RegisterOptions, RegistrationClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut out = String::from("warp-config.json");
    let mut name: Option<String> = None;
    let mut doh = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = args.next(),
            "--doh" => doh = true,
            other => out = other.to_string(),
        }
    }

    let opts = RegisterOptions {
        device_name: name,
        ..Default::default()
    };

    let cfg = if doh {
        eprintln!("Registering via DoH bypass (pinned api.cloudflareclient.com)…");
        RegistrationClient::with_doh_bypass().await?.register(&opts).await?
    } else {
        eprintln!("Registering a new WARP MASQUE device (auto direct→DoH)…");
        RegistrationClient::register_auto(&opts).await?
    };
    cfg.save(&out)?;

    eprintln!("OK — device {}", cfg.id);
    eprintln!("  endpoint_v4 : {}", cfg.endpoint_v4);
    eprintln!("  endpoint_v6 : {}", cfg.endpoint_v6);
    eprintln!("  assigned v4 : {}", cfg.ipv4);
    eprintln!("  assigned v6 : {}", cfg.ipv6);
    eprintln!("  saved to    : {out}");
    Ok(())
}
