//! Run a multi-account WARP pool: N tunnels (= N egress IPs) behind one SOCKS5
//! load-balancer, with a token-guarded control API.
//!
//! Usage:
//!   cargo run -p warp-masque --example pool -- [N] [SOCKS_BIND] [CTRL_BIND] [--http2]
//!
//! Defaults: N=2, SOCKS_BIND=127.0.0.1:1080, CTRL_BIND=127.0.0.1:47100.
//! It registers N fresh accounts each run (throwaway). Then:
//!   curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
//!   curl -H "X-Warp-Token: <printed>" http://127.0.0.1:47100/api/status

use warp_masque::pool::Pool;
use warp_masque::register::{RegisterOptions, RegistrationClient};
use warp_masque::{control, socks};

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut n = 2usize;
    let mut socks_bind = String::from("127.0.0.1:1080");
    let mut ctrl_bind = String::from("127.0.0.1:47100");
    let mut http2 = false;
    let mut pos = 0;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--http2" => http2 = true,
            _ if pos == 0 => {
                n = arg.parse().unwrap_or(2);
                pos += 1;
            }
            _ if pos == 1 => {
                socks_bind = arg;
                pos += 1;
            }
            _ => {
                ctrl_bind = arg;
                pos += 1;
            }
        }
    }

    eprintln!("Registering {n} WARP accounts…");
    let mut configs = Vec::new();
    for i in 1..=n {
        let opts = RegisterOptions {
            device_name: Some(format!("warp-proxy-{i}")),
            ..Default::default()
        };
        configs.push(RegistrationClient::register_auto(&opts).await?);
    }

    eprintln!("Establishing {n} tunnels…");
    let pool = Pool::new(configs, http2).await;

    let token = gen_token();
    let socks_listener = TcpListener::bind(&socks_bind).await?;
    let ctrl_listener = TcpListener::bind(&ctrl_bind).await?;

    eprintln!("SOCKS5 LB on {socks_bind} (round-robin across {n} egress IPs).");
    eprintln!("Control API on http://{ctrl_bind}  token: {token}");
    eprintln!("  curl --socks5-hostname {socks_bind} https://www.cloudflare.com/cdn-cgi/trace");
    eprintln!("  curl -H 'X-Warp-Token: {token}' http://{ctrl_bind}/api/status");

    tokio::spawn(control::serve(ctrl_listener, pool.clone(), token));
    socks::serve_pool(socks_listener, pool).await;
    Ok(())
}

/// A simple random-ish token (avoids adding a rand dep here; derived from the
/// per-account keys' entropy is overkill for a local demo).
fn gen_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{nanos:x}")
}
