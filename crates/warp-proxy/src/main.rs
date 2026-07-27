//! `warp-proxy` daemon: register/load a pool of Cloudflare WARP accounts, front
//! them with a local SOCKS5 load-balancer, and expose a token-guarded control
//! API — so any project (Electron, a browser, a CLI) can point at the SOCKS port
//! and drive egress selection over the control API.
//!
//! On startup it prints ONE line of JSON to stdout (the handshake) so a parent
//! process can discover the ports + token:
//!
//! ```json
//! {"socksPort":1080,"controlUrl":"http://127.0.0.1:47100","controlToken":"…"}
//! ```
//!
//! All logs go to stderr. It runs until SIGINT/SIGTERM, then stops.
//!
//! Usage:
//!   warp-proxy [--accounts N] [--socks ADDR] [--control ADDR]
//!              [--state-dir DIR] [--http2]

use std::path::PathBuf;

use anyhow::Context;
use rand::RngCore;
use tokio::net::TcpListener;

use warp_masque::{control, socks, Pool, RegisterOptions, RegistrationClient, WarpConfig};

struct Args {
    accounts: usize,
    socks: String,
    control: String,
    state_dir: Option<PathBuf>,
    http2: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        accounts: 2,
        socks: "127.0.0.1:1080".into(),
        control: "127.0.0.1:47100".into(),
        state_dir: None,
        http2: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--accounts" => a.accounts = it.next().and_then(|v| v.parse().ok()).unwrap_or(a.accounts),
            "--socks" => a.socks = it.next().unwrap_or(a.socks),
            "--control" => a.control = it.next().unwrap_or(a.control),
            "--state-dir" => a.state_dir = it.next().map(PathBuf::from),
            "--http2" => a.http2 = true,
            other => eprintln!("[warp-proxy] ignoring unknown arg {other:?}"),
        }
    }
    a.accounts = a.accounts.max(1);
    a
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args();

    let configs = load_or_register(args.state_dir.as_deref(), args.accounts)
        .await
        .context("provisioning accounts")?;

    eprintln!("[warp-proxy] establishing {} tunnel(s)…", configs.len());
    let pool = Pool::new(configs, args.http2).await;

    let token = gen_token();
    let socks_listener = TcpListener::bind(&args.socks)
        .await
        .with_context(|| format!("binding SOCKS {}", args.socks))?;
    let control_listener = TcpListener::bind(&args.control)
        .await
        .with_context(|| format!("binding control {}", args.control))?;

    let socks_port = socks_listener.local_addr()?.port();
    let control_addr = control_listener.local_addr()?;

    // Handshake line on stdout for a parent process; nothing else goes to stdout.
    let handshake = serde_json::json!({
        "socksPort": socks_port,
        "controlUrl": format!("http://{control_addr}"),
        "controlToken": token,
    });
    println!("{handshake}");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    eprintln!("[warp-proxy] SOCKS5 on {} · control http://{control_addr}", socks_listener.local_addr()?);

    tokio::spawn(control::serve(control_listener, pool.clone(), token));
    tokio::spawn(socks::serve_pool(socks_listener, pool));

    shutdown_signal().await;
    eprintln!("[warp-proxy] shutting down");
    Ok(())
}

/// Load persisted account configs from `state_dir` (registering any that are
/// missing and saving them), or register `n` throwaway accounts if no dir given.
async fn load_or_register(state_dir: Option<&std::path::Path>, n: usize) -> anyhow::Result<Vec<WarpConfig>> {
    let mut out = Vec::with_capacity(n);
    for i in 1..=n {
        let opts = RegisterOptions {
            device_name: Some(format!("warp-proxy-{i}")),
            ..Default::default()
        };
        if let Some(dir) = state_dir {
            let path = dir.join(format!("account-{i}.json"));
            if path.exists() {
                eprintln!("[warp-proxy] loading account {i} from {}", path.display());
                out.push(WarpConfig::load(&path).with_context(|| format!("loading {}", path.display()))?);
                continue;
            }
            eprintln!("[warp-proxy] registering account {i}…");
            let cfg = RegistrationClient::register_auto(&opts).await?;
            std::fs::create_dir_all(dir).ok();
            cfg.save(&path).with_context(|| format!("saving {}", path.display()))?;
            out.push(cfg);
        } else {
            eprintln!("[warp-proxy] registering account {i} (ephemeral)…");
            out.push(RegistrationClient::register_auto(&opts).await?);
        }
    }
    Ok(out)
}

/// A 16-byte hex control token.
fn gen_token() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Resolve when the process receives SIGINT or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
