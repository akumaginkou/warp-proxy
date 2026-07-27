//! Egress trace: fetch `cdn-cgi/trace` through a worker's netstack to report its
//! current egress IP / colo and whether WARP is active.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::netstack::NetHandle;
use crate::tls::insecure_client_config;

/// Parsed result of Cloudflare's `cdn-cgi/trace` for one account.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TraceInfo {
    pub ip: String,
    pub colo: String,
    /// `"on"` / `"off"` / `"plus"`.
    pub warp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

const TRACE_HOST: &str = "www.cloudflare.com";

/// Fetch the egress trace through `net`, capturing any error into the result.
pub async fn fetch_trace(net: &NetHandle) -> TraceInfo {
    match tokio::time::timeout(Duration::from_secs(15), do_fetch(net)).await {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => TraceInfo { err: Some(e), ..Default::default() },
        Err(_) => TraceInfo { err: Some("trace timeout".into()), ..Default::default() },
    }
}

async fn do_fetch(net: &NetHandle) -> Result<TraceInfo, String> {
    let ip = net.resolve(TRACE_HOST).await?;
    let conn = net.connect(SocketAddr::new(ip, 443)).await?;

    let cfg = insecure_client_config(&[b"http/1.1"]).map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let sni = rustls::pki_types::ServerName::try_from(TRACE_HOST).map_err(|e| e.to_string())?;
    let mut tls = connector.connect(sni, conn).await.map_err(|e| e.to_string())?;

    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\nUser-Agent: warp-proxy\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");

    let mut info = TraceInfo::default();
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "ip" => info.ip = v.trim().to_string(),
                "warp" => info.warp = v.trim().to_string(),
                "colo" => info.colo = v.trim().to_string(),
                _ => {}
            }
        }
    }
    if info.ip.is_empty() && info.warp.is_empty() {
        return Err("no trace fields in response".into());
    }
    Ok(info)
}
