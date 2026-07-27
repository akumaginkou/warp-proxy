//! A minimal, token-guarded HTTP control API over loopback for driving the
//! [`Pool`] live: status, WARP on/off, account select/rotate/reconnect, transport
//! toggle, egress trace, and account add/remove.
//!
//! It speaks just enough HTTP/1.1 to avoid a heavy dependency. Every request
//! must carry the shared `X-Warp-Token` header (the API is reachable from any
//! page the user visits, so this prevents a hostile site from toggling WARP off).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::pool::Pool;

/// Serve the control API on `listener`, guarded by `token`.
pub async fn serve(listener: TcpListener, pool: Arc<Pool>, token: String) {
    let token = Arc::new(token);
    loop {
        let Ok((conn, _)) = listener.accept().await else { continue };
        let pool = pool.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _ = handle(conn, pool, token).await;
        });
    }
}

async fn handle(mut conn: TcpStream, pool: Arc<Pool>, token: Arc<String>) -> std::io::Result<()> {
    // Read the request head (we don't need a body — args are query params).
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = conn.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // CORS preflight needs no token.
    if method == "OPTIONS" {
        return write_resp(&mut conn, "204 No Content", "").await;
    }

    let presented = lines
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("x-warp-token").then(|| v.trim().to_string())
        })
        .unwrap_or_default();
    if presented != *token {
        return write_json(&mut conn, "403 Forbidden", "{\"error\":\"forbidden\"}").await;
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match route(&pool, path, query).await {
        Ok(body) => write_json(&mut conn, "200 OK", &body).await,
        Err(msg) => {
            let body = format!("{{\"error\":{}}}", json_string(&msg));
            write_json(&mut conn, "400 Bad Request", &body).await
        }
    }
}

/// Dispatch one API call, returning the JSON body to send.
async fn route(pool: &Arc<Pool>, path: &str, query: &str) -> Result<String, String> {
    match path {
        "/api/status" => {}
        "/api/toggle" => pool.set_enabled(bool_param(query, "on", true)),
        "/api/select" => pool.select(int_param(query, "slot").unwrap_or(0) as usize),
        "/api/reconnect" => pool
            .reconnect(int_param(query, "slot").unwrap_or(0) as usize)
            .await
            .map_err(|e| e.to_string())?,
        "/api/rotate" => pool
            .rotate(int_param(query, "slot").unwrap_or(0) as usize)
            .await
            .map_err(|e| e.to_string())?,
        "/api/http2" => pool
            .set_http2(bool_param(query, "on", false))
            .await
            .map_err(|e| e.to_string())?,
        "/api/trace" => pool.refresh_trace(int_param(query, "slot").unwrap_or(0) as usize).await,
        "/api/account/add" => {
            pool.add_account().await.map_err(|e| e.to_string())?;
        }
        "/api/account/remove" => {
            let slot = int_param(query, "slot").ok_or("missing slot")? as usize;
            pool.remove_account(slot).map_err(|e| e.to_string())?;
        }
        _ => return Err(format!("no such endpoint {path}")),
    }
    serde_json::to_string(&pool.status()).map_err(|e| e.to_string())
}

fn bool_param(query: &str, key: &str, default: bool) -> bool {
    match param(query, key).as_deref() {
        Some("1" | "true" | "on" | "yes") => true,
        Some("0" | "false" | "off" | "no") => false,
        _ => default,
    }
}

fn int_param(query: &str, key: &str) -> Option<i64> {
    param(query, key)?.parse().ok()
}

fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

fn json_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ");
    format!("\"{escaped}\"")
}

async fn write_json(conn: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type, x-warp-token\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes()).await
}

async fn write_resp(conn: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: content-type, x-warp-token\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes()).await
}
