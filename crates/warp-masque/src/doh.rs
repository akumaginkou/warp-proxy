//! DNS-over-HTTPS bootstrap for registration on DNS-filtered networks.
//!
//! Some networks poison `api.cloudflareclient.com` (Cisco Umbrella, NextDNS,
//! captive filters). Registration still works if we resolve that hostname
//! out-of-band via DoH over 1.1.1.1 — reached by IP with SNI `cloudflare-dns.com`
//! so it needs no system DNS — and then pin the resulting IP while keeping the
//! real TLS SNI. The MASQUE tunnel itself dials Cloudflare anycast by IP, so it
//! is unaffected by poisoned DNS.

use std::net::{IpAddr, SocketAddr};

use crate::error::{Error, Result};

/// 1.1.1.1, reached by IP (no system DNS needed).
const DOH_IP: &str = "1.1.1.1";
/// The name 1.1.1.1's certificate is issued for.
const DOH_SNI: &str = "cloudflare-dns.com";

/// Known-good Cloudflare IPs for `api.cloudflareclient.com`, tried if DoH itself
/// is blocked/intercepted.
pub const API_FALLBACK_IPS: [&str; 2] = ["104.16.24.84", "104.16.192.82"];

/// The registration API host.
pub const API_HOST: &str = "api.cloudflareclient.com";

/// Resolve `host` to its A records via DoH over 1.1.1.1.
pub async fn resolve_a(host: &str) -> Result<Vec<IpAddr>> {
    let doh_addr: SocketAddr = format!("{DOH_IP}:443")
        .parse()
        .map_err(|e| Error::Config(format!("doh addr: {e}")))?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .resolve(DOH_SNI, doh_addr)
        .build()?;

    let url = format!("https://{DOH_SNI}/dns-query?name={host}&type=A");
    let resp = client
        .get(url)
        .header("accept", "application/dns-json")
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;

    let mut ips = Vec::new();
    if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
        for a in answers {
            // type 1 = A record
            if a.get("type").and_then(|t| t.as_u64()) == Some(1) {
                if let Some(data) = a.get("data").and_then(|d| d.as_str()) {
                    if let Ok(ip) = data.parse::<IpAddr>() {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    Ok(ips)
}

/// The candidate `host:443` addresses for the registration API: DoH-resolved
/// first, then baked-in fallbacks (deduped).
pub async fn api_addrs() -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut push = |ip: IpAddr, out: &mut Vec<SocketAddr>| {
        if seen.insert(ip) {
            out.push(SocketAddr::new(ip, 443));
        }
    };
    if let Ok(ips) = resolve_a(API_HOST).await {
        for ip in ips {
            push(ip, &mut out);
        }
    }
    for f in API_FALLBACK_IPS {
        if let Ok(ip) = f.parse::<IpAddr>() {
            push(ip, &mut out);
        }
    }
    out
}
