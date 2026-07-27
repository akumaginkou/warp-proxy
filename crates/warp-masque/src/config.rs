//! On-disk device configuration produced by registration and consumed by the
//! tunnel.
//!
//! The JSON schema is kept byte-compatible with the reference WARP MASQUE client
//! (`config.json`) so the two are interchangeable and easy to diff during
//! bring-up. Field meanings:
//! - `private_key`     : base64(SEC1 DER) of the device's P-256 private key.
//! - `endpoint_v4/v6`  : MASQUE anycast endpoints (QUIC/HTTP-3), no port.
//! - `endpoint_h2_v4/6`: endpoints used in the HTTP/2 (QUIC-blocked) fallback.
//! - `endpoint_pub_key`: PEM-encoded P-256 public key of the endpoint, pinned
//!                       during the tunnel TLS handshake.
//! - `id` / `access_token`: device id and REST bearer token (REST only; the
//!                       tunnel does not use the token).
//! - `ipv4` / `ipv6`   : the addresses Cloudflare assigned to us inside the
//!                       tunnel (static; there is no ADDRESS_ASSIGN capsule).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Default HTTP/2-fallback IPv4 endpoint (the only endpoint the reference client
/// hardcodes; the HTTP/3 endpoints come from the registration response).
pub const DEFAULT_ENDPOINT_H2_V4: &str = "162.159.198.2";

/// A registered WARP MASQUE device.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WarpConfig {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    #[serde(default)]
    pub endpoint_h2_v4: String,
    #[serde(default)]
    pub endpoint_h2_v6: String,
    pub endpoint_pub_key: String,
    pub id: String,
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl WarpConfig {
    /// Load a config from a JSON file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref())?;
        let cfg: WarpConfig = serde_json::from_slice(&bytes)?;
        Ok(cfg)
    }

    /// Write the config as pretty JSON, with private permissions where the OS
    /// supports it (it holds the device private key + bearer token).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path.as_ref(), &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path.as_ref(), perms)?;
        }
        Ok(())
    }
}

/// Strip the trailing `:port` from an IPv4 `host:port` endpoint string, e.g.
/// `"162.159.198.1:0"` -> `"162.159.198.1"`. Tolerant of an already-bare host.
pub(crate) fn strip_v4_port(s: &str) -> Result<String> {
    let s = s.trim();
    match s.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => Ok(host.to_string()),
        _ if !s.is_empty() => Ok(s.to_string()),
        _ => Err(Error::Response(format!("empty IPv4 endpoint {s:?}"))),
    }
}

/// Extract the address from a bracketed IPv6 `[addr]:port` endpoint string, e.g.
/// `"[2606:4700:103::]:0"` -> `"2606:4700:103::"`. Tolerant of a bare address.
pub(crate) fn strip_v6_brackets(s: &str) -> Result<String> {
    let s = s.trim();
    if let (Some(start), Some(end)) = (s.find('['), s.rfind(']')) {
        if end > start {
            return Ok(s[start + 1..end].to_string());
        }
    }
    if !s.is_empty() {
        return Ok(s.to_string());
    }
    Err(Error::Response(format!("empty IPv6 endpoint {s:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v4_endpoint() {
        assert_eq!(strip_v4_port("162.159.198.1:0").unwrap(), "162.159.198.1");
        assert_eq!(strip_v4_port("162.159.198.1").unwrap(), "162.159.198.1");
    }

    #[test]
    fn parses_v6_endpoint() {
        assert_eq!(
            strip_v6_brackets("[2606:4700:103::]:0").unwrap(),
            "2606:4700:103::"
        );
        assert_eq!(
            strip_v6_brackets("2606:4700:103::").unwrap(),
            "2606:4700:103::"
        );
    }

    #[test]
    fn config_json_roundtrips() {
        let cfg = WarpConfig {
            private_key: "priv".into(),
            endpoint_v4: "162.159.198.1".into(),
            endpoint_v6: "2606:4700:103::".into(),
            endpoint_h2_v4: DEFAULT_ENDPOINT_H2_V4.into(),
            endpoint_pub_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n".into(),
            id: "dev".into(),
            access_token: "tok".into(),
            ipv4: "100.96.0.3".into(),
            ipv6: "2606:4700:110::1".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: WarpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.endpoint_v4, "162.159.198.1");
        assert_eq!(back.ipv4, "100.96.0.3");
    }
}
