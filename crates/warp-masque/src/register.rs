//! Cloudflare WARP device registration (MASQUE variant).
//!
//! Two-step flow, mirroring the official Android app:
//!  1. `POST /{ver}/reg` with a throwaway WireGuard-style key to create a free
//!     account and obtain a device `id` + bearer `token`.
//!  2. `PATCH /{ver}/reg/{id}` (Bearer auth) to enroll the real P-256 MASQUE key
//!     and switch the device to `tunnel_type=masque`.
//!
//! The enroll response carries the MASQUE endpoints, the endpoint's pinned
//! public key, and our assigned tunnel addresses, which we fold into a
//! [`WarpConfig`].
//!
//! API host/version/headers are Cloudflare-internal (undocumented) and tracked
//! from the public WARP app behaviour; they change with app releases, so they
//! live as constants here. See DESIGN.md for provenance.

use serde::Deserialize;

use crate::config::{strip_v4_port, strip_v6_brackets, WarpConfig, DEFAULT_ENDPOINT_H2_V4};
use crate::error::{Error, Result};
use crate::keys::{random_android_serial, random_wg_pubkey_b64, DeviceKeypair};

/// Base URL of the WARP registration API.
pub const API_URL: &str = "https://api.cloudflareclient.com";
/// API version path segment (tracks the mimicked app build; bumps over time).
pub const API_VERSION: &str = "v0a4471";
/// `User-Agent` sent on every registration call.
pub const USER_AGENT: &str = "WARP for Android";
/// `CF-Client-Version` sent on every registration call (`a-<appver>-<build>`).
pub const CF_CLIENT_VERSION: &str = "a-6.35-4471";

const KEY_TYPE_WG: &str = "curve25519";
const TUN_TYPE_WG: &str = "wireguard";
const KEY_TYPE_MASQUE: &str = "secp256r1";
const TUN_TYPE_MASQUE: &str = "masque";
const DEFAULT_MODEL: &str = "PC";
const DEFAULT_LOCALE: &str = "en_US";

/// Options controlling a registration.
#[derive(Debug, Clone)]
pub struct RegisterOptions {
    /// Device model string (default `"PC"`).
    pub model: String,
    /// Locale (default `"en_US"`).
    pub locale: String,
    /// Optional device name shown in the WARP account's device list.
    pub device_name: Option<String>,
    /// Optional ZeroTrust team JWT (`CF-Access-Jwt-Assertion`).
    pub jwt: Option<String>,
}

impl Default for RegisterOptions {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.to_string(),
            locale: DEFAULT_LOCALE.to_string(),
            device_name: None,
            jwt: None,
        }
    }
}

/// A client for the WARP registration REST API.
///
/// The provided [`reqwest::Client`] owns TLS/connection behaviour; callers who
/// need DoH-bypass resolution on DNS-filtered networks can supply a client
/// pre-configured with pinned resolution (see the `doh` module, added later).
pub struct RegistrationClient {
    http: reqwest::Client,
}

impl RegistrationClient {
    /// Build a client over the given reqwest client.
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Build a client with a sensible default reqwest client.
    pub fn with_default_client() -> Result<Self> {
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(Error::Http)?;
        Ok(Self::new(http))
    }

    /// Build a client that reaches `api.cloudflareclient.com` via DoH-resolved
    /// (and fallback) IPs, pinning the address while keeping the real TLS SNI —
    /// for networks that poison the API hostname. No admin / hosts-file edit.
    pub async fn with_doh_bypass() -> Result<Self> {
        let addrs = crate::doh::api_addrs().await;
        if addrs.is_empty() {
            return Err(Error::Response(
                "DoH bypass could not resolve api.cloudflareclient.com".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .resolve_to_addrs(crate::doh::API_HOST, &addrs)
            .build()
            .map_err(Error::Http)?;
        Ok(Self::new(http))
    }

    /// Register, trying a direct connection first and falling back to the DoH
    /// bypass if the direct attempt fails (e.g. poisoned DNS).
    pub async fn register_auto(opts: &RegisterOptions) -> Result<WarpConfig> {
        let direct = Self::with_default_client()?;
        match direct.register(opts).await {
            Ok(cfg) => Ok(cfg),
            Err(direct_err) => {
                let bypass = Self::with_doh_bypass().await.map_err(|bypass_err| {
                    Error::Response(format!(
                        "direct register failed ({direct_err}); DoH bypass unavailable ({bypass_err})"
                    ))
                })?;
                bypass.register(opts).await.map_err(|bypass_err| {
                    Error::Response(format!(
                        "register failed (direct: {direct_err}; doh-bypass: {bypass_err})"
                    ))
                })
            }
        }
    }

    /// Run the full register + enroll flow and return a ready [`WarpConfig`].
    pub async fn register(&self, opts: &RegisterOptions) -> Result<WarpConfig> {
        let account = self.create_account(opts).await?;
        let token = account
            .token
            .clone()
            .ok_or_else(|| Error::Response("register response had no token".into()))?;

        let keypair = DeviceKeypair::generate();
        let enrolled = self
            .enroll_key(&account.id, &token, &keypair, opts.device_name.as_deref())
            .await?;

        build_config(&keypair, &token, &enrolled)
    }

    /// Step 1: create a free account with a throwaway WG key.
    async fn create_account(&self, opts: &RegisterOptions) -> Result<AccountData> {
        let body = serde_json::json!({
            "key": random_wg_pubkey_b64(),
            "install_id": "",
            "fcm_token": "",
            "tos": cf_timestamp_now(),
            "model": opts.model,
            "serial_number": random_android_serial(),
            "os_version": "",
            "key_type": KEY_TYPE_WG,
            "tunnel_type": TUN_TYPE_WG,
            "locale": opts.locale,
        });

        let url = format!("{API_URL}/{API_VERSION}/reg");
        let mut req = self.base_request(reqwest::Method::POST, &url).json(&body);
        if let Some(jwt) = &opts.jwt {
            req = req.header("CF-Access-Jwt-Assertion", jwt);
        }
        self.send_json(req).await
    }

    /// Step 2: enroll the real P-256 MASQUE public key.
    async fn enroll_key(
        &self,
        device_id: &str,
        token: &str,
        keypair: &DeviceKeypair,
        device_name: Option<&str>,
    ) -> Result<AccountData> {
        let mut body = serde_json::json!({
            "key": keypair.public_spki_b64()?,
            "key_type": KEY_TYPE_MASQUE,
            "tunnel_type": TUN_TYPE_MASQUE,
        });
        if let Some(name) = device_name {
            body["name"] = serde_json::Value::String(name.to_string());
        }

        let url = format!("{API_URL}/{API_VERSION}/reg/{device_id}");
        let req = self
            .base_request(reqwest::Method::PATCH, &url)
            .bearer_auth(token)
            .json(&body);
        self.send_json(req).await
    }

    /// A request pre-populated with the common WARP headers.
    fn base_request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header("User-Agent", USER_AGENT)
            .header("CF-Client-Version", CF_CLIENT_VERSION)
            .header("Content-Type", "application/json; charset=UTF-8")
            .header("Connection", "Keep-Alive")
    }

    /// Send a request and decode a JSON [`AccountData`], surfacing API errors.
    async fn send_json(&self, req: reqwest::RequestBuilder) -> Result<AccountData> {
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(Error::Json)
    }
}

/// Assemble a [`WarpConfig`] from the enroll response.
fn build_config(keypair: &DeviceKeypair, token: &str, data: &AccountData) -> Result<WarpConfig> {
    let peer = data
        .config
        .peers
        .first()
        .ok_or_else(|| Error::Response("enroll response had no peers".into()))?;

    Ok(WarpConfig {
        private_key: keypair.private_b64()?,
        endpoint_v4: strip_v4_port(&peer.endpoint.v4)?,
        endpoint_v6: strip_v6_brackets(&peer.endpoint.v6)?,
        endpoint_h2_v4: DEFAULT_ENDPOINT_H2_V4.to_string(),
        endpoint_h2_v6: String::new(),
        endpoint_pub_key: peer.public_key.clone(),
        id: data.id.clone(),
        access_token: token.to_string(),
        ipv4: data.config.interface.addresses.v4.clone(),
        ipv6: data.config.interface.addresses.v6.clone(),
    })
}

/// Format the current local time as Cloudflare expects for the `tos` field:
/// `YYYY-MM-DDTHH:MM:SS.mmm±HH:MM`.
fn cf_timestamp_now() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
        .to_string()
}

// ---- API response shapes (only the fields we consume) ----------------------

#[derive(Debug, Deserialize)]
struct AccountData {
    id: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    config: RegConfig,
}

#[derive(Debug, Default, Deserialize)]
struct RegConfig {
    #[serde(default)]
    peers: Vec<Peer>,
    #[serde(default)]
    interface: Interface,
}

#[derive(Debug, Default, Deserialize)]
struct Peer {
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    endpoint: Endpoint,
}

#[derive(Debug, Default, Deserialize)]
struct Endpoint {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

#[derive(Debug, Default, Deserialize)]
struct Interface {
    #[serde(default)]
    addresses: Addresses,
}

#[derive(Debug, Default, Deserialize)]
struct Addresses {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_timestamp_shape() {
        let ts = cf_timestamp_now();
        // e.g. 2026-07-27T12:34:56.789+09:00
        assert_eq!(ts.len(), 29, "unexpected timestamp {ts:?}");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[19..20], ".");
    }

    #[test]
    fn build_config_maps_fields() {
        let kp = DeviceKeypair::generate();
        let data = AccountData {
            id: "device-123".into(),
            token: Some("tok".into()),
            config: RegConfig {
                peers: vec![Peer {
                    public_key: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
                        .into(),
                    endpoint: Endpoint {
                        v4: "162.159.198.1:0".into(),
                        v6: "[2606:4700:103::]:0".into(),
                    },
                }],
                interface: Interface {
                    addresses: Addresses {
                        v4: "100.96.0.3/32".into(),
                        v6: "2606:4700:110::1/128".into(),
                    },
                },
            },
        };
        let cfg = build_config(&kp, "tok", &data).unwrap();
        assert_eq!(cfg.endpoint_v4, "162.159.198.1");
        assert_eq!(cfg.endpoint_v6, "2606:4700:103::");
        assert_eq!(cfg.endpoint_h2_v4, DEFAULT_ENDPOINT_H2_V4);
        assert_eq!(cfg.id, "device-123");
        assert_eq!(cfg.ipv4, "100.96.0.3/32");
        assert!(cfg.endpoint_pub_key.contains("BEGIN PUBLIC KEY"));
    }
}
