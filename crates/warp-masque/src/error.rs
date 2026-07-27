//! Error types for the warp-masque client.

use thiserror::Error;

/// Errors returned by registration, config handling and (later) the tunnel.
#[derive(Debug, Error)]
pub enum Error {
    /// A key could not be generated or encoded.
    #[error("key error: {0}")]
    Key(String),

    /// The Cloudflare registration API returned a non-success status.
    #[error("registration API returned HTTP {status}: {body}")]
    Api { status: u16, body: String },

    /// The registration response was missing a field we need.
    #[error("unexpected registration response: {0}")]
    Response(String),

    /// A config file could not be read/written or parsed.
    #[error("config error: {0}")]
    Config(String),

    /// Network / HTTP transport failure.
    #[error("http transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON (de)serialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Filesystem I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// MASQUE tunnel setup/transport failure.
    #[error("tunnel error: {0}")]
    Tunnel(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
