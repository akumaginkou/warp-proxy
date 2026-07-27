//! Cryptographic identity for a WARP MASQUE device.
//!
//! Cloudflare's MASQUE variant (unlike classic WireGuard WARP) identifies a
//! device with an **ECDSA P-256 (secp256r1)** keypair. Registration enrolls the
//! public key; the tunnel later authenticates with a short-lived self-signed
//! certificate wrapping this same key (mTLS), while the server is trusted by
//! pinning its advertised public key rather than by PKI validation.
//!
//! Wire encodings (must match what Cloudflare's API expects):
//! - private key: SEC1 `ECPrivateKey` DER, then base64 — stored in config.json.
//! - public key : SPKI (`SubjectPublicKeyInfo`) DER, then base64 — sent on enroll.
//!
//! These mirror Go's `x509.MarshalECPrivateKey` / `x509.MarshalPKIXPublicKey`,
//! which is what the reference client emits. (Protocol behaviour is referenced
//! from the public WARP API; no third-party source is copied — see DESIGN.md.)

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::pkcs8::EncodePublicKey;
use p256::SecretKey;
use rand::RngCore;

use crate::error::{Error, Result};

/// A device's P-256 identity keypair.
#[derive(Clone)]
pub struct DeviceKeypair {
    secret: SecretKey,
}

impl DeviceKeypair {
    /// Generate a fresh random P-256 keypair.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::random(&mut rand::rngs::OsRng),
        }
    }

    /// Restore a keypair from its base64(SEC1 DER) private-key encoding
    /// (as persisted in config.json).
    pub fn from_private_b64(b64: &str) -> Result<Self> {
        let der = B64
            .decode(b64.trim())
            .map_err(|e| Error::Key(format!("base64 private key: {e}")))?;
        let secret = SecretKey::from_sec1_der(&der)
            .map_err(|e| Error::Key(format!("parse SEC1 private key: {e}")))?;
        Ok(Self { secret })
    }

    /// base64(SEC1 `ECPrivateKey` DER) — the value stored as `private_key`.
    pub fn private_b64(&self) -> Result<String> {
        let doc = self
            .secret
            .to_sec1_der()
            .map_err(|e| Error::Key(format!("encode SEC1 private key: {e}")))?;
        Ok(B64.encode(doc.as_slice()))
    }

    /// base64(SPKI DER) of the public key — the value sent in the enroll `key`
    /// field.
    pub fn public_spki_b64(&self) -> Result<String> {
        let der = self
            .secret
            .public_key()
            .to_public_key_der()
            .map_err(|e| Error::Key(format!("encode SPKI public key: {e}")))?;
        Ok(B64.encode(der.as_bytes()))
    }

    /// The underlying [`SecretKey`], used later to build the tunnel's mTLS cert.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

/// A random 32-byte value, base64-encoded, used as the throwaway WireGuard-style
/// public key sent on the first `/reg` call purely to mimic the official app's
/// account-creation step. It is never used for the tunnel.
pub fn random_wg_pubkey_b64() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

/// A random 8-byte value as a 16-char lowercase hex string, mimicking an Android
/// device serial in the registration body.
pub fn random_android_serial() -> String {
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_roundtrips() {
        let kp = DeviceKeypair::generate();
        let b64 = kp.private_b64().unwrap();
        let restored = DeviceKeypair::from_private_b64(&b64).unwrap();
        // Same key => same public SPKI encoding.
        assert_eq!(
            kp.public_spki_b64().unwrap(),
            restored.public_spki_b64().unwrap()
        );
    }

    #[test]
    fn encodings_are_base64_der() {
        let kp = DeviceKeypair::generate();
        // SEC1 EC private keys start with the SEQUENCE tag 0x30.
        let priv_der = B64.decode(kp.private_b64().unwrap()).unwrap();
        assert_eq!(priv_der[0], 0x30);
        // SPKI public keys also start with 0x30 and are 91 bytes for P-256.
        let pub_der = B64.decode(kp.public_spki_b64().unwrap()).unwrap();
        assert_eq!(pub_der[0], 0x30);
        assert_eq!(pub_der.len(), 91);
    }

    #[test]
    fn helpers_have_expected_shape() {
        assert_eq!(random_android_serial().len(), 16);
        // 32 bytes base64 (no padding needed: 32 -> 44 chars incl. '=').
        assert_eq!(random_wg_pubkey_b64().len(), 44);
    }
}
