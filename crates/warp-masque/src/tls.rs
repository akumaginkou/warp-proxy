//! mTLS identity and endpoint pinning for the MASQUE tunnel.
//!
//! The tunnel authenticates the device with a **self-signed** certificate that
//! wraps the enrolled P-256 key (the server issues no client cert). The server
//! in turn is trusted not via PKI — its SNI deliberately does not match the
//! endpoint IP — but by **pinning** its certificate's public key to the
//! `endpoint_pub_key` captured at registration.
//!
//! All crypto goes through rustls' `ring` provider so the crate builds without a
//! C toolchain.

use std::sync::Arc;

use p256::pkcs8::{DecodePublicKey, EncodePrivateKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::{DigitallySignedStruct, SignatureScheme};
use x509_cert::der::{Decode, Encode};

use crate::config::WarpConfig;
use crate::error::{Error, Result};
use crate::keys::DeviceKeypair;

/// A self-signed X.509 (DER) plus its PKCS#8 private key (DER), ready to hand to
/// rustls as a client-auth identity.
pub struct ClientIdentity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivatePkcs8KeyDer<'static>,
}

/// Build a short-lived self-signed certificate over the device's P-256 key.
pub fn self_signed_identity(kp: &DeviceKeypair) -> Result<ClientIdentity> {
    // Export the device key as PKCS#8 DER and hand it to rcgen (P-256 / SHA-256).
    let pkcs8 = kp
        .secret()
        .to_pkcs8_der()
        .map_err(|e| Error::Key(format!("pkcs8 encode: {e}")))?;
    let key_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());

    let rcgen_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &key_der,
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| Error::Key(format!("rcgen key: {e}")))?;

    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| Error::Key(e.to_string()))?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::hours(24);

    let cert = params
        .self_signed(&rcgen_key)
        .map_err(|e| Error::Key(format!("self-sign: {e}")))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());

    Ok(ClientIdentity { cert_der, key_der })
}

/// Verifier that accepts the endpoint solely when its certificate carries the
/// pinned P-256 public key. The TLS handshake signature is still checked
/// normally (so a MITM without the pinned private key cannot complete it).
#[derive(Debug)]
struct PinnedVerifier {
    pinned: p256::PublicKey,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let cert = x509_cert::Certificate::from_der(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("parse server cert: {e}")))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| rustls::Error::General(format!("encode server spki: {e}")))?;
        let got = p256::PublicKey::from_public_key_der(&spki_der)
            .map_err(|e| rustls::Error::General(format!("server key not P-256: {e}")))?;
        if got == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "endpoint public key mismatch (pin failed)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Build the rustls `ClientConfig` for the tunnel: client-auth with the device's
/// self-signed cert, server trust by pinning `endpoint_pub_key`, and the given
/// ALPN protocol(s) (`b"h3"` for QUIC, `b"h2"` for the HTTP/2 fallback).
pub fn tunnel_client_config(
    cfg: &WarpConfig,
    kp: &DeviceKeypair,
    alpn: &[&[u8]],
) -> Result<rustls::ClientConfig> {
    let pinned = p256::PublicKey::from_public_key_pem(cfg.endpoint_pub_key.trim())
        .map_err(|e| Error::Config(format!("endpoint_pub_key not P-256 PEM: {e}")))?;

    let provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinnedVerifier { pinned, algs });

    let identity = self_signed_identity(kp)?;

    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(format!("rustls versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.cert_der], identity.key_der.into())
        .map_err(|e| Error::Config(format!("client auth cert: {e}")))?;

    client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(client)
}

/// Verifier that accepts any server certificate (still checks the handshake
/// signature). Used only for the read-only egress trace, which fetches our own
/// public trace page — a wrong cert would just yield wrong trace info, not leak
/// anything.
#[derive(Debug)]
struct AcceptAny {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A rustls client config that accepts any server certificate, with the given
/// ALPN. For the egress trace only — never for tunnel traffic.
pub fn insecure_client_config(alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(format!("rustls versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny { algs }))
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_cert_is_parseable_and_matches_key() {
        let kp = DeviceKeypair::generate();
        let id = self_signed_identity(&kp).unwrap();
        // Parses as X.509 and its SPKI equals the device public key.
        let cert = x509_cert::Certificate::from_der(id.cert_der.as_ref()).unwrap();
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let cert_pub = p256::PublicKey::from_public_key_der(&spki).unwrap();
        let device_pub = kp.secret().public_key();
        assert_eq!(cert_pub, device_pub);
    }
}
