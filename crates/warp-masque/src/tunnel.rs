//! MASQUE CONNECT-IP tunnel (Phase 0 core — in progress).
//!
//! This module will establish Cloudflare's MASQUE tunnel and expose a bytestream
//! of IP packets to a userspace netstack. It is the highest-risk part of the
//! project because Cloudflare's CONNECT-IP is **not** RFC-9484-clean; the
//! reference client uses a forked connect-ip implementation. The exact wire
//! contract to reproduce (verified against the public WARP client behaviour; see
//! DESIGN.md for provenance and citations):
//!
//! ## HTTP/3 path (default)
//! - Dial QUIC/UDP to the endpoint from [`WarpConfig::endpoint_v4`]/`_v6` on port
//!   [`MASQUE_PORT`], ALPN `h3`, TLS 1.3.
//! - TLS is **mTLS with a self-signed cert**: present a 24h self-signed X.509
//!   wrapping the device P-256 key; do NOT validate the server via PKI — instead
//!   pin the server cert's public key to `endpoint_pub_key`. SNI = [`CONNECT_SNI`]
//!   (which deliberately does not match the endpoint IP).
//! - Set QUIC connection id length to [`QUIC_CONNECTION_ID_LEN`] (the backend
//!   otherwise intermittently emits PROTOCOL_VIOLATION).
//! - Open HTTP/3 with datagrams enabled and additional setting
//!   [`H3_SETTING_DATAGRAM_00`]`=1` (legacy id the official client still sends).
//! - Issue an Extended CONNECT with `:protocol =` [`CONNECT_PROTOCOL`]
//!   (**`cf-connect-ip`**, the non-standard value), `:authority`/URI from
//!   [`CONNECT_URI`], an empty `User-Agent`, and the capsule protocol enabled.
//!   Proceed even if the peer did not advertise `ENABLE_CONNECT_PROTOCOL`.
//! - On HTTP 200, IP packets flow as HTTP Datagrams: each QUIC DATAGRAM is
//!   `varint(quarter_stream_id) || varint(context_id=0) || <full IP packet>`.
//!   Context id 0 (uncompressed full packet) is the only one used.
//!
//! ## HTTP/2 fallback (`--http2`, QUIC-blocked networks)
//! - TCP+TLS (ALPN `h2`) to [`config::DEFAULT_ENDPOINT_H2_V4`] on [`MASQUE_PORT`],
//!   same mTLS identity/pinning.
//! - Extended CONNECT (RFC 8441) with `:protocol = cf-connect-ip`, plus headers
//!   `cf-connect-proto: cf-connect-ip` and `pq-enabled: false`.
//! - Datagrams are carried by the Capsule Protocol (RFC 9297): each packet is a
//!   DATAGRAM capsule (type `0x00`) whose value is `varint(context_id=0) || IP`.
//!
//! ## Addressing / MTU
//! - Our tunnel addresses are **static** from registration
//!   ([`WarpConfig::ipv4`]/`ipv6`); there is no ADDRESS_ASSIGN capsule to await.
//! - Interface MTU is [`TUNNEL_MTU`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::config::WarpConfig;
use crate::error::{Error, Result};
use crate::keys::DeviceKeypair;
use crate::tls::tunnel_client_config;

/// UDP/TCP port for the MASQUE endpoints.
pub const MASQUE_PORT: u16 = 443;
/// TLS SNI used for the tunnel handshake (intentionally != endpoint IP).
pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
/// Extended-CONNECT `:protocol` value — Cloudflare's non-standard variant.
pub const CONNECT_PROTOCOL: &str = "cf-connect-ip";
/// The fixed request target used for the CONNECT-IP session.
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";
/// QUIC connection id length the backend expects to avoid PROTOCOL_VIOLATION.
pub const QUIC_CONNECTION_ID_LEN: usize = 20;
/// Legacy `SETTINGS_H3_DATAGRAM_00` id the official client still advertises.
pub const H3_SETTING_DATAGRAM_00: u64 = 0x276;
/// Tunnel interface MTU.
pub const TUNNEL_MTU: usize = 1280;
/// CONNECT-IP context id for a full (uncompressed) IP packet.
pub const CONTEXT_ID_FULL_PACKET: u64 = 0;

/// How to reach the MASQUE endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// QUIC / HTTP-3 (default).
    Http3,
    /// TCP / HTTP-2 fallback for QUIC-blocked networks.
    Http2,
}

/// Resolve the QUIC/HTTP-3 endpoint socket address from a config.
///
/// Prefers IPv4 (`endpoint_v4`); falls back to `endpoint_v6`.
pub fn quic_endpoint(cfg: &WarpConfig) -> Result<SocketAddr> {
    if let Ok(v4) = cfg.endpoint_v4.trim().parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(IpAddr::V4(v4), MASQUE_PORT));
    }
    if let Ok(v6) = cfg.endpoint_v6.trim().parse::<Ipv6Addr>() {
        return Ok(SocketAddr::new(IpAddr::V6(v6), MASQUE_PORT));
    }
    Err(Error::Config(format!(
        "no usable endpoint (v4={:?}, v6={:?})",
        cfg.endpoint_v4, cfg.endpoint_v6
    )))
}

/// Dial the MASQUE endpoint over QUIC (HTTP/3), presenting the device's mTLS
/// identity and pinning the endpoint's public key.
///
/// A completed handshake is itself meaningful: the server enforces client-cert
/// auth during the TLS handshake, so success means the enrolled key was
/// accepted **and** the endpoint matched its pinned key. This is the Phase 0b
/// milestone that de-risks the auth model; the HTTP/3 Extended CONNECT
/// (`cf-connect-ip`) and datagram layers build on the returned connection.
pub async fn dial_quic(
    cfg: &WarpConfig,
    kp: &DeviceKeypair,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let addr = quic_endpoint(cfg)?;

    let crypto = tunnel_client_config(cfg, kp)?;
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| Error::Tunnel(format!("quic tls config: {e}")))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30))
            .map_err(|e| Error::Tunnel(format!("idle timeout: {e}")))?,
    ));
    client_cfg.transport_config(Arc::new(transport));

    // Bind a UDP socket in the endpoint's address family.
    let bind: SocketAddr = if addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind)?;

    // Cloudflare's backend intermittently emits PROTOCOL_VIOLATION unless the
    // client uses 20-byte source connection IDs, so pin the generator length.
    let mut ep_cfg = quinn::EndpointConfig::default();
    ep_cfg.cid_generator(|| {
        Box::new(quinn_proto::RandomConnectionIdGenerator::new(
            QUIC_CONNECTION_ID_LEN,
        ))
    });

    let mut endpoint = quinn::Endpoint::new(ep_cfg, None, socket, Arc::new(quinn::TokioRuntime))
        .map_err(|e| Error::Tunnel(format!("quic endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(addr, CONNECT_SNI)
        .map_err(|e| Error::Tunnel(format!("connect: {e}")))?
        .await
        .map_err(|e| Error::Tunnel(format!("handshake: {e}")))?;

    Ok((endpoint, conn))
}

/// An established MASQUE CONNECT-IP tunnel.
///
/// Owns the QUIC connection and keeps the CONNECT-IP request stream + HTTP/3
/// driver alive for its lifetime. IP packets are exchanged with [`send_ip`] /
/// [`recv_ip`]; each is carried in one QUIC DATAGRAM framed per RFC 9297/9484 as
/// `varint(quarter_stream_id) || varint(context_id=0) || <IP packet>`.
///
/// [`send_ip`]: Tunnel::send_ip
/// [`recv_ip`]: Tunnel::recv_ip
pub struct Tunnel {
    quic: quinn::Connection,
    quarter_stream_id: u64,
    status: http::StatusCode,
    assigned_v4: Ipv4Addr,
    assigned_v6: Option<Ipv6Addr>,
    // Kept alive for the tunnel's lifetime: the endpoint drives QUIC I/O, the
    // driver services HTTP/3 control streams, and the request stream must stay
    // open to keep the CONNECT-IP session associated.
    _endpoint: quinn::Endpoint,
    _driver: tokio::task::JoinHandle<()>,
    _stream: Box<dyn std::any::Any + Send>,
    // h3 closes the connection once the last SendRequest handle is dropped, so
    // the tunnel must hold onto it for its lifetime.
    _send_request: Box<dyn std::any::Any + Send>,
}

impl Tunnel {
    /// Perform the full handshake: QUIC dial (mTLS + pinning) → HTTP/3 with
    /// datagrams → Extended CONNECT `:protocol=cf-connect-ip`. On HTTP 200 the
    /// tunnel is ready to carry IP packets.
    pub async fn connect(cfg: &WarpConfig, kp: &DeviceKeypair) -> Result<Tunnel> {
        let (endpoint, quic) = dial_quic(cfg, kp).await?;

        // Clone the connection handle for raw QUIC datagrams; h3-quinn's own
        // datagram support is a disabled feature, so it won't consume them.
        let dgram_conn = quic.clone();
        let h3_conn = h3_quinn::Connection::new(quic);

        let (mut driver, mut send_request) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build::<_, _, bytes::Bytes>(h3_conn)
            .await
            .map_err(|e| Error::Tunnel(format!("h3 connect: {e}")))?;

        let driver_handle = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(CONNECT_URI)
            .header("capsule-protocol", "?1")
            .header("user-agent", "")
            .extension(h3::ext::Protocol::CF_CONNECT_IP)
            .body(())
            .map_err(|e| Error::Tunnel(format!("build request: {e}")))?;

        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| Error::Tunnel(format!("send extended CONNECT: {e}")))?;

        // Keep the send side open: the request stream carries the IP datagrams.
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| Error::Tunnel(format!("recv response: {e}")))?;
        let status = resp.status();

        // HTTP/3 datagrams are keyed by the quarter stream id (RFC 9297 §2.4).
        let quarter_stream_id = stream.id().into_inner() / 4;

        let assigned_v4 = parse_assigned_v4(&cfg.ipv4)?;
        let assigned_v6 = parse_assigned_v6(&cfg.ipv6);

        Ok(Tunnel {
            quic: dgram_conn,
            quarter_stream_id,
            status,
            assigned_v4,
            assigned_v6,
            _endpoint: endpoint,
            _driver: driver_handle,
            _stream: Box::new(stream),
            _send_request: Box::new(send_request),
        })
    }

    /// The HTTP status the endpoint returned to the Extended CONNECT (200 = up).
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    /// The IPv4 address Cloudflare assigned us inside the tunnel.
    pub fn assigned_v4(&self) -> Ipv4Addr {
        self.assigned_v4
    }

    /// The IPv6 address Cloudflare assigned us inside the tunnel, if any.
    pub fn assigned_v6(&self) -> Option<Ipv6Addr> {
        self.assigned_v6
    }

    /// A cheap, `Send + Sync + Clone` handle for datagram I/O, detached from the
    /// tunnel's keep-alive resources. Hand these to the netstack / feeder while
    /// the owning [`Tunnel`] stays alive on the main task.
    pub fn io(&self) -> TunnelIo {
        TunnelIo {
            quic: self.quic.clone(),
            quarter_stream_id: self.quarter_stream_id,
        }
    }

    /// The largest IP packet that fits in one QUIC datagram.
    pub fn max_ip_packet(&self) -> usize {
        self.io().max_ip_packet()
    }

    /// Send one IP packet through the tunnel.
    pub fn send_ip(&self, packet: &[u8]) -> Result<()> {
        self.io().send_ip(packet)
    }

    /// Receive one IP packet from the tunnel.
    pub async fn recv_ip(&self) -> Result<Vec<u8>> {
        self.io().recv_ip().await
    }
}

/// Datagram I/O half of a [`Tunnel`]: send/receive IP packets, framed as
/// `varint(quarter_stream_id) || varint(context_id=0) || IP`. Cloneable and
/// thread-safe; valid only while the owning [`Tunnel`] is alive.
#[derive(Clone)]
pub struct TunnelIo {
    quic: quinn::Connection,
    quarter_stream_id: u64,
}

impl TunnelIo {
    /// The largest IP packet that fits in one QUIC datagram (accounting for the
    /// quarter-stream-id + context-id varints).
    pub fn max_ip_packet(&self) -> usize {
        let overhead = varint_len(self.quarter_stream_id) + varint_len(0);
        self.quic
            .max_datagram_size()
            .map(|m| m.saturating_sub(overhead))
            .unwrap_or(0)
    }

    /// Send one IP packet through the tunnel.
    pub fn send_ip(&self, packet: &[u8]) -> Result<()> {
        let mut buf = Vec::with_capacity(packet.len() + 16);
        encode_varint(&mut buf, self.quarter_stream_id);
        encode_varint(&mut buf, CONTEXT_ID_FULL_PACKET);
        buf.extend_from_slice(packet);
        self.quic.send_datagram(bytes::Bytes::from(buf)).map_err(|e| {
            let reason = self
                .quic
                .close_reason()
                .map(|r| format!(" (close reason: {r})"))
                .unwrap_or_default();
            Error::Tunnel(format!("send datagram: {e}{reason}"))
        })
    }

    /// Receive one IP packet from the tunnel. Datagrams for other flows or with
    /// a non-zero context id are skipped.
    pub async fn recv_ip(&self) -> Result<Vec<u8>> {
        loop {
            let dg = self
                .quic
                .read_datagram()
                .await
                .map_err(|e| Error::Tunnel(format!("read datagram: {e}")))?;
            let mut rest = &dg[..];
            let Some(qsid) = decode_varint(&mut rest) else {
                continue;
            };
            let Some(ctx) = decode_varint(&mut rest) else {
                continue;
            };
            if qsid != self.quarter_stream_id || ctx != CONTEXT_ID_FULL_PACKET {
                continue;
            }
            return Ok(rest.to_vec());
        }
    }
}

fn parse_assigned_v4(s: &str) -> Result<Ipv4Addr> {
    let addr = s.trim().split('/').next().unwrap_or("").trim();
    addr.parse::<Ipv4Addr>()
        .map_err(|e| Error::Config(format!("assigned ipv4 {s:?}: {e}")))
}

fn parse_assigned_v6(s: &str) -> Option<Ipv6Addr> {
    s.trim().split('/').next()?.trim().parse::<Ipv6Addr>().ok()
}

// ---- QUIC variable-length integers (RFC 9000 §16) --------------------------

/// Append `v` as a QUIC varint.
fn encode_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Number of bytes `encode_varint` would use for `v`.
fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Read a QUIC varint from the front of `buf`, advancing it. Returns None if
/// truncated.
fn decode_varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    *buf = &buf[len..];
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_protocol() {
        assert_eq!(CONNECT_PROTOCOL, "cf-connect-ip");
        assert_eq!(MASQUE_PORT, 443);
        assert_eq!(QUIC_CONNECTION_ID_LEN, 20);
        assert_eq!(TUNNEL_MTU, 1280);
    }

    #[test]
    fn varint_roundtrips_across_size_classes() {
        // QUIC varints span 0..=2^62-1.
        for v in [0u64, 63, 64, 16383, 16384, 1 << 29, 1 << 30, u64::from(u32::MAX), (1 << 62) - 1] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v), "len mismatch for {v}");
            let mut slice = &buf[..];
            assert_eq!(decode_varint(&mut slice), Some(v), "roundtrip for {v}");
            assert!(slice.is_empty(), "trailing bytes for {v}");
        }
    }

    #[test]
    fn decode_varint_rejects_truncated() {
        // A 4-byte varint header but only 2 bytes present.
        let mut slice: &[u8] = &[0x80, 0x00];
        assert_eq!(decode_varint(&mut slice), None);
    }

    #[test]
    fn parses_assigned_addresses() {
        assert_eq!(parse_assigned_v4("172.16.0.2").unwrap(), Ipv4Addr::new(172, 16, 0, 2));
        assert_eq!(parse_assigned_v4("172.16.0.2/32").unwrap(), Ipv4Addr::new(172, 16, 0, 2));
        assert!(parse_assigned_v6("2606:4700:110::1/128").is_some());
        assert!(parse_assigned_v6("").is_none());
    }
}
