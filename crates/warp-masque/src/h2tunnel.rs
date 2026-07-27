//! HTTP/2 fallback transport for QUIC-blocked networks (`usque --http2`).
//!
//! Over TCP+TLS (ALPN `h2`) with the same self-signed mTLS identity + endpoint
//! pinning as HTTP/3. Cloudflare's H2 endpoint does **not** advertise RFC 8441
//! extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL=false`), so this uses a
//! **plain CONNECT** to the authority plus a `cf-connect-proto: cf-connect-ip`
//! header to select connect-ip. IP packets travel as **DATAGRAM capsules**
//! (RFC 9297, type `0x00`) carrying `varint(context_id=0) || <IP packet>`.
//!
//! Status: **experimental.** The handshake succeeds (HTTP 200), but Cloudflare's
//! H2 datagram plane is non-RFC (the reference client forks `connect-ip-go` for
//! it) and does not round-trip standard capsules in testing — the exact H2
//! datagram framing still needs reverse-engineering. HTTP/3 is the working
//! default; use this only for QUIC-blocked networks once completed.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::config::{WarpConfig, DEFAULT_ENDPOINT_H2_V4};
use crate::error::{Error, Result};
use crate::keys::DeviceKeypair;
use crate::tls::tunnel_client_config;
use crate::tunnel::{
    decode_varint, encode_varint, parse_assigned_v4, parse_assigned_v6, Tunnel, TunnelIo,
    CONNECT_SNI, CONNECT_URI, MASQUE_PORT,
};

/// DATAGRAM capsule type (RFC 9297).
const CAPSULE_DATAGRAM: u64 = 0x00;
/// MTU for the HTTP/2 path (matches WARP; capsule size is not datagram-limited).
const H2_MTU: usize = 1280;

/// HTTP/2 datagram I/O half: send/receive IP packets over the capsule stream.
#[derive(Clone)]
pub struct H2Io {
    out: mpsc::UnboundedSender<Vec<u8>>,
    in_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

impl H2Io {
    /// The largest IP packet the HTTP/2 path carries in one capsule.
    pub fn max_ip_packet(&self) -> usize {
        H2_MTU
    }

    /// Queue one IP packet to send through the tunnel.
    pub fn send_ip(&self, packet: &[u8]) -> Result<()> {
        self.out
            .send(packet.to_vec())
            .map_err(|_| Error::Tunnel("h2 tunnel closed".into()))
    }

    /// Receive one IP packet from the tunnel.
    pub async fn recv_ip(&self) -> Result<Vec<u8>> {
        self.in_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::Tunnel("h2 tunnel closed".into()))
    }
}

/// Establish the MASQUE tunnel over HTTP/2.
pub async fn connect_h2(cfg: &WarpConfig, kp: &DeviceKeypair) -> Result<Tunnel> {
    let ep = {
        let v4 = if cfg.endpoint_h2_v4.trim().is_empty() {
            DEFAULT_ENDPOINT_H2_V4
        } else {
            cfg.endpoint_h2_v4.trim()
        };
        let ip: Ipv4Addr = v4
            .parse()
            .map_err(|e| Error::Config(format!("endpoint_h2_v4 {v4:?}: {e}")))?;
        SocketAddr::from((ip, MASQUE_PORT))
    };

    // TCP + TLS (ALPN h2), same mTLS identity + endpoint pinning as HTTP/3.
    let tcp = TcpStream::connect(ep).await?;
    tcp.set_nodelay(true).ok();
    let tls_cfg = tunnel_client_config(cfg, kp, &[b"h2"])?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(CONNECT_SNI)
        .map_err(|e| Error::Tunnel(format!("sni: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Tunnel(format!("h2 tls handshake: {e}")))?;

    let (mut send_req, connection) = h2::client::handshake(tls)
        .await
        .map_err(|e| Error::Tunnel(format!("h2 handshake: {e}")))?;
    let conn_driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    // Cloudflare's H2 endpoint does NOT advertise RFC 8441 extended CONNECT;
    // it uses a *plain* CONNECT to the authority plus the `cf-connect-proto`
    // header to select connect-ip (verified: the server sets
    // SETTINGS_ENABLE_CONNECT_PROTOCOL=false, so sending `:protocol` is RST'd).
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(CONNECT_URI)
        .header("user-agent", "")
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .header("capsule-protocol", "?1")
        .body(())
        .map_err(|e| Error::Tunnel(format!("build request: {e}")))?;

    let (resp_fut, send_stream) = send_req
        .send_request(req, false)
        .map_err(|e| Error::Tunnel(format!("send extended CONNECT: {e}")))?;
    let resp = resp_fut
        .await
        .map_err(|e| Error::Tunnel(format!("recv response: {e}")))?;
    let status = resp.status();
    let recv_stream = resp.into_body();

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(writer_loop(send_stream, out_rx));
    let reader = tokio::spawn(reader_loop(recv_stream, in_tx));

    let io = H2Io {
        out: out_tx,
        in_rx: Arc::new(Mutex::new(in_rx)),
    };
    let assigned_v4 = parse_assigned_v4(&cfg.ipv4)?;
    let assigned_v6 = parse_assigned_v6(&cfg.ipv6);

    Ok(Tunnel::from_parts(
        TunnelIo::H2(io),
        status,
        assigned_v4,
        assigned_v6,
        vec![Box::new(conn_driver), Box::new(writer), Box::new(reader)],
    ))
}

/// Drain outbound IP packets and write them as DATAGRAM capsules, honouring
/// HTTP/2 flow control.
async fn writer_loop(mut send: h2::SendStream<Bytes>, mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(pkt) = out_rx.recv().await {
        let mut ctx = Vec::with_capacity(1);
        encode_varint(&mut ctx, 0); // context id 0 (full IP packet)
        let value_len = (ctx.len() + pkt.len()) as u64;

        let mut cap = Vec::with_capacity(pkt.len() + 16);
        encode_varint(&mut cap, CAPSULE_DATAGRAM);
        encode_varint(&mut cap, value_len);
        cap.extend_from_slice(&ctx);
        cap.extend_from_slice(&pkt);

        send.reserve_capacity(cap.len());
        while send.capacity() < cap.len() {
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                _ => return, // stream/connection closed
            }
        }
        if send.send_data(Bytes::from(cap), false).is_err() {
            return;
        }
    }
}

/// Read DATA frames, reassemble capsules across frame boundaries, and forward
/// the IP packet from each DATAGRAM capsule.
async fn reader_loop(mut recv: h2::RecvStream, in_tx: mpsc::UnboundedSender<Vec<u8>>) {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = recv.data().await {
        let data = match chunk {
            Ok(d) => d,
            Err(_) => break,
        };
        // Return flow-control credit so the peer keeps sending.
        let _ = recv.flow_control().release_capacity(data.len());
        buf.extend_from_slice(&data);

        loop {
            let mut p: &[u8] = &buf;
            let before = p.len();
            let (Some(ctype), Some(clen)) = (decode_varint(&mut p), decode_varint(&mut p)) else {
                break; // incomplete capsule header
            };
            let header = before - p.len();
            let clen = clen as usize;
            if p.len() < clen {
                break; // capsule value not fully arrived yet
            }
            let value = p[..clen].to_vec();
            let total = header + clen;

            if ctype == CAPSULE_DATAGRAM {
                let mut v: &[u8] = &value;
                if decode_varint(&mut v) == Some(0) {
                    // context id 0 => the rest is a full IP packet
                    if in_tx.send(v.to_vec()).is_err() {
                        return;
                    }
                }
            }
            buf.drain(..total);
        }
    }
}
