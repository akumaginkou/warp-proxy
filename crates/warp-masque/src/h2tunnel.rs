//! HTTP/2 fallback transport for QUIC-blocked networks (`usque --http2`).
//!
//! Over TCP+TLS (ALPN `h2`) with the same self-signed mTLS identity + endpoint
//! pinning as HTTP/3. Cloudflare's H2 endpoint does **not** advertise RFC 8441
//! extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL=false`), so this uses a
//! **plain CONNECT** to the authority plus a `cf-connect-proto: cf-connect-ip`
//! header to select connect-ip. IP packets travel as **DATAGRAM capsules**
//! (type `0x00`), and — Cloudflare's non-RFC quirk — the capsule value is the
//! **bare IP packet**: the connect-ip context id (0) is omitted, not included as
//! RFC 9297 would (matched to the `connect-ip-go` fork Cloudflare's client uses).

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
    // Signal death when the HTTP/2 connection ends.
    let (dead_tx, dead_rx) = tokio::sync::watch::channel(false);
    let conn_driver = tokio::spawn(async move {
        let _ = connection.await;
        let _ = dead_tx.send(true);
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
        dead_rx,
        vec![Box::new(conn_driver), Box::new(writer), Box::new(reader)],
    ))
}

/// Frame an IP packet as a DATAGRAM capsule. Cloudflare's H2 quirk: the capsule
/// value is the bare IP packet — the connect-ip context id (0) is NOT included
/// (verified against the `connect-ip-go` fork's `SendDatagram`).
fn encode_datagram_capsule(pkt: &[u8]) -> Vec<u8> {
    let mut cap = Vec::with_capacity(pkt.len() + 8);
    encode_varint(&mut cap, CAPSULE_DATAGRAM);
    encode_varint(&mut cap, pkt.len() as u64);
    cap.extend_from_slice(pkt);
    cap
}

/// Parse one capsule at the front of `buf`, returning `(type, value_offset,
/// total_len)`, or `None` if the capsule has not fully arrived.
fn parse_capsule(buf: &[u8]) -> Option<(u64, usize, usize)> {
    let mut p: &[u8] = buf;
    let before = p.len();
    let ctype = decode_varint(&mut p)?;
    let clen = decode_varint(&mut p)? as usize;
    let header = before - p.len();
    if p.len() < clen {
        return None;
    }
    Some((ctype, header, header + clen))
}

/// Drain outbound IP packets and write them as DATAGRAM capsules, honouring
/// HTTP/2 flow control.
async fn writer_loop(
    mut send: h2::SendStream<Bytes>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(pkt) = out_rx.recv().await {
        let cap = encode_datagram_capsule(&pkt);

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

        while let Some((ctype, voff, total)) = parse_capsule(&buf) {
            if ctype == CAPSULE_DATAGRAM {
                // The capsule value is the bare IP packet (no context id).
                if in_tx.send(buf[voff..total].to_vec()).is_err() {
                    return;
                }
            }
            buf.drain(..total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_capsule_roundtrips() {
        let pkt = b"\x45\x00\x00\x1c-fake-ip-packet";
        let cap = encode_datagram_capsule(pkt);
        let (ctype, voff, total) = parse_capsule(&cap).unwrap();
        assert_eq!(ctype, CAPSULE_DATAGRAM);
        assert_eq!(total, cap.len());
        assert_eq!(&cap[voff..total], pkt);
        // A truncated buffer is not yet parseable.
        assert!(parse_capsule(&cap[..cap.len() - 1]).is_none());
    }

    #[test]
    fn parses_back_to_back_capsules() {
        let mut buf = encode_datagram_capsule(b"aaa");
        buf.extend(encode_datagram_capsule(b"bbbb"));
        let (_, v1, t1) = parse_capsule(&buf).unwrap();
        assert_eq!(&buf[v1..t1], b"aaa");
        let (_, v2, t2) = parse_capsule(&buf[t1..]).unwrap();
        assert_eq!(&buf[t1..][v2..t2], b"bbbb");
    }
}
