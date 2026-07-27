//! A minimal SOCKS5 server that routes CONNECT requests through the netstack
//! (and therefore through the WARP tunnel), resolving domain names remotely so
//! DNS does not leak.
//!
//! [`serve`] fronts a single netstack; [`serve_pool`] fronts an account [`Pool`]
//! as a load-balancer (round-robin / pinned, WARP-off and loopback go direct).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::netstack::NetHandle;
use crate::pool::Pool;

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// Serve SOCKS5 on `listener`, routing every CONNECT through `net`.
pub async fn serve(listener: TcpListener, net: NetHandle) {
    loop {
        let Ok((client, _)) = listener.accept().await else { continue };
        let net = net.clone();
        tokio::spawn(async move {
            let _ = handle_single(client, net).await;
        });
    }
}

async fn handle_single(mut client: TcpStream, net: NetHandle) -> std::io::Result<()> {
    let Some((host, port)) = read_request(&mut client).await? else {
        return Ok(());
    };
    via_netstack(client, &net, &host, port).await
}

/// Serve SOCKS5 on `listener`, load-balancing across the account [`Pool`].
pub async fn serve_pool(listener: TcpListener, pool: Arc<Pool>) {
    loop {
        let Ok((client, _)) = listener.accept().await else { continue };
        let pool = pool.clone();
        tokio::spawn(async move {
            let _ = handle_pool(client, pool).await;
        });
    }
}

async fn handle_pool(mut client: TcpStream, pool: Arc<Pool>) -> std::io::Result<()> {
    let Some((host, port)) = read_request(&mut client).await? else {
        return Ok(());
    };

    // WARP off, or a loopback target, connects straight out (never tunnelled).
    if !pool.enabled() || is_loopback_host(&host) {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(upstream) => {
                client.write_all(&reply(0x00)).await?;
                relay_direct(client, upstream).await;
            }
            Err(_) => {
                client.write_all(&reply(0x05)).await?;
            }
        }
        return Ok(());
    }

    let Some(net) = pool.pick() else {
        client.write_all(&reply(0x01)).await?; // general failure: no worker ready
        return Ok(());
    };
    via_netstack(client, &net, &host, port).await
}

/// Resolve + connect `host:port` through `net`, then splice with the client.
async fn via_netstack(
    mut client: TcpStream,
    net: &NetHandle,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    let ip = match net.resolve(host).await {
        Ok(ip) => ip,
        Err(_) => {
            client.write_all(&reply(0x04)).await?; // host unreachable
            return Ok(());
        }
    };
    let conn = match net.connect(SocketAddr::new(ip, port)).await {
        Ok(c) => c,
        Err(_) => {
            client.write_all(&reply(0x05)).await?; // connection refused
            return Ok(());
        }
    };
    client.write_all(&reply(0x00)).await?;
    relay(client, conn).await;
    Ok(())
}

/// Perform the SOCKS5 greeting + CONNECT request parse, returning the target
/// `host:port`. Writes the appropriate reply and returns `None` on a
/// bad/unsupported request.
async fn read_request(client: &mut TcpStream) -> std::io::Result<Option<(String, u16)>> {
    // Greeting: VER, NMETHODS, METHODS...
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VER {
        return Ok(None);
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[VER, 0x00]).await?; // no authentication

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != VER {
        return Ok(None);
    }
    if req[1] != CMD_CONNECT {
        client.write_all(&reply(0x07)).await?; // command not supported
        return Ok(None);
    }

    let host = match req[3] {
        ATYP_V4 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            IpAddr::V4(Ipv4Addr::from(a)).to_string()
        }
        ATYP_V6 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            IpAddr::V6(Ipv6Addr::from(a)).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            client.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => {
            client.write_all(&reply(0x08)).await?; // address type not supported
            return Ok(None);
        }
    };
    let mut pb = [0u8; 2];
    client.read_exact(&mut pb).await?;
    Ok(Some((host, u16::from_be_bytes(pb))))
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Splice the client and the tunnelled connection until either ends.
async fn relay(client: TcpStream, conn: crate::netstack::TcpConn) {
    let (mut cr, mut cw) = client.into_split();
    let (mut reader, writer) = conn.into_split();

    let net_to_client = async {
        while let Some(chunk) = reader.recv().await {
            if cw.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = cw.shutdown().await;
    };
    let client_to_net = async {
        let mut buf = [0u8; 8192];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => writer.send(buf[..n].to_vec()),
            }
        }
        writer.close();
    };

    tokio::select! {
        _ = net_to_client => {}
        _ = client_to_net => {}
    }
}

/// Splice two plain TCP streams (WARP-off / loopback direct path).
async fn relay_direct(mut client: TcpStream, mut upstream: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// A SOCKS5 reply with the given status and a zeroed bound address.
fn reply(status: u8) -> [u8; 10] {
    [VER, status, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0]
}
