//! A minimal SOCKS5 server that routes CONNECT requests through the netstack
//! (and therefore through the WARP tunnel), resolving domain names remotely so
//! DNS does not leak.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::netstack::NetHandle;

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// Serve SOCKS5 on `listener`, routing every CONNECT through `net`.
pub async fn serve(listener: TcpListener, net: NetHandle) {
    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let net = net.clone();
        tokio::spawn(async move {
            let _ = handle_client(client, net).await;
        });
    }
}

async fn handle_client(mut client: TcpStream, net: NetHandle) -> std::io::Result<()> {
    // Greeting: VER, NMETHODS, METHODS...
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VER {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[VER, 0x00]).await?; // no authentication

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != VER {
        return Ok(());
    }
    if req[1] != CMD_CONNECT {
        client.write_all(&reply(0x07)).await?; // command not supported
        return Ok(());
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
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    client.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    // Resolve remotely (through the tunnel), then connect.
    let ip = match net.resolve(&host).await {
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

    client.write_all(&reply(0x00)).await?; // succeeded
    relay(client, conn).await;
    Ok(())
}

/// Splice the client TCP stream and the tunnelled connection until either ends.
async fn relay(client: TcpStream, conn: crate::netstack::TcpConn) {
    let (mut cr, mut cw) = client.into_split();
    let (mut reader, writer) = conn.into_split();

    // net -> client
    let net_to_client = async {
        while let Some(chunk) = reader.recv().await {
            if cw.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = cw.shutdown().await;
    };

    // client -> net
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

/// A SOCKS5 reply with the given status and a zeroed bound address.
fn reply(status: u8) -> [u8; 10] {
    [VER, status, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0]
}
