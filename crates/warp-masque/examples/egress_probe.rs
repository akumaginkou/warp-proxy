//! Prove that traffic egresses through WARP by sending a real DNS query *through
//! the MASQUE tunnel* and reading the reply.
//!
//! We hand-craft an IPv4/UDP/DNS packet (source = our WARP-assigned address) that
//! asks Cloudflare's resolver (1.1.1.1) for the CHAOS/TXT record
//! `whoami.cloudflare`, which echoes back the client's egress IP as the resolver
//! sees it. A reply carrying a WARP egress IP (not the host's own address)
//! demonstrates the end-to-end IP-datagram forwarding path works and exits via
//! WARP.
//!
//! Usage:
//!   cargo run -p warp-masque --example egress_probe -- [CONFIG_PATH]

use std::net::Ipv4Addr;
use std::time::Duration;

use warp_masque::tunnel::Tunnel;
use warp_masque::{DeviceKeypair, WarpConfig};

const RESOLVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const SRC_PORT: u16 = 40000;
/// DNS CHAOS class, used by `whoami.cloudflare`.
const CLASS_CH: u16 = 3;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "warp-config.json".into());
    let cfg = WarpConfig::load(&path)?;
    let kp = DeviceKeypair::from_private_b64(&cfg.private_key)?;

    let tunnel = Tunnel::connect(&cfg, &kp).await?;
    anyhow::ensure!(tunnel.status().is_success(), "tunnel not up: {}", tunnel.status());
    let src = tunnel.assigned_v4();
    eprintln!("Tunnel up. Assigned WARP IPv4: {src}");

    let dns = build_dns_txt_query(0xBEEF, "whoami.cloudflare", CLASS_CH);
    let packet = build_ipv4_udp(src, RESOLVER, SRC_PORT, 53, &dns);

    // Send a few times (datagrams are unreliable) and wait for a reply from :53.
    for attempt in 1..=4 {
        tunnel.send_ip(&packet)?;
        eprintln!("Sent DNS query through the tunnel (attempt {attempt})…");
        match tokio::time::timeout(Duration::from_secs(3), recv_udp_from(&tunnel, RESOLVER, 53)).await {
            Ok(Ok(payload)) => {
                match parse_first_txt(&payload) {
                    Some(txt) => {
                        eprintln!("\n✅ WARP egress IP (as Cloudflare's resolver sees us): {txt}");
                        eprintln!("   Traffic left through the MASQUE tunnel — bidirectional IP forwarding works.");
                    }
                    None => eprintln!(
                        "\n✅ Got a DNS reply through the tunnel ({} bytes) — round-trip works.",
                        payload.len()
                    ),
                }
                return Ok(());
            }
            _ => eprintln!("  no reply yet, retrying…"),
        }
    }
    anyhow::bail!("no DNS reply received through the tunnel");
}

/// Read IP packets from the tunnel until one is a UDP datagram from `src:port`,
/// returning the UDP payload.
async fn recv_udp_from(tunnel: &Tunnel, src: Ipv4Addr, port: u16) -> anyhow::Result<Vec<u8>> {
    loop {
        let pkt = tunnel.recv_ip().await?;
        if let Some(payload) = extract_udp(&pkt, src, port) {
            return Ok(payload);
        }
    }
}

// ---- packet building -------------------------------------------------------

fn build_dns_txt_query(id: u16, name: &str, qclass: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0); // root
    m.extend_from_slice(&16u16.to_be_bytes()); // QTYPE TXT
    m.extend_from_slice(&qclass.to_be_bytes()); // QCLASS
    m
}

fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut ip = Vec::with_capacity(total_len);
    ip.push(0x45); // v4, IHL=5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // id
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    ip.push(64); // TTL
    ip.push(17); // UDP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ip_csum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    udp.extend_from_slice(payload);
    let ucsum = udp_checksum(src, dst, &udp);
    udp[6..8].copy_from_slice(&ucsum.to_be_bytes());

    ip.extend_from_slice(&udp);
    ip
}

/// Internet checksum (ones' complement of the ones' complement 16-bit sum).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    match checksum(&pseudo) {
        0 => 0xffff, // 0 means "no checksum"; transmit as all-ones instead
        c => c,
    }
}

// ---- response parsing ------------------------------------------------------

/// If `pkt` is an IPv4/UDP datagram from `src:port`, return the UDP payload.
fn extract_udp(pkt: &[u8], src: Ipv4Addr, port: u16) -> Option<Vec<u8>> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let psrc = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    if psrc != src || pkt.len() < ihl + 8 {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    if sport != port {
        return None;
    }
    Some(pkt[ihl + 8..].to_vec())
}

/// Extract the first TXT record string from a DNS response message.
fn parse_first_txt(dns: &[u8]) -> Option<String> {
    if dns.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    // Skip the single question: QNAME then QTYPE+QCLASS.
    pos = skip_name(dns, pos)?;
    pos += 4;
    for _ in 0..ancount {
        pos = skip_name(dns, pos)?;
        if pos + 10 > dns.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([dns[pos], dns[pos + 1]]);
        let rdlen = u16::from_be_bytes([dns[pos + 8], dns[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > dns.len() {
            return None;
        }
        if rtype == 16 && rdlen >= 1 {
            let txt_len = dns[rdata] as usize;
            let text = &dns[rdata + 1..(rdata + 1 + txt_len).min(dns.len())];
            return Some(String::from_utf8_lossy(text).into_owned());
        }
        pos = rdata + rdlen;
    }
    None
}

/// Advance past a DNS name (handles compression pointers), returning the offset
/// just after it.
fn skip_name(dns: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *dns.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2); // compression pointer ends the name
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}
