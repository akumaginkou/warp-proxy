//! A userspace TCP/IP netstack that turns the raw IP-packet [`TunnelIo`] into
//! usable outbound TCP connections and DNS resolution.
//!
//! smoltcp is synchronous/poll-driven, so it runs on its own OS thread (the
//! "actor"): it owns the [`Interface`], the [`SocketSet`] and a channel-backed
//! [`Device`], drives `iface.poll()`, and forwards packets to/from the tunnel.
//! The async world (the SOCKS server) talks to it through a [`NetHandle`] over a
//! command channel; each TCP connection gets a pair of byte channels bridged to
//! a smoltcp socket.
//!
//! Assigned addresses are static (from registration); the interface is
//! configured with them plus default routes so every off-link destination is
//! emitted to the tunnel device.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc as smpsc;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::{mpsc as tmpsc, oneshot};

use crate::tunnel::TunnelIo;

const SOCK_BUF: usize = 64 * 1024;
const RECV_CHUNK: usize = 8 * 1024;
const CHAN_DEPTH: usize = 64;

/// Commands sent from the async world to the smoltcp actor thread.
enum Cmd {
    Inbound(Vec<u8>),
    Connect {
        remote: SocketAddr,
        from_net: tmpsc::Sender<Vec<u8>>,
        reply: oneshot::Sender<Result<SocketHandle, String>>,
    },
    Send {
        handle: SocketHandle,
        data: Vec<u8>,
    },
    Close {
        handle: SocketHandle,
    },
    Resolve {
        name: String,
        reply: oneshot::Sender<Result<IpAddr, String>>,
    },
}

/// A cloneable async handle to the netstack.
#[derive(Clone)]
pub struct NetHandle {
    cmd: smpsc::Sender<Cmd>,
}

impl NetHandle {
    /// Resolve a hostname to an IP address through the tunnel.
    pub async fn resolve(&self, name: &str) -> Result<IpAddr, String> {
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Resolve { name: name.to_string(), reply })
            .map_err(|_| "netstack stopped".to_string())?;
        rx.await.map_err(|_| "netstack dropped".to_string())?
    }

    /// Open an outbound TCP connection to `remote` through the tunnel.
    pub async fn connect(&self, remote: SocketAddr) -> Result<TcpConn, String> {
        let (from_net_tx, from_net_rx) = tmpsc::channel(CHAN_DEPTH);
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Connect { remote, from_net: from_net_tx, reply })
            .map_err(|_| "netstack stopped".to_string())?;
        let handle = rx.await.map_err(|_| "netstack dropped".to_string())??;
        Ok(TcpConn { handle, cmd: self.cmd.clone(), from_net: from_net_rx })
    }
}

/// One outbound TCP connection through the netstack.
pub struct TcpConn {
    handle: SocketHandle,
    cmd: smpsc::Sender<Cmd>,
    from_net: tmpsc::Receiver<Vec<u8>>,
}

impl TcpConn {
    /// Receive the next chunk of bytes from the remote, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_net.recv().await
    }

    /// Queue bytes to send to the remote.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Send { handle: self.handle, data });
    }

    /// Ask the netstack to close the sending half once drained.
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Close { handle: self.handle });
    }

    /// Split into independent read/write halves for concurrent relaying.
    pub fn into_split(self) -> (TcpReader, TcpWriter) {
        (
            TcpReader { from_net: self.from_net },
            TcpWriter { handle: self.handle, cmd: self.cmd },
        )
    }
}

/// Read half of a [`TcpConn`].
pub struct TcpReader {
    from_net: tmpsc::Receiver<Vec<u8>>,
}

impl TcpReader {
    /// Receive the next chunk from the remote, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_net.recv().await
    }
}

/// Write half of a [`TcpConn`]. Closes the connection when dropped.
pub struct TcpWriter {
    handle: SocketHandle,
    cmd: smpsc::Sender<Cmd>,
}

impl TcpWriter {
    /// Queue bytes to send to the remote.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Send { handle: self.handle, data });
    }

    /// Close the sending half once drained.
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Close { handle: self.handle });
    }
}

impl Drop for TcpWriter {
    fn drop(&mut self) {
        self.close();
    }
}

/// Spawn the netstack: a feeder task pumping tunnel→actor, and the smoltcp actor
/// thread. Returns a [`NetHandle`] for the async world.
pub fn spawn(io: TunnelIo, assigned_v4: Ipv4Addr, assigned_v6: Option<Ipv6Addr>) -> NetHandle {
    let mtu = io.max_ip_packet().clamp(576, 1280);
    let (cmd_tx, cmd_rx) = smpsc::channel::<Cmd>();

    // Feeder: read IP packets off the tunnel and hand them to the actor.
    let feeder_io = io.clone();
    let feeder_cmd = cmd_tx.clone();
    tokio::spawn(async move {
        loop {
            match feeder_io.recv_ip().await {
                Ok(pkt) => {
                    if feeder_cmd.send(Cmd::Inbound(pkt)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    std::thread::Builder::new()
        .name("warp-netstack".into())
        .spawn(move || Actor::new(io, mtu, assigned_v4, assigned_v6).run(cmd_rx))
        .expect("spawn netstack thread");

    NetHandle { cmd: cmd_tx }
}

// ---- the smoltcp actor -----------------------------------------------------

struct Conn {
    from_net: tmpsc::Sender<Vec<u8>>,
    out_buf: VecDeque<u8>,
    connect_reply: Option<oneshot::Sender<Result<SocketHandle, String>>>,
    closing: bool,
}

struct PendingDns {
    query: dns::QueryHandle,
    reply: oneshot::Sender<Result<IpAddr, String>>,
}

struct Actor {
    io: TunnelIo,
    device: TunDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    start: StdInstant,
    next_port: u16,
    conns: HashMap<SocketHandle, Conn>,
    dns_handle: SocketHandle,
    dns_pending: Vec<PendingDns>,
}

impl Actor {
    fn new(io: TunnelIo, mtu: usize, v4: Ipv4Addr, v6: Option<Ipv6Addr>) -> Self {
        let mut device = TunDevice { rx: VecDeque::new(), tx: Vec::new(), mtu };
        let start = StdInstant::now();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 32));
            if let Some(v6) = v6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        // Point-to-point tunnel: no L2, so the gateway value is only used for
        // route matching. Any address works; send everything off-link to the tun.
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(172, 16, 0, 1));
        if v6.is_some() {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        }

        let mut sockets = SocketSet::new(Vec::new());
        let servers = [IpAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1))];
        let dns_handle = sockets.add(dns::Socket::new(&servers, Vec::new()));

        Actor {
            io,
            device,
            iface,
            sockets,
            start,
            next_port: 49152,
            conns: HashMap::new(),
            dns_handle,
            dns_pending: Vec::new(),
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    fn next_ephemeral_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if self.next_port >= 65535 { 49152 } else { self.next_port + 1 };
        p
    }

    fn run(mut self, cmd_rx: smpsc::Receiver<Cmd>) {
        loop {
            let now = self.now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);

            // Egress: flush packets smoltcp produced to the tunnel.
            for pkt in self.device.tx.drain(..) {
                let _ = self.io.send_ip(&pkt);
            }

            self.service_sockets();
            self.service_dns();

            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_millis(500))
                .clamp(Duration::from_millis(1), Duration::from_millis(500));

            match cmd_rx.recv_timeout(delay) {
                Ok(cmd) => {
                    self.handle_cmd(cmd);
                    // Drain any other queued commands before re-polling.
                    while let Ok(cmd) = cmd_rx.try_recv() {
                        self.handle_cmd(cmd);
                    }
                }
                Err(smpsc::RecvTimeoutError::Timeout) => {}
                Err(smpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Inbound(pkt) => self.device.rx.push_back(pkt),
            Cmd::Connect { remote, from_net, reply } => self.handle_connect(remote, from_net, reply),
            Cmd::Send { handle, data } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.out_buf.extend(data);
                }
            }
            Cmd::Close { handle } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.closing = true;
                }
            }
            Cmd::Resolve { name, reply } => self.handle_resolve(name, reply),
        }
    }

    fn handle_connect(
        &mut self,
        remote: SocketAddr,
        from_net: tmpsc::Sender<Vec<u8>>,
        reply: oneshot::Sender<Result<SocketHandle, String>>,
    ) {
        let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
        let handle = self.sockets.add(tcp::Socket::new(rx, tx));
        let local_port = self.next_ephemeral_port();
        let remote_ep = IpEndpoint::new(to_ip(remote.ip()), remote.port());
        let local_ep = IpListenEndpoint { addr: None, port: local_port };

        let iface = &mut self.iface;
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        match sock.connect(iface.context(), remote_ep, local_ep) {
            Ok(()) => {
                self.conns.insert(
                    handle,
                    Conn {
                        from_net,
                        out_buf: VecDeque::new(),
                        connect_reply: Some(reply),
                        closing: false,
                    },
                );
            }
            Err(e) => {
                self.sockets.remove(handle);
                let _ = reply.send(Err(format!("connect: {e}")));
            }
        }
    }

    fn handle_resolve(&mut self, name: String, reply: oneshot::Sender<Result<IpAddr, String>>) {
        // A literal IP needs no lookup.
        if let Ok(ip) = name.parse::<IpAddr>() {
            let _ = reply.send(Ok(ip));
            return;
        }
        let dns_handle = self.dns_handle;
        let iface = &mut self.iface;
        let sock = self.sockets.get_mut::<dns::Socket>(dns_handle);
        match sock.start_query(iface.context(), &name, DnsQueryType::A) {
            Ok(query) => self.dns_pending.push(PendingDns { query, reply }),
            Err(e) => {
                let _ = reply.send(Err(format!("dns query: {e:?}")));
            }
        }
    }

    fn service_sockets(&mut self) {
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            let mut remove = false;
            {
                let sock = self.sockets.get_mut::<tcp::Socket>(h);
                let conn = self.conns.get_mut(&h).expect("conn for handle");

                // Resolve the pending connect once established or failed.
                if conn.connect_reply.is_some() {
                    if sock.state() == tcp::State::Established {
                        let _ = conn.connect_reply.take().unwrap().send(Ok(h));
                    } else if !sock.is_active() {
                        let _ = conn
                            .connect_reply
                            .take()
                            .unwrap()
                            .send(Err("connection refused".into()));
                        remove = true;
                    }
                }

                // socks -> net
                while sock.can_send() && !conn.out_buf.is_empty() {
                    let (head, _) = conn.out_buf.as_slices();
                    match sock.send_slice(head) {
                        Ok(0) => break,
                        Ok(n) => drop(conn.out_buf.drain(..n)),
                        Err(_) => break,
                    }
                }

                // net -> socks (bounded by the channel to apply TCP backpressure)
                while sock.can_recv() {
                    let Ok(permit) = conn.from_net.try_reserve() else { break };
                    let mut buf = [0u8; RECV_CHUNK];
                    match sock.recv_slice(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => permit.send(buf[..n].to_vec()),
                        Err(_) => break,
                    }
                }

                if conn.closing && conn.out_buf.is_empty() {
                    sock.close();
                }
                if sock.state() == tcp::State::Closed {
                    remove = true;
                }
            }
            if remove {
                self.sockets.remove(h);
                self.conns.remove(&h); // dropping from_net signals EOF to the reader
            }
        }
    }

    fn service_dns(&mut self) {
        let dns_handle = self.dns_handle;
        let mut i = 0;
        while i < self.dns_pending.len() {
            let sock = self.sockets.get_mut::<dns::Socket>(dns_handle);
            match sock.get_query_result(self.dns_pending[i].query) {
                Ok(addrs) => {
                    let pending = self.dns_pending.remove(i);
                    let result = addrs
                        .iter()
                        .next()
                        .map(|a| from_ip(*a))
                        .ok_or_else(|| "no address".to_string());
                    let _ = pending.reply.send(result);
                }
                Err(dns::GetQueryResultError::Pending) => i += 1,
                Err(dns::GetQueryResultError::Failed) => {
                    let pending = self.dns_pending.remove(i);
                    let _ = pending.reply.send(Err("resolution failed".into()));
                }
            }
        }
    }
}

fn to_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

fn from_ip(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
        IpAddress::Ipv6(a) => IpAddr::V6(a),
    }
}

// ---- channel-backed smoltcp device -----------------------------------------

struct TunDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

impl Device for TunDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.rx.pop_front()?;
        Some((RxTok { buf }, TxTok { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxTok {
    buf: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

struct TxTok<'a> {
    tx: &'a mut Vec<Vec<u8>>,
}

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.push(buf);
        r
    }
}
