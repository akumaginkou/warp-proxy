//! A pool of WARP accounts, each backing one tunnel + netstack (= one egress
//! IP), fronted by a load-balancer the SOCKS server selects from.
//!
//! The browser/app only ever talks to the front SOCKS port; underneath, accounts
//! can reconnect, rotate to a fresh egress, or switch transport without the
//! client noticing. Selection is round-robin over ready workers, or pinned to a
//! specific account; WARP can be toggled off (direct) entirely.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::netstack::{self, NetHandle};
use crate::register::{RegisterOptions, RegistrationClient};
use crate::tunnel::{Transport, Tunnel};
use crate::trace::TraceInfo;
use crate::{DeviceKeypair, WarpConfig};

/// One pooled account: its config, live tunnel + netstack, and last trace.
pub struct Worker {
    id: usize,
    inner: Mutex<WorkerInner>,
}

struct WorkerInner {
    config: WarpConfig,
    net: Option<NetHandle>,
    tunnel: Option<Tunnel>, // keep-alive; dropping tears down the old tunnel
    assigned_v4: Ipv4Addr,
    trace: Option<TraceInfo>,
}

impl Worker {
    fn new(id: usize, config: WarpConfig) -> Arc<Worker> {
        Arc::new(Worker {
            id,
            inner: Mutex::new(WorkerInner {
                config,
                net: None,
                tunnel: None,
                assigned_v4: Ipv4Addr::UNSPECIFIED,
                trace: None,
            }),
        })
    }

    /// The current netstack handle, if the worker is up.
    pub fn net(&self) -> Option<NetHandle> {
        self.inner.lock().unwrap().net.clone()
    }
}

/// The account pool + front-LB selection state.
pub struct Pool {
    workers: Mutex<Vec<Arc<Worker>>>,
    enabled: AtomicBool,
    pinned: AtomicUsize, // 0 = auto (round-robin)
    http2: AtomicBool,
    rr: AtomicUsize,
    next_id: AtomicUsize,
    device_name: String,
}

impl Pool {
    /// Build a pool from pre-registered configs and establish every tunnel.
    pub async fn new(configs: Vec<WarpConfig>, http2: bool) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            workers: Mutex::new(Vec::new()),
            enabled: AtomicBool::new(true),
            pinned: AtomicUsize::new(0),
            http2: AtomicBool::new(http2),
            rr: AtomicUsize::new(0),
            next_id: AtomicUsize::new(1),
            device_name: "warp-proxy".to_string(),
        });
        for cfg in configs {
            let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
            let w = Worker::new(id, cfg);
            if let Err(e) = pool.establish(&w).await {
                eprintln!("[pool] worker {id} failed to connect: {e}");
            }
            pool.workers.lock().unwrap().push(w);
        }
        pool
    }

    fn transport(&self) -> Transport {
        if self.http2.load(Ordering::Relaxed) {
            Transport::Http2
        } else {
            Transport::Http3
        }
    }

    fn snapshot(&self) -> Vec<Arc<Worker>> {
        self.workers.lock().unwrap().clone()
    }

    /// (Re)establish a worker's tunnel + netstack from its current config.
    async fn establish(&self, w: &Arc<Worker>) -> crate::Result<()> {
        let config = w.inner.lock().unwrap().config.clone();
        let kp = DeviceKeypair::from_private_b64(&config.private_key)?;
        let tunnel = Tunnel::connect_with(&config, &kp, self.transport()).await?;
        let v4 = tunnel.assigned_v4();
        let net = netstack::spawn(tunnel.io(), v4, tunnel.assigned_v6());
        let mut inner = w.inner.lock().unwrap();
        inner.tunnel = Some(tunnel); // drops the previous tunnel (stops its netstack)
        inner.net = Some(net);
        inner.assigned_v4 = v4;
        Ok(())
    }

    /// Whether traffic is currently tunnelled (vs direct).
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Toggle WARP on/off (off = direct).
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Pin egress to a specific account id (0 = auto round-robin).
    pub fn select(&self, id: usize) {
        self.pinned.store(id, Ordering::Relaxed);
    }

    /// Pick the netstack for a new connection: the pinned worker if ready, else
    /// round-robin over ready workers. `None` if none are ready.
    pub fn pick(&self) -> Option<NetHandle> {
        let workers = self.snapshot();
        if workers.is_empty() {
            return None;
        }
        let pin = self.pinned.load(Ordering::Relaxed);
        if pin != 0 {
            if let Some(w) = workers.iter().find(|w| w.id == pin) {
                if let Some(net) = w.net() {
                    return Some(net);
                }
            }
        }
        let start = self.rr.fetch_add(1, Ordering::Relaxed);
        for off in 0..workers.len() {
            if let Some(net) = workers[(start + off) % workers.len()].net() {
                return Some(net);
            }
        }
        None
    }

    /// Reconnect a worker (same account) — or all workers when `id == 0`.
    pub async fn reconnect(&self, id: usize) -> crate::Result<()> {
        for w in self.snapshot() {
            if id == 0 || w.id == id {
                self.establish(&w).await?;
            }
        }
        Ok(())
    }

    /// Rotate a worker to a fresh account/egress by re-registering — or the
    /// pinned/first worker when `id == 0`.
    pub async fn rotate(&self, id: usize) -> crate::Result<()> {
        let workers = self.snapshot();
        let target = if id != 0 {
            workers.into_iter().find(|w| w.id == id)
        } else {
            let pin = self.pinned.load(Ordering::Relaxed);
            workers
                .iter()
                .find(|w| w.id == pin)
                .cloned()
                .or_else(|| workers.first().cloned())
        };
        let Some(w) = target else {
            return Err(crate::Error::Config("no such account".into()));
        };
        let opts = RegisterOptions {
            device_name: Some(format!("{}-{}", self.device_name, w.id)),
            ..Default::default()
        };
        let fresh = RegistrationClient::register_auto(&opts).await?;
        w.inner.lock().unwrap().config = fresh;
        self.establish(&w).await
    }

    /// Switch transport (QUIC ↔ HTTP/2) and reconnect all workers.
    pub async fn set_http2(&self, on: bool) -> crate::Result<()> {
        self.http2.store(on, Ordering::Relaxed);
        self.reconnect(0).await
    }

    /// Add a freshly-registered account to the pool. Returns its id.
    pub async fn add_account(&self) -> crate::Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let opts = RegisterOptions {
            device_name: Some(format!("{}-{}", self.device_name, id)),
            ..Default::default()
        };
        let cfg = RegistrationClient::register_auto(&opts).await?;
        let w = Worker::new(id, cfg);
        self.establish(&w).await?;
        self.workers.lock().unwrap().push(w);
        Ok(id)
    }

    /// Remove a pooled account (keeps at least one).
    pub fn remove_account(&self, id: usize) -> crate::Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if workers.len() <= 1 {
            return Err(crate::Error::Config("cannot remove the last account".into()));
        }
        let before = workers.len();
        workers.retain(|w| w.id != id);
        if workers.len() == before {
            return Err(crate::Error::Config(format!("no such account {id}")));
        }
        if self.pinned.load(Ordering::Relaxed) == id {
            self.pinned.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Refresh a worker's egress trace (or all when `id == 0`).
    pub async fn refresh_trace(&self, id: usize) {
        for w in self.snapshot() {
            if id != 0 && w.id != id {
                continue;
            }
            if let Some(net) = w.net() {
                let info = crate::trace::fetch_trace(&net).await;
                w.inner.lock().unwrap().trace = Some(info);
            }
        }
    }

    /// A JSON-serialisable snapshot of pool state for the control API.
    pub fn status(&self) -> PoolStatus {
        let pinned = self.pinned.load(Ordering::Relaxed);
        let accounts = self
            .snapshot()
            .iter()
            .map(|w| {
                let inner = w.inner.lock().unwrap();
                AccountStatus {
                    id: w.id,
                    ready: inner.net.is_some(),
                    ip: inner.assigned_v4.to_string(),
                    trace: inner.trace.clone(),
                }
            })
            .collect();
        PoolStatus {
            enabled: self.enabled(),
            mode: if pinned == 0 { "auto" } else { "pinned" },
            pinned,
            http2: self.http2.load(Ordering::Relaxed),
            accounts,
        }
    }
}

/// JSON shape returned by the control API's `/api/status`.
#[derive(Serialize)]
pub struct PoolStatus {
    pub enabled: bool,
    pub mode: &'static str,
    pub pinned: usize,
    pub http2: bool,
    pub accounts: Vec<AccountStatus>,
}

/// Per-account view in [`PoolStatus`].
#[derive(Serialize)]
pub struct AccountStatus {
    pub id: usize,
    pub ready: bool,
    pub ip: String,
    pub trace: Option<TraceInfo>,
}
