//! A pool of WARP accounts, each backing one tunnel + netstack (= one egress
//! IP), fronted by a load-balancer the SOCKS server selects from.
//!
//! Each worker is supervised: if its tunnel dies it reconnects with exponential
//! backoff, and it can be told to rebuild (reconnect / rotate / switch transport)
//! live. An optional timer rotates one account to a fresh egress on a cadence.
//! The client only ever talks to the front SOCKS port, so all of this is
//! invisible to it.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{watch, Notify};

use crate::netstack::{self, NetHandle};
use crate::register::{RegisterOptions, RegistrationClient};
use crate::trace::TraceInfo;
use crate::tunnel::{Transport, Tunnel};
use crate::{DeviceKeypair, WarpConfig};

const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Cloudflare dislikes sub-minute re-registration, so clamp the auto-rotate
/// cadence to at least this.
const MIN_ROTATE_SECS: u64 = 60;

/// One pooled account: its config, live tunnel + netstack, and last trace.
pub struct Worker {
    id: usize,
    /// Poked to make the supervisor rebuild the tunnel now.
    rebuild: Notify,
    inner: Mutex<WorkerInner>,
}

struct WorkerInner {
    config: WarpConfig,
    net: Option<NetHandle>,
    tunnel: Option<Tunnel>, // keep-alive; dropping tears down the old tunnel
    dead: Option<watch::Receiver<bool>>,
    assigned_v4: Ipv4Addr,
    trace: Option<TraceInfo>,
}

impl Worker {
    fn new(id: usize, config: WarpConfig) -> Arc<Worker> {
        Arc::new(Worker {
            id,
            rebuild: Notify::new(),
            inner: Mutex::new(WorkerInner {
                config,
                net: None,
                tunnel: None,
                dead: None,
                assigned_v4: Ipv4Addr::UNSPECIFIED,
                trace: None,
            }),
        })
    }

    /// The current netstack handle, if the worker is up.
    pub fn net(&self) -> Option<NetHandle> {
        self.inner.lock().unwrap().net.clone()
    }

    fn dead_signal(&self) -> Option<watch::Receiver<bool>> {
        self.inner.lock().unwrap().dead.clone()
    }

    fn clear_net(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.net = None;
        inner.dead = None;
        // Keep the (dead) tunnel until the next build replaces it.
    }

    fn set_trace(&self, t: TraceInfo) {
        self.inner.lock().unwrap().trace = Some(t);
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
    rotate_secs: AtomicU64, // 0 = auto-rotation disabled
    device_name: String,
}

impl Pool {
    /// Build a pool from pre-registered configs, establish every tunnel, and
    /// start each worker's supervisor + the auto-rotator.
    pub async fn new(configs: Vec<WarpConfig>, http2: bool) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            workers: Mutex::new(Vec::new()),
            enabled: AtomicBool::new(true),
            pinned: AtomicUsize::new(0),
            http2: AtomicBool::new(http2),
            rr: AtomicUsize::new(0),
            next_id: AtomicUsize::new(1),
            rotate_secs: AtomicU64::new(0),
            device_name: "warp-proxy".to_string(),
        });
        for cfg in configs {
            let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
            let w = Worker::new(id, cfg);
            pool.workers.lock().unwrap().push(w.clone());
            if let Err(e) = pool.build_tunnel(&w).await {
                eprintln!("[pool] worker {id} initial connect failed: {e}");
            }
            Pool::spawn_supervisor(pool.clone(), w);
        }
        Pool::spawn_rotator(pool.clone());
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
    async fn build_tunnel(&self, w: &Arc<Worker>) -> crate::Result<()> {
        let config = w.inner.lock().unwrap().config.clone();
        let kp = DeviceKeypair::from_private_b64(&config.private_key)?;
        let tunnel = Tunnel::connect_with(&config, &kp, self.transport()).await?;
        let v4 = tunnel.assigned_v4();
        let dead = tunnel.dead_signal();
        let net = netstack::spawn(tunnel.io(), v4, tunnel.assigned_v6());
        let mut inner = w.inner.lock().unwrap();
        inner.tunnel = Some(tunnel); // drops the previous tunnel (stops its netstack)
        inner.net = Some(net);
        inner.assigned_v4 = v4;
        inner.dead = Some(dead);
        Ok(())
    }

    /// Supervise one worker: wait for its tunnel to die (or a rebuild request),
    /// then reconnect with exponential backoff. Exits when the pool is dropped.
    fn spawn_supervisor(pool: Arc<Pool>, w: Arc<Worker>) {
        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::spawn(async move {
            loop {
                // If a tunnel is up, wait for it to die or for a rebuild request.
                if let Some(mut dead) = w.dead_signal() {
                    tokio::select! {
                        _ = wait_true(&mut dead) => {}
                        _ = w.rebuild.notified() => {}
                    }
                    w.clear_net();
                }

                // (Re)connect with exponential backoff.
                let mut backoff = Duration::from_secs(1);
                loop {
                    let Some(pool) = weak.upgrade() else { return };
                    let result = pool.build_tunnel(&w).await;
                    drop(pool);
                    match result {
                        Ok(()) => {
                            spawn_trace(&w);
                            break;
                        }
                        Err(e) => {
                            eprintln!(
                                "[pool] worker {} connect failed: {e}; retry in {:?}",
                                w.id, backoff
                            );
                            tokio::select! {
                                _ = tokio::time::sleep(backoff) => {}
                                _ = w.rebuild.notified() => {}
                            }
                            backoff = (backoff * 2).min(MAX_BACKOFF);
                        }
                    }
                }
            }
        });
    }

    /// Periodically rotate one account to a fresh egress, round-robining across
    /// accounts. Disabled while the interval is 0.
    fn spawn_rotator(pool: Arc<Pool>) {
        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                let secs = match weak.upgrade() {
                    Some(p) => p.rotate_secs.load(Ordering::Relaxed),
                    None => return,
                };
                if secs == 0 {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
                tokio::time::sleep(Duration::from_secs(secs)).await;
                let Some(pool) = weak.upgrade() else { return };
                if pool.rotate_secs.load(Ordering::Relaxed) == 0 {
                    continue;
                }
                let ids: Vec<usize> = pool.snapshot().iter().map(|w| w.id).collect();
                if ids.is_empty() {
                    continue;
                }
                let id = ids[idx % ids.len()];
                idx += 1;
                eprintln!("[pool] auto-rotating account {id}");
                if let Err(e) = pool.rotate(id).await {
                    eprintln!("[pool] auto-rotate {id} failed: {e}");
                }
            }
        });
    }

    // ---- live controls -----------------------------------------------------

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
            if let Some(net) = workers.iter().find(|w| w.id == pin).and_then(|w| w.net()) {
                return Some(net);
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

    /// Ask a worker's supervisor to reconnect (same account) — or all when 0.
    pub fn reconnect(&self, id: usize) {
        for w in self.snapshot() {
            if id == 0 || w.id == id {
                w.rebuild.notify_one();
            }
        }
    }

    /// Rotate a worker to a fresh account/egress by re-registering, then rebuild
    /// — or the pinned/first worker when `id == 0`.
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
        w.rebuild.notify_one();
        Ok(())
    }

    /// Switch transport (QUIC ↔ HTTP/2) and reconnect all workers.
    pub fn set_http2(&self, on: bool) {
        self.http2.store(on, Ordering::Relaxed);
        self.reconnect(0);
    }

    /// Set (or disable, with 0) the auto-rotate cadence in seconds.
    pub fn set_rotate_interval(&self, secs: u64) {
        let secs = if secs == 0 {
            0
        } else {
            secs.max(MIN_ROTATE_SECS)
        };
        self.rotate_secs.store(secs, Ordering::Relaxed);
    }

    /// Add a freshly-registered account to the pool. Returns its id.
    pub async fn add_account(self: &Arc<Self>) -> crate::Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let opts = RegisterOptions {
            device_name: Some(format!("{}-{}", self.device_name, id)),
            ..Default::default()
        };
        let cfg = RegistrationClient::register_auto(&opts).await?;
        let w = Worker::new(id, cfg);
        self.workers.lock().unwrap().push(w.clone());
        self.build_tunnel(&w).await?;
        Pool::spawn_supervisor(self.clone(), w.clone());
        spawn_trace(&w);
        Ok(id)
    }

    /// Remove a pooled account (keeps at least one).
    pub fn remove_account(&self, id: usize) -> crate::Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if workers.len() <= 1 {
            return Err(crate::Error::Config(
                "cannot remove the last account".into(),
            ));
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
                w.set_trace(info);
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
            rotate_seconds: self.rotate_secs.load(Ordering::Relaxed),
            accounts,
        }
    }
}

/// Await the watch flipping to `true` (or the sender being dropped).
async fn wait_true(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Fetch a worker's egress trace in the background.
fn spawn_trace(w: &Arc<Worker>) {
    let w = w.clone();
    tokio::spawn(async move {
        if let Some(net) = w.net() {
            let t = crate::trace::fetch_trace(&net).await;
            w.set_trace(t);
        }
    });
}

/// JSON shape returned by the control API's `/api/status`.
#[derive(Serialize)]
pub struct PoolStatus {
    pub enabled: bool,
    pub mode: &'static str,
    pub pinned: usize,
    pub http2: bool,
    pub rotate_seconds: u64,
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
