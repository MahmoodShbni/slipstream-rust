use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

// ── ANSI colour helpers ───────────────────────────────────────────────────────
const CYAN_BOLD: &str = "\x1b[1;36m";
const GREEN:     &str = "\x1b[32m";
const YELLOW:    &str = "\x1b[33m";
const DIM:       &str = "\x1b[2m";
const RESET:     &str = "\x1b[0m";

pub fn log_refresh_start(slot: usize, old_port: u16, new_port: u16) {
    eprintln!(
        "{CYAN_BOLD}[TUNNEL-REFRESH]{RESET} slot={slot} \
         starting warm standby on :{new_port} \
         {DIM}(current: :{old_port}){RESET}"
    );
}

pub fn log_refresh_ready(slot: usize, new_port: u16) {
    eprintln!(
        "{GREEN}[TUNNEL-REFRESH]{RESET} slot={slot} \
         warm standby :{new_port} {GREEN}READY{RESET} — swapping into load balancer"
    );
}

pub fn log_refresh_drain(slot: usize, old_port: u16, drain_secs: u64) {
    eprintln!(
        "{YELLOW}[TUNNEL-REFRESH]{RESET} slot={slot} \
         draining old tunnel :{old_port} \
         {DIM}(drain window: {drain_secs}s){RESET}"
    );
}

pub fn log_refresh_done(slot: usize, old_port: u16) {
    eprintln!(
        "{DIM}[TUNNEL-REFRESH]{RESET} slot={slot} \
         old tunnel :{old_port} retired"
    );
}

// ── TunnelPool ────────────────────────────────────────────────────────────────

pub struct TunnelEntry {
    pub port: u16,
    pub conn_cnt: AtomicU64,
}

/// Dynamic pool — ports can be added and removed while the LB is running.
pub struct TunnelPool {
    tunnels: RwLock<Vec<Arc<TunnelEntry>>>,
    counter: AtomicU64,
    pub strategy: String,
}

impl TunnelPool {
    pub fn new(ports: &[u16], strategy: &str) -> Arc<Self> {
        Arc::new(Self {
            tunnels: RwLock::new(
                ports
                    .iter()
                    .map(|&p| Arc::new(TunnelEntry { port: p, conn_cnt: AtomicU64::new(0) }))
                    .collect(),
            ),
            counter: AtomicU64::new(0),
            strategy: strategy.to_string(),
        })
    }

    pub fn ports(&self) -> Vec<u16> {
        self.tunnels.read().unwrap().iter().map(|t| t.port).collect()
    }

    pub fn len(&self) -> usize {
        self.tunnels.read().unwrap().len()
    }

    /// Add a port to the active pool (new connections start going to it).
    pub fn add_port(&self, port: u16) {
        let mut guard = self.tunnels.write().unwrap();
        if !guard.iter().any(|t| t.port == port) {
            guard.push(Arc::new(TunnelEntry { port, conn_cnt: AtomicU64::new(0) }));
        }
    }

    /// Remove a port from the active pool (no new connections; existing ones drain).
    pub fn remove_port(&self, port: u16) {
        let mut guard = self.tunnels.write().unwrap();
        guard.retain(|t| t.port != port);
    }

    /// Pick a tunnel using the configured strategy.
    pub fn pick(&self) -> Option<Arc<TunnelEntry>> {
        let guard = self.tunnels.read().unwrap();
        if guard.is_empty() {
            return None;
        }
        match self.strategy.as_str() {
            "leastconn" => guard
                .iter()
                .min_by_key(|t| t.conn_cnt.load(Ordering::Relaxed))
                .cloned(),
            _ => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % guard.len();
                Some(guard[idx].clone())
            }
        }
    }
}

// ── Load balancer ─────────────────────────────────────────────────────────────

/// Run the TCP load balancer. Never returns under normal operation.
pub async fn run_load_balancer(
    port: u16,
    bind: &str,
    pool: Arc<TunnelPool>,
) -> std::io::Result<()> {
    let addr = format!("{}:{}", bind, port);
    let listener = TcpListener::bind(&addr).await?;
    info!(
        "lb: [{}] listening on {} → tunnels {:?}",
        pool.strategy, addr, pool.ports()
    );

    loop {
        match listener.accept().await {
            Ok((client, _peer)) => {
                let pool = pool.clone();
                tokio::spawn(async move { handle_conn(client, pool).await });
            }
            Err(err) => warn!("lb: accept error: {}", err),
        }
    }
}

async fn handle_conn(client: TcpStream, pool: Arc<TunnelPool>) {
    let total = pool.len().max(1);
    for _ in 0..total {
        let entry = match pool.pick() {
            Some(e) => e,
            None => break,
        };
        match TcpStream::connect(format!("127.0.0.1:{}", entry.port)).await {
            Ok(target) => {
                entry.conn_cnt.fetch_add(1, Ordering::Relaxed);
                let _ = pipe(client, target).await;
                entry.conn_cnt.fetch_sub(1, Ordering::Relaxed);
                return;
            }
            Err(err) => {
                warn!("lb: tunnel :{} unreachable ({}), trying next", entry.port, err);
            }
        }
    }
    warn!("lb: no tunnel reachable, dropping connection");
}

async fn pipe(a: TcpStream, b: TcpStream) -> io::Result<()> {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();
    tokio::select! {
        _ = io::copy(&mut ar, &mut bw) => {}
        _ = io::copy(&mut br, &mut aw) => {}
    }
    Ok(())
}

/// Poll until a TCP port is accepting connections, or timeout.
pub async fn wait_for_port(port: u16, timeout_secs: u64) -> bool {
    let deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(timeout_secs);
    loop {
        if TcpStream::connect(format!("127.0.0.1:{}", port)).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}
