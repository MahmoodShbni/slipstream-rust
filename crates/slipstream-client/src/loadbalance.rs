use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// A single tunnel slot tracked by the load balancer.
pub struct TunnelEntry {
    pub port: u16,
    conn_cnt: AtomicU64,
}

/// Pool of tunnel ports. No health state — all tunnels are always eligible.
pub struct TunnelPool {
    tunnels: Vec<Arc<TunnelEntry>>,
    counter: AtomicU64,
    pub strategy: String,
}

impl TunnelPool {
    pub fn new(ports: &[u16], strategy: &str) -> Arc<Self> {
        Arc::new(Self {
            tunnels: ports
                .iter()
                .map(|&p| {
                    Arc::new(TunnelEntry {
                        port: p,
                        conn_cnt: AtomicU64::new(0),
                    })
                })
                .collect(),
            counter: AtomicU64::new(0),
            strategy: strategy.to_string(),
        })
    }

    pub fn ports(&self) -> Vec<u16> {
        self.tunnels.iter().map(|t| t.port).collect()
    }

    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Pick a tunnel according to the configured strategy.
    /// Never returns None as long as the pool is non-empty.
    pub fn pick(&self) -> Option<Arc<TunnelEntry>> {
        if self.tunnels.is_empty() {
            return None;
        }
        match self.strategy.as_str() {
            "leastconn" => self
                .tunnels
                .iter()
                .min_by_key(|t| t.conn_cnt.load(Ordering::Relaxed))
                .cloned(),
            _ => {
                // roundrobin
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize
                    % self.tunnels.len();
                Some(self.tunnels[idx].clone())
            }
        }
    }
}

/// Run the TCP load balancer.  Never returns under normal operation.
pub async fn run_load_balancer(
    port: u16,
    bind: &str,
    pool: Arc<TunnelPool>,
) -> std::io::Result<()> {
    let addr = format!("{}:{}", bind, port);
    let listener = TcpListener::bind(&addr).await?;
    info!(
        "lb: [{}] listening on {} → tunnels {:?}",
        pool.strategy,
        addr,
        pool.ports()
    );

    loop {
        match listener.accept().await {
            Ok((client, _peer)) => {
                let pool = pool.clone();
                tokio::spawn(async move {
                    handle_conn(client, pool).await;
                });
            }
            Err(err) => {
                warn!("lb: accept error: {}", err);
            }
        }
    }
}

async fn handle_conn(client: TcpStream, pool: Arc<TunnelPool>) {
    let total = pool.len();
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
                warn!(
                    "lb: tunnel :{} unreachable ({}), trying next",
                    entry.port, err
                );
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
