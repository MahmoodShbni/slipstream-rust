use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub tunnels: Vec<TunnelConfig>,
    #[serde(rename = "load-balance")]
    pub load_balance: Option<LoadBalanceConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TunnelConfig {
    /// Local TCP port this tunnel listens on.
    #[serde(rename = "tcp-listen-port")]
    pub tcp_listen_port: u16,

    /// Local TCP host (default: "::").
    #[serde(rename = "tcp-listen-host", default = "default_host")]
    pub tcp_listen_host: String,

    /// One or more recursive resolvers, e.g. ["127.0.0.1:8853"].
    #[serde(default)]
    pub resolver: Vec<String>,

    /// One or more authoritative resolvers.
    #[serde(default)]
    pub authoritative: Vec<String>,

    /// DNS tunnel domain, e.g. "example.com".
    pub domain: String,

    /// Path to a PEM certificate for server pinning (optional).
    pub cert: Option<String>,

    /// Congestion control algorithm: "bbr" or "dcubic".
    #[serde(rename = "congestion-control")]
    pub congestion_control: Option<String>,

    /// Keep-alive interval in ms (default: 400).
    #[serde(rename = "keep-alive-interval", default = "default_keep_alive")]
    pub keep_alive_interval: u16,

    /// Enable GSO (default: false).
    #[serde(default)]
    pub gso: bool,

    /// How often (in seconds) to transparently refresh the tunnel connection.
    /// 0 = disabled (default).
    #[serde(rename = "refresh-interval", default)]
    pub refresh_interval_secs: u64,

    /// How long (in seconds) to let old connections drain before the old
    /// tunnel thread is allowed to exit. Default: 30.
    #[serde(rename = "drain-secs", default = "default_drain_secs")]
    pub drain_secs: u64,

    /// Port offset used for the warm-standby alternate port.
    /// Alternate port = tcp-listen-port + refresh-port-offset. Default: 10000.
    #[serde(rename = "refresh-port-offset", default = "default_port_offset")]
    pub refresh_port_offset: u16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LoadBalanceConfig {
    /// Port the load balancer listens on.
    pub port: u16,

    /// Bind address for the load balancer (default: "127.0.0.1").
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Strategy: "roundrobin" or "leastconn" (default: "roundrobin").
    #[serde(default = "default_strategy")]
    pub strategy: String,
}

fn default_host() -> String { "::".to_string() }
fn default_keep_alive() -> u16 { 400 }
fn default_bind() -> String { "127.0.0.1".to_string() }
fn default_strategy() -> String { "roundrobin".to_string() }
fn default_drain_secs() -> u64 { 30 }
fn default_port_offset() -> u16 { 10000 }

impl Config {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path, e))?;
        serde_json::from_str(&contents).map_err(|e| format!("Invalid JSON in {}: {}", path, e))
    }
}
