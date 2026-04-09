mod config;
mod dns;
mod error;
mod loadbalance;
mod pacing;
mod pinning;
mod runtime;
mod streams;

use clap::{parser::ValueSource, ArgGroup, CommandFactory, FromArgMatches, Parser};
use config::{Config, TunnelConfig};
use loadbalance::{
    log_refresh_done, log_refresh_drain, log_refresh_ready, log_refresh_start,
    run_load_balancer, wait_for_port, TunnelPool,
};
use slipstream_core::{
    cli::{exit_with_error, exit_with_message, init_logging, unwrap_or_exit},
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, AddressKind, HostPort,
};
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::runtime::Builder;

use runtime::run_client;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)",
    group(
        ArgGroup::new("resolvers")
            .multiple(true)
            .args(["resolver", "authoritative"])
    )
)]
struct Args {
    /// Path to a JSON config file (enables multi-tunnel + load balancer mode).
    #[arg(long = "config", short = 'C', value_name = "PATH")]
    config: Option<String>,

    #[arg(long = "tcp-listen-host", default_value = "::")]
    tcp_listen_host: String,
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver)]
    resolver: Vec<HostPort>,
    #[arg(long = "congestion-control", short = 'c', value_parser = ["bbr", "dcubic"])]
    congestion_control: Option<String>,
    #[arg(long = "authoritative", value_parser = parse_resolver)]
    authoritative: Vec<HostPort>,
    #[arg(short = 'g', long = "gso", num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    gso: bool,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domain: Option<String>,
    #[arg(long = "cert", value_name = "PATH")]
    cert: Option<String>,
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,
    #[arg(long = "debug-poll")]
    debug_poll: bool,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    init_logging();
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());

    if let Some(config_path) = &args.config {
        let cfg = unwrap_or_exit(Config::from_file(config_path), "Config error", 2);
        if cfg.tunnels.is_empty() {
            exit_with_message("Config must contain at least one tunnel", 2);
        }
        run_multi_tunnel(cfg);
        return;
    }

    // ── Single-tunnel mode ────────────────────────────────────────────────────
    let sip003_env = unwrap_or_exit(sip003::read_sip003_env(), "SIP003 env error", 2);
    if sip003_env.is_present() {
        tracing::info!("SIP003 env detected; applying SS_* overrides with CLI precedence");
    }

    let tcp_listen_host_provided = cli_provided(&matches, "tcp_listen_host");
    let tcp_listen_port_provided = cli_provided(&matches, "tcp_listen_port");
    let (tcp_listen_host, tcp_listen_port) = unwrap_or_exit(
        sip003::select_host_port(
            &args.tcp_listen_host,
            args.tcp_listen_port,
            tcp_listen_host_provided,
            tcp_listen_port_provided,
            sip003_env.local_host.as_deref(),
            sip003_env.local_port.as_deref(),
            "SS_LOCAL",
        ),
        "SIP003 env error",
        2,
    );

    let domain = resolve_domain(&args, &sip003_env);
    let resolvers = resolve_resolvers_cli(&matches, &sip003_env);
    let congestion_control = resolve_cc(&args, &sip003_env);
    let cert = resolve_cert(&args, &sip003_env);
    if cert.is_none() {
        tracing::warn!(
            "Server certificate pinning is disabled; this allows MITM. \
             Provide --cert to pin the server leaf."
        );
    }
    let keep_alive_interval = resolve_keep_alive(&args, &matches, &sip003_env);

    let config = ClientConfig {
        tcp_listen_host: &tcp_listen_host,
        tcp_listen_port,
        resolvers: &resolvers,
        congestion_control: congestion_control.as_deref(),
        gso: args.gso,
        domain: &domain,
        cert: cert.as_deref(),
        keep_alive_interval: keep_alive_interval as usize,
        debug_poll: args.debug_poll,
        debug_streams: args.debug_streams,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_client(&config)) {
        Ok(code) => std::process::exit(code),
        Err(err) => exit_with_error("Client error", err, 1),
    }
}

// ── Multi-tunnel mode ─────────────────────────────────────────────────────────

fn run_multi_tunnel(cfg: Config) {
    tracing::info!("Multi-tunnel mode: {} tunnels", cfg.tunnels.len());

    let lb_cfg = cfg.load_balance.clone();
    let initial_ports: Vec<u16> = cfg.tunnels.iter().map(|t| t.tcp_listen_port).collect();

    // One OS thread per tunnel — run_client uses raw pointers so it is !Send.
    let mut handles = Vec::new();

    for (slot, tunnel) in cfg.tunnels.into_iter().enumerate() {
        // Build pool reference only if LB is configured (we need it for refresh swaps).
        // The actual pool is created below; we share it via Arc.
        // To break the ordering dependency we create the pool first, then spawn tunnels.
        // → We'll pass pool_opt into each thread after creating it.
        // Collect info now, spawn after pool creation.
        handles.push((slot, tunnel));
    }

    // Create the shared LB pool.
    let pool = match &lb_cfg {
        Some(lb) => Some(TunnelPool::new(&initial_ports, &lb.strategy)),
        None => None,
    };

    // Spawn tunnel threads.
    let mut thread_handles = Vec::new();
    for (slot, tunnel) in handles {
        let pool_clone = pool.clone();
        let handle = std::thread::Builder::new()
            .name(format!("tunnel-{}", slot))
            .spawn(move || {
                run_tunnel_with_refresh(slot, tunnel, pool_clone);
            })
            .expect("Failed to spawn tunnel thread");
        thread_handles.push(handle);
    }

    // Spawn load balancer thread.
    if let Some(lb) = lb_cfg {
        let pool = pool.expect("pool must be Some when lb_cfg is Some");
        let strategy = lb.strategy.clone();
        let bind = lb.bind.clone();
        let port = lb.port;

        let lb_handle = std::thread::Builder::new()
            .name("load-balancer".to_string())
            .spawn(move || {
                let runtime = Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .expect("Failed to build LB runtime");
                tracing::info!("lb: [{}] starting on :{}", strategy, port);
                if let Err(err) = runtime.block_on(run_load_balancer(port, &bind, pool)) {
                    tracing::error!("load balancer error: {}", err);
                }
            })
            .expect("Failed to spawn LB thread");
        thread_handles.push(lb_handle);
    } else {
        tracing::info!("No load-balance config; tunnels on ports {:?}", initial_ports);
    }

    for h in thread_handles {
        let _ = h.join();
    }
}

/// Manages a single logical tunnel slot, including periodic refresh.
fn run_tunnel_with_refresh(slot: usize, tunnel: TunnelConfig, pool: Option<Arc<TunnelPool>>) {
    let refresh_enabled = tunnel.refresh_interval_secs > 0;
    let refresh_interval = Duration::from_secs(tunnel.refresh_interval_secs);
    let drain_secs = tunnel.drain_secs;
    let port_offset = tunnel.refresh_port_offset;

    // Port A and Port B alternate.  A = base port, B = base + offset.
    let port_a = tunnel.tcp_listen_port;
    let port_b = tunnel.tcp_listen_port.wrapping_add(port_offset);

    // Start with port A.
    let mut active_port = port_a;
    let mut standby_port = port_b;

    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Spawn initial tunnel on active_port.
    spawn_tunnel_thread(slot, active_port, &tunnel, shutdown_flag.clone());
    tracing::info!("tunnel[{}]: started on :{}", slot, active_port);

    if !refresh_enabled {
        // No refresh — just block forever (the spawned thread runs independently).
        // Park this manager thread so it doesn't exit.
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // Refresh loop.
    loop {
        std::thread::sleep(refresh_interval);

        // ── Phase 1: start warm standby ──────────────────────────────────────
        log_refresh_start(slot, active_port, standby_port);
        let new_shutdown = Arc::new(AtomicBool::new(false));
        spawn_tunnel_thread(slot, standby_port, &tunnel, new_shutdown.clone());

        // ── Phase 2: wait until standby is accepting connections ─────────────
        let ready = {
            let rt = Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("rt");
            rt.block_on(wait_for_port(standby_port, 15))
        };

        if !ready {
            tracing::warn!(
                "tunnel[{}]: warm standby :{} did not become ready in 15s — skipping refresh",
                slot, standby_port
            );
            // Kill the failed standby so it doesn't linger.
            new_shutdown.store(true, Ordering::Relaxed);
            continue;
        }

        log_refresh_ready(slot, standby_port);

        // ── Phase 3: atomic swap in load balancer ────────────────────────────
        if let Some(ref p) = pool {
            p.add_port(standby_port);
            p.remove_port(active_port);
        }

        // ── Phase 4: drain old tunnel ────────────────────────────────────────
        log_refresh_drain(slot, active_port, drain_secs);
        std::thread::sleep(Duration::from_secs(drain_secs));

        // Signal old tunnel to stop after its next reconnect cycle.
        shutdown_flag.store(true, Ordering::Relaxed);
        log_refresh_done(slot, active_port);

        // Rotate for next cycle.
        std::mem::swap(&mut active_port, &mut standby_port);
        // new_shutdown becomes the shutdown handle for the now-active tunnel.
        // We hold it until the next cycle.
        // (old shutdown_flag has been set; old thread will stop on next reconnect.)
        // Replace our tracking variables.
        // We need to keep new_shutdown alive — shadow the outer binding.
        // Use a separate binding per iteration via a helper struct.
        run_tunnel_refresh_loop(
            slot,
            active_port,
            standby_port,
            &tunnel,
            pool.clone(),
            new_shutdown,
            drain_secs,
            port_offset,
            refresh_interval,
        );
        return; // The helper runs the rest of the loop.
    }
}

/// Continuation of the refresh loop after the first swap has happened.
/// Exists to take ownership of the new shutdown handle cleanly.
#[allow(clippy::too_many_arguments)]
fn run_tunnel_refresh_loop(
    slot: usize,
    mut active_port: u16,
    mut standby_port: u16,
    tunnel: &TunnelConfig,
    pool: Option<Arc<TunnelPool>>,
    mut active_shutdown: Arc<AtomicBool>,
    drain_secs: u64,
    _port_offset: u16,
    refresh_interval: Duration,
) {
    loop {
        std::thread::sleep(refresh_interval);

        log_refresh_start(slot, active_port, standby_port);
        let new_shutdown = Arc::new(AtomicBool::new(false));
        spawn_tunnel_thread(slot, standby_port, tunnel, new_shutdown.clone());

        let ready = {
            let rt = Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("rt");
            rt.block_on(wait_for_port(standby_port, 15))
        };

        if !ready {
            tracing::warn!(
                "tunnel[{}]: warm standby :{} did not become ready in 15s — skipping refresh",
                slot, standby_port
            );
            new_shutdown.store(true, Ordering::Relaxed);
            continue;
        }

        log_refresh_ready(slot, standby_port);

        if let Some(ref p) = pool {
            p.add_port(standby_port);
            p.remove_port(active_port);
        }

        log_refresh_drain(slot, active_port, drain_secs);
        std::thread::sleep(Duration::from_secs(drain_secs));

        active_shutdown.store(true, Ordering::Relaxed);
        log_refresh_done(slot, active_port);

        std::mem::swap(&mut active_port, &mut standby_port);
        active_shutdown = new_shutdown;
    }
}

/// Spawn an OS thread that runs run_client in a loop, respecting shutdown_flag.
fn spawn_tunnel_thread(
    slot: usize,
    port: u16,
    tunnel: &TunnelConfig,
    shutdown: Arc<AtomicBool>,
) {
    let resolvers = match resolvers_from_tunnel_config(tunnel) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("tunnel[{}]: resolver error: {}", slot, e);
            return;
        }
    };
    let domain = tunnel.domain.clone();
    let tcp_host = tunnel.tcp_listen_host.clone();
    let cert = tunnel.cert.clone();
    let cc = tunnel.congestion_control.clone();
    let keep_alive = tunnel.keep_alive_interval;
    let gso = tunnel.gso;

    std::thread::Builder::new()
        .name(format!("tunnel-{}-:{}", slot, port))
        .spawn(move || {
            let config = ClientConfig {
                tcp_listen_host: &tcp_host,
                tcp_listen_port: port,
                resolvers: &resolvers,
                congestion_control: cc.as_deref(),
                gso,
                domain: &domain,
                cert: cert.as_deref(),
                keep_alive_interval: keep_alive as usize,
                debug_poll: false,
                debug_streams: false,
            };

            let runtime = Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to build tunnel runtime");

            let mut attempt = 0u32;
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    tracing::debug!("tunnel[{}] :{}: shutdown flag set — stopping", slot, port);
                    break;
                }
                attempt += 1;
                match runtime.block_on(run_client(&config)) {
                    Ok(0) => {
                        tracing::info!("tunnel[{}] :{}: exited cleanly", slot, port);
                        break;
                    }
                    Ok(code) => {
                        tracing::warn!(
                            "tunnel[{}] :{}: exited code {} (attempt {})",
                            slot, port, code, attempt
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            "tunnel[{}] :{}: error: {} (attempt {})",
                            slot, port, err, attempt
                        );
                    }
                }
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        })
        .expect("Failed to spawn tunnel thread");
}

// ── Resolver helpers ──────────────────────────────────────────────────────────

fn resolvers_from_tunnel_config(tc: &TunnelConfig) -> Result<Vec<ResolverSpec>, String> {
    let mut specs = Vec::new();
    for r in &tc.resolver {
        let hp = parse_host_port(r, 53, AddressKind::Resolver).map_err(|e| e.to_string())?;
        specs.push(ResolverSpec { resolver: hp, mode: ResolverMode::Recursive });
    }
    for r in &tc.authoritative {
        let hp = parse_host_port(r, 53, AddressKind::Resolver).map_err(|e| e.to_string())?;
        specs.push(ResolverSpec { resolver: hp, mode: ResolverMode::Authoritative });
    }
    if specs.is_empty() {
        return Err("At least one resolver is required per tunnel".to_string());
    }
    Ok(specs)
}

// ── Single-tunnel CLI helpers (unchanged) ─────────────────────────────────────

fn resolve_domain(args: &Args, sip003_env: &sip003::Sip003Env) -> String {
    if let Some(domain) = args.domain.clone() {
        return domain;
    }
    let option_domain =
        unwrap_or_exit(parse_domain_option(&sip003_env.plugin_options), "SIP003 env error", 2);
    if let Some(domain) = option_domain {
        return domain;
    }
    exit_with_message("A domain is required", 2);
}

fn resolve_resolvers_cli(
    matches: &clap::ArgMatches,
    sip003_env: &sip003::Sip003Env,
) -> Vec<ResolverSpec> {
    if has_cli_resolvers(matches) {
        return unwrap_or_exit(build_resolvers(matches, true), "Resolver error", 2);
    }
    let resolver_options = unwrap_or_exit(
        parse_resolvers_from_options(&sip003_env.plugin_options),
        "SIP003 env error",
        2,
    );
    if !resolver_options.resolvers.is_empty() {
        return resolver_options.resolvers;
    }
    let sip003_remote = unwrap_or_exit(
        sip003::parse_endpoint(
            sip003_env.remote_host.as_deref(),
            sip003_env.remote_port.as_deref(),
            "SS_REMOTE",
        ),
        "SIP003 env error",
        2,
    );
    if let Some(endpoint) = &sip003_remote {
        let mode = if resolver_options.authoritative_remote {
            ResolverMode::Authoritative
        } else {
            ResolverMode::Recursive
        };
        let resolver = unwrap_or_exit(
            parse_host_port_parts(&endpoint.host, endpoint.port, AddressKind::Resolver),
            "SIP003 env error",
            2,
        );
        return vec![ResolverSpec { resolver, mode }];
    }
    exit_with_message("At least one resolver is required", 2);
}

fn resolve_cc(args: &Args, sip003_env: &sip003::Sip003Env) -> Option<String> {
    if args.congestion_control.is_some() {
        return args.congestion_control.clone();
    }
    unwrap_or_exit(
        parse_congestion_control(&sip003_env.plugin_options),
        "SIP003 env error",
        2,
    )
}

fn resolve_cert(args: &Args, sip003_env: &sip003::Sip003Env) -> Option<String> {
    if args.cert.is_some() {
        return args.cert.clone();
    }
    sip003::last_option_value(&sip003_env.plugin_options, "cert")
}

fn resolve_keep_alive(
    args: &Args,
    matches: &clap::ArgMatches,
    sip003_env: &sip003::Sip003Env,
) -> u16 {
    if cli_provided(matches, "keep_alive_interval") {
        return args.keep_alive_interval;
    }
    let override_val = unwrap_or_exit(
        parse_keep_alive_interval(&sip003_env.plugin_options),
        "SIP003 env error",
        2,
    );
    override_val.unwrap_or(args.keep_alive_interval)
}

fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_resolver(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 53, AddressKind::Resolver).map_err(|err| err.to_string())
}

fn build_resolvers(
    matches: &clap::ArgMatches,
    require: bool,
) -> Result<Vec<ResolverSpec>, String> {
    let mut ordered = Vec::new();
    collect_resolvers(matches, "resolver", ResolverMode::Recursive, &mut ordered)?;
    collect_resolvers(matches, "authoritative", ResolverMode::Authoritative, &mut ordered)?;
    if ordered.is_empty() && require {
        return Err("At least one resolver is required".to_string());
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    Ok(ordered.into_iter().map(|(_, spec)| spec).collect())
}

fn collect_resolvers(
    matches: &clap::ArgMatches,
    name: &str,
    mode: ResolverMode,
    ordered: &mut Vec<(usize, ResolverSpec)>,
) -> Result<(), String> {
    let indices: Vec<usize> = matches.indices_of(name).into_iter().flatten().collect();
    let values: Vec<HostPort> = matches
        .get_many::<HostPort>(name)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if indices.len() != values.len() {
        return Err(format!("Mismatched {} arguments", name));
    }
    for (idx, resolver) in indices.into_iter().zip(values) {
        ordered.push((idx, ResolverSpec { resolver, mode }));
    }
    Ok(())
}

fn cli_provided(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn has_cli_resolvers(matches: &clap::ArgMatches) -> bool {
    matches.get_many::<HostPort>("resolver").map(|v| v.len() > 0).unwrap_or(false)
        || matches.get_many::<HostPort>("authoritative").map(|v| v.len() > 0).unwrap_or(false)
}

fn parse_domain_option(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut domain = None;
    let mut saw_domain = false;
    for option in options {
        if option.key == "domain" {
            if saw_domain {
                return Err("SIP003 domain option must not be repeated".to_string());
            }
            saw_domain = true;
            let mut entries =
                sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            if entries.len() > 1 {
                return Err("SIP003 domain option must contain a single value".to_string());
            }
            let entry = entries.pop().ok_or_else(|| {
                "SIP003 domain option must contain a single value".to_string()
            })?;
            domain = Some(normalize_domain(&entry).map_err(|err| err.to_string())?);
        }
    }
    Ok(domain)
}

struct ResolverOptions {
    resolvers: Vec<ResolverSpec>,
    authoritative_remote: bool,
}

fn parse_resolvers_from_options(
    options: &[sip003::Sip003Option],
) -> Result<ResolverOptions, String> {
    let mut ordered = Vec::new();
    let mut authoritative_remote = false;
    for option in options {
        let mode = match option.key.as_str() {
            "resolver" => ResolverMode::Recursive,
            "authoritative" => ResolverMode::Authoritative,
            _ => continue,
        };
        let trimmed = option.value.trim();
        if trimmed.is_empty() {
            if mode == ResolverMode::Authoritative {
                authoritative_remote = true;
                continue;
            }
            return Err("Empty resolver value is not allowed".to_string());
        }
        let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
        for entry in entries {
            let resolver = parse_host_port(&entry, 53, AddressKind::Resolver)
                .map_err(|err| err.to_string())?;
            ordered.push(ResolverSpec { resolver, mode });
        }
    }
    Ok(ResolverOptions { resolvers: ordered, authoritative_remote })
}

fn parse_congestion_control(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut last = None;
    for option in options {
        if option.key == "congestion-control" {
            let value = option.value.trim();
            if value != "bbr" && value != "dcubic" {
                return Err(format!("Invalid congestion-control value: {}", value));
            }
            last = Some(value.to_string());
        }
    }
    Ok(last)
}

fn parse_keep_alive_interval(options: &[sip003::Sip003Option]) -> Result<Option<u16>, String> {
    let mut last = None;
    for option in options {
        if option.key == "keep-alive-interval" {
            let value = option.value.trim();
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("Invalid keep-alive-interval value: {}", value))?;
            last = Some(parsed);
        }
    }
    Ok(last)
}
