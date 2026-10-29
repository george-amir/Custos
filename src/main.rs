use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use jevsec::SecurityPipeline;
use jevsec::bouncer_api::{
    AppState, BouncerCheckResponse, FirewallStatusResponse, ManualBanRequest, StatsResponse,
    build_bouncer_router,
};
use jevsec::config::{AppConfig, LogFormat, LogSourceConfig};
use jevsec::firewall::{FirewallBackend, FirewallBouncer};
use jevsec::jev::JevBatchAnalyzer;
use jevsec::store::{BanDecision, DecisionStore};
use jevsec::tailer::{replay_log_file, spawn_log_tailer};
use jevsec::window::SlidingWindowEngine;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "jevsec",
    version,
    about = "CrowdSec-inspired behavioral security engine powered by TypeSafe AI's Jev (/v1/systemone)"
)]
struct Cli {
    /// Path to config.toml
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the jevsec daemon (tails configured log files, runs Jev batch analyzer, serves Bouncer HTTP API & OS Firewall Bouncer)
    Run {
        /// Additional log file to tail (can be specified without a config file)
        #[arg(long)]
        log: Option<PathBuf>,

        /// Read tailed log files from the beginning instead of seeking to EOF
        #[arg(long, default_value_t = false)]
        from_start: bool,

        /// Use local deterministic Jev simulator (no API key required)
        #[arg(long, default_value_t = false)]
        mock_jev: bool,

        /// Override OS firewall backend: auto, pf, nftables, ipset, windows_netsh
        #[arg(long)]
        firewall_backend: Option<String>,

        /// Execute live OS kernel firewall commands instead of dry-run simulation (requires root/Administrator)
        #[arg(long, default_value_t = false)]
        firewall_live: bool,
    },

    /// Replay a log file from start to finish, evaluate suspicious windows in bulk via Jev, and print results
    Replay {
        /// Path to access log file
        #[arg(long)]
        log: PathBuf,

        /// Log format: nginx_combined or json
        #[arg(long, default_value = "nginx_combined")]
        format: String,

        /// Use local deterministic Jev simulator (no API key required)
        #[arg(long, default_value_t = false)]
        mock_jev: bool,

        /// Override OS firewall backend: auto, pf, nftables, ipset, windows_netsh
        #[arg(long)]
        firewall_backend: Option<String>,

        /// Execute live OS kernel firewall commands instead of dry-run simulation (requires root/Administrator)
        #[arg(long, default_value_t = false)]
        firewall_live: bool,
    },

    /// Sync active bans to the cross-platform OS firewall or preview commands across Linux/macOS/Windows backends
    Firewall {
        /// Backend to target: auto, pf, nftables, ipset, windows_netsh, or "all" to preview all platforms
        #[arg(long, default_value = "auto")]
        backend: String,

        /// Execute live OS kernel firewall commands instead of dry-run simulation (requires root/Administrator)
        #[arg(long, default_value_t = false)]
        live: bool,
    },

    /// Query active ban decisions from the running daemon (or local decisions.jsonl)
    Decisions {
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        api_url: String,
    },

    /// Manually ban an IP address
    Ban {
        ip: IpAddr,
        #[arg(long, default_value = "manual_block")]
        threat: String,
        #[arg(long, default_value = "Manually banned via jevsec CLI")]
        reason: String,
        #[arg(long)]
        ttl_secs: Option<u64>,
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        api_url: String,
    },

    /// Remove an active ban for an IP address
    Unban {
        ip: IpAddr,
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        api_url: String,
    },

    /// Check if an IP is allowed or blocked via the Bouncer API
    Check {
        ip: IpAddr,
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        api_url: String,
    },

    /// Show real-time pipeline, Jev token, and OS firewall telemetry from the running daemon
    Stats {
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        api_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let mut cfg = AppConfig::load_or_default(cli.config.as_deref())?;

    match cli.command {
        Commands::Run {
            log,
            from_start,
            mock_jev,
            firewall_backend,
            firewall_live,
        } => {
            if let Some(log_path) = log {
                cfg.logs.push(LogSourceConfig {
                    path: log_path,
                    format: LogFormat::NginxCombined,
                });
            }
            if let Some(b) = firewall_backend {
                cfg.firewall.backend = parse_backend(&b);
            }
            if firewall_live {
                cfg.firewall.dry_run = false;
            }
            run_daemon(cfg, from_start, mock_jev).await
        }
        Commands::Replay {
            log,
            format,
            mock_jev,
            firewall_backend,
            firewall_live,
        } => {
            let fmt = if format.eq_ignore_ascii_case("json") {
                LogFormat::Json
            } else {
                LogFormat::NginxCombined
            };
            if let Some(b) = firewall_backend {
                cfg.firewall.backend = parse_backend(&b);
            }
            if firewall_live {
                cfg.firewall.dry_run = false;
            }
            run_replay(cfg, &log, fmt, mock_jev).await
        }
        Commands::Firewall { backend, live } => cmd_firewall(cfg, &backend, live),
        Commands::Decisions { api_url } => cmd_decisions(&api_url, &cfg).await,
        Commands::Ban {
            ip,
            threat,
            reason,
            ttl_secs,
            api_url,
        } => cmd_ban(ip, threat, reason, ttl_secs, &api_url).await,
        Commands::Unban { ip, api_url } => cmd_unban(ip, &api_url).await,
        Commands::Check { ip, api_url } => cmd_check(ip, &api_url).await,
        Commands::Stats { api_url } => cmd_stats(&api_url).await,
    }
}

fn parse_backend(s: &str) -> FirewallBackend {
    match s.trim().to_ascii_lowercase().as_str() {
        "nftables" | "nft" => FirewallBackend::Nftables,
        "ipset" | "iptables" => FirewallBackend::Ipset,
        "pf" | "pfctl" | "macos" | "bsd" => FirewallBackend::Pf,
        "windows_netsh" | "netsh" | "windows" => FirewallBackend::WindowsNetsh,
        _ => FirewallBackend::Auto,
    }
}

async fn run_daemon(cfg: AppConfig, from_start: bool, mock_jev: bool) -> Result<()> {
    let use_mock = mock_jev || cfg.jev.api_key.trim().is_empty();
    if use_mock && !mock_jev {
        info!("No TYPESAFE_API_KEY configured; starting JevBatchAnalyzer in --mock-jev mode");
    }

    let store = Arc::new(DecisionStore::open(
        cfg.daemon.decisions_file.clone(),
        cfg.daemon.default_ban_ttl_secs,
    )?);
    let window = Arc::new(SlidingWindowEngine::new(cfg.window.clone()));
    let jev = Arc::new(JevBatchAnalyzer::new(cfg.jev.clone(), use_mock)?);
    let firewall = Arc::new(FirewallBouncer::new(cfg.firewall.clone()));
    let pipeline = SecurityPipeline::new(
        store.clone(),
        window.clone(),
        jev.clone(),
        firewall.clone(),
    );

    // Sync any restored active bans from disk into the OS firewall on startup
    for decision in store.list_active() {
        let ttl = (decision.expires_at - chrono::Utc::now())
            .num_seconds()
            .max(1) as u64;
        let _ = firewall.ban_ip(decision.ip, ttl);
    }

    let (tx, mut rx) = mpsc::channel(8192);
    for source in &cfg.logs {
        info!(path = %source.path.display(), format = ?source.format, "Tailing log source");
        spawn_log_tailer(source.clone(), tx.clone(), from_start);
    }

    let ingest_pipeline = pipeline.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Err(err) = ingest_pipeline.process_event(&ev) {
                error!(error = %err, "Failed to process log event");
            }
        }
    });

    let flush_pipeline = pipeline.clone();
    let flush_ms = cfg.window.flush_interval_ms.max(500);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(flush_ms));
        loop {
            ticker.tick().await;
            if let Err(err) = flush_pipeline.flush_and_analyze(false).await {
                error!(error = %err, "Jev batch flush failed");
            }
        }
    });

    let app_state = AppState {
        store,
        window,
        jev,
        firewall: firewall.clone(),
    };
    let router = build_bouncer_router(app_state);
    let listener = tokio::net::TcpListener::bind(&cfg.daemon.bouncer_listen)
        .await
        .with_context(|| format!("Failed to bind Bouncer API on {}", cfg.daemon.bouncer_listen))?;

    info!(
        listen = %cfg.daemon.bouncer_listen,
        mock_jev = use_mock,
        firewall_backend = firewall.resolved_backend().as_str(),
        firewall_dry_run = firewall.is_dry_run(),
        "JevSec daemon listening (HTTP Bouncer: GET /v1/bouncer/check?ip=<IP>, Firewall status: GET /v1/firewall)"
    );

    axum::serve(listener, router).await?;
    Ok(())
}

async fn run_replay(
    cfg: AppConfig,
    log_path: &std::path::Path,
    format: LogFormat,
    mock_jev: bool,
) -> Result<()> {
    let use_mock = mock_jev || cfg.jev.api_key.trim().is_empty();
    let store = Arc::new(DecisionStore::open(
        cfg.daemon.decisions_file.clone(),
        cfg.daemon.default_ban_ttl_secs,
    )?);
    let window = Arc::new(SlidingWindowEngine::new(cfg.window.clone()));
    let jev = Arc::new(JevBatchAnalyzer::new(cfg.jev.clone(), use_mock)?);
    let firewall = Arc::new(FirewallBouncer::new(cfg.firewall.clone()));
    let pipeline = SecurityPipeline::new(
        store.clone(),
        window.clone(),
        jev.clone(),
        firewall.clone(),
    );

    let events = replay_log_file(log_path, format)?;
    println!(
        "=== JevSec Replay: {} ({} parsed events, mode={}, firewall={} [dry_run={}]) ===",
        log_path.display(),
        events.len(),
        if use_mock { "mock-jev" } else { "live-jev" },
        firewall.resolved_backend().as_str(),
        firewall.is_dry_run()
    );

    for ev in &events {
        pipeline.process_event(ev)?;
    }

    let verdicts = pipeline.flush_and_analyze(true).await?;

    println!(
        "\n--- L1 & Window Telemetry ---\n  Events Processed     : {}\n  Static Assets Ignored: {}\n  L1 Instant Bans      : {}\n  Promoted to Jev L2   : {}",
        window.metrics.events_processed.load(Ordering::Relaxed),
        window.metrics.static_ignored.load(Ordering::Relaxed),
        window.metrics.l1_instant_bans.load(Ordering::Relaxed),
        window.metrics.windows_promoted_to_jev.load(Ordering::Relaxed),
    );

    let in_tok = jev.metrics.input_tokens_total.load(Ordering::Relaxed);
    let cost = (in_tok as f64 / 1_000_000.0) * 0.042;
    println!(
        "\n--- TypeSafe Jev (/v1/systemone) Batch Telemetry ---\n  API Batches Sent     : {}\n  Actors Evaluated     : {}\n  Input Tokens         : {} (est. ${:.6})\n  Auto-Signatures      : {}",
        jev.metrics.batches_evaluated.load(Ordering::Relaxed),
        jev.metrics.actors_evaluated.load(Ordering::Relaxed),
        in_tok,
        cost,
        window.active_signature_count()
    );

    println!("\n--- Jev L2 Actor Verdicts ({}) ---", verdicts.len());
    println!(
        "{:<18} {:<10} {:<8} {:<24} {:<10}",
        "CLIENT IP", "VERDICT", "NOUL", "THREAT CLASS", "CONFIDENCE"
    );
    println!("{}", "-".repeat(74));
    for v in &verdicts {
        println!(
            "{:<18} {:<10} {:<8.3} {:<24} {:<10.3}",
            v.client_ip,
            if v.should_ban { "BAN" } else { "ALLOW" },
            v.noul_malicious_prob,
            v.threat_class,
            v.choice_confidence
        );
    }

    let active = store.list_active();
    println!("\n--- Active Bouncer Decisions ({}) ---", active.len());
    for d in &active {
        println!(
            "  [BLOCK] {:<16} | {:<22} | source={:?} | reason={}",
            d.ip, d.threat_class, d.source, d.reason
        );
    }

    let fw_cmds = firewall.recent_commands();
    println!(
        "\n--- OS Firewall Bouncer Commands (backend={}, dry_run={}, count={}) ---",
        firewall.resolved_backend().as_str(),
        firewall.is_dry_run(),
        fw_cmds.len()
    );
    for cmd in &fw_cmds {
        println!("  $ {cmd}");
    }

    Ok(())
}

fn cmd_firewall(mut cfg: AppConfig, backend_arg: &str, live: bool) -> Result<()> {
    let store = DecisionStore::open(
        cfg.daemon.decisions_file.clone(),
        cfg.daemon.default_ban_ttl_secs,
    )?;
    let active = store.list_active();

    if backend_arg.eq_ignore_ascii_case("all") {
        let backends = [
            FirewallBackend::Pf,
            FirewallBackend::Nftables,
            FirewallBackend::Ipset,
            FirewallBackend::WindowsNetsh,
        ];
        println!(
            "=== Cross-Platform OS Firewall Preview ({} active bans) ===",
            active.len()
        );
        for b in backends {
            let mut b_cfg = cfg.firewall.clone();
            b_cfg.backend = b;
            b_cfg.dry_run = true;
            let fw = FirewallBouncer::new(b_cfg);
            println!("\n[Backend: {}]", b.as_str());
            for init_spec in fw.build_init_commands() {
                println!("  $ {}", init_spec.to_shell_string());
            }
            for d in &active {
                let ttl = (d.expires_at - chrono::Utc::now()).num_seconds().max(60) as u64;
                println!("  $ {}", fw.build_ban_command(d.ip, ttl).to_shell_string());
            }
        }
        return Ok(());
    }

    cfg.firewall.backend = parse_backend(backend_arg);
    if live {
        cfg.firewall.dry_run = false;
    }

    let fw = FirewallBouncer::new(cfg.firewall);
    let _ = fw.init_backend()?;
    for d in &active {
        let ttl = (d.expires_at - chrono::Utc::now()).num_seconds().max(60) as u64;
        fw.ban_ip(d.ip, ttl)?;
    }

    println!(
        "=== OS Firewall Sync Complete (backend={}, dry_run={}, rules_applied={}) ===",
        fw.resolved_backend().as_str(),
        fw.is_dry_run(),
        fw.metrics.rules_applied.load(Ordering::Relaxed)
    );
    for cmd in fw.recent_commands() {
        println!("  $ {cmd}");
    }
    Ok(())
}

async fn cmd_decisions(api_url: &str, cfg: &AppConfig) -> Result<()> {
    let url = format!("{}/v1/decisions", api_url.trim_end_matches('/'));
    if let Ok(resp) = reqwest::get(&url).await {
        if let Ok(decisions) = resp.json::<Vec<BanDecision>>().await {
            print_decisions(&decisions);
            return Ok(());
        }
    }
    let store = DecisionStore::open(
        cfg.daemon.decisions_file.clone(),
        cfg.daemon.default_ban_ttl_secs,
    )?;
    print_decisions(&store.list_active());
    Ok(())
}

fn print_decisions(decisions: &[BanDecision]) {
    if decisions.is_empty() {
        println!("No active ban decisions.");
        return;
    }
    println!(
        "{:<18} {:<24} {:<18} {:<8} {}",
        "IP", "THREAT CLASS", "SOURCE", "NOUL", "EXPIRES AT"
    );
    println!("{}", "-".repeat(92));
    for d in decisions {
        println!(
            "{:<18} {:<24} {:<18} {:<8.2} {}",
            d.ip,
            d.threat_class,
            format!("{:?}", d.source),
            d.noul_probability,
            d.expires_at.to_rfc3339()
        );
    }
}

async fn cmd_ban(
    ip: IpAddr,
    threat_class: String,
    reason: String,
    ttl_secs: Option<u64>,
    api_url: &str,
) -> Result<()> {
    let url = format!("{}/v1/decisions", api_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let payload = ManualBanRequest {
        ip,
        threat_class,
        reason,
        ttl_secs,
    };
    let resp = client.post(&url).json(&payload).send().await?;
    let decision: BanDecision = resp.error_for_status()?.json().await?;
    println!(
        "Banned {} ({}) until {}",
        decision.ip, decision.threat_class, decision.expires_at
    );
    Ok(())
}

async fn cmd_unban(ip: IpAddr, api_url: &str) -> Result<()> {
    let url = format!("{}/v1/decisions/{}", api_url.trim_end_matches('/'), ip);
    let client = reqwest::Client::new();
    let resp = client.delete(&url).send().await?;
    println!("Unban {}: HTTP {}", ip, resp.status());
    Ok(())
}

async fn cmd_check(ip: IpAddr, api_url: &str) -> Result<()> {
    let url = format!(
        "{}/v1/bouncer/check?ip={}",
        api_url.trim_end_matches('/'),
        ip
    );
    let resp = reqwest::get(&url).await?;
    let status = resp.status();
    let body: BouncerCheckResponse = resp.json().await?;
    println!(
        "HTTP {} -> ip={} action={} threat={:?} noul={:?}",
        status, body.ip, body.action, body.threat_class, body.noul_probability
    );
    Ok(())
}

async fn cmd_stats(api_url: &str) -> Result<()> {
    let base = api_url.trim_end_matches('/');
    let stats: StatsResponse = reqwest::get(&format!("{base}/v1/stats"))
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("{}", serde_json::to_string_pretty(&stats)?);

    if let Ok(fw_resp) = reqwest::get(&format!("{base}/v1/firewall")).await {
        if let Ok(fw) = fw_resp.json::<FirewallStatusResponse>().await {
            println!("\n--- Firewall Status ---");
            println!("{}", serde_json::to_string_pretty(&fw)?);
        }
    }
    Ok(())
}
