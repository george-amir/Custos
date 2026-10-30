use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use custos::SecurityPipeline;
use custos::bouncer_api::{
    AppState, BouncerCheckResponse, FirewallStatusResponse, ManualBanRequest, StatsResponse,
    build_bouncer_router,
};
use custos::config::{AppConfig, LogFormat, LogSourceConfig};
use custos::firewall::{FirewallBackend, FirewallBouncer};
use custos::hub::{
    CustosHubGrpcService, HubEngine, build_signal_batch_from_verdicts, pull_and_apply_via_grpc,
    push_verdicts_via_grpc,
};
use custos::jev::JevBatchAnalyzer;
use custos::store::{BanDecision, DecisionStore};
use custos::tailer::{replay_log_file, spawn_log_tailer};
use custos::window::SlidingWindowEngine;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "custos",
    version,
    about = "Custos: Autonomous behavioral security engine & cross-platform firewall bouncer powered by TypeSafe AI's Jev (/v1/systemone)"
)]
struct Cli {
    /// Path to config.toml
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, hide = true, global = true)]
    windows_service: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Auto-detect host OS firewall & web server logs and generate a ready-to-run config.toml
    Init {
        /// Output path for the generated configuration file
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,

        /// Configure live OS kernel firewall enforcement (dry_run = false)
        #[arg(long, default_value_t = false)]
        firewall_live: bool,
    },

    /// Run the custos daemon (tails configured or auto-discovered log files, runs Jev batch analyzer, serves Bouncer HTTP API, OS Firewall, and gRPC Hub stream)
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

        /// Connect to a CustosHub gRPC coordinator (e.g. http://127.0.0.1:50051) for real-time bidirectional streaming sync
        #[arg(long)]
        hub: Option<String>,

        /// Unique node identifier when reporting to CustosHub
        #[arg(long)]
        node_id: Option<String>,
    },

    /// Replay a log file from start to finish, evaluate suspicious windows in bulk via Jev, and optionally push verdicts to CustosHub over gRPC
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

        /// Push convicted Jev verdicts & L1 signatures to a CustosHub gRPC endpoint (e.g. http://127.0.0.1:50051)
        #[arg(long)]
        hub: Option<String>,

        /// Unique node identifier when reporting to CustosHub
        #[arg(long)]
        node_id: Option<String>,
    },

    /// Run the standalone gRPC Threat-Intelligence Hub server (`CustosHubService` over HTTP/2)
    Hub {
        /// Address for the gRPC server to listen on
        #[arg(long, default_value = "127.0.0.1:50051")]
        listen: String,

        /// Minimum distinct reporting nodes required to promote an IP or signature globally
        #[arg(long, default_value_t = 1)]
        quorum: usize,
    },

    /// Pull incremental IP & L1 signature deltas from a CustosHub gRPC server and apply them in a single batched OS firewall call
    HubSync {
        /// CustosHub gRPC endpoint URL
        #[arg(long, default_value = "http://127.0.0.1:50051")]
        hub: String,

        /// Sequence cursor (0 fetches all active intelligence)
        #[arg(long, default_value_t = 0)]
        since_seq: u64,

        /// Override OS firewall backend: auto, pf, nftables, ipset, windows_netsh
        #[arg(long)]
        firewall_backend: Option<String>,

        /// Execute live OS kernel firewall commands instead of dry-run simulation
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
        #[arg(long, default_value = "Manually banned via custos CLI")]
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

    /// Manage Custos as a persistent background OS service (Linux systemd, macOS launchd, Windows SCM)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Install and start Custos as an auto-starting background OS service
    Install {
        /// Configure live OS kernel firewall enforcement in the installed service
        #[arg(long, default_value_t = false)]
        firewall_live: bool,

        /// Preview the generated OS service manifest without writing system files
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Start the installed Custos background service
    Start,
    /// Stop the running Custos background service
    Stop,
    /// Show OS service status
    Status,
    /// Stop and remove the Custos background service
    Uninstall,
}

fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--windows-service") {
        custos::windows_service::dispatch(run_async_main)
    } else {
        run_async_main()
    }
}

fn run_async_main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let mut cfg = AppConfig::load_or_default(cli.config.as_deref())?;

    let command = cli.command.unwrap_or(Commands::Run {
        log: None,
        from_start: false,
        mock_jev: false,
        firewall_backend: None,
        firewall_live: false,
        hub: None,
        node_id: None,
    });

    match command {
        Commands::Init {
            output,
            firewall_live,
        } => cmd_init(&output, firewall_live),
        Commands::Run {
            log,
            from_start,
            mock_jev,
            firewall_backend,
            firewall_live,
            hub,
            node_id,
        } => {
            if let Some(log_path) = log {
                cfg.logs.push(LogSourceConfig {
                    path: log_path,
                    format: LogFormat::NginxCombined,
                });
            }
            if cfg.logs.is_empty() {
                let discovered = AppConfig::discover_system_logs();
                if !discovered.is_empty() {
                    info!(
                        count = discovered.len(),
                        "Auto-discovered host web-server access logs"
                    );
                    cfg.logs.extend(discovered);
                }
            }
            if let Some(b) = firewall_backend {
                cfg.firewall.backend = parse_backend(&b);
            }
            if firewall_live {
                cfg.firewall.dry_run = false;
            }
            if let Some(hub_url) = hub {
                cfg.hub.enabled = true;
                cfg.hub.endpoint = hub_url;
            }
            if let Some(nid) = node_id {
                cfg.hub.node_id = nid;
            }
            run_daemon(cfg, from_start, mock_jev).await
        }
        Commands::Replay {
            log,
            format,
            mock_jev,
            firewall_backend,
            firewall_live,
            hub,
            node_id,
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
            if let Some(hub_url) = hub {
                cfg.hub.enabled = true;
                cfg.hub.endpoint = hub_url;
            }
            if let Some(nid) = node_id {
                cfg.hub.node_id = nid;
            }
            run_replay(cfg, &log, fmt, mock_jev).await
        }
        Commands::Hub { listen, quorum } => run_hub_server(&listen, quorum, &cfg).await,
        Commands::HubSync {
            hub,
            since_seq,
            firewall_backend,
            firewall_live,
        } => {
            if let Some(b) = firewall_backend {
                cfg.firewall.backend = parse_backend(&b);
            }
            if firewall_live {
                cfg.firewall.dry_run = false;
            }
            cmd_hub_sync(cfg, &hub, since_seq).await
        }
        Commands::Firewall { backend, live } => cmd_firewall(cfg, &backend, live),
        Commands::Decisions { api_url } => cmd_decisions(&api_url, &cfg).await,
        Commands::Ban {
            ip,
            threat,
            reason,
            ttl_secs,
            api_url,
        } => {
            cmd_ban(
                ip,
                threat,
                reason,
                ttl_secs,
                &api_url,
                &cfg.daemon.api_token,
            )
            .await
        }
        Commands::Unban { ip, api_url } => cmd_unban(ip, &api_url, &cfg.daemon.api_token).await,
        Commands::Check { ip, api_url } => cmd_check(ip, &api_url).await,
        Commands::Stats { api_url } => cmd_stats(&api_url).await,
        Commands::Service { action } => match action {
            ServiceAction::Install {
                firewall_live,
                dry_run,
            } => custos::service::install_service(firewall_live, dry_run),
            ServiceAction::Start => custos::service::start_service(),
            ServiceAction::Stop => custos::service::stop_service(),
            ServiceAction::Status => custos::service::status_service(),
            ServiceAction::Uninstall => custos::service::uninstall_service(),
        },
    }
}

fn cmd_init(output: &std::path::Path, firewall_live: bool) -> Result<()> {
    let mut cfg = AppConfig::default();
    let resolved_fw = FirewallBackend::Auto.resolve();
    cfg.firewall.backend = resolved_fw;
    cfg.firewall.dry_run = !firewall_live;

    let discovered_logs = AppConfig::discover_system_logs();
    if discovered_logs.is_empty() {
        cfg.logs.push(LogSourceConfig {
            path: PathBuf::from("/var/log/nginx/access.log"),
            format: LogFormat::NginxCombined,
        });
    } else {
        cfg.logs = discovered_logs.clone();
    }

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let serialized = toml::to_string_pretty(&cfg)?;
    custos::service::write_secret_file(output, serialized.as_bytes())
        .with_context(|| format!("Failed to write config to {}", output.display()))?;

    println!("=== Custos Zero-Config Initialization Complete ===");
    println!("  Config Written       : {}", output.display());
    println!(
        "  Detected OS Firewall : {} (dry_run={})",
        resolved_fw.as_str(),
        cfg.firewall.dry_run
    );
    if discovered_logs.is_empty() {
        println!(
            "  Discovered Logs      : none found in standard paths (defaulted to /var/log/nginx/access.log)"
        );
    } else {
        for l in &discovered_logs {
            println!(
                "  Discovered Log       : {} ({:?})",
                l.path.display(),
                l.format
            );
        }
    }
    println!("\nNext steps:");
    println!("  1. Set your TypeSafe Jev key : export TYPESAFE_API_KEY=\"ts_live_...\"");
    println!("  2. Start Custos daemon       : custos run");
    Ok(())
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

async fn run_hub_server(listen: &str, quorum: usize, cfg: &AppConfig) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("Invalid gRPC listen socket address: {listen}"))?;
    let engine = Arc::new(HubEngine::new(quorum));
    let svc = CustosHubGrpcService::with_auth(
        engine,
        cfg.hub.api_token.clone(),
        cfg.hub.node_tokens.clone(),
    )?;

    info!(
        listen = %addr,
        quorum_min_nodes = quorum.max(1),
        "CustosHub gRPC Threat-Intelligence Server listening (HTTP/2 Protobuf streaming)"
    );

    tonic::transport::Server::builder()
        .add_service(svc.into_server())
        .serve(addr)
        .await
        .context("CustosHub gRPC server terminated with error")?;
    Ok(())
}

async fn cmd_hub_sync(cfg: AppConfig, hub_endpoint: &str, since_seq: u64) -> Result<()> {
    let store = Arc::new(DecisionStore::open(
        cfg.daemon.decisions_file.clone(),
        cfg.daemon.default_ban_ttl_secs,
    )?);
    let window = Arc::new(SlidingWindowEngine::new(cfg.window.clone()));
    let jev = Arc::new(JevBatchAnalyzer::new(cfg.jev.clone(), true)?);
    let firewall = Arc::new(FirewallBouncer::new(cfg.firewall.clone()));
    let pipeline =
        SecurityPipeline::new(store.clone(), window.clone(), jev.clone(), firewall.clone())?;

    let (latest_seq, ips_applied, sigs_applied) = pull_and_apply_via_grpc(
        hub_endpoint,
        &cfg.hub.node_id,
        &cfg.hub.api_token,
        since_seq,
        &pipeline,
    )
    .await?;

    println!(
        "=== CustosHub gRPC Delta Sync Complete (endpoint={}, since_seq={} -> latest_seq={}) ===",
        hub_endpoint, since_seq, latest_seq
    );
    println!("  New IP Bans Applied       : {ips_applied}");
    println!("  New L1 Signatures Applied : {sigs_applied}");
    println!(
        "  Batched Firewall Commands : {}",
        firewall.recent_commands().len()
    );
    for cmd in firewall.recent_commands() {
        println!("    $ {cmd}");
    }
    Ok(())
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
    let pipeline =
        SecurityPipeline::new(store.clone(), window.clone(), jev.clone(), firewall.clone())?;

    // Startup initialization already reconciles durable decisions. Retry failures later.
    let sweep_pipeline = pipeline.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let p = sweep_pipeline.clone();
            match tokio::task::spawn_blocking(move || {
                p.reconcile_firewall()?;
                p.store.compact_persistence_file()
            })
            .await
            {
                Ok(Ok(())) => {}
                other => {
                    error!(result = ?other, "Firewall reconciliation or compaction failed; will retry")
                }
            }
        }
    });

    let (hub_tx, hub_rx) = mpsc::channel(256);
    if cfg.hub.enabled {
        if cfg.hub.api_token.trim().is_empty() {
            anyhow::bail!("Hub sync requires hub.api_token or CUSTOS_HUB_TOKEN");
        }
        let endpoint = cfg.hub.endpoint.clone();
        let node_id = cfg.hub.node_id.clone();
        let token = cfg.hub.api_token.clone();
        let sync_pipeline = pipeline.clone();
        tokio::spawn(async move {
            if let Err(error) =
                custos::hub::run_hub_sync(endpoint, node_id, token, sync_pipeline, hub_rx).await
            {
                error!(%error, "Hub synchronization stopped");
            }
        });
    }

    let (tx, mut rx) = mpsc::channel(8192);
    let mut tailer_tasks = Vec::new();
    for source in &cfg.logs {
        info!(path = %source.path.display(), format = ?source.format, "Tailing log source");
        tailer_tasks.push(spawn_log_tailer(source.clone(), tx.clone(), from_start));
    }

    drop(tx);
    let ingest_pipeline = pipeline.clone();
    let ingest_task = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Err(err) = ingest_pipeline.submit_event(ev).await {
                error!(error = %err, "Failed to process log event");
            }
        }
    });

    let flush_pipeline = pipeline.clone();
    let flush_ms = cfg.window.flush_interval_ms.max(500);
    let hub_enabled = cfg.hub.enabled;
    let node_id = cfg.hub.node_id.clone();
    let api_token = cfg.hub.api_token.clone();
    let default_ttl = cfg.daemon.default_ban_ttl_secs;

    let (stop_flush, mut flush_stopped) = tokio::sync::oneshot::channel();
    let flush_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(flush_ms));
        loop {
            tokio::select! {
                biased;
                _ = &mut flush_stopped => break,
                _ = ticker.tick() => {}
            }
            match flush_pipeline.flush_and_analyze(false).await {
                Ok(verdicts) => {
                    if hub_enabled && !verdicts.is_empty() {
                        let sig_batch = build_signal_batch_from_verdicts(
                            &node_id,
                            &api_token,
                            &verdicts,
                            default_ttl,
                        );
                        let _ = hub_tx.send(sig_batch).await;
                    }
                }
                Err(err) => error!(error = %err, "Jev batch flush failed"),
            }
        }
    });

    let shutdown_pipeline = pipeline.clone();
    let app_state = AppState {
        pipeline: pipeline.clone(),
        api_token: cfg.daemon.api_token.clone(),
    };
    let router = build_bouncer_router(app_state);
    let listener = tokio::net::TcpListener::bind(&cfg.daemon.bouncer_listen)
        .await
        .with_context(|| {
            format!(
                "Failed to bind Bouncer API on {}",
                cfg.daemon.bouncer_listen
            )
        })?;

    info!(
        listen = %cfg.daemon.bouncer_listen,
        mock_jev = use_mock,
        firewall_backend = firewall.resolved_backend().as_str(),
        firewall_dry_run = firewall.is_dry_run(),
        "Custos daemon listening (HTTP Bouncer: GET /v1/bouncer/check?ip=<IP>, Metrics: GET /metrics)"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            for task in &tailer_tasks {
                task.abort();
            }
            for task in tailer_tasks {
                let _ = task.await;
            }
            let _ = ingest_task.await;
            // Finish any in-flight batch before the final forced drain.
            let _ = stop_flush.send(());
            let _ = flush_task.await;
            info!("Shutdown signal received; flushing pending windows and compacting store...");
            if let Err(error) = shutdown_pipeline.flush_and_analyze(true).await {
                error!(%error, "Final analysis failed during shutdown");
            }
            if let Err(error) = shutdown_pipeline.store.compact_persistence_file() {
                error!(%error, "Final persistence compaction failed");
            }
        })
        .await?;
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
    let pipeline =
        SecurityPipeline::new(store.clone(), window.clone(), jev.clone(), firewall.clone())?;

    let events = replay_log_file(log_path, format)?;
    println!(
        "=== Custos Replay: {} ({} parsed events, mode={}, firewall={} [dry_run={}]) ===",
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

    if cfg.hub.enabled && !verdicts.is_empty() {
        let ack = push_verdicts_via_grpc(
            &cfg.hub.endpoint,
            &cfg.hub.node_id,
            &cfg.hub.api_token,
            &verdicts,
            cfg.daemon.default_ban_ttl_secs,
        )
        .await?;
        println!(
            "\n--- CustosHub gRPC Signal Push ({}) ---\n  Node ID              : {}\n  Accepted IP Signals  : {}\n  Accepted Signatures  : {}\n  Rejected Canary      : {}\n  Hub Latest Seq       : {}",
            cfg.hub.endpoint,
            cfg.hub.node_id,
            ack.accepted_ips,
            ack.accepted_signatures,
            ack.rejected_canary,
            ack.latest_seq
        );
    }

    println!(
        "\n--- L1 & Window Telemetry ---\n  Events Processed     : {}\n  Static Assets Ignored: {}\n  L1 Instant Bans      : {}\n  Promoted to Jev L2   : {}",
        window.metrics.events_processed.load(Ordering::Relaxed),
        window.metrics.static_ignored.load(Ordering::Relaxed),
        window.metrics.l1_instant_bans.load(Ordering::Relaxed),
        window
            .metrics
            .windows_promoted_to_jev
            .load(Ordering::Relaxed),
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
    let batch_entries: Vec<(IpAddr, u64)> = active
        .iter()
        .map(|d| {
            let ttl = (d.expires_at - chrono::Utc::now()).num_seconds().max(60) as u64;
            (d.ip, ttl)
        })
        .collect();

    if backend_arg.eq_ignore_ascii_case("all") {
        let backends = [
            FirewallBackend::Pf,
            FirewallBackend::Nftables,
            FirewallBackend::Ipset,
            FirewallBackend::WindowsNetsh,
        ];
        println!(
            "=== Cross-Platform OS Firewall Preview ({} active bans, batched mode) ===",
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
            for batch_spec in fw.build_batch_ban_commands(&batch_entries) {
                println!("  $ {}", batch_spec.to_shell_string());
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
    fw.ban_ips_batch(&batch_entries)?;

    println!(
        "=== OS Firewall Sync Complete (backend={}, dry_run={}, rules_applied={}, commands={}) ===",
        fw.resolved_backend().as_str(),
        fw.is_dry_run(),
        fw.metrics.rules_applied.load(Ordering::Relaxed),
        fw.recent_commands().len()
    );
    for cmd in fw.recent_commands() {
        println!("  $ {cmd}");
    }
    Ok(())
}

async fn cmd_decisions(api_url: &str, cfg: &AppConfig) -> Result<()> {
    let url = format!("{}/v1/decisions", api_url.trim_end_matches('/'));
    if let Ok(resp) = reqwest::get(&url).await
        && let Ok(decisions) = resp.json::<Vec<BanDecision>>().await
    {
        print_decisions(&decisions);
        return Ok(());
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
        "{:<18} {:<24} {:<18} {:<8} EXPIRES AT",
        "IP", "THREAT CLASS", "SOURCE", "NOUL"
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
    api_token: &str,
) -> Result<()> {
    let url = format!("{}/v1/decisions", api_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let payload = ManualBanRequest {
        ip,
        threat_class,
        reason,
        ttl_secs,
    };
    let resp = client
        .post(&url)
        .bearer_auth(api_token)
        .json(&payload)
        .send()
        .await?;
    let decision: BanDecision = resp.error_for_status()?.json().await?;
    println!(
        "Banned {} ({}) until {}",
        decision.ip, decision.threat_class, decision.expires_at
    );
    Ok(())
}

async fn cmd_unban(ip: IpAddr, api_url: &str, api_token: &str) -> Result<()> {
    let url = format!("{}/v1/decisions/{}", api_url.trim_end_matches('/'), ip);
    let client = reqwest::Client::new();
    let resp = client
        .delete(&url)
        .bearer_auth(api_token)
        .send()
        .await?
        .error_for_status()?;
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

    if let Ok(fw_resp) = reqwest::get(&format!("{base}/v1/firewall")).await
        && let Ok(fw) = fw_resp.json::<FirewallStatusResponse>().await
    {
        println!("\n--- Firewall Status ---");
        println!("{}", serde_json::to_string_pretty(&fw)?);
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(windows)]
    {
        // SCM services have no console. A console-handler initialization error
        // must not be mistaken for a service stop request.
        if std::env::args_os().any(|arg| arg == "--windows-service") {
            custos::windows_service::shutdown_requested().await;
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = tokio::signal::ctrl_c().await;
}
