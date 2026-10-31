use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    routing::get,
};
use custos::{
    SecurityPipeline,
    bouncer_api::{AppState, build_bouncer_router},
    config::{AppConfig, DecisionCapacityPolicy, FirewallConfig},
    firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
    jev::JevBatchAnalyzer,
    limits::MemoryLimits,
    middleware::custos_bouncer_middleware,
    store::{DecisionSource, DecisionStore},
    window::SlidingWindowEngine,
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;

fn ip(n: u32) -> IpAddr {
    std::net::Ipv4Addr::from(0xc6330000 + n).into()
}

fn ban(p: &SecurityPipeline, n: u32, ttl: u64) {
    p.record_ban(
        ip(n),
        "test".into(),
        DecisionSource::ManualAdmin,
        1.,
        1.,
        "regression".into(),
        Some(ttl),
    )
    .unwrap();
}

fn app(p: &SecurityPipeline) -> Router {
    build_bouncer_router(AppState {
        pipeline: p.clone(),
        api_token: String::new(),
    })
}

async fn check(app: &Router, n: u32) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/bouncer/check?ip={}", ip(n)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

fn embedded(p: &SecurityPipeline, called: Arc<AtomicUsize>) -> Router {
    Router::new()
        .fallback(get(move || {
            let called = called.clone();
            async move {
                called.fetch_add(1, Ordering::Relaxed);
                "healthy"
            }
        }))
        .layer(axum::middleware::from_fn_with_state(
            p.clone(),
            custos_bouncer_middleware,
        ))
}

async fn visit(app: &Router, n: u32, path: &str) -> StatusCode {
    let mut request = Request::builder().uri(path).body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip(n), 12345)));
    app.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn full_ledger_preserves_website_availability_existing_bans_and_signatures() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    cfg.memory.max_decisions = 2;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    ban(&p, 1, 3600);
    ban(&p, 2, 3600);
    p.window
        .register_auto_signature("GET", "/.env", "vulnerability_scanner");
    let checker = app(&p);
    let called = Arc::new(AtomicUsize::new(0));
    let website = embedded(&p, called.clone());
    for n in 10..110 {
        assert_eq!(check(&checker, n).await, StatusCode::OK);
        assert_eq!(visit(&website, n, "/products").await, StatusCode::OK);
    }
    assert_eq!(
        visit(&website, 200, "/wp-login.php").await,
        StatusCode::OK,
        "a suspicious-path heuristic alone is not a signature"
    );
    assert_eq!(check(&checker, 1).await, StatusCode::FORBIDDEN);
    assert_eq!(visit(&website, 1, "/products").await, StatusCode::FORBIDDEN);
    assert_eq!(visit(&website, 300, "/.env").await, StatusCode::FORBIDDEN);
    assert_eq!(
        called.load(Ordering::Relaxed),
        101,
        "blocked requests must never reach the handler"
    );
    assert_eq!(p.store.retained_count(), 2);
    assert!(
        p.record_ban(
            ip(300),
            "test".into(),
            DecisionSource::ManualAdmin,
            1.,
            1.,
            "full".into(),
            None
        )
        .is_err()
    );
    assert_eq!(
        p.store.capacity_rejected.load(Ordering::Relaxed),
        1,
        "normal requests do not count as rejected ban admissions"
    );
    let response = checker
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let metrics = std::str::from_utf8(&bytes).unwrap();
    assert!(metrics.contains("custos_decision_saturated 1\n"));
    assert!(metrics.contains("custos_decision_capacity_rejected_total 1\n"));
    assert!(p.capacity_allowed.load(Ordering::Relaxed) >= 201);
    assert_eq!(
        DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 2)
            .unwrap()
            .active_count(),
        2
    );
}

#[tokio::test]
async fn strict_policy_and_ingestion_backpressure_remain_independent() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    cfg.memory.max_decisions = 1;
    cfg.memory.event_queue_bytes = custos::limits::EVENT_RESERVATION_BYTES;
    cfg.daemon.on_decision_capacity = DecisionCapacityPolicy::FailClosed;
    let mut p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    ban(&p, 1, 3600);
    assert_eq!(check(&app(&p), 2).await, StatusCode::SERVICE_UNAVAILABLE);
    let called = Arc::new(AtomicUsize::new(0));
    assert_eq!(
        visit(&embedded(&p, called.clone()), 2, "/products").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(called.load(Ordering::Relaxed), 0);
    p.on_decision_capacity = DecisionCapacityPolicy::EnforceExisting;
    let held = p.reserve_event().unwrap();
    assert!(
        p.reserve_event().is_err(),
        "decision policy must not bypass the byte budget"
    );
    assert_eq!(
        check(&app(&p), 2).await,
        StatusCode::OK,
        "read-only checks need no ingestion reservation"
    );
    drop(held);
    assert!(p.reserve_event().is_ok());
}

#[tokio::test]
async fn proxy_metadata_enforces_exact_signatures_and_rejects_invalid_pairs() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    p.window.register_auto_signature("GET", "/.env", "scanner");
    let checker = app(&p);
    for (method, uri, expected) in [
        (Some("GET"), Some("/.env?x=1"), StatusCode::FORBIDDEN),
        (Some("POST"), Some("/.env"), StatusCode::OK),
        (Some("GET"), Some("/.env.example"), StatusCode::OK),
        (None, None, StatusCode::OK),
        (Some("GET"), None, StatusCode::BAD_REQUEST),
        (None, Some("/.env"), StatusCode::BAD_REQUEST),
        (
            Some("GET"),
            Some("https://example.com/.env"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut request = Request::builder().uri(format!("/v1/bouncer/check?ip={}", ip(1)));
        if let Some(method) = method {
            request = request.header("x-original-method", method);
        }
        if let Some(uri) = uri {
            request = request.header("x-original-uri", uri);
        }
        assert_eq!(
            checker
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            expected
        );
    }
    assert_eq!(p.store.retained_count(), 0);
}

#[derive(Default)]
struct Kernel {
    live: Mutex<HashSet<IpAddr>>,
    fail_delete: AtomicBool,
    failed_ip: Mutex<Option<IpAddr>>,
    deletes: AtomicUsize,
    adds: AtomicUsize,
    gate: Mutex<Option<CleanupGate>>,
}

type CleanupGate = Arc<(Mutex<bool>, Condvar)>;

impl FirewallCommandRunner for Kernel {
    fn run(&self, command: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
        assert_eq!(command.program, "pfctl");
        let addresses: Vec<IpAddr> = command.args[4..]
            .iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        if command.args[3] == "add" {
            if !addresses.is_empty() {
                self.adds.fetch_add(1, Ordering::Relaxed);
            }
            self.live.lock().unwrap().extend(addresses);
        } else {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                let (open, changed) = &*gate;
                let (guard, timeout) = changed
                    .wait_timeout_while(open.lock().unwrap(), Duration::from_secs(5), |open| !*open)
                    .unwrap();
                assert!(
                    *guard && !timeout.timed_out(),
                    "test cleanup gate timed out"
                );
            }
            if self.fail_delete.load(Ordering::Relaxed)
                || self
                    .failed_ip
                    .lock()
                    .unwrap()
                    .is_some_and(|ip| addresses.contains(&ip))
            {
                return Ok(2);
            }
            let mut live = self.live.lock().unwrap();
            for ip in addresses {
                live.remove(&ip);
            }
        }
        Ok(0)
    }
}

fn kernel_pipeline(
    dir: &std::path::Path,
    kernel: Arc<Kernel>,
    capacity: usize,
) -> SecurityPipeline {
    kernel_pipeline_with_limits(
        dir,
        kernel,
        MemoryLimits {
            max_decisions: capacity,
            ..Default::default()
        },
    )
}

fn kernel_pipeline_with_limits(
    dir: &std::path::Path,
    kernel: Arc<Kernel>,
    limits: MemoryLimits,
) -> SecurityPipeline {
    SecurityPipeline::new_with_limits(
        Arc::new(
            DecisionStore::open_with_limit(dir.join("ledger"), 3600, limits.max_decisions).unwrap(),
        ),
        Arc::new(SlidingWindowEngine::new(Default::default())),
        Arc::new(JevBatchAnalyzer::new(Default::default(), true).unwrap()),
        Arc::new(FirewallBouncer::with_runner(
            FirewallConfig {
                backend: FirewallBackend::Pf,
                dry_run: false,
                ..Default::default()
            },
            kernel,
            Duration::from_secs(1),
        )),
        limits,
    )
    .unwrap()
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn capacity_pressure_reclaims_expired_entries_without_waiting_for_periodic_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let p = kernel_pipeline(dir.path(), kernel.clone(), 1);
    ban(&p, 1, 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(p.store.is_at_capacity());
    assert!(p.store.check_ip(&ip(1)).is_none());
    assert_eq!(check(&app(&p), 2).await, StatusCode::OK);
    wait_until(|| p.store.retained_count() == 0).await;
    assert!(!kernel.live.lock().unwrap().contains(&ip(1)));
    assert_eq!(kernel.deletes.load(Ordering::Relaxed), 1);
    assert_eq!(
        kernel.adds.load(Ordering::Relaxed),
        1,
        "pressure cleanup must not refresh all active rules"
    );
    assert_eq!(
        DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 1)
            .unwrap()
            .retained_count(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_cleanup_does_not_block_normal_requests_or_new_ban_capacity_rejections() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let p = kernel_pipeline(dir.path(), kernel.clone(), 2);
    ban(&p, 1, 3600);
    ban(&p, 2, 3600);
    p.store.remove_ban(&ip(2)).unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    *kernel.gate.lock().unwrap() = Some(gate.clone());
    let checker = app(&p);
    assert_eq!(check(&checker, 3).await, StatusCode::OK);
    wait_until(|| kernel.deletes.load(Ordering::SeqCst) > 0).await;
    let website = embedded(&p, Arc::new(AtomicUsize::new(0)));
    tokio::time::timeout(Duration::from_secs(2), async {
        for n in 10..110 {
            assert_eq!(check(&checker, n).await, StatusCode::OK);
            assert_eq!(visit(&website, n, "/products").await, StatusCode::OK);
        }
        let attempt = p.clone();
        assert!(
            tokio::task::spawn_blocking(move || attempt.record_ban(
                ip(500),
                "test".into(),
                DecisionSource::ManualAdmin,
                1.,
                1.,
                "full".into(),
                None
            ))
            .await
            .unwrap()
            .is_err()
        );
    })
    .await
    .unwrap();
    assert_eq!(p.store.retained_count(), 2);
    assert!(p.store.check_ip(&ip(1)).is_some());
    assert_eq!(p.store.sweep_expired(), vec![ip(2)]);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    wait_until(|| p.store.retained_count() == 1).await;
}

#[test]
fn partial_batch_failure_preserves_only_unconfirmed_cleanup_and_every_active_ban() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let p = kernel_pipeline(dir.path(), kernel.clone(), 257);
    ban(&p, 1, 3600);
    for n in 2..=257 {
        ban(&p, n, 3600);
        p.store.remove_ban(&ip(n)).unwrap();
    }
    *kernel.failed_ip.lock().unwrap() = Some(ip(200));
    assert!(p.reconcile_firewall().is_err());
    assert_eq!(
        kernel.deletes.load(Ordering::Relaxed),
        2,
        "256 IPs use two bounded delete groups"
    );
    assert_eq!(p.store.sweep_expired().len(), 128);
    let reopened = DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 257).unwrap();
    assert_eq!(reopened.sweep_expired().len(), 128);
    assert!(reopened.check_ip(&ip(1)).is_some());
    *kernel.failed_ip.lock().unwrap() = None;
    p.reconcile_firewall().unwrap();
    assert!(p.store.sweep_expired().is_empty());
    assert_eq!(*kernel.live.lock().unwrap(), HashSet::from([ip(1)]));
}

#[test]
fn journal_failure_after_kernel_cleanup_keeps_every_obligation_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let p = kernel_pipeline(dir.path(), kernel, 8);
    for n in 1..=8 {
        ban(&p, n, 3600);
        p.store.remove_ban(&ip(n)).unwrap();
    }
    let path = dir.path().join("ledger");
    let saved = dir.path().join("saved");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(p.reconcile_firewall().is_err());
    assert_eq!(p.store.sweep_expired().len(), 8);
    assert_eq!(
        DecisionStore::open_with_limit(saved.clone(), 3600, 8)
            .unwrap()
            .sweep_expired()
            .len(),
        8
    );
    std::fs::remove_dir(path).unwrap();
    std::fs::rename(saved, dir.path().join("ledger")).unwrap();
    p.reconcile_firewall().unwrap();
    assert_eq!(
        DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 8)
            .unwrap()
            .retained_count(),
        0
    );
}

#[test]
fn reban_waits_for_cleanup_acknowledgment_and_survives_in_kernel_and_journal() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let p = kernel_pipeline(dir.path(), kernel.clone(), 1);
    ban(&p, 1, 3600);
    p.store.remove_ban(&ip(1)).unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    *kernel.gate.lock().unwrap() = Some(gate.clone());
    let cleanup = {
        let p = p.clone();
        std::thread::spawn(move || p.reconcile_firewall().unwrap())
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while kernel.deletes.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    let reban = {
        let p = p.clone();
        std::thread::spawn(move || ban(&p, 1, 3600))
    };
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    cleanup.join().unwrap();
    reban.join().unwrap();
    assert!(p.store.check_ip(&ip(1)).is_some());
    assert!(p.store.sweep_expired().is_empty());
    assert!(kernel.live.lock().unwrap().contains(&ip(1)));
    assert!(
        DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 1)
            .unwrap()
            .check_ip(&ip(1))
            .is_some()
    );
}

#[test]
fn capacity_policy_defaults_and_validation_are_backward_compatible() {
    let cfg: AppConfig = toml::from_str("[daemon]\n").unwrap();
    assert_eq!(
        cfg.daemon.on_decision_capacity,
        DecisionCapacityPolicy::EnforceExisting
    );
    let cfg: AppConfig =
        toml::from_str("[daemon]\non_decision_capacity = 'fail_closed'\n").unwrap();
    assert_eq!(
        cfg.daemon.on_decision_capacity,
        DecisionCapacityPolicy::FailClosed
    );
    assert!(toml::from_str::<AppConfig>("[daemon]\non_decision_capacity = 'typo'\n").is_err());
    let mut limits = MemoryLimits {
        max_pending_bytes: 0,
        ..Default::default()
    };
    assert!(limits.validate().is_err());
    limits.max_pending_bytes = 1024;
    limits.analysis_ttl_secs = u64::MAX;
    assert!(limits.validate().is_err());
}

#[test]
fn dry_run_cannot_acknowledge_cleanup_inherited_from_live_enforcement() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let live = kernel_pipeline(dir.path(), kernel.clone(), 1);
    ban(&live, 1, 3600);
    drop(live);
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.memory.max_decisions = 1;
    cfg.firewall.backend = FirewallBackend::Pf;
    cfg.firewall.dry_run = true;
    let dry = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    assert!(dry.remove_ban(&ip(1)).is_err());
    assert_eq!(dry.store.sweep_expired(), vec![ip(1)]);
    dry.store.compact_persistence_file().unwrap();
    drop(dry);
    let reopened = DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 1).unwrap();
    assert!(reopened.cleanup_requires_kernel(&ip(1)));
    assert_eq!(reopened.retained_count(), 1);
    assert!(kernel.live.lock().unwrap().contains(&ip(1)));
    assert_eq!(kernel.deletes.load(Ordering::Relaxed), 0);
    let live = kernel_pipeline(dir.path(), kernel.clone(), 1);
    assert_eq!(live.store.retained_count(), 0);
    assert!(kernel.live.lock().unwrap().is_empty());
}

#[test]
fn http_only_bans_become_durably_marked_before_first_live_enforcement() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    let http = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    ban(&http, 1, 3600);
    assert!(!http.store.cleanup_requires_kernel(&ip(1)));
    drop(http);
    let kernel = Arc::new(Kernel::default());
    let live = kernel_pipeline(dir.path(), kernel.clone(), 1);
    assert!(kernel.live.lock().unwrap().contains(&ip(1)));
    assert!(
        DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 1)
            .unwrap()
            .cleanup_requires_kernel(&ip(1))
    );
    live.remove_ban(&ip(1)).unwrap();
    assert!(kernel.live.lock().unwrap().is_empty());
    assert_eq!(live.store.retained_count(), 0);
}

#[test]
fn legacy_cleanup_records_require_live_removal_and_are_not_discarded_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    std::fs::write(
        &path,
        format!("{{\"operation\":\"remove\",\"ip\":\"{}\"}}\n", ip(1)),
    )
    .unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = path.clone();
    cfg.firewall.enabled = false;
    assert!(
        SecurityPipeline::builder()
            .with_config(cfg)
            .with_mock_jev(true)
            .build()
            .is_err()
    );
    let store = DecisionStore::open(path, 3600).unwrap();
    assert_eq!(store.sweep_expired(), vec![ip(1)]);
    assert!(store.cleanup_requires_kernel(&ip(1)));
}

#[test]
fn renewing_a_live_ban_in_dry_run_preserves_its_kernel_cleanup_requirement() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let live = kernel_pipeline(dir.path(), kernel.clone(), 1);
    ban(&live, 1, 3600);
    drop(live);
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.backend = FirewallBackend::Pf;
    let dry = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    ban(&dry, 1, 3600);
    assert!(dry.store.cleanup_requires_kernel(&ip(1)));
    assert!(dry.remove_ban(&ip(1)).is_err());
    assert!(kernel.live.lock().unwrap().contains(&ip(1)));
}

#[tokio::test]
async fn full_ledger_can_learn_validated_signatures_without_allocating_another_ban() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    cfg.memory.max_decisions = 1;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    ban(&p, 1, 3600);
    let event = custos::tailer::parse_log_line(
        r#"{"ip":"198.51.100.2","uri":"/.env","status":404}"#,
        custos::config::LogFormat::Json,
    )
    .unwrap();
    p.process_event(&event).unwrap();
    assert!(p.flush_and_analyze(true).await.is_err());
    assert!(p.window.cached_signature("GET", "/.env").is_some());
    assert_eq!(p.store.retained_count(), 1);
    let site = embedded(&p, Arc::new(AtomicUsize::new(0)));
    assert_eq!(visit(&site, 3, "/.env").await, StatusCode::FORBIDDEN);
    assert_eq!(visit(&site, 3, "/products").await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn analysis_expiring_while_waiting_for_cleanup_cannot_create_a_late_ban() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::default());
    let p = kernel_pipeline_with_limits(
        dir.path(),
        kernel.clone(),
        MemoryLimits {
            max_decisions: 2,
            analysis_ttl_secs: 1,
            ..Default::default()
        },
    );
    ban(&p, 99, 3600);
    p.store.remove_ban(&ip(99)).unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    *kernel.gate.lock().unwrap() = Some(gate.clone());
    let cleanup = {
        let p = p.clone();
        std::thread::spawn(move || p.reconcile_firewall().unwrap())
    };
    wait_until(|| kernel.deletes.load(Ordering::SeqCst) != 0).await;
    let event = custos::tailer::parse_log_line(
        r#"{"ip":"198.51.100.1","uri":"/search?q=1+UNION+SELECT+password","status":500}"#,
        custos::config::LogFormat::Json,
    )
    .unwrap();
    p.process_event(&event).unwrap();
    let flush = {
        let p = p.clone();
        tokio::spawn(async move { p.flush_and_analyze(true).await })
    };
    wait_until(|| p.jev.metrics.actors_evaluated.load(Ordering::Relaxed) == 1).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    cleanup.join().unwrap();
    assert!(flush.await.unwrap().is_err());
    assert!(p.store.check_ip(&ip(1)).is_none());
    assert_eq!(p.analysis_metrics.expired.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn trusted_original_headers_take_precedence_over_query_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    p.window.register_auto_signature("GET", "/.env", "scanner");
    let response = app(&p)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/bouncer/check?ip={}&method=POST&uri=%2Fsafe",
                    ip(1)
                ))
                .header("x-original-method", "GET")
                .header("x-original-uri", "/.env")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
