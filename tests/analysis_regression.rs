use axum::{Json, extract::State, routing::post};
use custos::{
    SecurityPipeline,
    config::{AppConfig, LogFormat},
    limits::MemoryLimits,
    tailer::{AccessLogEvent, parse_log_line},
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
struct Provider {
    mode: AtomicUsize,
    requests: Mutex<Vec<serde_json::Value>>,
    release: tokio::sync::Notify,
}

async fn provider() -> (String, Arc<Provider>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Provider::default());
    let app = axum::Router::new().route("/", post(|State(state): State<Arc<Provider>>, Json(request): Json<serde_json::Value>| async move {
        state.requests.lock().unwrap().push(request.clone());
        let mode = state.mode.load(Ordering::Relaxed);
        if mode == 3 { state.release.notified().await; }
        let poisoned = request["state"]["actors"].as_array().unwrap().iter().any(|line| line.as_str().unwrap().contains("ip=198.51.100.1 |"));
        if mode == 1 || (mode == 2 && poisoned) { return Json(serde_json::json!({"answers":{}})); }
        let answers: serde_json::Map<_, _> = request["questions"].as_object().unwrap().keys().map(|key| {
            (key.clone(), if key.ends_with("_should_ban") { serde_json::json!({"type":"noul","noul":0.99}) } else { serde_json::json!({"type":"choice","choice":"sqli_or_injection","confidence":0.99}) })
        }).collect();
        Json(serde_json::json!({"answers": answers}))
    })).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), state, task)
}

fn event(n: u8) -> AccessLogEvent {
    parse_log_line(
        &format!(
            r#"{{"ip":"198.51.100.{n}","uri":"/search?q=1+UNION+SELECT+password","status":500}}"#
        ),
        LogFormat::Json,
    )
    .unwrap()
}

fn pipeline(
    dir: &std::path::Path,
    endpoint: String,
    limits: MemoryLimits,
    batch: usize,
) -> SecurityPipeline {
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.join("ledger");
    cfg.firewall.enabled = false;
    cfg.jev.endpoint = endpoint;
    cfg.jev.api_key = "loopback-only".into();
    cfg.jev.max_actors_per_batch = batch;
    cfg.memory = limits;
    SecurityPipeline::builder()
        .with_config(cfg)
        .build()
        .unwrap()
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn outage_queue_is_count_and_byte_bounded_and_admits_fresh_windows() {
    let (url, provider, server) = provider().await;
    provider.mode.store(1, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    let limits = MemoryLimits {
        max_pending_actors: 4,
        max_pending_bytes: 64 * 1024,
        analysis_batches_per_flush: 1,
        ..Default::default()
    };
    let p = pipeline(dir.path(), url, limits.clone(), 2);
    for wave in 0..10u8 {
        for n in 1..=8 {
            p.process_event(&event(wave * 8 + n)).unwrap();
        }
        assert!(p.flush_and_analyze(true).await.is_err());
        assert!(p.analysis_metrics.pending_actors.load(Ordering::Relaxed) <= 4);
        assert!(
            p.analysis_metrics.pending_bytes.load(Ordering::Relaxed) <= limits.max_pending_bytes
        );
    }
    assert!(p.analysis_metrics.capacity_dropped.load(Ordering::Relaxed) >= 76);
    assert_eq!(
        provider.requests.lock().unwrap().len(),
        10,
        "outages cannot exceed the per-flush work budget"
    );
    provider.mode.store(0, Ordering::Relaxed);
    for _ in 0..4 {
        p.flush_and_analyze(true).await.unwrap();
    }
    assert_eq!(p.analysis_metrics.pending_actors.load(Ordering::Relaxed), 0);
    let bans = p.store.list_active();
    assert_eq!(bans.len(), 4);
    assert!(
        bans.iter()
            .all(|ban| (73..=80).any(|n| event(n).client_ip == ban.ip)),
        "fresh evidence must replace stale uncommitted windows"
    );
    server.abort();
}

#[tokio::test]
async fn byte_limit_alone_rejects_evidence_that_cannot_fit() {
    let (url, provider, server) = provider().await;
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(
        dir.path(),
        url,
        MemoryLimits {
            max_pending_bytes: 1,
            ..Default::default()
        },
        25,
    );
    p.process_event(&event(1)).unwrap();
    assert!(p.flush_and_analyze(true).await.unwrap().is_empty());
    assert_eq!(
        p.analysis_metrics.capacity_dropped.load(Ordering::Relaxed),
        1
    );
    assert_eq!(p.analysis_metrics.pending_bytes.load(Ordering::Relaxed), 0);
    assert!(provider.requests.lock().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn stale_evidence_expires_from_observation_and_retries_do_not_extend_its_lifetime() {
    let (url, provider, server) = provider().await;
    provider.mode.store(1, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(
        dir.path(),
        url,
        MemoryLimits {
            analysis_ttl_secs: 1,
            ..Default::default()
        },
        25,
    );
    p.process_event(&event(1)).unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(p.flush_and_analyze(true).await.unwrap().is_empty());
    assert!(provider.requests.lock().unwrap().is_empty());
    p.process_event(&event(2)).unwrap();
    assert!(p.flush_and_analyze(true).await.is_err());
    for _ in 0..10 {
        assert!(p.flush_and_analyze(false).await.is_err());
    }
    assert_eq!(
        provider.requests.lock().unwrap().len(),
        1,
        "backoff suppresses repeated requests"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    provider.mode.store(0, Ordering::Relaxed);
    p.process_event(&event(3)).unwrap();
    let verdicts = p.flush_and_analyze(true).await.unwrap();
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].client_ip, event(3).client_ip);
    assert_eq!(p.analysis_metrics.expired.load(Ordering::Relaxed), 2);
    assert!(p.store.check_ip(&event(2).client_ip).is_none());
    server.abort();
}

#[tokio::test]
async fn poisoned_actor_does_not_starve_other_retry_actors_or_new_windows() {
    let (url, provider, server) = provider().await;
    provider.mode.store(2, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(dir.path(), url, MemoryLimits::default(), 25);
    p.process_event(&event(1)).unwrap();
    p.process_event(&event(2)).unwrap();
    assert!(p.flush_and_analyze(true).await.is_err());
    let recovered = p.flush_and_analyze(true).await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].client_ip, event(2).client_ip);
    p.process_event(&event(3)).unwrap();
    assert_eq!(
        p.flush_and_analyze(true).await.unwrap()[0].client_ip,
        event(3).client_ip
    );
    assert!(p.store.check_ip(&event(1).client_ip).is_none());
    assert!(p.store.check_ip(&event(2).client_ip).is_some());
    assert!(p.store.check_ip(&event(3).client_ip).is_some());
    assert_eq!(p.analysis_metrics.pending_actors.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn merged_drains_keep_unique_actor_questions_and_preserve_every_verdict() {
    let (url, provider, server) = provider().await;
    provider.mode.store(1, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(
        dir.path(),
        url,
        MemoryLimits {
            analysis_batches_per_flush: 1,
            ..Default::default()
        },
        2,
    );
    for n in 1..=3 {
        p.process_event(&event(n)).unwrap();
    }
    assert!(p.flush_and_analyze(true).await.is_err());
    for n in 4..=6 {
        p.process_event(&event(n)).unwrap();
    }
    provider.mode.store(0, Ordering::Relaxed);
    for _ in 0..6 {
        p.flush_and_analyze(true).await.unwrap();
    }
    assert_eq!(p.store.active_count(), 6);
    for request in provider.requests.lock().unwrap().iter() {
        let actors = request["state"]["actors"].as_array().unwrap();
        assert_eq!(
            request["questions"].as_object().unwrap().len(),
            actors.len() * 2
        );
        let keys: std::collections::HashSet<_> = actors
            .iter()
            .map(|actor| actor.as_str().unwrap().split(" | ").next().unwrap())
            .collect();
        assert_eq!(keys.len(), actors.len());
    }
    server.abort();
}

#[tokio::test]
async fn each_flush_has_a_fixed_work_budget_and_concurrent_flushes_do_not_queue() {
    let (url, provider, server) = provider().await;
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(
        dir.path(),
        url,
        MemoryLimits {
            analysis_batches_per_flush: 2,
            ..Default::default()
        },
        2,
    );
    for n in 1..=10 {
        p.process_event(&event(n)).unwrap();
    }
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 4);
    assert_eq!(provider.requests.lock().unwrap().len(), 2);
    provider.mode.store(3, Ordering::Relaxed);
    let running = {
        let p = p.clone();
        tokio::spawn(async move { p.flush_and_analyze(true).await })
    };
    wait_until(|| provider.requests.lock().unwrap().len() == 3).await;
    for _ in 0..100 {
        assert!(p.flush_and_analyze(true).await.is_err());
    }
    assert_eq!(provider.requests.lock().unwrap().len(), 3);
    provider.mode.store(0, Ordering::Relaxed);
    provider.release.notify_one();
    assert_eq!(running.await.unwrap().unwrap().len(), 4);
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 2);
    server.abort();
}

#[tokio::test]
async fn evidence_expiring_during_provider_call_is_never_enforced() {
    let (url, provider, server) = provider().await;
    provider.mode.store(3, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(
        dir.path(),
        url,
        MemoryLimits {
            analysis_ttl_secs: 1,
            ..Default::default()
        },
        25,
    );
    p.process_event(&event(1)).unwrap();
    let running = {
        let p = p.clone();
        tokio::spawn(async move { p.flush_and_analyze(true).await })
    };
    wait_until(|| !provider.requests.lock().unwrap().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    provider.release.notify_one();
    assert!(running.await.unwrap().unwrap().is_empty());
    assert_eq!(p.store.retained_count(), 0);
    assert_eq!(p.analysis_metrics.expired.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_flush_cannot_accumulate_blocked_enforcement_jobs() {
    use custos::{
        config::FirewallConfig,
        firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
        jev::JevBatchAnalyzer,
        store::DecisionStore,
        window::SlidingWindowEngine,
    };
    use std::sync::{Condvar, atomic::AtomicBool};
    struct Gate {
        entered: AtomicBool,
        open: Mutex<bool>,
        changed: Condvar,
    }
    impl FirewallCommandRunner for Gate {
        fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
            self.entered.store(true, Ordering::SeqCst);
            let (open, timeout) = self
                .changed
                .wait_timeout_while(self.open.lock().unwrap(), Duration::from_secs(5), |open| {
                    !*open
                })
                .unwrap();
            assert!(*open && !timeout.timed_out());
            Ok(0)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(Gate {
        entered: AtomicBool::new(false),
        open: Mutex::new(false),
        changed: Condvar::new(),
    });
    let p = SecurityPipeline::new(
        Arc::new(DecisionStore::open(dir.path().join("ledger"), 3600).unwrap()),
        Arc::new(SlidingWindowEngine::new(Default::default())),
        Arc::new(JevBatchAnalyzer::new(Default::default(), true).unwrap()),
        Arc::new(FirewallBouncer::with_runner(
            FirewallConfig {
                backend: FirewallBackend::Pf,
                dry_run: false,
                ..Default::default()
            },
            gate.clone(),
            Duration::from_secs(1),
        )),
    )
    .unwrap();
    p.process_event(&event(1)).unwrap();
    let running = {
        let p = p.clone();
        tokio::spawn(async move { p.flush_and_analyze(true).await })
    };
    wait_until(|| gate.entered.load(Ordering::SeqCst)).await;
    running.abort();
    let _ = running.await;
    for _ in 0..100 {
        assert!(p.flush_and_analyze(true).await.is_err());
    }
    assert!(p.store.check_ip(&event(1).client_ip).is_some());
    *gate.open.lock().unwrap() = true;
    gate.changed.notify_all();
    wait_until(|| p.firewall.metrics.rules_applied.load(Ordering::Relaxed) > 0).await;
    p.flush_and_analyze(true).await.unwrap();
    assert_eq!(p.analysis_metrics.pending_actors.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn durable_ban_enforcement_retries_independently_of_expired_analysis_evidence() {
    use custos::{
        config::FirewallConfig,
        firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
        jev::JevBatchAnalyzer,
        store::DecisionStore,
        window::SlidingWindowEngine,
    };
    use std::sync::atomic::AtomicBool;
    struct Switch(AtomicBool);
    impl FirewallCommandRunner for Switch {
        fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
            Ok(if self.0.load(Ordering::Relaxed) { 2 } else { 0 })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(Switch(AtomicBool::new(true)));
    let p = SecurityPipeline::new_with_limits(
        Arc::new(DecisionStore::open(dir.path().join("ledger"), 3600).unwrap()),
        Arc::new(SlidingWindowEngine::new(Default::default())),
        Arc::new(JevBatchAnalyzer::new(Default::default(), true).unwrap()),
        Arc::new(FirewallBouncer::with_runner(
            FirewallConfig {
                backend: FirewallBackend::Pf,
                dry_run: false,
                ..Default::default()
            },
            runner.clone(),
            Duration::from_secs(1),
        )),
        MemoryLimits {
            analysis_ttl_secs: 1,
            ..Default::default()
        },
    )
    .unwrap();
    p.process_event(&event(1)).unwrap();
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 1);
    assert_eq!(p.analysis_metrics.pending_actors.load(Ordering::Relaxed), 0);
    assert!(p.store.check_ip(&event(1).client_ip).is_some());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    runner.0.store(false, Ordering::Relaxed);
    wait_until(|| p.firewall.metrics.rules_applied.load(Ordering::Relaxed) > 0).await;
    assert!(p.store.check_ip(&event(1).client_ip).is_some());
    assert!(
        DecisionStore::open(dir.path().join("ledger"), 3600)
            .unwrap()
            .check_ip(&event(1).client_ip)
            .is_some()
    );
}
