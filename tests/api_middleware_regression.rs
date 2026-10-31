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
    config::{AppConfig, FirewallConfig},
    firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
    jev::JevBatchAnalyzer,
    middleware::custos_bouncer_middleware,
    store::{DecisionSource, DecisionStore},
    window::SlidingWindowEngine,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
use tower::ServiceExt;

fn pipeline(dir: &tempfile::TempDir, proxies: Vec<IpAddr>) -> SecurityPipeline {
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("decisions.jsonl");
    cfg.daemon.trusted_proxies = proxies;
    cfg.firewall.enabled = false;
    SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap()
}

fn ban(p: &SecurityPipeline, ip: &str) {
    p.record_ban(
        ip.parse().unwrap(),
        "manual".into(),
        DecisionSource::ManualAdmin,
        1.0,
        1.0,
        "test".into(),
        None,
    )
    .unwrap();
}

#[tokio::test]
async fn admin_mutations_require_the_configured_token_and_unban_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(&dir, vec![]);
    let app = build_bouncer_router(AppState {
        pipeline: p.clone(),
        api_token: "correct-secret".into(),
    });
    for token in [None, Some("Bearer wrong")] {
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/decisions")
            .header("content-type", "application/json");
        if let Some(token) = token {
            req = req.header("authorization", token);
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::from(r#"{"ip":"198.51.100.22"}"#)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/decisions")
                .header("authorization", "Bearer correct-secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ip":"198.51.100.22"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/decisions/198.51.100.22")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        p.store
            .check_ip(&"198.51.100.22".parse().unwrap())
            .is_some()
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/decisions/198.51.100.22")
                .header("authorization", "Bearer correct-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let reopened = DecisionStore::open(dir.path().join("decisions.jsonl"), 3600).unwrap();
    assert!(
        reopened
            .check_ip(&"198.51.100.22".parse().unwrap())
            .is_none()
    );
}

#[tokio::test]
async fn absent_admin_secret_disables_mutations_but_not_checks() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_bouncer_router(AppState {
        pipeline: pipeline(&dir, vec![]),
        api_token: String::new(),
    });
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/decisions/198.51.100.22")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=198.51.100.22")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
}

fn embedded(p: SecurityPipeline) -> Router {
    Router::new().route("/hello", get(|| async { "ok" })).layer(
        axum::middleware::from_fn_with_state(p, custos_bouncer_middleware),
    )
}
fn request(peer: &str) -> axum::http::request::Builder {
    Request::builder()
        .uri("/hello")
        .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
}

#[tokio::test]
async fn direct_clients_cannot_spoof_or_omit_their_banned_identity() {
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(&dir, vec![]);
    ban(&p, "198.51.100.22");
    let app = embedded(p);
    for spoof in [false, true] {
        let mut req = request("198.51.100.22:1234");
        if spoof {
            req = req
                .header("x-real-ip", "198.51.100.23")
                .header("x-forwarded-for", "198.51.100.23");
        }
        assert_eq!(
            app.clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(
                request("198.51.100.23:1234")
                    .header("x-real-ip", "198.51.100.22")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/hello")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn trusted_proxy_chain_ignores_spoofed_leftmost_address() {
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(&dir, vec!["127.0.0.1".parse().unwrap()]);
    ban(&p, "198.51.100.22");
    let app = embedded(p);
    let mut duplicate = request("127.0.0.1:1234")
        .header("x-forwarded-for", "198.51.100.23")
        .body(Body::empty())
        .unwrap();
    duplicate
        .headers_mut()
        .append("x-forwarded-for", "198.51.100.22".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    for forwarded in [
        "198.51.100.23, 198.51.100.22",
        "198.51.100.23, 198.51.100.22, 127.0.0.1",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(
                    request("127.0.0.1:1234")
                        .header("x-forwarded-for", forwarded)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(
                request("127.0.0.1:1234")
                    .header("x-real-ip", "198.51.100.22")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.oneshot(
            request("127.0.0.1:1234")
                .header("x-forwarded-for", "malformed")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}

struct SlowFirewall {
    gate: (Mutex<bool>, Condvar),
    started: tokio::sync::Notify,
}
impl FirewallCommandRunner for SlowFirewall {
    fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
        self.started.notify_one();
        let guard = self.gate.0.lock().unwrap();
        let _guard = self
            .gate
            .1
            .wait_timeout_while(guard, Duration::from_secs(2), |open| !*open)
            .unwrap();
        Ok(0)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn slow_firewall_does_not_block_http_response_or_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(SlowFirewall {
        gate: (Mutex::new(false), Condvar::new()),
        started: tokio::sync::Notify::new(),
    });
    let firewall = Arc::new(FirewallBouncer::with_runner(
        FirewallConfig {
            enabled: true,
            backend: FirewallBackend::Pf,
            dry_run: false,
            table_name: "test".into(),
        },
        runner.clone(),
        Duration::from_secs(3),
    ));
    let p = SecurityPipeline::new(
        Arc::new(DecisionStore::open(dir.path().join("decisions.jsonl"), 3600).unwrap()),
        Arc::new(SlidingWindowEngine::new(custos::config::WindowConfig {
            l1_flood_threshold: 1,
            flood_action: custos::config::FloodAction::Ban,
            ..Default::default()
        })),
        Arc::new(JevBatchAnalyzer::new(Default::default(), true).unwrap()),
        firewall,
    )
    .unwrap();
    let start = Instant::now();
    let response = embedded(p.clone())
        .oneshot(request("198.51.100.22:1234").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let elapsed = start.elapsed();
    tokio::time::timeout(Duration::from_secs(1), runner.started.notified())
        .await
        .expect("queued event must reach enforcement");
    *runner.gate.0.lock().unwrap() = true;
    runner.gate.1.notify_all();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        elapsed < Duration::from_secs(1),
        "HTTP handler waited for blocking enforcement: {elapsed:?}"
    );
    p.flush_and_analyze(true).await.unwrap();
}

struct SwitchableFirewall(std::sync::atomic::AtomicBool);
impl FirewallCommandRunner for SwitchableFirewall {
    fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
        Ok(if self.0.load(std::sync::atomic::Ordering::Relaxed) {
            1
        } else {
            0
        })
    }
}

#[tokio::test]
async fn api_reports_enforcement_failure_and_reconciliation_retries_bans_and_unbans() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(SwitchableFirewall(AtomicBool::new(true)));
    let firewall = Arc::new(FirewallBouncer::with_runner(
        FirewallConfig {
            enabled: true,
            backend: FirewallBackend::Pf,
            dry_run: false,
            table_name: "test".into(),
        },
        runner.clone(),
        Duration::from_secs(1),
    ));
    let p = SecurityPipeline::new(
        Arc::new(DecisionStore::open(dir.path().join("retry.jsonl"), 3600).unwrap()),
        Arc::new(SlidingWindowEngine::new(Default::default())),
        Arc::new(JevBatchAnalyzer::new(Default::default(), true).unwrap()),
        firewall.clone(),
    )
    .unwrap();
    let app = build_bouncer_router(AppState {
        pipeline: p.clone(),
        api_token: "secret".into(),
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/decisions")
                .header("authorization", "Bearer secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ip":"198.51.100.22"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let ip = "198.51.100.22".parse().unwrap();
    assert!(p.store.check_ip(&ip).is_some());
    assert_eq!(firewall.metrics.rules_applied.load(Ordering::Relaxed), 0);
    runner.0.store(false, Ordering::Relaxed);
    p.reconcile_firewall().unwrap();
    // Background retry and explicit reconciliation may both apply the idempotent rule.
    assert!(firewall.metrics.rules_applied.load(Ordering::Relaxed) >= 1);
    runner.0.store(true, Ordering::Relaxed);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/decisions/198.51.100.22")
                .header("authorization", "Bearer secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(p.store.check_ip(&ip).is_none());
    assert_eq!(p.store.sweep_expired(), vec![ip]);
    runner.0.store(false, Ordering::Relaxed);
    p.reconcile_firewall().unwrap();
    assert!(p.store.sweep_expired().is_empty());
    let reopened = DecisionStore::open(dir.path().join("retry.jsonl"), 3600).unwrap();
    assert!(reopened.check_ip(&ip).is_none());
    assert!(reopened.sweep_expired().is_empty());
}
