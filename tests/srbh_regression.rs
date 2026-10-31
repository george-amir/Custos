use chrono::{TimeDelta, Utc};
use custos::{
    SecurityPipeline,
    config::{AppConfig, LogFormat, WindowConfig},
    tailer::{AccessLogEvent, parse_log_line},
    window::{L1Disposition, SlidingWindowEngine},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn event(uri: &str) -> AccessLogEvent {
    parse_log_line(
        &serde_json::json!({"ip":"198.51.100.10","uri":uri,
        "method":"GET","status":200,"ua":"Mozilla/5.0"})
        .to_string(),
        LogFormat::Json,
    )
    .unwrap()
}

async fn provider() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    use axum::{Json, extract::State, http::StatusCode, routing::post};
    let mode = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new().route("/", post(|State(mode): State<Arc<AtomicUsize>>, Json(req): Json<serde_json::Value>| async move {
        let mode = mode.load(Ordering::SeqCst);
        if mode == 5 { return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({}))); }
        let mut answers = serde_json::Map::new();
        if mode != 0 {
            for key in req["questions"].as_object().unwrap().keys() {
                let v = if key.ends_with("should_ban") {
                    serde_json::json!({"type":"noul","noul":if mode == 3 {1.4} else {0.99}})
                } else {
                    if mode == 1 || (mode == 10 && key.starts_with("actor_1_")) { continue; }
                    serde_json::json!({"type":"choice", "choice":if mode == 2 {"unknown"} else {"vulnerability_scanner"},"confidence":0.99})
                };
                let mut v = v;
                if key.ends_with("threat_class") {
                    if mode == 6 { v["confidence"] = serde_json::json!(1.5); }
                    if mode == 7 { v["probabilities"] = serde_json::json!({"vulnerability_scanner":-0.2}); }
                    if mode == 8 { v.as_object_mut().unwrap().remove("confidence"); }
                }
                if mode == 9 && key.ends_with("should_ban") { v = serde_json::json!({"type":"score","score":0.99}); }
                answers.insert(key.clone(), v);
            }
        }
        (StatusCode::OK, Json(serde_json::json!({"answers":answers})))
    })).with_state(mode.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (endpoint, mode, task)
}

fn pipeline(dir: &std::path::Path, endpoint: String) -> SecurityPipeline {
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.join("decisions.jsonl");
    cfg.jev.api_key = "loopback-only".into();
    cfg.jev.endpoint = endpoint;
    SecurityPipeline::builder()
        .with_config(cfg)
        .build()
        .unwrap()
}

#[tokio::test]
async fn failed_analysis_never_turns_slow_traffic_into_a_flood_and_can_recover() {
    let (endpoint, mode, server) = provider().await;
    mode.store(5, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(dir.path(), endpoint);
    p.process_event(&event("/.env")).unwrap();
    assert!(p.flush_and_analyze(true).await.is_err());
    let start = Utc::now() - TimeDelta::seconds(1200);
    for i in 0..120 {
        let mut ev = event("/api/ping");
        ev.client_ip = "198.51.100.20".parse().unwrap();
        ev.timestamp = start + TimeDelta::seconds(i * 10);
        p.process_event(&ev).unwrap();
        assert!(p.flush_and_analyze(false).await.is_err());
    }
    assert!(
        p.store
            .check_ip(&"198.51.100.20".parse().unwrap())
            .is_none()
    );
    mode.store(4, Ordering::SeqCst);
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 1);
    assert!(
        p.store
            .check_ip(&"198.51.100.10".parse().unwrap())
            .is_some()
    );
    server.abort();
}

#[test]
fn static_requests_count_toward_flood_limits() {
    let w = SlidingWindowEngine::new(WindowConfig::default());
    for _ in 0..119 {
        assert_eq!(
            w.ingest(&event("/image.webp")),
            L1Disposition::IgnoredStatic
        );
    }
    assert!(matches!(
        w.ingest(&event("/image.webp")),
        L1Disposition::InstantBan { .. }
    ));
}

#[test]
fn static_suffix_never_hides_attack_signals_or_cached_signatures() {
    for (uri, ua) in [
        ("/admin/config/settings.css", "Mozilla"),
        ("/logo.png", "sqlmap"),
    ] {
        let w = SlidingWindowEngine::new(WindowConfig::default());
        let mut e = event(uri);
        e.user_agent = ua.into();
        w.ingest(&e);
        assert_eq!(w.drain_suspicious_summaries(true).len(), 1, "{uri}");
    }
    let w = SlidingWindowEngine::new(WindowConfig::default());
    w.register_auto_signature("GET", "/exploit.css", "vulnerability_scanner");
    assert!(matches!(
        w.ingest(&event("/exploit.css")),
        L1Disposition::InstantBan { .. }
    ));
}

#[tokio::test]
async fn invalid_provider_decisions_are_retained_for_retry_without_bans() {
    let (endpoint, mode, server) = provider().await;
    for invalid in [0, 1, 2, 3, 6, 7, 8, 9] {
        let dir = tempfile::tempdir().unwrap();
        let p = pipeline(dir.path(), endpoint.clone());
        p.process_event(&event("/.env")).unwrap();
        mode.store(invalid, Ordering::SeqCst);
        assert!(
            p.flush_and_analyze(true).await.is_err(),
            "invalid mode {invalid}"
        );
        assert!(p.store.list_active().is_empty());
        assert_eq!(p.jev.metrics.actors_evaluated.load(Ordering::Relaxed), 0);
        mode.store(4, Ordering::SeqCst);
        assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 1);
        assert_eq!(p.store.list_active().len(), 1);
    }
    server.abort();
}

#[test]
fn encoded_and_comment_separated_attack_variants_are_screened() {
    for uri in [
        "/%2eenv",
        "/%252eenv",
        "/view?file=%2Fetc%2Fpasswd",
        "/?id=-1+UNION/**/SELECT+1",
        "/?id=-1%20UNION%09SELECT%201",
    ] {
        let w = SlidingWindowEngine::new(WindowConfig::default());
        w.ingest(&event(uri));
        assert_eq!(w.drain_suspicious_summaries(true).len(), 1, "{uri}");
    }
}

#[test]
fn triggering_payload_survives_sample_crowding_and_long_prefixes() {
    let w = SlidingWindowEngine::new(WindowConfig::default());
    for i in 0..10 {
        w.ingest(&event(&format!("/products/{i}")));
    }
    w.ingest(&event(&format!(
        "/union-of-products/search?q={}+UNION/**/SELECT+password",
        "a".repeat(400)
    )));
    let summaries = w.drain_suspicious_summaries(true);
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].sample_requests.len() <= 10);
    assert!(
        summaries[0]
            .sample_requests
            .iter()
            .any(|s| s.to_lowercase().contains("select"))
    );
}

#[test]
fn credentials_are_redacted_before_any_outbound_state_is_built() {
    let w = SlidingWindowEngine::new(WindowConfig::default());
    w.ingest(&event("/account?access_token=SYNTHETIC_SECRET%26ENCODED_SECRET&api%5Fkey=SECOND_SECRET&password=THIRD_SECRET&mode=grid"));
    w.ingest(&event("/.env"));
    let summaries = w.drain_suspicious_summaries(true);
    let c = custos::jev::JevBatchAnalyzer::new(Default::default(), true).unwrap();
    let state = c.build_batch_request(&summaries).state.to_string();
    for secret in [
        "SYNTHETIC_SECRET",
        "ENCODED_SECRET",
        "SECOND_SECRET",
        "THIRD_SECRET",
    ] {
        assert!(!state.contains(secret), "credential redaction failed");
    }
    assert!(state.contains("REDACTED"));
}

#[test]
fn window_expiration_preserves_evidence_without_combining_request_counts() {
    let w = SlidingWindowEngine::new(WindowConfig::default());
    let mut first = event("/.env");
    first.timestamp = Utc::now() - TimeDelta::seconds(60);
    w.ingest(&first);
    let mut second = event("/.git/config");
    second.timestamp = first.timestamp + TimeDelta::seconds(20);
    w.ingest(&second);
    let summaries = w.drain_suspicious_summaries(true);
    assert_eq!(summaries.len(), 2);
    assert!(summaries.iter().all(|s| s.total_requests == 1));
    assert_ne!(summaries[0].actor_key, summaries[1].actor_key);
}

#[test]
fn retained_state_is_bounded_even_with_extreme_count_configuration() {
    let w = SlidingWindowEngine::new(WindowConfig {
        max_sample_requests: usize::MAX,
        l1_flood_threshold: usize::MAX,
        ..Default::default()
    });
    for i in 0..2048 {
        w.ingest(&event(&format!("/products/{i}/{}", "x".repeat(8000))));
    }
    w.ingest(&event("/.env"));
    let summaries = w.drain_suspicious_summaries(true);
    assert_eq!(summaries[0].unique_paths, 1024);
    assert_eq!(summaries[0].sample_requests.len(), 32);
    assert!(
        summaries[0]
            .sample_requests
            .iter()
            .all(|s| s.chars().count() < 180)
    );
}

#[test]
fn byte_budget_bounds_active_and_expired_windows() {
    let w = SlidingWindowEngine::new(WindowConfig {
        max_state_bytes: 1,
        ..Default::default()
    });
    let start = Utc::now() - TimeDelta::seconds(100);
    for i in 0..5 {
        let mut e = event("/.env");
        e.timestamp = start + TimeDelta::seconds(i * 20);
        w.ingest(&e);
    }
    let mut other = event("/.env");
    other.client_ip = "198.51.100.20".parse().unwrap();
    other.timestamp = start + TimeDelta::seconds(80);
    assert_eq!(w.ingest(&other), L1Disposition::CapacityExceeded);
    assert_eq!(
        w.metrics.expired_evidence_dropped.load(Ordering::Relaxed),
        3
    );
    assert_eq!(w.drain_suspicious_summaries(true).len(), 2);
}

#[tokio::test]
async fn oversized_queued_event_is_bounded_and_keeps_its_security_signal() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("decisions.jsonl");
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    let mut oversized = event("/");
    oversized.path = format!("/{}", "é".repeat(50000));
    p.submit_event(oversized).await.unwrap();
    let verdicts = p.flush_and_analyze(true).await.unwrap();
    assert_eq!(
        verdicts.len(),
        1,
        "oversized input must be referred rather than silently becoming benign"
    );
    assert!(
        !verdicts[0].should_ban,
        "oversize alone must not trigger an automatic ban"
    );
    assert!(verdicts[0].sample_requests[0].chars().count() < 180);
}

#[test]
fn ordinary_encoded_routes_and_static_assets_do_not_require_analysis() {
    let w = SlidingWindowEngine::new(WindowConfig::default());
    for uri in [
        "/products/coffee%20beans",
        "/search?q=tea+bags",
        "/assets/app.css",
    ] {
        w.ingest(&event(uri));
    }
    assert!(w.drain_suspicious_summaries(true).is_empty());
}

#[test]
fn percent_encoding_density_is_retained_as_a_signal_after_decoding() {
    let w = SlidingWindowEngine::new(WindowConfig::default());
    w.ingest(&event("/search?q=%61%62%63%64"));
    let summaries = w.drain_suspicious_summaries(true);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].max_special_chars_in_uri, 4);
}

#[test]
fn idle_suspicious_windows_release_capacity_without_a_provider_flush() {
    let w = SlidingWindowEngine::new(WindowConfig {
        max_tracked_ips: 1,
        ..Default::default()
    });
    let mut first = event("/.env");
    first.timestamp = Utc::now() - TimeDelta::seconds(60);
    w.ingest(&first);
    let mut second = event("/.git/config");
    second.client_ip = "198.51.100.20".parse().unwrap();
    assert!(matches!(w.ingest(&second), L1Disposition::Buffered { .. }));
    assert_eq!(w.drain_suspicious_summaries(true).len(), 2);
}

#[tokio::test]
async fn partial_response_never_applies_or_acknowledges_any_actor_in_the_batch() {
    let (endpoint, mode, server) = provider().await;
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(dir.path(), endpoint);
    p.process_event(&event("/.env")).unwrap();
    let mut second = event("/.env");
    second.client_ip = "198.51.100.20".parse().unwrap();
    p.process_event(&second).unwrap();
    mode.store(10, Ordering::SeqCst);
    assert!(p.flush_and_analyze(true).await.is_err());
    assert!(p.store.list_active().is_empty());
    mode.store(4, Ordering::SeqCst);
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 2);
    server.abort();
}
