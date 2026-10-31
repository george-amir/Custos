use chrono::Utc;
use custos::{SecurityPipeline, config::AppConfig, tailer::AccessLogEvent};

fn event(method: &str, uri: &str, status: u16) -> AccessLogEvent {
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    AccessLogEvent {
        timestamp: Utc::now(),
        client_ip: "198.51.100.80".parse().unwrap(),
        method: method.into(),
        path: path.into(),
        query: query.into(),
        status,
        bytes_sent: 100,
        referer: "-".into(),
        user_agent: "MobileApp/1.0".into(),
    }
}

fn pipeline(dir: &tempfile::TempDir) -> SecurityPipeline {
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("decisions.jsonl");
    SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap()
}

#[tokio::test]
async fn mobile_token_refresh_and_shared_resource_errors_never_convict_an_ip() {
    for status in [401, 403] {
        let dir = tempfile::tempdir().unwrap();
        let p = pipeline(&dir);
        for route in ["/api/profile", "/api/feed", "/api/notifications"] {
            p.process_event(&event("GET", route, status)).unwrap();
        }
        p.process_event(&event("POST", "/api/token/refresh", 200))
            .unwrap();
        p.process_event(&event("GET", "/api/feed", 200)).unwrap();
        p.flush_and_analyze(true).await.unwrap();
        assert!(
            p.store.list_active().is_empty(),
            "resource errors caused an IP ban"
        );
        assert_eq!(
            p.jev
                .metrics
                .actors_evaluated
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}

#[tokio::test]
async fn retries_of_one_missing_route_with_healthy_routes_do_not_reach_jev() {
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(&dir);
    for route in ["/home", "/profile", "/settings"] {
        p.process_event(&event("GET", route, 200)).unwrap();
    }
    for _ in 0..5 {
        p.process_event(&event("GET", "/api/user-avatarr", 404))
            .unwrap();
    }
    p.flush_and_analyze(true).await.unwrap();
    assert!(p.store.list_active().is_empty());
    assert_eq!(
        p.jev
            .metrics
            .actors_evaluated
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn shared_ip_volume_is_http_throttled_without_a_durable_ban() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use custos::bouncer_api::{AppState, build_bouncer_router};
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let p = pipeline(&dir);
    // Ten devices behind one public IP, twelve asset/API requests each.
    for user in 0..10 {
        for request in 0..12 {
            let mut ev = event("GET", "/app.js", 200);
            ev.user_agent = format!("device-{user}-{request}");
            p.process_event(&ev).unwrap();
        }
    }
    assert!(
        p.store.list_active().is_empty(),
        "volume alone created a durable IP ban"
    );
    let app = build_bouncer_router(AppState {
        pipeline: p.clone(),
        api_token: String::new(),
    });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=198.51.100.80")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));
    assert_eq!(
        p.firewall
            .metrics
            .rules_applied
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn backend_errors_and_encoded_json_filters_are_context_only() {
    use std::sync::atomic::Ordering;
    for status in [200, 500, 503] {
        let dir = tempfile::tempdir().unwrap();
        let p = pipeline(&dir);
        for _ in 0..8 {
            p.process_event(&event(
                "GET",
                "/api/orders?filter=%7B%22status%22%3A%22open%22%7D",
                status,
            ))
            .unwrap();
        }
        p.flush_and_analyze(true).await.unwrap();
        assert!(p.store.list_active().is_empty());
        assert_eq!(p.jev.metrics.actors_evaluated.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn missing_path_diversity_and_sample_frequencies_describe_the_actual_errors() {
    let w = custos::window::SlidingWindowEngine::new(Default::default());
    for route in ["/home", "/profile", "/settings"] {
        w.ingest(&event("GET", route, 200));
    }
    for _ in 0..5 {
        w.ingest(&event("GET", "/bad-route", 404));
    }
    // Keep the window for analysis using independent, genuine exploit evidence.
    w.ingest(&event("GET", "/.env", 200));
    let summary = w.drain_suspicious_summaries(true).pop().unwrap();
    assert_eq!(summary.status_404, 5);
    assert_eq!(summary.unique_404_paths, 1);
    assert_eq!(summary.unique_paths, 5);
    assert!(
        summary
            .sample_requests
            .iter()
            .any(|s| s == "GET /bad-route -> 404 [x5]")
    );
    assert!(summary.to_compact_line().contains("uniq_404=1"));
}

#[tokio::test]
async fn configured_login_failures_need_the_threshold_and_no_auth_recovery() {
    for (route, failures, recover, expected_ban) in [
        ("/api/login", 9, false, false),
        ("/api/login", 10, false, true),
        ("/api/login", 10, true, false),
        ("/wp-login.php", 9, false, false),
        ("/wp-login.php", 10, false, true),
        ("/wp-login.php", 10, true, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = AppConfig::default();
        cfg.daemon.decisions_file = dir.path().join("decisions.jsonl");
        cfg.firewall.enabled = false;
        cfg.window.auth_paths = vec![route.into()];
        let p = SecurityPipeline::builder()
            .with_config(cfg)
            .with_mock_jev(true)
            .build()
            .unwrap();
        for _ in 0..failures {
            p.process_event(&event("POST", route, 401)).unwrap();
        }
        if recover {
            p.process_event(&event("POST", route, 200)).unwrap();
        }
        p.flush_and_analyze(true).await.unwrap();
        assert_eq!(
            !p.store.list_active().is_empty(),
            expected_ban,
            "route={route}, failures={failures}, recover={recover}"
        );
    }
}

#[tokio::test]
async fn genuine_diverse_probes_and_injections_still_convict() {
    for routes in [
        vec!["/probe-a", "/probe-b", "/probe-c", "/probe-d", "/probe-e"],
        vec!["/search?q=1+UNION+SELECT+password"],
        vec!["/file?path=../../etc/passwd"],
        vec!["/.env"],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = pipeline(&dir);
        for route in routes {
            p.process_event(&event("GET", route, 404)).unwrap();
        }
        p.flush_and_analyze(true).await.unwrap();
        assert_eq!(p.store.list_active().len(), 1);
    }
}

#[tokio::test]
async fn high_confidence_live_provider_cannot_convict_context_only_windows() {
    use axum::{Json, Router, extract::State, routing::post};
    use custos::{
        config::{JevConfig, WindowConfig},
        jev::JevBatchAnalyzer,
        window::SlidingWindowEngine,
    };
    use std::sync::{Arc, Mutex, atomic::Ordering};
    let class = Arc::new(Mutex::new(String::new()));
    let app = Router::new().route("/", post(|State(class): State<Arc<Mutex<String>>>, Json(req): Json<serde_json::Value>| async move {
        let mut answers = serde_json::Map::new();
        for key in req["questions"].as_object().unwrap().keys() {
            answers.insert(key.clone(), if key.ends_with("should_ban") {
                serde_json::json!({"type":"noul", "noul":1.0})
            } else {
                serde_json::json!({"type":"choice", "choice":class.lock().unwrap().clone(), "confidence":1.0})
            });
        }
        Json(serde_json::json!({"answers":answers}))
    })).with_state(class.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let analyzer = JevBatchAnalyzer::new(
        JevConfig {
            endpoint,
            api_key: "loopback-fixture".into(),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let mut summaries = Vec::new();
    for (uri, status, count) in [
        ("/api/feed", 401, 3),
        ("/api/cart", 403, 3),
        ("/api/bad-route", 404, 5),
        ("/api/orders", 500, 10),
        ("/api/orders?filter=%7B%22x%22%3A%22y%22%7D", 503, 5),
        ("/app.js", 200, 150),
    ] {
        // Force contextual evidence through the real HTTP provider boundary even
        // though default settings deliberately avoid spending tokens on it.
        let w = SlidingWindowEngine::new(WindowConfig {
            min_suspicion_score: 0,
            ..Default::default()
        });
        for _ in 0..count {
            w.ingest(&event("GET", uri, status));
        }
        let mut summary = w.drain_suspicious_summaries(true).pop().unwrap();
        summary.actor_key = format!("actor_{}", summaries.len());
        summaries.push(summary);
    }
    for threat in [
        "credential_stuffing",
        "api_enumeration_idor",
        "vulnerability_scanner",
        "sqli_or_injection",
        "path_traversal_lfi",
        "layer7_dos",
    ] {
        *class.lock().unwrap() = threat.into();
        let verdicts = analyzer.analyze_summaries(&summaries).await.unwrap();
        assert_eq!(verdicts.len(), summaries.len());
        assert!(
            verdicts
                .iter()
                .all(|v| !v.should_ban && !v.recommend_auto_signature),
            "unsupported conviction class {threat}"
        );
    }
    assert_eq!(
        analyzer.metrics.evidence_rejected.load(Ordering::Relaxed),
        36
    );
    server.abort();
}

#[tokio::test]
async fn throttle_expires_and_nginx_compatibility_preserves_the_action() {
    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
        routing::get,
    };
    use custos::{
        bouncer_api::{AppState, build_bouncer_router},
        config::WindowConfig,
        middleware::custos_bouncer_middleware,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_decisions_file(dir.path().join("ledger"))
        .with_firewall_config(custos::config::FirewallConfig {
            enabled: false,
            ..Default::default()
        })
        .with_window_config(WindowConfig {
            l1_flood_threshold: 3,
            throttle_secs: 1,
            ..Default::default()
        })
        .with_mock_jev(true)
        .build()
        .unwrap();
    for _ in 0..3 {
        p.process_event(&event("GET", "/api/feed", 200)).unwrap();
    }
    // Draining evidence must not discard HTTP throttles.
    p.flush_and_analyze(true).await.unwrap();
    let checks = build_bouncer_router(AppState {
        pipeline: p.clone(),
        api_token: String::new(),
    });
    for (suffix, expected) in [
        ("", StatusCode::TOO_MANY_REQUESTS),
        ("&auth_request=true", StatusCode::FORBIDDEN),
    ] {
        let response = checks
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/bouncer/check?ip=198.51.100.80{suffix}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["x-custos-action"], "throttle");
        assert_eq!(response.headers()["retry-after"], "1");
    }
    let handlers = Arc::new(AtomicUsize::new(0));
    let calls = handlers.clone();
    let website = Router::new()
        .route(
            "/api/feed",
            get(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    "ok"
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            p.clone(),
            custos_bouncer_middleware,
        ));
    let request = || {
        Request::builder()
            .uri("/api/feed")
            .extension(ConnectInfo(
                "198.51.100.80:2345"
                    .parse::<std::net::SocketAddr>()
                    .unwrap(),
            ))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        website.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(handlers.load(Ordering::Relaxed), 0);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        website.oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(handlers.load(Ordering::Relaxed), 1);
    assert!(p.store.list_active().is_empty());
}

#[tokio::test]
async fn strict_volume_bans_are_explicit_opt_in() {
    use custos::config::{FloodAction, WindowConfig};
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_decisions_file(dir.path().join("ledger"))
        .with_firewall_config(custos::config::FirewallConfig {
            enabled: false,
            ..Default::default()
        })
        .with_window_config(WindowConfig {
            l1_flood_threshold: 3,
            flood_action: FloodAction::Ban,
            ..Default::default()
        })
        .with_mock_jev(true)
        .build()
        .unwrap();
    for _ in 0..3 {
        p.process_event(&event("GET", "/app.js", 200)).unwrap();
    }
    assert_eq!(p.store.list_active().len(), 1);
    assert_eq!(p.store.list_active()[0].threat_class, "layer7_dos");
}

#[tokio::test]
async fn auth_recovery_does_not_erase_independent_probe_evidence() {
    use custos::config::WindowConfig;
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_decisions_file(dir.path().join("ledger"))
        .with_firewall_config(custos::config::FirewallConfig {
            enabled: false,
            ..Default::default()
        })
        .with_window_config(WindowConfig {
            auth_paths: vec!["/login".into()],
            ..Default::default()
        })
        .with_mock_jev(true)
        .build()
        .unwrap();
    for _ in 0..10 {
        p.process_event(&event("POST", "/login", 401)).unwrap();
    }
    for route in ["/probe-a", "/probe-b", "/probe-c", "/probe-d", "/probe-e"] {
        p.process_event(&event("GET", route, 404)).unwrap();
    }
    p.process_event(&event("POST", "/login", 200)).unwrap();
    let verdicts = p.flush_and_analyze(true).await.unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].should_ban);
    assert_eq!(verdicts[0].threat_class, "api_enumeration_idor");
}

#[test]
fn distinct_missing_path_storage_is_bounded_under_enumeration() {
    use custos::{config::WindowConfig, window::SlidingWindowEngine};
    let w = SlidingWindowEngine::new(WindowConfig {
        l1_flood_threshold: usize::MAX,
        max_sample_requests: usize::MAX,
        ..Default::default()
    });
    for n in 0..20_000 {
        w.ingest(&event("GET", &format!("/probe/{n}"), 404));
    }
    let summary = w.drain_suspicious_summaries(true).pop().unwrap();
    assert_eq!(summary.total_requests, 20_000);
    assert_eq!(summary.unique_404_paths, 1024);
    assert!(summary.sample_requests.len() <= 32);
}

#[test]
fn old_configuration_receives_safe_defaults_and_invalid_policies_are_rejected() {
    use custos::config::{FloodAction, WindowConfig};
    let cfg: AppConfig =
        toml::from_str("[window]\nwindow_secs=15\nl1_flood_threshold=120\n").unwrap();
    assert_eq!(cfg.window.flood_action, FloodAction::Throttle);
    assert_eq!(cfg.window.throttle_secs, 5);
    assert!(cfg.window.auth_paths.is_empty());
    assert_eq!(cfg.window.auth_failure_threshold, 10);
    for cfg in [
        WindowConfig {
            throttle_secs: 0,
            ..Default::default()
        },
        WindowConfig {
            throttle_secs: 61,
            ..Default::default()
        },
        WindowConfig {
            auth_failure_threshold: 2,
            ..Default::default()
        },
        WindowConfig {
            auth_paths: vec!["/login?token=x".into()],
            ..Default::default()
        },
    ] {
        assert!(cfg.validate().is_err());
    }
}
