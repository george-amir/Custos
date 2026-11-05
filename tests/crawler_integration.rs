use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use custos::{
    SecurityPipeline,
    bouncer_api::{AppState, build_bouncer_router},
    config::AppConfig,
};
use tower::ServiceExt;

#[test]
fn crawler_state_cannot_replace_the_ban_journal_through_a_path_alias() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("subdir")).unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = directory.path().join("ledger");
    cfg.crawlers.state_file = Some(directory.path().join("subdir/../ledger"));
    let result = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build();
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("must not overwrite")
    );
    assert!(!directory.path().join("ledger").exists());
}

#[tokio::test]
async fn slow_management_reads_do_not_consume_bouncer_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_config(fresh_config(dir.path()))
        .with_mock_jev(true)
        .build()
        .unwrap();
    let app = build_bouncer_router(AppState {
        pipeline: p,
        api_token: "test-admin".into(),
    });
    let mut held = Vec::new();
    for _ in 0..4 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
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
                .uri("/v1/bouncer/check?ip=203.0.113.8")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn log_health_reports_parsing_errors_rotations_and_backlog_without_unbounded_sources() {
    use std::{io::Write, sync::atomic::Ordering, time::Duration};
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_config(fresh_config(dir.path()))
        .with_mock_jev(true)
        .build()
        .unwrap();
    let path = dir.path().join("access.log");
    let valid = r#"{"ClientHost":"198.51.100.3","RequestMethod":"GET","RequestPath":"/health","DownstreamStatus":200}"#;
    std::fs::write(
        &path,
        format!(
            "{valid}\nnot-json\n{}\n",
            "x".repeat(custos::tailer::MAX_LOG_RECORD_BYTES + 20)
        ),
    )
    .unwrap();
    let job = custos::tailer::spawn_pipeline_tailer(
        custos::config::LogSourceConfig {
            path: path.clone(),
            format: custos::config::LogFormat::Json,
        },
        p.clone(),
        true,
    );
    let health = p.health.source(&path).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while health.parsed.load(Ordering::Relaxed) < 1
            || health.oversized.load(Ordering::Relaxed) < 1
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(health.malformed.load(Ordering::Relaxed), 1);
    std::fs::rename(&path, dir.path().join("rotated.log")).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "{valid}").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while health.parsed.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(health.rotations.load(Ordering::Relaxed), 1);
    assert_eq!(health.backlog_bytes.load(Ordering::Relaxed), 0);
    assert!(health.last_read_unix.load(Ordering::Relaxed) > 0);
    for i in 0..1000 {
        let _ = p.health.source(&dir.path().join(format!("unused-{i}")));
    }
    assert_eq!(p.health.source_count(), 16);
    job.abort();
    let _ = job.await;
}

fn fresh_config(directory: &std::path::Path) -> AppConfig {
    let mut snapshot: serde_json::Value =
        serde_json::from_str(include_str!("../data/crawler_ranges.json")).unwrap();
    for feed in snapshot["feeds"].as_object_mut().unwrap().values_mut() {
        feed["verified_at"] = chrono::Utc::now().to_rfc3339().into();
    }
    let path = directory.join("crawlers.json");
    custos::service::write_secret_file(&path, &serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = directory.join("ledger");
    cfg.crawlers.state_file = Some(path);
    cfg.crawlers.auto_refresh = false;
    cfg
}

fn event(ip: &str, path: &str) -> custos::tailer::AccessLogEvent {
    custos::tailer::AccessLogEvent {
        timestamp: chrono::Utc::now(),
        client_ip: ip.parse().unwrap(),
        method: "GET".into(),
        path: path.into(),
        query: String::new(),
        status: 404,
        bytes_sent: 0,
        user_agent: String::new(),
        referer: String::new(),
    }
}

#[test]
fn an_inflight_policy_ban_cannot_undo_a_completed_unblock() {
    use custos::{
        config::FirewallConfig,
        crawlers::CrawlerPolicy,
        firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
        jev::JevBatchAnalyzer,
        store::{DecisionSource, DecisionStore},
        window::SlidingWindowEngine,
    };
    use std::{
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::Duration,
    };
    struct Gate {
        armed: AtomicBool,
        ready: mpsc::SyncSender<()>,
        release: (Mutex<bool>, Condvar),
    }
    impl FirewallCommandRunner for Gate {
        fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
            if self.armed.swap(false, Ordering::Relaxed) {
                self.ready.send(()).unwrap();
                let (lock, signal) = &self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = signal.wait(released).unwrap();
                }
            }
            Ok(0)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = fresh_config(dir.path());
    let (ready, received) = mpsc::sync_channel(1);
    let gate = Arc::new(Gate {
        armed: AtomicBool::new(false),
        ready,
        release: (Mutex::new(false), Condvar::new()),
    });
    let p = SecurityPipeline::new_with_crawlers(
        Arc::new(DecisionStore::open(cfg.daemon.decisions_file, 3600).unwrap()),
        Arc::new(SlidingWindowEngine::new(Default::default())),
        Arc::new(JevBatchAnalyzer::new(Default::default(), true).unwrap()),
        Arc::new(FirewallBouncer::with_runner(
            FirewallConfig {
                backend: FirewallBackend::Pf,
                dry_run: false,
                ..Default::default()
            },
            gate.clone(),
            Duration::from_secs(2),
        )),
        Default::default(),
        cfg.crawlers,
    )
    .unwrap();
    p.set_crawler_policy("nokia_genome", CrawlerPolicy::Block)
        .unwrap();
    gate.armed.store(true, Ordering::Relaxed);
    let manual = p.clone();
    let first = std::thread::spawn(move || {
        manual.record_ban(
            "198.51.100.1".parse().unwrap(),
            "manual_block".into(),
            DecisionSource::ManualAdmin,
            1.,
            1.,
            "Keep manual".into(),
            None,
        )
    });
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    let incoming = p.clone();
    let event_worker =
        std::thread::spawn(move || incoming.process_event(&event("216.180.246.202", "/")));
    while p.health.events_received.load(Ordering::Relaxed) == 0 {
        std::thread::yield_now();
    }
    let change = p.clone();
    let policy_worker =
        std::thread::spawn(move || change.set_crawler_policy("nokia_genome", CrawlerPolicy::Allow));
    std::thread::sleep(Duration::from_millis(10));
    *gate.release.0.lock().unwrap() = true;
    gate.release.1.notify_all();
    first.join().unwrap().unwrap();
    event_worker.join().unwrap().unwrap();
    policy_worker.join().unwrap().unwrap();
    assert!(
        p.store
            .check_ip(&"216.180.246.202".parse().unwrap())
            .is_none()
    );
    assert!(p.store.check_ip(&"198.51.100.1".parse().unwrap()).is_some());
}

#[tokio::test]
async fn redacted_evidence_is_private_and_scores_have_explicit_names() {
    use http_body_util::BodyExt;
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_config(fresh_config(dir.path()))
        .with_mock_jev(true)
        .build()
        .unwrap();
    let mut probe = event("198.51.100.11", "/api/search");
    probe.query = "token=private-fixture-token&id=1 UNION SELECT password FROM users".into();
    p.process_event(&probe).unwrap();
    p.flush_and_analyze(true).await.unwrap();
    let app = build_bouncer_router(AppState {
        pipeline: p,
        api_token: "admin-secret".into(),
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/decisions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let public: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(public[0].get("evidence").is_none());
    assert_eq!(
        public[0]["maliciousness_score"],
        public[0]["noul_probability"]
    );
    assert_eq!(
        public[0]["threat_class_confidence"],
        public[0]["confidence"]
    );
    for route in ["/v1/decisions/198.51.100.11/evidence", "/v1/logs"] {
        assert_eq!(
            app.clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/decisions/198.51.100.11/evidence")
                .header("authorization", "Bearer admin-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let audit = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(audit.contains("sqli_or_xss_token_pattern"));
    assert!(!audit.contains("private-fixture-token"));
    assert!(audit.contains("REDACTED"));
}

#[tokio::test]
async fn untrusted_peers_and_conflicting_traefik_headers_cannot_bypass_checks() {
    let dir = tempfile::tempdir().unwrap();
    let p = SecurityPipeline::builder()
        .with_config(fresh_config(dir.path()))
        .with_mock_jev(true)
        .build()
        .unwrap();
    p.window
        .register_auto_signature("GET", "/.env", "vulnerability_scanner");
    let app = build_bouncer_router(AppState {
        pipeline: p,
        api_token: "admin-secret".into(),
    });
    let request = Request::builder()
        .uri("/v1/bouncer/check?ip=198.51.100.8")
        .extension(axum::extract::ConnectInfo(
            "203.0.113.5:1234".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .header("x-forwarded-for", "66.249.66.1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    // Administrative diagnostics can query a private daemon from a non-proxy peer,
    // but an incorrect credential must not grant that exception.
    for (token, expected) in [
        ("wrong", StatusCode::FORBIDDEN),
        ("admin-secret", StatusCode::OK),
    ] {
        let request = Request::builder()
            .uri("/v1/bouncer/check?ip=198.51.100.8")
            .extension(axum::extract::ConnectInfo(
                "203.0.113.5:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
    let request = Request::builder()
        .uri("/v1/bouncer/check?ip=198.51.100.8")
        .header("x-forwarded-method", "GET")
        .header("x-forwarded-uri", "/.env")
        .header("x-original-uri", "/innocent")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let request = Request::builder()
        .uri("/v1/bouncer/check")
        .header("x-forwarded-method", "GET")
        .header("x-forwarded-uri", "/.env")
        .header("x-forwarded-for", "198.51.100.8")
        .header("x-real-ip", "66.249.66.1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn failed_unblock_keeps_cleanup_durable_and_preserves_other_bans() {
    use custos::{
        config::FirewallConfig,
        crawlers::CrawlerPolicy,
        firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
        jev::JevBatchAnalyzer,
        store::{DecisionSource, DecisionStore},
        window::SlidingWindowEngine,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    struct Runner(AtomicBool);
    impl FirewallCommandRunner for Runner {
        fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
            Ok(if self.0.load(Ordering::Relaxed) { 2 } else { 0 })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = fresh_config(dir.path());
    let runner = Arc::new(Runner(AtomicBool::new(false)));
    let p = SecurityPipeline::new_with_crawlers(
        Arc::new(DecisionStore::open(cfg.daemon.decisions_file.clone(), 3600).unwrap()),
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
        Default::default(),
        cfg.crawlers,
    )
    .unwrap();
    let ip = "216.180.246.202".parse().unwrap();
    p.record_ban(
        ip,
        "crawler_policy".into(),
        DecisionSource::CrawlerPolicy,
        0.,
        0.,
        "Operator blocked crawler".into(),
        None,
    )
    .unwrap();
    p.record_ban(
        "198.51.100.1".parse().unwrap(),
        "manual_block".into(),
        DecisionSource::ManualAdmin,
        1.,
        1.,
        "Keep this ban".into(),
        None,
    )
    .unwrap();
    runner.0.store(true, Ordering::Relaxed);
    assert!(
        p.set_crawler_policy("nokia_genome", CrawlerPolicy::Allow)
            .is_err()
    );
    assert!(p.store.sweep_expired().contains(&ip));
    assert!(p.store.cleanup_requires_kernel(&ip));
    assert!(p.store.check_ip(&"198.51.100.1".parse().unwrap()).is_some());
    let disk = DecisionStore::open(cfg.daemon.decisions_file, 3600).unwrap();
    assert!(
        disk.sweep_expired().contains(&ip),
        "failed cleanup must survive restart"
    );
    assert_eq!(disk.retained_count(), 2);
    runner.0.store(false, Ordering::Relaxed);
    p.reconcile_firewall().unwrap();
    assert_eq!(p.store.retained_count(), 1);
    assert_eq!(p.store.active_count(), 1);
}

#[test]
fn docker_initialization_uses_both_families_without_flushing_other_tables() {
    use custos::{
        config::FirewallConfig,
        firewall::{FirewallBackend, FirewallBouncer},
    };
    let fw = FirewallBouncer::new(FirewallConfig {
        backend: FirewallBackend::Nftables,
        protect_docker: true,
        ..Default::default()
    });
    let commands = fw
        .build_init_commands()
        .iter()
        .map(|command| command.to_shell_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(commands.contains("hook forward priority -10"));
    assert!(commands.contains("docker_forward ip saddr @block_v4 counter drop"));
    assert!(commands.contains("docker_forward ip6 saddr @block_v6 counter drop"));
    assert!(!commands.contains("flush ruleset"));
}

#[tokio::test]
async fn blocking_a_service_is_immediate_and_allowing_it_removes_only_ordinary_automatic_bans() {
    use custos::{crawlers::CrawlerPolicy, store::DecisionSource};
    let dir = tempfile::tempdir().unwrap();
    let pipeline = SecurityPipeline::builder()
        .with_config(fresh_config(dir.path()))
        .with_mock_jev(true)
        .build()
        .unwrap();
    let ip = "216.180.246.202".parse().unwrap();
    pipeline
        .set_crawler_policy("nokia_genome", CrawlerPolicy::Block)
        .unwrap();
    let app = build_bouncer_router(AppState {
        pipeline: pipeline.clone(),
        api_token: "admin-secret".into(),
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=216.180.246.202")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        pipeline.store.active_count(),
        0,
        "read-only checks must not fill the ledger"
    );
    pipeline
        .process_event(&event("216.180.246.202", "/"))
        .unwrap();
    assert_eq!(
        pipeline.store.check_ip(&ip).unwrap().source,
        DecisionSource::CrawlerPolicy
    );
    pipeline
        .record_ban(
            "216.180.246.203".parse().unwrap(),
            "manual_block".into(),
            DecisionSource::ManualAdmin,
            1.0,
            1.0,
            "Operator decision".into(),
            None,
        )
        .unwrap();
    assert_eq!(
        pipeline
            .set_crawler_policy("nokia_genome", CrawlerPolicy::Allow)
            .unwrap(),
        1
    );
    assert!(pipeline.store.check_ip(&ip).is_none());
    assert!(
        pipeline
            .store
            .check_ip(&"216.180.246.203".parse().unwrap())
            .is_some()
    );
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=216.180.246.202")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
    assert_eq!(pipeline.store.retained_count(), 1);
}

#[tokio::test]
async fn allowed_measurement_scanners_keep_exploit_protection_and_do_not_consume_jev_for_enumeration()
 {
    use custos::crawlers::CrawlerPolicy;
    let dir = tempfile::tempdir().unwrap();
    let pipeline = SecurityPipeline::builder()
        .with_config(fresh_config(dir.path()))
        .with_mock_jev(true)
        .build()
        .unwrap();
    pipeline
        .set_crawler_policy("nokia_genome", CrawlerPolicy::Allow)
        .unwrap();
    for path in [
        "/",
        "/manage/account/login",
        "/admin/index.html",
        "/index.html",
        "/+CSCOE+/logon.html",
        "/cgi-bin/login.cgi",
        "/login.htm",
    ] {
        pipeline
            .process_event(&event("216.180.246.202", path))
            .unwrap();
    }
    assert!(pipeline.flush_and_analyze(true).await.unwrap().is_empty());
    assert_eq!(pipeline.store.active_count(), 0);
    let mut injection = event("216.180.246.202", "/api/search");
    injection.query = "id=1 UNION SELECT password FROM users".into();
    pipeline.process_event(&injection).unwrap();
    let verdicts = pipeline.flush_and_analyze(true).await.unwrap();
    assert!(verdicts.iter().any(|verdict| verdict.should_ban));
    let decision = pipeline.store.check_ip(&injection.client_ip).unwrap();
    assert!(decision.evidence.unwrap().has_exploit());
    assert_eq!(decision.crawler.unwrap().id, "nokia_genome");
    assert_eq!(
        pipeline
            .set_crawler_policy("nokia_genome", CrawlerPolicy::Allow)
            .unwrap(),
        0
    );
    assert!(pipeline.store.check_ip(&injection.client_ip).is_some());
}

#[test]
fn malformed_or_overbroad_feeds_never_create_trusted_identities() {
    use custos::crawlers::{MAX_FEED_BYTES, MAX_PREFIXES_PER_FEED, parse_feed};
    for raw in [
        r#"{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}"#,
        r#"{"prefixes":[{"ipv4Prefix":"127.0.0.0/8"}]}"#,
        r#"{"prefixes":[{"ipv4Prefix":"10.0.0.0/8"}]}"#,
        r#"{"prefixes":[{"ipv4Prefix":"198.51.100.1/24"}]}"#,
        r#"{"prefixes":[{"ipv4Prefix":"198.51.100.0/24","ipv6Prefix":"2001:db8::/32"}]}"#,
        r#"{"prefixes":[]}"#,
    ] {
        assert!(parse_feed(raw.as_bytes(), false).is_err(), "{raw}");
    }
    assert!(parse_feed(&vec![b' '; MAX_FEED_BYTES + 1], false).is_err());
    assert!(
        parse_feed(
            "198.51.100.1/32\n"
                .repeat(MAX_PREFIXES_PER_FEED + 1)
                .as_bytes(),
            true
        )
        .is_err()
    );
    assert_eq!(
        parse_feed(b"216.180.246.0/24\n2620:ce:e001::/48\n", true)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn expired_verification_and_unknown_cloud_ips_cannot_receive_crawler_exceptions() {
    use custos::crawlers::{CrawlerPolicy, CrawlerRegistry};
    let dir = tempfile::tempdir().unwrap();
    let cfg = fresh_config(dir.path());
    let registry = CrawlerRegistry::open(cfg.crawlers, None).unwrap();
    registry
        .set_policy("nokia_genome", CrawlerPolicy::Allow)
        .unwrap();
    assert!(
        registry
            .identify("2620:ce:e001::1234".parse().unwrap())
            .is_some()
    );
    assert!(
        registry
            .identify("216.180.247.202".parse().unwrap())
            .is_none()
    );
    assert!(
        registry
            .identify("35.232.76.162".parse().unwrap())
            .is_none()
    );
    assert!(
        registry
            .identify_at(
                "216.180.246.202".parse().unwrap(),
                chrono::Utc::now() + chrono::Duration::days(8)
            )
            .is_none()
    );
}

#[test]
fn firewall_packet_counters_are_not_ban_application_counts() {
    use custos::{
        config::FirewallConfig,
        firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
    };
    use std::{sync::Arc, time::Duration};
    struct Counters;
    impl FirewallCommandRunner for Counters {
        fn run(&self, _: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
            Ok(0)
        }
        fn read_output(
            &self,
            _: &FirewallCommandSpec,
            _: Duration,
            _: usize,
        ) -> anyhow::Result<Vec<u8>> {
            Ok(br#"{"nftables":[{"rule":{"expr":[{"match":{"right":"@block_v4"}},{"counter":{"packets":2290,"bytes":209628}},{"drop":null}]}},{"rule":{"expr":[{"match":{"right":"@block_v6"}},{"counter":{"packets":7,"bytes":700}},{"drop":null}]}}]}"#.to_vec())
        }
    }
    let fw = FirewallBouncer::with_runner(
        FirewallConfig {
            backend: FirewallBackend::Nftables,
            dry_run: false,
            ..Default::default()
        },
        Arc::new(Counters),
        Duration::from_secs(1),
    );
    fw.sample_counters();
    let counters = fw.kernel_counters().unwrap();
    assert_eq!(
        (counters.dropped_packets, counters.dropped_bytes),
        (2297, 210328)
    );
    fw.ban_ip("198.51.100.1".parse().unwrap(), 60).unwrap();
    fw.sample_counters();
    assert_eq!(fw.kernel_counters().unwrap().dropped_packets, 2297);
    assert_eq!(
        fw.metrics
            .rules_applied
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn crawler_policy_mutations_require_the_existing_admin_token() {
    for (configured, supplied, expected) in [
        ("admin-secret", None, StatusCode::UNAUTHORIZED),
        (
            "admin-secret",
            Some("Bearer wrong"),
            StatusCode::UNAUTHORIZED,
        ),
        ("", Some("Bearer anything"), StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = AppConfig::default();
        cfg.firewall.enabled = false;
        cfg.daemon.decisions_file = dir.path().join("ledger");
        let pipeline = SecurityPipeline::builder()
            .with_config(cfg)
            .with_mock_jev(true)
            .build()
            .unwrap();
        let app = build_bouncer_router(AppState {
            pipeline,
            api_token: configured.into(),
        });
        let mut request = Request::builder()
            .method("PUT")
            .uri("/v1/crawlers/nokia_genome")
            .header("content-type", "application/json");
        if let Some(token) = supplied {
            request = request.header("authorization", token);
        }
        assert_eq!(
            app.oneshot(request.body(Body::from(r#"{"policy":"allow"}"#)).unwrap())
                .await
                .unwrap()
                .status(),
            expected
        );
    }
}

#[test]
fn verified_identity_controls_persist_without_trusting_google_cloud_addresses() {
    use custos::crawlers::{CrawlerConfig, CrawlerPolicy, CrawlerRegistry};
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("crawlers.json");
    fresh_config(dir.path());
    let registry = CrawlerRegistry::open(CrawlerConfig::default(), Some(state.clone())).unwrap();
    let ip = "216.180.246.202".parse().unwrap();
    assert_eq!(registry.identify(ip).unwrap().id, "nokia_genome");
    assert!(
        registry
            .identify("35.232.76.162".parse().unwrap())
            .is_none()
    );
    registry
        .set_policy("nokia_genome", CrawlerPolicy::Block)
        .unwrap();
    assert_eq!(registry.identify(ip).unwrap().policy, CrawlerPolicy::Block);
    drop(registry);
    let restored = CrawlerRegistry::open(CrawlerConfig::default(), Some(state)).unwrap();
    assert_eq!(restored.identify(ip).unwrap().policy, CrawlerPolicy::Block);
    restored
        .set_policy("nokia_genome", CrawlerPolicy::Allow)
        .unwrap();
    assert_eq!(restored.identify(ip).unwrap().policy, CrawlerPolicy::Allow);
    assert!(
        restored
            .set_policy("unknown", CrawlerPolicy::Allow)
            .is_err()
    );
}

#[tokio::test]
async fn traefik_forwardauth_blocks_a_cached_signature_before_the_backend() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("decisions");
    let pipeline = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    pipeline
        .window
        .register_auto_signature("GET", "/.git/config", "vulnerability_scanner");
    let app = build_bouncer_router(AppState {
        pipeline,
        api_token: "test-admin".into(),
    });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check")
                .header("x-forwarded-for", "198.51.100.90")
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-uri", "/.git/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
