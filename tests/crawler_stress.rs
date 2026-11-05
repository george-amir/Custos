//! Isolated sustained-traffic profile, so peak RSS excludes other parallel tests.
use custos::{SecurityPipeline, config::AppConfig, crawlers::CrawlerPolicy, store::DecisionSource};

#[cfg(unix)]
fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let rss = unsafe { usage.assume_init() }.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        rss
    } else {
        rss * 1024
    }
}
#[cfg(not(unix))]
fn peak_rss() -> u64 {
    0
}

#[test]
fn sustained_crawler_saturation_keeps_the_site_available_and_memory_bounded() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crawler_flood_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
#[ignore = "executed in isolation by the parent stress test"]
fn crawler_flood_worker() {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(async {
        use axum::{body::Body, http::{Request, StatusCode}};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("crawlers.json");
        let mut snapshot: serde_json::Value = serde_json::from_str(include_str!("../data/crawler_ranges.json")).unwrap();
        for feed in snapshot["feeds"].as_object_mut().unwrap().values_mut() { feed["verified_at"] = chrono::Utc::now().to_rfc3339().into(); }
        custos::service::write_secret_file(&state_path, &serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let mut cfg = AppConfig::default();
        cfg.firewall.enabled = false;
        cfg.daemon.decisions_file = dir.path().join("ledger");
        cfg.crawlers.state_file = Some(state_path);
        cfg.crawlers.auto_refresh = false;
        cfg.window.max_tracked_ips = 4;
        cfg.window.max_state_bytes = 96 * 1024;
        cfg.memory.max_decisions = 8;
        cfg.memory.max_pending_actors = 4;
        cfg.memory.max_pending_bytes = 4096;
        cfg.memory.max_signatures = 4;
        let p = SecurityPipeline::builder().with_config(cfg).with_mock_jev(true).build().unwrap();
        p.set_crawler_policy("nokia_genome", CrawlerPolicy::Allow).unwrap();
        let manual = "198.51.100.1".parse().unwrap();
        let cleanup = "198.51.100.2".parse().unwrap();
        p.record_ban(manual, "manual_block".into(), DecisionSource::ManualAdmin, 1., 1., "Preserve active ban".into(), None).unwrap();
        p.store.upsert_ban(cleanup, "manual_block".into(), DecisionSource::ManualAdmin, 1., 1., "Preserve pending kernel cleanup".into(), None).unwrap();
        p.store.remove_ban(&cleanup).unwrap();
        p.window.register_auto_signature("GET", "/.git/config", "vulnerability_scanner");
        let app = custos::bouncer_api::build_bouncer_router(custos::bouncer_api::AppState { pipeline: p.clone(), api_token: "stress-test".into() });
        let base = u128::from("2620:ce:e001::".parse::<Ipv6Addr>().unwrap());
        let mut baseline = 0;
        let mut iterations = 0u64;
        for (phase, count) in [10_000u32, 50_000, 50_000].into_iter().enumerate() {
            for i in 0..count {
                let n = iterations + i as u64 + 10;
                let allowed = custos::tailer::AccessLogEvent { timestamp: chrono::Utc::now(), client_ip: IpAddr::V6((base + n as u128).into()),
                    method: "GET".into(), path: "/admin/index.html".into(), query: String::new(), status: 404,
                    bytes_sent: 0, user_agent: "GenomeCrawlerd".into(), referer: String::new() };
                let _ = p.process_event(&allowed);
                let mut attack = allowed;
                attack.client_ip = IpAddr::V4(Ipv4Addr::new(198, 19, (n >> 8) as u8, n as u8));
                attack.path = "/.git/config".into();
                let _ = p.process_event(&attack);
            }
            iterations += count as u64;
            p.flush_and_analyze(true).await.unwrap();
            let response = app.clone().oneshot(Request::builder().uri("/v1/bouncer/check?ip=203.0.113.1").body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "a full ledger must not take down the site");
            assert_eq!(p.store.check_ip(&manual).unwrap().source, DecisionSource::ManualAdmin);
            assert!(p.store.cleanup_requires_kernel(&cleanup));
            assert!(p.store.sweep_expired().contains(&cleanup));
            assert!(p.store.retained_count() <= 8);
            let rss = peak_rss();
            if phase == 0 { baseline = rss; }
            else { assert!(rss <= baseline + 24 * 1024 * 1024, "RSS grew after saturation: {rss} > {baseline}"); }
        }
        assert!(p.store.is_at_capacity());
        println!("{}", serde_json::json!({"events":iterations * 2, "warm_rss_bytes":baseline, "peak_rss_bytes":peak_rss(), "retained_decisions":p.store.retained_count(), "healthy_checks":3, "rss_supported":cfg!(unix)}));
    });
}
