use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jevsec::SecurityPipeline;
use jevsec::bouncer_api::{
    AppState, BouncerCheckResponse, FirewallStatusResponse, build_bouncer_router,
};
use jevsec::config::{FirewallConfig, JevConfig, LogFormat, WindowConfig};
use jevsec::firewall::FirewallBouncer;
use jevsec::jev::JevBatchAnalyzer;
use jevsec::store::DecisionStore;
use jevsec::tailer::{parse_log_line, replay_log_file};
use jevsec::window::SlidingWindowEngine;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn test_full_pipeline_and_bouncer_api_end_to_end() {
    let dir = tempdir().unwrap();
    let decisions_path = dir.path().join("decisions.jsonl");

    let store = Arc::new(DecisionStore::open(decisions_path, 3600).unwrap());
    let window = Arc::new(SlidingWindowEngine::new(WindowConfig::default()));
    let jev = Arc::new(JevBatchAnalyzer::new(JevConfig::default(), true).unwrap());
    let firewall = Arc::new(FirewallBouncer::new(FirewallConfig::default()));
    let pipeline = SecurityPipeline::new(
        store.clone(),
        window.clone(),
        jev.clone(),
        firewall.clone(),
    );

    let events = replay_log_file(
        Path::new("tests/fixtures/sample_access.log"),
        LogFormat::NginxCombined,
    )
    .expect("should parse sample_access.log");

    assert_eq!(events.len(), 19);

    for ev in &events {
        pipeline.process_event(ev).unwrap();
    }

    // Flush all suspicious windows through the Jev batch analyzer in a single batch
    let verdicts = pipeline.flush_and_analyze(true).await.unwrap();
    assert_eq!(verdicts.len(), 4, "Expected 4 suspicious actors evaluated");

    // Verify only 1 batch request was sent for all 4 suspicious actors
    assert_eq!(
        jev.metrics
            .batches_evaluated
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Verify OS firewall bouncer rules were automatically applied for all 4 banned IPs
    assert_eq!(
        firewall
            .metrics
            .rules_applied
            .load(std::sync::atomic::Ordering::Relaxed),
        4
    );

    // Build the Bouncer HTTP API router
    let router = build_bouncer_router(AppState {
        store: store.clone(),
        window: window.clone(),
        jev: jev.clone(),
        firewall: firewall.clone(),
    });

    // 1. Benign user IP (192.0.2.10) should be ALLOWED (200 OK)
    let resp_benign = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=192.0.2.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_benign.status(), StatusCode::OK);
    let body_bytes = resp_benign.into_body().collect().await.unwrap().to_bytes();
    let check_benign: BouncerCheckResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(check_benign.action, "allow");

    // 2. SQLi attacker IP (198.51.100.44) should be BLOCKED (403 Forbidden)
    let resp_sqli = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=198.51.100.44")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_sqli.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp_sqli
            .headers()
            .get("x-jevsec-threat")
            .unwrap()
            .to_str()
            .unwrap(),
        "sqli_or_injection"
    );

    // 3. Prompt-injection evasion attacker (203.0.113.199) should also be BLOCKED (403 Forbidden)
    let resp_inj = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check")
                .header("x-real-ip", "203.0.113.199")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_inj.status(), StatusCode::FORBIDDEN);

    // 4. Verify Auto-Signature Cache blocks a brand-new botnet peer IP (203.0.113.250)
    // hitting `GET /.env` at L1 and enforces an OS firewall rule without another Jev API call!
    let new_bot_line = r#"203.0.113.250 - - [29/Oct/2026:21:12:00 +0300] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.4.0""#;
    let new_bot_ev = parse_log_line(new_bot_line, LogFormat::NginxCombined).unwrap();
    pipeline.process_event(&new_bot_ev).unwrap();

    let resp_bot = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/bouncer/check?ip=203.0.113.250")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_bot.status(), StatusCode::FORBIDDEN);

    // 5. Verify /v1/firewall status endpoint reports 5 applied OS firewall rules
    let resp_fw = router
        .oneshot(
            Request::builder()
                .uri("/v1/firewall")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_fw.status(), StatusCode::OK);
    let fw_bytes = resp_fw.into_body().collect().await.unwrap().to_bytes();
    let fw_status: FirewallStatusResponse = serde_json::from_slice(&fw_bytes).unwrap();
    assert_eq!(fw_status.rules_applied, 5);
    assert_eq!(fw_status.recent_commands.len(), 5);
}
