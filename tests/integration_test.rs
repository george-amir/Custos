use axum::body::Body;
use axum::http::{Request, StatusCode};
use custos::SecurityPipeline;
use custos::bouncer_api::{
    AppState, BouncerCheckResponse, FirewallStatusResponse, build_bouncer_router,
};
use custos::config::{FirewallConfig, JevConfig, LogFormat, WindowConfig};
use custos::firewall::{FirewallBackend, FirewallBouncer};
use custos::hub::{CustosHubGrpcService, HubEngine};
use custos::jev::JevBatchAnalyzer;
use custos::middleware::custos_bouncer_middleware;
use custos::store::DecisionStore;
use custos::tailer::{parse_log_line, replay_log_file};
use custos::window::SlidingWindowEngine;
use http_body_util::BodyExt;
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
    let pipeline =
        SecurityPipeline::new(store.clone(), window.clone(), jev.clone(), firewall.clone());

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

    // 2. SQLi attacker IP (198.51.100.44) should be BLOCKED (403 Forbidden) with `x-custos-threat`
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
            .get("x-custos-threat")
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
        .clone()
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

    // 6. Verify Prometheus `/metrics` endpoint exposes OpenMetrics counters
    let resp_metrics = router
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_metrics.status(), StatusCode::OK);
    let metrics_text = String::from_utf8(
        resp_metrics
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(metrics_text.contains("custos_active_bans 5"));
    assert!(metrics_text.contains("custos_jev_batches_total 1"));
}

#[tokio::test]
async fn test_grpc_custoshub_multi_node_sync_and_batched_firewall() {
    use custos::hub::proto::PullRequest;
    use custos::hub::proto::custos_hub_service_server::CustosHubService;
    use custos::hub::{apply_hub_delta_to_pipeline, build_signal_batch_from_verdicts};

    // 1. Initialize the gRPC CustosHub service
    let hub_engine = Arc::new(HubEngine::new(1));
    let hub_grpc = CustosHubGrpcService::new(hub_engine.clone());

    // 2. Node A processes `sample_access.log` and pushes its Jev verdicts + L1 signatures to CustosHub via gRPC `push_signals`
    let dir_a = tempdir().unwrap();
    let pipeline_a = SecurityPipeline::builder()
        .with_decisions_file(dir_a.path().join("decisions_a.jsonl"))
        .with_mock_jev(true)
        .build()
        .unwrap();

    let events = replay_log_file(
        Path::new("tests/fixtures/sample_access.log"),
        LogFormat::NginxCombined,
    )
    .unwrap();
    for ev in &events {
        pipeline_a.process_event(ev).unwrap();
    }
    let verdicts_a = pipeline_a.flush_and_analyze(true).await.unwrap();
    let signal_batch = build_signal_batch_from_verdicts("node-a", "", &verdicts_a, 3600);

    let ack = hub_grpc
        .push_signals(tonic::Request::new(signal_batch))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ack.accepted_ips, 4);
    assert_eq!(ack.accepted_signatures, 3);
    assert_eq!(ack.latest_seq, 7);

    // 3. Node B (a completely fresh server) pulls incremental binary deltas from CustosHub via gRPC `pull_deltas`
    let dir_b = tempdir().unwrap();
    let fw_b = Arc::new(FirewallBouncer::new(FirewallConfig {
        enabled: true,
        backend: FirewallBackend::Pf,
        dry_run: true,
        table_name: "custos_block".to_string(),
    }));
    let pipeline_b = SecurityPipeline::new(
        Arc::new(DecisionStore::open(dir_b.path().join("decisions_b.jsonl"), 3600).unwrap()),
        Arc::new(SlidingWindowEngine::new(WindowConfig::default())),
        Arc::new(JevBatchAnalyzer::new(JevConfig::default(), true).unwrap()),
        fw_b.clone(),
    );

    let delta_batch = hub_grpc
        .pull_deltas(tonic::Request::new(PullRequest {
            node_id: "node-b".to_string(),
            since_seq: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    let (ips_applied, sigs_applied) =
        apply_hub_delta_to_pipeline(&pipeline_b, &delta_batch).unwrap();

    assert_eq!(delta_batch.latest_seq, 7);
    assert_eq!(ips_applied, 4);
    assert_eq!(sigs_applied, 3);

    // Verify Node B applied all 4 IPs in a SINGLE batched `pfctl` command (count == 1)!
    let cmds_b = fw_b.recent_commands();
    assert_eq!(
        cmds_b.len(),
        1,
        "Expected 1 batched pfctl command for all 4 IPs, got: {cmds_b:?}"
    );
    assert!(cmds_b[0].starts_with("pfctl -t custos_block -T add "));

    // Verify Node B's L1 auto-signature cache (synced from Node A via gRPC) immediately blocks
    // a brand-new botnet IP (203.0.113.252) probing `GET /.env` with ZERO Jev calls!
    let bot_line = r#"203.0.113.252 - - [29/Oct/2026:21:15:00 +0300] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.5.0""#;
    let bot_ev = parse_log_line(bot_line, LogFormat::NginxCombined).unwrap();
    pipeline_b.process_event(&bot_ev).unwrap();

    assert!(
        pipeline_b
            .store
            .check_ip(&"203.0.113.252".parse().unwrap())
            .is_some(),
        "Node B should block 203.0.113.252 at L1 using the signature synced from Node A via gRPC"
    );

    // 4. Verify embedded Axum middleware (`custos_bouncer_middleware`) blocks `203.0.113.252` in-process
    let app = axum::Router::new()
        .route("/hello", axum::routing::get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            pipeline_b.clone(),
            custos_bouncer_middleware,
        ));

    let blocked_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hello")
                .header("x-real-ip", "203.0.113.252")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked_resp.status(), StatusCode::FORBIDDEN);

    let allowed_resp = app
        .oneshot(
            Request::builder()
                .uri("/hello")
                .header("x-real-ip", "192.0.2.55")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed_resp.status(), StatusCode::OK);
}
