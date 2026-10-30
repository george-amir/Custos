use custos::{
    SecurityPipeline,
    config::{AppConfig, LogFormat, WindowConfig},
    hub::{
        HubEngine, ip_to_bytes,
        proto::{IpSignal, SignalBatch, SignatureSignal},
    },
    limits::{EVENT_RESERVATION_BYTES, MemoryLimits},
    store::{DecisionSource, DecisionStore},
    tailer::{AccessLogEvent, parse_log_line},
    window::SlidingWindowEngine,
};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

fn ip(n: u32) -> std::net::IpAddr {
    std::net::Ipv4Addr::from(0xc6330000 + n).into()
}
fn event(n: u32) -> AccessLogEvent {
    parse_log_line(
        &serde_json::json!({"ip":ip(n).to_string(),"uri":"/.env","status":200}).to_string(),
        LogFormat::Json,
    )
    .unwrap()
}
fn ban(store: &DecisionStore, n: u32) -> anyhow::Result<custos::store::BanDecision> {
    store.upsert_ban(
        ip(n),
        "test".into(),
        DecisionSource::L1Deterministic,
        1.,
        1.,
        "test".into(),
        None,
    )
}
fn batch(n: u32, node: &str) -> SignalBatch {
    SignalBatch {
        node_id: node.into(),
        api_token: String::new(),
        ip_signals: vec![IpSignal {
            ip: ip_to_bytes(ip(n)),
            threat: 3,
            noul: 0.99,
            confidence: 0.99,
            suggested_ttl_secs: 2,
        }],
        signature_signals: vec![SignatureSignal {
            method: "GET".into(),
            path_prefix: format!("/exploit/{n}"),
            threat: 3,
            confidence: 0.99,
        }],
    }
}

#[test]
fn decision_capacity_preserves_bans_and_failed_cleanup_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let store = DecisionStore::open_with_limit(path.clone(), 3600, 2).unwrap();
    ban(&store, 1).unwrap();
    ban(&store, 2).unwrap();
    assert!(ban(&store, 3).is_err());
    store.remove_ban(&ip(1)).unwrap();
    assert!(
        ban(&store, 3).is_err(),
        "unacknowledged cleanup retains its slot"
    );
    assert_eq!(store.retained_count(), 2);
    drop(store);
    let store = DecisionStore::open_with_limit(path, 3600, 2).unwrap();
    assert!(store.check_ip(&ip(2)).is_some());
    assert!(store.sweep_expired().contains(&ip(1)));
    assert!(ban(&store, 3).is_err());
    store.acknowledge_cleanup(&ip(1)).unwrap();
    ban(&store, 3).unwrap();
    assert_eq!(store.retained_count(), 2);
}

#[test]
fn decision_replay_rejects_oversized_journals_and_metadata_without_growing_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let store = DecisionStore::open_with_limit(path.clone(), 3600, 2).unwrap();
    ban(&store, 1).unwrap();
    ban(&store, 2).unwrap();
    assert!(DecisionStore::open_with_limit(path.clone(), 3600, 1).is_err());
    let original = std::fs::read(&path).unwrap();
    assert!(
        store
            .upsert_ban(
                ip(1),
                "x".into(),
                DecisionSource::ManualAdmin,
                1.,
                1.,
                "x".repeat(513),
                None
            )
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    std::fs::write(&path, "x".repeat(100_000)).unwrap();
    assert!(DecisionStore::open_with_limit(path, 3600, 2).is_err());
}

#[tokio::test]
async fn ingestion_bytes_are_reserved_before_processing_and_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.memory.event_queue_bytes = EVENT_RESERVATION_BYTES * 2;
    cfg.memory.event_queue_capacity = 100;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    let a = p.reserve_event().unwrap();
    let b = p.reserve_event().unwrap();
    assert_eq!(p.available_queue_bytes(), 0);
    assert!(p.reserve_event().is_err());
    assert!(p.submit_event(event(3)).await.is_err());
    drop(a);
    assert_eq!(p.available_queue_bytes(), EVENT_RESERVATION_BYTES);
    b.send(event(1));
    p.flush_and_analyze(true).await.unwrap();
    assert_eq!(p.available_queue_bytes(), EVENT_RESERVATION_BYTES * 2);
}

#[test]
fn hub_votes_signatures_and_history_expire_with_bounded_admission() {
    let now = Arc::new(AtomicI64::new(100));
    let clock = now.clone();
    let limits = MemoryLimits {
        hub_max_entries: 2,
        max_signatures: 2,
        hub_retention_secs: 2,
        ..Default::default()
    };
    let hub = HubEngine::with_limits_and_clock(
        2,
        limits,
        Arc::new(move || clock.load(Ordering::Relaxed)),
    );
    hub.ingest_batch(batch(1, "a"));
    hub.ingest_batch(batch(2, "a"));
    let rejected = hub.ingest_batch(batch(3, "a"));
    assert_eq!(rejected.rejected_capacity, 2);
    assert_eq!(hub.retained_counts(), (2, 2, 0));
    hub.ingest_batch(batch(1, "b"));
    hub.ingest_batch(batch(2, "b"));
    assert_eq!(hub.retained_counts(), (2, 2, 4));
    now.store(103, Ordering::Relaxed);
    assert_eq!(hub.retained_counts(), (0, 0, 0));
    hub.ingest_batch(batch(3, "b"));
    assert!(
        hub.pull_since(0).ip_deltas.is_empty(),
        "expired votes cannot contribute to a new quorum"
    );
    hub.ingest_batch(batch(3, "a"));
    assert_eq!(hub.pull_since(0).ip_deltas.len(), 1);
}

#[test]
fn cached_signature_admission_is_bounded_even_for_unique_attacker_paths() {
    let w = SlidingWindowEngine::with_limits(
        WindowConfig::default(),
        MemoryLimits {
            max_signatures: 2,
            ..Default::default()
        },
    );
    assert!(w.try_register_auto_signature("GET", "/first", "test"));
    assert!(w.try_register_auto_signature("GET", "/second", "test"));
    for n in 0..10000 {
        assert!(!w.try_register_auto_signature("GET", &format!("/other/{n}"), "test"));
    }
    assert!(!w.try_register_auto_signature("GET", &"x".repeat(257), "test"));
    assert_eq!(w.active_signature_count(), 2);
}

#[tokio::test]
async fn provider_success_and_error_bodies_are_bounded_without_content_length() {
    use axum::{
        body::{Body, Bytes},
        http::StatusCode,
        response::Response,
        routing::post,
    };
    use std::sync::atomic::AtomicBool;
    let failed = Arc::new(AtomicBool::new(false));
    let server_flag = failed.clone();
    let app = axum::Router::new().route(
        "/",
        post(move || {
            let flag = server_flag.clone();
            async move {
                let chunks = tokio_stream::iter(
                    (0..1024)
                        .map(|_| Ok::<_, std::convert::Infallible>(Bytes::from(vec![b'x'; 4096]))),
                );
                Response::builder()
                    .status(if flag.load(Ordering::Relaxed) {
                        StatusCode::BAD_GATEWAY
                    } else {
                        StatusCode::OK
                    })
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.firewall.enabled = false;
    cfg.memory.max_provider_response_bytes = 1024;
    cfg.jev.api_key = "loopback-only".into();
    cfg.jev.endpoint = format!("http://{addr}/");
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .build()
        .unwrap();
    p.process_event(&event(1)).unwrap();
    for bad_status in [false, true] {
        failed.store(bad_status, Ordering::Relaxed);
        let error = p.flush_and_analyze(true).await.unwrap_err();
        assert!(error.to_string().contains("byte limit"), "{error}");
        assert_eq!(p.jev.metrics.actors_evaluated.load(Ordering::Relaxed), 0);
        assert!(p.store.list_active().is_empty());
    }
    server.abort();
}

#[tokio::test]
async fn slow_api_readers_cannot_accumulate_unlimited_response_bodies() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("ledger");
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    let app = custos::bouncer_api::build_bouncer_router(custos::bouncer_api::AppState {
        pipeline: p,
        api_token: String::new(),
    });
    let mut held = Vec::new();
    for _ in 0..16 {
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
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }
    let request = || {
        Request::builder()
            .uri("/v1/decisions")
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(held);
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn retained_ban_capacity_blocks_new_http_admission_until_cleanup_completes() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("ledger");
    cfg.memory.max_decisions = 1;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    ban(&p.store, 1).unwrap();
    assert!(p.reserve_event().is_err());
    let app = custos::bouncer_api::build_bouncer_router(custos::bouncer_api::AppState {
        pipeline: p.clone(),
        api_token: String::new(),
    });
    let request = || {
        Request::builder()
            .uri(format!("/v1/bouncer/check?ip={}", ip(2)))
            .body(Body::empty())
            .unwrap()
    };
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(response);
    p.remove_ban(&ip(1)).unwrap();
    assert!(p.reserve_event().is_ok());
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn hub_rejects_oversized_wire_messages_before_creating_vote_state() {
    use custos::hub::{
        CustosHubGrpcService, proto::custos_hub_service_client::CustosHubServiceClient,
    };
    use tokio_stream::wrappers::TcpListenerStream;
    let hub = Arc::new(HubEngine::new(1));
    let service =
        CustosHubGrpcService::with_auth(hub.clone(), "test".into(), Default::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service.into_server())
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap()
    });
    let mut client = CustosHubServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let mut huge = batch(1, "a");
    huge.api_token = "test".into();
    huge.ip_signals[0].ip = vec![1; 512 * 1024];
    let error = client
        .push_signals(tonic::Request::new(huge))
        .await
        .unwrap_err();
    assert!(matches!(
        error.code(),
        tonic::Code::OutOfRange | tonic::Code::ResourceExhausted
    ));
    assert_eq!(hub.retained_counts(), (0, 0, 0));
    server.abort();
}

#[tokio::test]
async fn hub_stream_slots_are_bounded_and_released_when_the_response_is_dropped() {
    use custos::hub::{
        CustosHubGrpcService,
        proto::{NodeStreamMessage, custos_hub_service_client::CustosHubServiceClient},
    };
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    let hub = Arc::new(HubEngine::with_limits(
        1,
        MemoryLimits {
            hub_max_streams: 1,
            ..Default::default()
        },
    ));
    let service = CustosHubGrpcService::with_auth(hub, "test".into(), Default::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service.into_server())
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap()
    });
    let mut client = CustosHubServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let request = || {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut request = tonic::Request::new(ReceiverStream::new(rx));
        request
            .metadata_mut()
            .insert("authorization", "Bearer test".parse().unwrap());
        request
            .metadata_mut()
            .insert("x-custos-node", "node".parse().unwrap());
        (tx, request)
    };
    let (sender, first) = request();
    let held = client.stream_intel(first).await.unwrap();
    // Keep the incoming half open so gRPC cannot finish the response before this assertion.
    sender
        .send(NodeStreamMessage {
            node_id: "node".into(),
            since_seq: 0,
            signals: None,
        })
        .await
        .unwrap();
    let (_sender, second) = request();
    assert_eq!(
        client.stream_intel(second).await.unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    drop(held);
    drop(sender);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (_tx, request) = request();
            match client.stream_intel(request).await {
                Ok(_) => break,
                Err(e) if e.code() == tonic::Code::ResourceExhausted => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await
    .unwrap();
    server.abort();
}

#[test]
fn concurrent_ban_admission_cannot_exceed_capacity_or_corrupt_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let store = Arc::new(DecisionStore::open_with_limit(path.clone(), 3600, 8).unwrap());
    let mut workers = Vec::new();
    for n in 1..=64 {
        let store = store.clone();
        workers.push(std::thread::spawn(move || {
            let _ = ban(&store, n);
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(store.retained_count(), 8);
    assert_eq!(store.capacity_rejected.load(Ordering::Relaxed), 56);
    drop(store);
    assert_eq!(
        DecisionStore::open_with_limit(path, 3600, 8)
            .unwrap()
            .retained_count(),
        8
    );
}
