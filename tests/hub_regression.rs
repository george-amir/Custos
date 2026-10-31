use custos::hub::proto::custos_hub_service_server::CustosHubService;
use custos::hub::proto::{IpSignal, PullRequest, SignalBatch};
use custos::hub::{CustosHubGrpcService, HubEngine, HubSubscription, ip_to_bytes};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};
use tonic::{Code, Request};

fn batch(node: &str, token: &str, ip: [u8; 4]) -> SignalBatch {
    SignalBatch {
        node_id: node.into(),
        api_token: token.into(),
        ip_signals: vec![IpSignal {
            ip: ip_to_bytes(ip.into()),
            threat: 3,
            noul: 0.99,
            confidence: 0.99,
            suggested_ttl_secs: 3600,
        }],
        signature_signals: vec![],
    }
}

#[test]
fn one_reporter_cannot_exhaust_candidate_slots_or_block_independent_quorum() {
    use custos::{hub::proto::SignatureSignal, limits::MemoryLimits};
    let hub = HubEngine::with_limits(
        2,
        MemoryLimits {
            hub_max_entries: 16,
            max_signatures: 16,
            hub_max_pending_entries: 8,
            hub_max_pending_signatures: 8,
            hub_max_pending_per_node: 4,
            ..Default::default()
        },
    );
    let signal = |node: &str, n: u8| {
        let mut batch = batch(node, "", [198, 51, 100, n]);
        batch.signature_signals.push(SignatureSignal {
            method: "GET".into(),
            path_prefix: format!("/exploit/{n}"),
            threat: 3,
            confidence: 0.99,
        });
        batch
    };
    for n in 1..=100 {
        let ack = hub.ingest_batch(signal("noisy", n));
        assert_eq!(ack.rejected_capacity, if n <= 4 { 0 } else { 2 });
    }
    assert_eq!(hub.pending_counts(), (4, 4, 1, 1));
    assert_eq!(
        hub.ingest_batch(signal("honest-a", 200)).rejected_capacity,
        0
    );
    assert_eq!(
        hub.ingest_batch(signal("honest-b", 200)).rejected_capacity,
        0
    );
    let delta = hub.pull_since(0);
    assert_eq!(delta.ip_deltas.len(), 1);
    assert_eq!(delta.signature_deltas.len(), 1);
    // A reporter already at quota can still supply a vote completing quorum.
    hub.ingest_batch(signal("honest-a", 1));
    assert_eq!(hub.pull_since(0).ip_deltas.len(), 2);
    assert_eq!(
        hub.ingest_batch(signal("noisy", 5)).rejected_capacity,
        0,
        "promotion releases reporter accounting"
    );
}

#[test]
fn full_candidate_budget_still_allows_existing_candidates_to_promote_without_eviction() {
    use custos::limits::MemoryLimits;
    let hub = HubEngine::with_limits(
        2,
        MemoryLimits {
            hub_max_entries: 4,
            hub_max_pending_entries: 2,
            ..Default::default()
        },
    );
    hub.ingest_batch(batch("a", "", [198, 51, 100, 1]));
    hub.ingest_batch(batch("b", "", [198, 51, 100, 2]));
    assert_eq!(
        hub.ingest_batch(batch("c", "", [198, 51, 100, 3]))
            .rejected_capacity,
        1
    );
    hub.ingest_batch(batch("a", "", [198, 51, 100, 2]));
    hub.ingest_batch(batch("b", "", [198, 51, 100, 1]));
    assert_eq!(hub.pull_since(0).ip_deltas.len(), 2);
    assert_eq!(hub.pending_counts(), (0, 0, 0, 0));
    // New candidates can use the freed candidate budget alongside promoted bans.
    hub.ingest_batch(batch("c", "", [198, 51, 100, 3]));
    assert_eq!(hub.pending_counts().0, 1);
    assert_eq!(
        hub.pull_since(0).ip_deltas.len(),
        2,
        "active promotions must never be evicted to admit votes"
    );
}

#[test]
fn candidate_ttl_is_shorter_than_promoted_retention_and_frees_reporter_accounting() {
    use custos::{hub::proto::SignatureSignal, limits::MemoryLimits};
    let clock = Arc::new(AtomicI64::new(100));
    let now = clock.clone();
    let hub = HubEngine::with_limits_and_clock(
        2,
        MemoryLimits {
            hub_vote_ttl_secs: 5,
            hub_retention_secs: 3600,
            ..Default::default()
        },
        Arc::new(move || now.load(Ordering::Relaxed)),
    );
    let signal = |node: &str, n: u8| {
        let mut batch = batch(node, "", [198, 51, 100, n]);
        batch.signature_signals.push(SignatureSignal {
            method: "GET".into(),
            path_prefix: format!("/exploit/{n}"),
            threat: 3,
            confidence: 0.99,
        });
        batch
    };
    hub.ingest_batch(signal("a", 1));
    hub.ingest_batch(signal("b", 1));
    hub.ingest_batch(signal("a", 2));
    clock.store(106, Ordering::Relaxed);
    assert_eq!(hub.pending_counts(), (0, 0, 0, 0));
    assert_eq!(hub.retained_counts(), (1, 1, 2));
    hub.ingest_batch(signal("b", 2));
    assert_eq!(
        hub.pull_since(0).ip_deltas.len(),
        1,
        "expired votes cannot contribute to quorum"
    );
    hub.ingest_batch(signal("a", 2));
    assert_eq!(hub.retained_counts(), (2, 2, 4));
}

#[test]
fn reporter_identity_churn_keeps_vote_accounting_bounded_without_evicting_promotions() {
    use custos::limits::MemoryLimits;
    let clock = Arc::new(AtomicI64::new(100));
    let now = clock.clone();
    let hub = HubEngine::with_limits_and_clock(
        64,
        MemoryLimits {
            hub_max_entries: 8,
            hub_max_pending_entries: 4,
            hub_vote_ttl_secs: 2,
            ..Default::default()
        },
        Arc::new(move || now.load(Ordering::Relaxed)),
    );
    for n in 0..10_000 {
        hub.ingest_batch(batch(
            &format!("node-{n}"),
            "",
            [198, 51, 100, (n % 8 + 1) as u8],
        ));
        let (ips, _, reporters, _) = hub.pending_counts();
        assert!(ips <= 4 && reporters <= 4 * 64);
    }
    clock.store(103, Ordering::Relaxed);
    assert_eq!(hub.pending_counts(), (0, 0, 0, 0));
    assert_eq!(hub.retained_counts(), (8, 0, 8));
}

#[tokio::test]
async fn hub_requires_credentials_and_prevents_forged_quorum() {
    let engine = Arc::new(HubEngine::new(2));
    let svc = CustosHubGrpcService::with_auth(
        engine.clone(),
        "shared".into(),
        BTreeMap::from([
            ("a".into(), "token-a".into()),
            ("b".into(), "token-b".into()),
        ]),
    )
    .unwrap();
    assert_eq!(
        svc.push_signals(Request::new(batch("a", "wrong", [198, 51, 100, 1])))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(
        svc.push_signals(Request::new(batch("b", "token-a", [198, 51, 100, 1])))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    for forged in ["fake-a", "fake-b"] {
        svc.push_signals(Request::new(batch(forged, "shared", [198, 51, 100, 2])))
            .await
            .unwrap();
    }
    assert!(engine.pull_since(0).ip_deltas.is_empty());
    for (node, token) in [("a", "token-a"), ("b", "token-b")] {
        svc.push_signals(Request::new(batch(node, token, [198, 51, 100, 1])))
            .await
            .unwrap();
    }
    assert_eq!(engine.pull_since(0).ip_deltas.len(), 1);
    assert_eq!(
        svc.pull_deltas(Request::new(PullRequest {
            node_id: "a".into(),
            since_seq: 0
        }))
        .await
        .unwrap_err()
        .code(),
        Code::Unauthenticated
    );
    let mut pull = Request::new(PullRequest {
        node_id: "a".into(),
        since_seq: 0,
    });
    pull.metadata_mut()
        .insert("authorization", "Bearer token-a".parse().unwrap());
    assert_eq!(
        svc.pull_deltas(pull)
            .await
            .unwrap()
            .into_inner()
            .ip_deltas
            .len(),
        1
    );
}

#[test]
fn hub_rejects_empty_or_reused_credentials() {
    assert!(
        CustosHubGrpcService::with_auth(
            Arc::new(HubEngine::new(1)),
            String::new(),
            BTreeMap::new()
        )
        .is_err()
    );
    assert!(
        CustosHubGrpcService::with_auth(
            Arc::new(HubEngine::new(2)),
            String::new(),
            BTreeMap::from([("a".into(), "same".into()), ("b".into(), "same".into())])
        )
        .is_err()
    );
}

#[test]
fn hub_cursor_never_skips_concurrent_publications() {
    let hub = Arc::new(HubEngine::new(1));
    let writer_hub = hub.clone();
    let writer = std::thread::spawn(move || {
        for n in 0..2000u32 {
            writer_hub.ingest_batch(batch("a", "", [198, 51, (n >> 8) as u8, n as u8]));
        }
    });
    let mut cursor = 0;
    let mut received = std::collections::HashSet::new();
    loop {
        let delta = hub.pull_since(cursor);
        for ban in delta.ip_deltas {
            assert!(ban.seq <= delta.latest_seq);
            received.insert(ban.seq);
        }
        cursor = delta.latest_seq;
        if cursor == 2000 {
            break;
        }
        std::thread::yield_now();
    }
    writer.join().unwrap();
    assert_eq!(received.len(), 2000);
}

#[test]
fn expired_hub_bans_are_not_replayed_and_can_be_reconvicted() {
    let expiring = |node: &str| {
        let mut signal = batch(node, "", [198, 51, 100, 1]);
        signal.ip_signals[0].suggested_ttl_secs = 10;
        signal
    };
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let hub = HubEngine::with_clock(2, Arc::new(move || clock.load(Ordering::Relaxed)));
    hub.ingest_batch(expiring("a"));
    hub.ingest_batch(expiring("b"));
    assert_eq!(hub.pull_since(0).ip_deltas[0].expires_at_unix_secs, 1010);
    now.store(1007, Ordering::Relaxed);
    assert_eq!(hub.pull_since(0).ip_deltas[0].ttl_secs, 3);
    now.store(1010, Ordering::Relaxed);
    assert!(hub.pull_since(0).ip_deltas.is_empty());
    hub.ingest_batch(expiring("a"));
    assert!(
        hub.pull_since(0).ip_deltas.is_empty(),
        "fresh quorum is needed after expiry"
    );
    hub.ingest_batch(expiring("b"));
    let fresh = hub.pull_since(1);
    assert_eq!(fresh.ip_deltas.len(), 1);
    assert_eq!(fresh.ip_deltas[0].expires_at_unix_secs, 1020);
}

#[tokio::test]
async fn slow_subscription_recovers_every_ban_after_buffer_overflow() {
    let hub = Arc::new(HubEngine::new(1));
    let mut subscription = HubSubscription::new(hub.clone(), 0);
    for n in 0..1500u32 {
        hub.ingest_batch(batch("a", "", [198, 51, (n >> 8) as u8, n as u8]));
    }
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(1), subscription.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.latest_seq, 1500);
    assert_eq!(snapshot.ip_deltas.len(), 1500);
    hub.ingest_batch(batch("a", "", [203, 0, 113, 1]));
    assert_eq!(subscription.next().await.unwrap().ip_deltas.len(), 1);
}

async fn serve(
    hub: Arc<HubEngine>,
    listener: tokio::net::TcpListener,
) -> tokio::task::JoinHandle<()> {
    let svc = CustosHubGrpcService::with_auth(
        hub,
        String::new(),
        BTreeMap::from([
            ("a".into(), "token-a".into()),
            ("b".into(), "token-b".into()),
        ]),
    )
    .unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc.into_server())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    })
}

#[tokio::test]
async fn streamed_signals_are_authenticated_and_bound_to_connection_identity() {
    use custos::hub::proto::{
        NodeStreamMessage, custos_hub_service_client::CustosHubServiceClient,
    };
    use tokio_stream::wrappers::ReceiverStream;
    let hub = Arc::new(HubEngine::new(2));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = serve(hub.clone(), listener).await;
    let mut client = CustosHubServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let (_tx, rx) = tokio::sync::mpsc::channel::<NodeStreamMessage>(2);
    assert_eq!(
        client
            .stream_intel(ReceiverStream::new(rx))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    let mut req = Request::new(ReceiverStream::new(rx));
    req.metadata_mut()
        .insert("authorization", "Bearer token-a".parse().unwrap());
    req.metadata_mut()
        .insert("x-custos-node", "a".parse().unwrap());
    let mut stream = client.stream_intel(req).await.unwrap().into_inner();
    tx.send(NodeStreamMessage {
        node_id: "a".into(),
        since_seq: 0,
        signals: Some(batch("a", "token-a", [198, 51, 100, 1])),
    })
    .await
    .unwrap();
    stream.message().await.unwrap().unwrap(); // initial snapshot
    tx.send(NodeStreamMessage {
        node_id: "b".into(),
        since_seq: 0,
        signals: Some(batch("b", "token-b", [198, 51, 100, 1])),
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        hub.latest_seq(),
        0,
        "changing body identity cannot fabricate a second authenticated voter"
    );
    client
        .push_signals(Request::new(batch("b", "token-b", [198, 51, 100, 1])))
        .await
        .unwrap();
    let delta = tokio::time::timeout(std::time::Duration::from_secs(2), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(delta.ip_deltas.len(), 1);
    server.abort();
}

#[tokio::test]
async fn synchronization_retries_initial_failure_without_losing_outbound_signals() {
    use custos::{SecurityPipeline, config::AppConfig};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("bans.jsonl");
    cfg.firewall.enabled = false;
    let pipeline = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(batch("a", "token-a", [198, 51, 100, 1]))
        .await
        .unwrap();
    let sync = tokio::spawn(custos::hub::run_hub_sync(
        format!("http://{addr}"),
        "a".into(),
        "token-a".into(),
        pipeline.clone(),
        rx,
    ));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let hub = Arc::new(HubEngine::new(1));
    let server = serve(
        hub.clone(),
        tokio::net::TcpListener::bind(addr).await.unwrap(),
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while hub.latest_seq() == 0 || pipeline.store.list_active().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("sync must recover and apply the queued signal");
    drop(tx);
    tokio::time::timeout(std::time::Duration::from_secs(2), sync)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.abort();
}

#[test]
fn expired_deltas_do_not_resurrect_bans_on_reconnect() {
    use custos::hub::proto::{HubDeltaBatch, IpBanDelta};
    use custos::{SecurityPipeline, config::AppConfig};
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("bans.jsonl");
    cfg.firewall.enabled = false;
    let pipeline = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    let expired = HubDeltaBatch {
        latest_seq: 1,
        ip_deltas: vec![IpBanDelta {
            seq: 1,
            ip: vec![198, 51, 100, 1],
            threat: 3,
            noul: 0.99,
            confidence: 0.99,
            ttl_secs: 3600,
            expires_at_unix_secs: chrono::Utc::now().timestamp() - 1,
        }],
        signature_deltas: vec![],
    };
    assert_eq!(
        custos::hub::apply_hub_delta_to_pipeline(&pipeline, &expired).unwrap(),
        (0, 0)
    );
    assert!(pipeline.store.list_active().is_empty());
}

#[derive(Clone)]
struct CloseFirstStream {
    inner: CustosHubGrpcService,
    streams: Arc<std::sync::atomic::AtomicUsize>,
    pushes: Arc<std::sync::atomic::AtomicUsize>,
}

#[tonic::async_trait]
impl CustosHubService for CloseFirstStream {
    async fn push_signals(
        &self,
        req: Request<SignalBatch>,
    ) -> Result<tonic::Response<custos::hub::proto::PushAck>, tonic::Status> {
        if self.pushes.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(tonic::Status::unavailable(
                "injected interruption before acknowledgement",
            ));
        }
        self.inner.push_signals(req).await
    }
    async fn pull_deltas(
        &self,
        req: Request<PullRequest>,
    ) -> Result<tonic::Response<custos::hub::proto::HubDeltaBatch>, tonic::Status> {
        self.inner.pull_deltas(req).await
    }
    type StreamIntelStream = <CustosHubGrpcService as CustosHubService>::StreamIntelStream;
    async fn stream_intel(
        &self,
        req: Request<tonic::Streaming<custos::hub::proto::NodeStreamMessage>>,
    ) -> Result<tonic::Response<Self::StreamIntelStream>, tonic::Status> {
        let response = self.inner.stream_intel(req).await?;
        if self.streams.fetch_add(1, Ordering::SeqCst) == 0 {
            drop(response); // Simulate a connection ending after a successful handshake.
            Ok(tonic::Response::new(Box::pin(tokio_stream::empty())))
        } else {
            Ok(response)
        }
    }
}

#[tokio::test]
async fn synchronization_reconnects_after_an_established_stream_closes() {
    use custos::{SecurityPipeline, config::AppConfig};
    let hub = Arc::new(HubEngine::new(1));
    let streams = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let svc = CloseFirstStream {
        inner: CustosHubGrpcService::with_auth(hub.clone(), "shared".into(), BTreeMap::new())
            .unwrap(),
        streams: streams.clone(),
        pushes: pushes.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                custos::hub::proto::custos_hub_service_server::CustosHubServiceServer::new(svc),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("bans.jsonl");
    cfg.firewall.enabled = false;
    let pipeline = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let sync = tokio::spawn(custos::hub::run_hub_sync(
        format!("http://{addr}"),
        "a".into(),
        "shared".into(),
        pipeline.clone(),
        rx,
    ));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while streams.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("closed stream must reconnect");
    tx.send(batch("a", "shared", [198, 51, 100, 2]))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while pipeline.store.list_active().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        pushes.load(Ordering::SeqCst) >= 2,
        "unacknowledged batch must be retried"
    );
    drop(tx);
    tokio::time::timeout(std::time::Duration::from_secs(2), sync)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.abort();
}

#[test]
fn hub_preserves_exact_exploit_paths_without_broadening_them() {
    use custos::hub::proto::SignatureSignal;
    let hub = HubEngine::new(1);
    let mut signal = batch("a", "", [198, 51, 100, 1]);
    let exploit = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php";
    signal.signature_signals.push(SignatureSignal {
        method: "GET".into(),
        path_prefix: exploit.into(),
        threat: 5,
        confidence: 0.99,
    });
    hub.ingest_batch(signal);
    assert_eq!(hub.pull_since(0).signature_deltas[0].path_prefix, exploit);
}
