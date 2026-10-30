use custos::{
    SecurityPipeline,
    config::{AppConfig, LogFormat, LogSourceConfig, WindowConfig},
    tailer::{parse_log_line, spawn_log_tailer},
    window::SlidingWindowEngine,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn event(ip: &str, uri: &str, status: u16) -> custos::tailer::AccessLogEvent {
    parse_log_line(&format!(r#"{{"client_ip":"{ip}","method":"GET","uri":"{uri}","status":{status},"user_agent":"Mozilla/5.0"}}"#), LogFormat::Json).unwrap()
}

#[tokio::test]
async fn actor_verdict_never_poisons_first_benign_route() {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("decisions.jsonl");
    cfg.firewall.enabled = false;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    p.process_event(&event("198.51.100.11", "/products", 200))
        .unwrap();
    p.process_event(&event("198.51.100.11", "/.env", 404))
        .unwrap();
    let verdicts = p.flush_and_analyze(true).await.unwrap();
    assert!(verdicts[0].should_ban && verdicts[0].recommend_auto_signature);
    p.process_event(&event("198.51.100.22", "/products", 200))
        .unwrap();
    assert!(
        p.store
            .check_ip(&"198.51.100.22".parse().unwrap())
            .is_none(),
        "a clean route must never become a blocking signature"
    );
}

#[test]
fn suspicious_windows_respect_configured_memory_cap() {
    let engine = SlidingWindowEngine::new(WindowConfig {
        max_tracked_ips: 64,
        ..WindowConfig::default()
    });
    for n in 1..=256u32 {
        let ip = std::net::Ipv4Addr::from(0xc6330000 + n).to_string();
        engine.ingest(&event(&ip, "/.env", 404));
    }
    assert_eq!(engine.drain_suspicious_summaries(true).len(), 64);
}

#[tokio::test]
async fn later_batch_failure_preserves_completed_verdicts_and_pending_windows() {
    use axum::{Json, extract::State, http::StatusCode, routing::post};
    let requests = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new().route("/", post(|State(count): State<Arc<AtomicUsize>>, Json(request): Json<serde_json::Value>| async move {
        let n = count.fetch_add(1, Ordering::Relaxed);
        if n == 0 || n >= 4 {
            let mut answers = serde_json::Map::new();
            for key in request["questions"].as_object().unwrap().keys() {
                let value = if key.ends_with("_should_ban") { serde_json::json!({"type":"noul","noul":0.99}) } else { serde_json::json!({"type":"choice","choice":"vulnerability_scanner","confidence":0.99}) };
                answers.insert(key.clone(), value);
            }
            (StatusCode::OK, Json(serde_json::json!({"answers": answers})))
        } else { (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"temporary failure"}))) }
    })).with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("decisions.jsonl");
    cfg.firewall.enabled = false;
    cfg.jev.api_key = "local-test-key".into();
    cfg.jev.endpoint = format!("http://{addr}/");
    cfg.jev.max_actors_per_batch = 1;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .build()
        .unwrap();
    p.process_event(&event("198.51.100.11", "/.env", 404))
        .unwrap();
    p.process_event(&event("198.51.100.22", "/.env", 404))
        .unwrap();
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 1);
    assert_eq!(requests.load(Ordering::Relaxed), 4);
    assert_eq!(p.jev.metrics.actors_evaluated.load(Ordering::Relaxed), 1);
    assert_eq!(p.store.list_active().len(), 1);
    // New buffered traffic must also be included when forcing a retry flush.
    p.process_event(&event(
        "198.51.100.33",
        "/products?id=1+UNION+SELECT+password",
        500,
    ))
    .unwrap();
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 2);
    assert_eq!(p.store.list_active().len(), 3);
    assert!(p.flush_and_analyze(true).await.unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn rotation_to_larger_file_preserves_all_new_events() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("access.log");
    let line =
        |ip| format!(r#"{{"client_ip":"{ip}","method":"GET","uri":"/.env","status":404}}"#) + "\n";
    std::fs::write(&path, line("198.51.100.11")).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let task = spawn_log_tailer(
        LogSourceConfig {
            path: path.clone(),
            format: LogFormat::Json,
        },
        tx,
        true,
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .client_ip
            .to_string(),
        "198.51.100.11"
    );
    let replacement = temp.path().join("replacement.log");
    std::fs::write(&replacement, line("198.51.100.22") + &line("198.51.100.33")).unwrap();
    std::fs::rename(replacement, path).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .client_ip
            .to_string(),
        "198.51.100.22",
        "first new-file event must not be skipped"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .client_ip
            .to_string(),
        "198.51.100.33"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(350), rx.recv())
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn partial_line_is_retained_until_completion() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("access.log");
    std::fs::write(&path, b"").unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let task = spawn_log_tailer(
        LogSourceConfig {
            path: path.clone(),
            format: LogFormat::Json,
        },
        tx,
        true,
    );
    let line = r#"{"client_ip":"198.51.100.11","method":"GET","uri":"/.env","status":404}"#;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&line.as_bytes()[..25]).unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    file.write_all(&line.as_bytes()[25..]).unwrap();
    file.write_all(b"\n").unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .client_ip
            .to_string(),
        "198.51.100.11"
    );
    task.abort();
}

#[test]
fn native_caddy_log_is_parsed() {
    let log = r#"{"level":"info","ts":1793350000.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.11","client_ip":"198.51.100.11","method":"GET","uri":"/.env","headers":{"User-Agent":["Nuclei"]}},"status":404,"size":0}"#;
    let ev = parse_log_line(log, LogFormat::Json).expect("native Caddy log should parse");
    assert_eq!(ev.client_ip.to_string(), "198.51.100.11");
    assert_eq!(ev.path, "/.env");
    assert_eq!(ev.user_agent, "Nuclei");
}

#[tokio::test]
async fn forced_flush_waits_for_all_previously_queued_events() {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("queued.jsonl");
    cfg.firewall.enabled = false;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    p.submit_event(event("198.51.100.11", "/.env", 404))
        .await
        .unwrap();
    assert_eq!(p.flush_and_analyze(true).await.unwrap().len(), 1);
    assert!(
        p.store
            .check_ip(&"198.51.100.11".parse().unwrap())
            .is_some()
    );
}

#[test]
fn concurrent_suspicious_ingestion_cannot_exceed_the_cap() {
    let engine = Arc::new(SlidingWindowEngine::new(WindowConfig {
        max_tracked_ips: 8,
        ..Default::default()
    }));
    let barrier = Arc::new(std::sync::Barrier::new(32));
    let threads: Vec<_> = (1..=32)
        .map(|n| {
            let engine = engine.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                engine.ingest(&event(&format!("198.51.100.{n}"), "/.env", 404));
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(engine.drain_suspicious_summaries(true).len(), 8);
    assert_eq!(engine.metrics.capacity_dropped.load(Ordering::Relaxed), 24);
}

#[tokio::test]
async fn malicious_query_never_promotes_an_ordinary_application_route() {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = temp.path().join("query.jsonl");
    cfg.firewall.enabled = false;
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    p.process_event(&event(
        "198.51.100.11",
        "/products?id=1+UNION+SELECT+password",
        500,
    ))
    .unwrap();
    assert!(p.flush_and_analyze(true).await.unwrap()[0].should_ban);
    assert_eq!(p.window.active_signature_count(), 0);
    p.process_event(&event("198.51.100.22", "/products", 200))
        .unwrap();
    assert!(
        p.store
            .check_ip(&"198.51.100.22".parse().unwrap())
            .is_none()
    );
}
