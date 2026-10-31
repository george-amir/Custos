use custos::{config::LogFormat, tailer::parse_log_line};

const LOG: &str = include_str!("fixtures/traefik_access.jsonl");

#[test]
fn dokploy_traefik_records_preserve_client_response_and_nanosecond_time() {
    let paths = [
        "/microservice/.env",
        "/service/.env",
        "/api/v3/.env",
        "/api/dev/.env",
        "/api/staging/.env",
    ];
    assert_eq!(LOG.lines().count(), paths.len());
    for (line, expected) in LOG.lines().zip(paths) {
        let ev =
            parse_log_line(line, LogFormat::Json).expect("Traefik JSON access record must parse");
        assert_eq!(ev.client_ip.to_string(), "198.51.100.44");
        assert_eq!(ev.path, expected);
        assert_eq!(ev.method, "GET");
        assert_eq!(
            ev.status, 404,
            "DownstreamStatus must win over OriginStatus=0"
        );
        assert_eq!(ev.bytes_sent, 19);
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            ev.timestamp,
            chrono::DateTime::parse_from_rfc3339(record["StartUTC"].as_str().unwrap()).unwrap()
        );
        assert!(ev.query.is_empty() && ev.user_agent.is_empty());
    }
}

#[tokio::test]
async fn live_cli_accepts_json_format_and_tails_native_traefik_records() {
    use custos::config::AppConfig;
    use std::{
        process::{Child, Command, Stdio},
        time::Duration,
    };
    struct Daemon(Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let log = directory.path().join("access.log");
    std::fs::write(&log, LOG).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cfg = AppConfig::default();
    cfg.daemon.bouncer_listen = format!("127.0.0.1:{port}");
    cfg.daemon.decisions_file = directory.path().join("ledger");
    cfg.firewall.enabled = false;
    cfg.window.flush_interval_ms = 100;
    custos::service::write_secret_file(&config, toml::to_string(&cfg).unwrap().as_bytes()).unwrap();
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_custos"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "run",
                "--log",
                log.to_str().unwrap(),
                "--format",
                "json",
                "--from-start",
                "--mock-jev",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "daemon rejected --format json or exited before processing logs"
            );
            if let Ok(response) = client
                .get(format!(
                    "http://127.0.0.1:{port}/v1/bouncer/check?ip=198.51.100.44"
                ))
                .send()
                .await
                && response.status() == reqwest::StatusCode::FORBIDDEN
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the native Traefik exploit probes must produce an enforced ban");
}

fn record() -> serde_json::Value {
    serde_json::from_str(LOG.lines().next().unwrap()).unwrap()
}

#[test]
fn traefik_preserves_query_headers_and_the_client_facing_status() {
    let mut raw = record();
    raw["RequestPath"] = "/api/search?q=one%20two&id=1".into();
    raw["DownstreamStatus"] = 200.into();
    raw["OriginStatus"] = 503.into();
    raw["ClientAddr"] = "203.0.113.1:1234".into();
    raw["request_User-Agent"] = "Nuclei".into();
    raw["request_Referer"] = "https://example.com/".into();
    raw["request_X-Forwarded-For"] = "203.0.113.2".into();
    raw["request_Cookie"] = "session=ignored-fixture".into();
    let ev = parse_log_line(&raw.to_string(), LogFormat::Json).unwrap();
    assert_eq!(ev.path, "/api/search");
    assert_eq!(ev.query, "q=one%20two&id=1");
    assert_eq!(ev.client_ip.to_string(), "198.51.100.44");
    assert_eq!(ev.status, 200);
    assert_eq!(ev.user_agent, "Nuclei");
    assert_eq!(ev.referer, "https://example.com/");
    let w = custos::window::SlidingWindowEngine::new(Default::default());
    w.ingest(&ev);
    let summaries = w.drain_suspicious_summaries(true);
    assert_eq!(summaries.len(), 1);
    assert!(
        !summaries[0].to_compact_line().contains("ignored-fixture"),
        "Unexpected header retained in analysis state"
    );
}

#[test]
fn traefik_falls_back_to_client_socket_address_for_ipv4_and_ipv6() {
    for (addr, expected) in [
        ("198.51.100.90:443", "198.51.100.90"),
        ("[2001:db8::9]:443", "2001:db8::9"),
    ] {
        let mut raw = record();
        raw.as_object_mut().unwrap().remove("ClientHost");
        raw["ClientAddr"] = addr.into();
        assert_eq!(
            parse_log_line(&raw.to_string(), LogFormat::Json)
                .unwrap()
                .client_ip
                .to_string(),
            expected
        );
    }
    let mut raw = record();
    raw["ClientHost"] = "2001:db8::10".into();
    assert_eq!(
        parse_log_line(&raw.to_string(), LogFormat::Json)
            .unwrap()
            .client_ip
            .to_string(),
        "2001:db8::10"
    );
}

#[test]
fn traefik_uses_local_time_or_log_time_when_start_utc_is_dropped() {
    for local in [true, false] {
        let mut raw = record();
        raw.as_object_mut().unwrap().remove("StartUTC");
        raw["StartLocal"] = "2026-10-30T23:33:37.445806577+03:00".into();
        if !local {
            raw.as_object_mut().unwrap().remove("StartLocal");
        }
        let expected = if local {
            "2026-10-30T20:33:37.445806577Z"
        } else {
            "2026-10-30T20:33:37Z"
        };
        assert_eq!(
            parse_log_line(&raw.to_string(), LogFormat::Json)
                .unwrap()
                .timestamp,
            chrono::DateTime::parse_from_rfc3339(expected).unwrap()
        );
    }
}

#[test]
fn invalid_traefik_identity_and_missing_request_fields_are_rejected() {
    for key in ["RequestMethod", "RequestPath", "DownstreamStatus"] {
        let mut raw = record();
        raw.as_object_mut().unwrap().remove(key);
        assert!(
            parse_log_line(&raw.to_string(), LogFormat::Json).is_none(),
            "missing {key}"
        );
    }
    let mut raw = record();
    raw["ClientHost"] = "not-an-ip".into();
    assert!(parse_log_line(&raw.to_string(), LogFormat::Json).is_none());
    raw.as_object_mut().unwrap().remove("ClientHost");
    raw.as_object_mut().unwrap().remove("ClientAddr");
    raw["request_X-Forwarded-For"] = "198.51.100.5".into();
    raw["ServiceAddr"] = "198.51.100.6:80".into();
    assert!(parse_log_line(&raw.to_string(), LogFormat::Json).is_none());
    for line in [
        r#"{"level":"error","time":"2026-10-31T03:13:40Z","msg":"Error while peeking client hello bytes"}"#,
        "2026-10-31T03:13:40Z ERR Error while peeking client hello bytes error=EOF",
    ] {
        assert!(parse_log_line(line, LogFormat::Json).is_none());
    }
}

#[tokio::test]
async fn traefik_request_count_is_not_treated_as_an_ip_request_counter() {
    use custos::{SecurityPipeline, config::AppConfig};
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("ledger");
    let p = SecurityPipeline::builder()
        .with_config(cfg)
        .with_mock_jev(true)
        .build()
        .unwrap();
    for line in LOG.lines() {
        p.process_event(&parse_log_line(line, LogFormat::Json).unwrap())
            .unwrap();
    }
    assert!(
        p.store.list_active().is_empty(),
        "five records must not trigger an instant flood ban"
    );
    assert!(
        p.window
            .retry_after_secs(&"198.51.100.44".parse().unwrap())
            .is_none()
    );
    let verdicts = p.flush_and_analyze(true).await.unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].should_ban);
    assert_eq!(verdicts[0].threat_class, "vulnerability_scanner");
    assert_eq!(p.store.active_count(), 1);
}

#[test]
fn replay_cli_reads_native_traefik_json_and_rejects_unknown_formats() {
    use custos::config::AppConfig;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("ledger");
    custos::service::write_secret_file(&config, toml::to_string(&cfg).unwrap().as_bytes()).unwrap();
    for format in ["json", "JSON", "jsno"] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_custos"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "replay",
                "--log",
                "tests/fixtures/traefik_access.jsonl",
                "--format",
                format,
                "--mock-jev",
            ])
            .output()
            .unwrap();
        if format == "jsno" {
            assert!(!result.status.success());
        } else {
            assert!(result.status.success());
            assert!(String::from_utf8_lossy(&result.stdout).contains("5 parsed events"));
        }
    }
}
