use custos::config::{LogFormat, LogSourceConfig};
use custos::tailer::spawn_log_tailer;
use std::time::Duration;

#[tokio::test]
async fn malformed_utf8_does_not_discard_or_stall_valid_records() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("access.log");
    let first = br#"{"client_ip":"198.51.100.1","uri":"/first","status":404}"#;
    let second = br#"{"client_ip":"198.51.100.2","uri":"/second","status":404}"#;
    let mut contents = first.to_vec();
    contents.extend_from_slice(b"\n\xff\n");
    contents.extend_from_slice(second);
    contents.push(b'\n');
    std::fs::write(&path, contents).unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
    let task = spawn_log_tailer(
        LogSourceConfig {
            path,
            format: LogFormat::Json,
        },
        sender,
        true,
    );
    for expected_path in ["/first", "/second"] {
        let event = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("valid records must survive the malformed record")
            .expect("tailer stays active");
        assert_eq!(event.path, expected_path);
    }
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn oversized_partial_record_is_discarded_without_losing_following_records() {
    use custos::tailer::{MAX_LOG_RECORD_BYTES, parse_log_line, replay_log_file};
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("access.log");
    let huge = format!(
        "{{\"ip\":\"198.51.100.1\",\"uri\":\"/{}\"}}",
        "x".repeat(MAX_LOG_RECORD_BYTES * 3)
    );
    assert!(parse_log_line(&huge, LogFormat::Json).is_none());
    std::fs::write(&path, &huge).unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
    let task = spawn_log_tailer(
        LogSourceConfig {
            path: path.clone(),
            format: LogFormat::Json,
        },
        sender,
        true,
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(350), receiver.recv())
            .await
            .is_err()
    );
    let valid = "{\"ip\":\"198.51.100.2\",\"uri\":\"/after-oversized\"}\n";
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writeln!(file).unwrap();
    file.write_all(valid.as_bytes()).unwrap();
    let e = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e.path, "/after-oversized");
    let replay = replay_log_file(&path, LogFormat::Json).unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].path, "/after-oversized");
    task.abort();
    let _ = task.await;
}
