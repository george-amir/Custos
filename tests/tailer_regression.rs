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
