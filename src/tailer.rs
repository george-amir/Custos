use crate::config::{LogFormat, LogSourceConfig};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Normalized HTTP access log event produced by the tailer/parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEvent {
    pub timestamp: DateTime<Utc>,
    pub client_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub bytes_sent: u64,
    pub referer: String,
    pub user_agent: String,
}

static NGINX_COMBINED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)""#,
    )
    .expect("valid nginx combined regex")
});

/// Parses a single line according to the configured `LogFormat`.
pub fn parse_log_line(line: &str, format: LogFormat) -> Option<AccessLogEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    match format {
        LogFormat::NginxCombined => parse_nginx_combined(trimmed),
        LogFormat::Json => parse_json_log(trimmed),
    }
}

fn split_uri(uri: &str) -> (String, String) {
    if let Some((path, query)) = uri.split_once('?') {
        (path.to_string(), query.to_string())
    } else {
        (uri.to_string(), String::new())
    }
}

fn parse_nginx_combined(line: &str) -> Option<AccessLogEvent> {
    let caps = NGINX_COMBINED_RE.captures(line)?;
    let client_ip: IpAddr = caps.name("ip")?.as_str().parse().ok()?;
    let time_str = caps.name("time")?.as_str();
    let timestamp = DateTime::parse_from_str(time_str, "%d/%b/%Y:%H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let method = caps.name("method")?.as_str().to_string();
    let raw_uri = caps.name("uri")?.as_str();
    let (path, query) = split_uri(raw_uri);
    let status: u16 = caps.name("status")?.as_str().parse().ok()?;
    let bytes_sent: u64 = caps
        .name("bytes")
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0);
    let referer = caps
        .name("referer")
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let user_agent = caps
        .name("ua")
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    Some(AccessLogEvent {
        timestamp,
        client_ip,
        method,
        path,
        query,
        status,
        bytes_sent,
        referer,
        user_agent,
    })
}

#[derive(Deserialize)]
struct RawJsonLog {
    #[serde(alias = "remote_addr", alias = "ip", alias = "client_ip")]
    client_ip: String,
    #[serde(alias = "request_method", default = "default_method")]
    method: String,
    #[serde(alias = "request_uri", alias = "uri", alias = "path")]
    uri: String,
    #[serde(default = "default_status")]
    status: u16,
    #[serde(alias = "body_bytes_sent", default)]
    bytes_sent: u64,
    #[serde(alias = "http_referer", default)]
    referer: String,
    #[serde(alias = "http_user_agent", alias = "ua", default)]
    user_agent: String,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_status() -> u16 {
    200
}

fn parse_json_log(line: &str) -> Option<AccessLogEvent> {
    let raw: RawJsonLog = serde_json::from_str(line).ok()?;
    let client_ip: IpAddr = raw.client_ip.parse().ok()?;
    let (path, query) = split_uri(&raw.uri);
    Some(AccessLogEvent {
        timestamp: Utc::now(),
        client_ip,
        method: raw.method,
        path,
        query,
        status: raw.status,
        bytes_sent: raw.bytes_sent,
        referer: raw.referer,
        user_agent: raw.user_agent,
    })
}

/// Reads an entire log file from beginning to end for deterministic replay/testing.
pub fn replay_log_file(path: &Path, format: LogFormat) -> Result<Vec<AccessLogEvent>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open log file for replay: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Some(ev) = parse_log_line(&line, format) {
            events.push(ev);
        }
    }
    Ok(events)
}

/// Spawns a background task that tails `source.path` (similar to `tail -F`),
/// handling file truncation/rotation and streaming parsed `AccessLogEvent`s.
pub fn spawn_log_tailer(
    source: LogSourceConfig,
    tx: mpsc::Sender<AccessLogEvent>,
    read_from_start: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut offset: u64 = 0;
        let mut initialized = false;

        loop {
            match std::fs::File::open(&source.path) {
                Ok(mut file) => {
                    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
                    if !initialized {
                        offset = if read_from_start { 0 } else { file_len };
                        initialized = true;
                        debug!(
                            path = %source.path.display(),
                            offset,
                            "Initialized log tailer"
                        );
                    } else if file_len < offset {
                        // Log file was truncated or rotated
                        debug!(
                            path = %source.path.display(),
                            old_offset = offset,
                            new_len = file_len,
                            "Detected log truncation/rotation; resetting offset to 0"
                        );
                        offset = 0;
                    }

                    if file.seek(SeekFrom::Start(offset)).is_ok() {
                        let mut reader = BufReader::new(file);
                        let mut line = String::new();
                        while let Ok(bytes_read) = reader.read_line(&mut line) {
                            if bytes_read == 0 {
                                break;
                            }
                            offset += bytes_read as u64;
                            if let Some(ev) = parse_log_line(&line, source.format) {
                                if tx.send(ev).await.is_err() {
                                    return;
                                }
                            }
                            line.clear();
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        path = %source.path.display(),
                        error = %err,
                        "Waiting for log file to become available"
                    );
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nginx_combined_line() {
        let line = r#"203.0.113.42 - - [29/Oct/2026:21:15:02 +0300] "GET /wp-admin/setup-config.php?step=1 HTTP/1.1" 404 512 "-" "Nuclei - Open-source project""#;
        let ev = parse_log_line(line, LogFormat::NginxCombined).expect("should parse");
        assert_eq!(ev.client_ip.to_string(), "203.0.113.42");
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.path, "/wp-admin/setup-config.php");
        assert_eq!(ev.query, "step=1");
        assert_eq!(ev.status, 404);
        assert_eq!(ev.user_agent, "Nuclei - Open-source project");
    }

    #[test]
    fn test_parse_json_log_line() {
        let line = r#"{"client_ip":"198.51.100.9","method":"POST","uri":"/api/v1/login?redirect=/admin","status":401,"bytes_sent":89,"user_agent":"python-requests/2.32"}"#;
        let ev = parse_log_line(line, LogFormat::Json).expect("should parse json");
        assert_eq!(ev.client_ip.to_string(), "198.51.100.9");
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.path, "/api/v1/login");
        assert_eq!(ev.query, "redirect=/admin");
        assert_eq!(ev.status, 401);
    }
}
