use crate::config::{LogFormat, LogSourceConfig};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::LazyLock;
use tokio::sync::mpsc;
use tracing::warn;

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

/// Limits apply before buffering or retaining attacker-controlled HTTP fields.
pub const MAX_LOG_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_URI_BYTES: usize = 8 * 1024;
pub const MAX_UA_BYTES: usize = 1024;
pub const MAX_METHOD_BYTES: usize = 32;

pub(crate) fn bounded_str(raw: &str, max: usize) -> &str {
    let mut end = raw.len().min(max);
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    &raw[..end]
}

pub(crate) fn bound_event(mut ev: AccessLogEvent) -> (AccessLogEvent, bool) {
    fn trim(value: &mut String, max: usize) -> bool {
        let end = bounded_str(value, max).len();
        if end == value.len() {
            if value.capacity() > max {
                value.shrink_to_fit();
            }
            return false;
        }
        value.truncate(end);
        value.shrink_to_fit();
        true
    }
    let mut oversized = trim(&mut ev.path, MAX_URI_BYTES);
    oversized |= trim(&mut ev.query, MAX_URI_BYTES.saturating_sub(ev.path.len()));
    oversized |= trim(&mut ev.user_agent, MAX_UA_BYTES);
    oversized |= trim(&mut ev.method, MAX_METHOD_BYTES);
    trim(&mut ev.referer, 2048);
    (ev, oversized)
}

static NGINX_COMBINED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)""#,
    )
    .expect("valid nginx combined regex")
});

/// Parses a single line according to the configured `LogFormat`.
pub fn parse_log_line(line: &str, format: LogFormat) -> Option<AccessLogEvent> {
    if line.len() > MAX_LOG_RECORD_BYTES {
        return None;
    }
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

#[derive(Deserialize)]
struct CaddyLog {
    ts: Option<f64>,
    request: CaddyRequest,
    status: u16,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize)]
struct CaddyRequest {
    remote_ip: String,
    #[serde(default)]
    client_ip: String,
    method: String,
    uri: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, Vec<String>>,
}

/// Traefik's native JSON schema, including responses generated by the proxy itself.
/// Unknown fields (cookies, credentials, backend addresses) are never retained.
#[derive(Deserialize)]
struct TraefikLog {
    #[serde(rename = "ClientHost")]
    client_host: Option<String>,
    #[serde(rename = "ClientAddr")]
    client_addr: Option<String>,
    #[serde(rename = "RequestMethod")]
    method: String,
    #[serde(rename = "RequestPath")]
    uri: String,
    #[serde(rename = "DownstreamStatus")]
    status: u16,
    #[serde(rename = "DownstreamContentSize", default)]
    bytes_sent: u64,
    #[serde(rename = "StartUTC")]
    start_utc: Option<DateTime<Utc>>,
    #[serde(rename = "StartLocal")]
    start_local: Option<DateTime<Utc>>,
    time: Option<DateTime<Utc>>,
    #[serde(rename = "request_User-Agent", alias = "request_user-agent", default)]
    user_agent: String,
    #[serde(rename = "request_Referer", alias = "request_referer", default)]
    referer: String,
}

fn parse_traefik_json(line: &str) -> Option<AccessLogEvent> {
    let raw: TraefikLog = serde_json::from_str(line).ok()?;
    let client_ip = if let Some(host) = raw.client_host {
        // Never fall back to a header/backend address when the logged host is invalid.
        host.parse().ok()?
    } else {
        let addr = raw.client_addr?;
        addr.parse::<IpAddr>()
            .ok()
            .or_else(|| addr.parse::<SocketAddr>().ok().map(|a| a.ip()))?
    };
    let (path, query) = split_uri(&raw.uri);
    Some(AccessLogEvent {
        timestamp: raw
            .start_utc
            .or(raw.start_local)
            .or(raw.time)
            .unwrap_or_else(Utc::now),
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

fn parse_json_log(line: &str) -> Option<AccessLogEvent> {
    if let Ok(raw) = serde_json::from_str::<RawJsonLog>(line) {
        let (path, query) = split_uri(&raw.uri);
        return Some(AccessLogEvent {
            timestamp: Utc::now(),
            client_ip: raw.client_ip.parse().ok()?,
            method: raw.method,
            path,
            query,
            status: raw.status,
            bytes_sent: raw.bytes_sent,
            referer: raw.referer,
            user_agent: raw.user_agent,
        });
    }
    if let Some(event) = parse_traefik_json(line) {
        return Some(event);
    }
    let raw: CaddyLog = serde_json::from_str(line).ok()?;
    let header = |name: &str| {
        raw.request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, values)| values.first())
            .cloned()
            .unwrap_or_default()
    };
    let (path, query) = split_uri(&raw.request.uri);
    let client = if raw.request.client_ip.is_empty() {
        &raw.request.remote_ip
    } else {
        &raw.request.client_ip
    };
    Some(AccessLogEvent {
        timestamp: raw
            .ts
            .filter(|v| v.is_finite())
            .and_then(|v| DateTime::from_timestamp_millis((v * 1000.0) as i64))
            .unwrap_or_else(Utc::now),
        client_ip: client.parse().ok()?,
        method: raw.request.method.clone(),
        path,
        query,
        status: raw.status,
        bytes_sent: raw.size,
        referer: header("referer"),
        user_agent: header("user-agent"),
    })
}

/// Reads an entire log file from beginning to end for deterministic replay/testing.
pub fn replay_log_file(path: &Path, format: LogFormat) -> Result<Vec<AccessLogEvent>> {
    let mut events = Vec::new();
    visit_log_file(path, format, |event| {
        events.push(event);
        Ok(())
    })?;
    Ok(events)
}

/// Stream bounded records without retaining the file; stop immediately on callback errors.
pub fn visit_log_file(
    path: &Path,
    format: LogFormat,
    mut visit: impl FnMut(AccessLogEvent) -> Result<()>,
) -> Result<usize> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open log file for replay: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut count = 0;
    let mut reader = reader;
    let mut discarding = false;
    loop {
        let mut record = Vec::new();
        let bytes = (&mut reader)
            .take((MAX_LOG_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut record)?;
        if bytes == 0 {
            break;
        }
        let oversized = discarding || bytes > MAX_LOG_RECORD_BYTES;
        discarding = oversized && !record.ends_with(b"\n");
        if !oversized
            && let Ok(line) = std::str::from_utf8(&record)
            && let Some(ev) = parse_log_line(line, format)
        {
            visit(ev)?;
            count += 1;
        }
    }
    Ok(count)
}

#[derive(Default)]
struct TailCursor {
    offset: u64,
    identity: Option<(u64, u64)>,
    discarding_oversized: bool,
    full_batch: bool,
}

#[cfg(unix)]
fn file_identity(file: &std::fs::File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &std::fs::File) -> std::io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct FileInfo {
        attributes: u32,
        creation: FileTime,
        access: FileTime,
        write: FileTime,
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut FileInfo) -> i32;
    }
    let mut info = std::mem::MaybeUninit::<FileInfo>::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    Ok((
        info.volume as u64,
        ((info.index_high as u64) << 32) | info.index_low as u64,
    ))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(file: &std::fs::File) -> std::io::Result<(u64, u64)> {
    let created = file
        .metadata()?
        .created()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Ok((created.as_secs(), created.subsec_nanos() as u64))
}

fn read_available(
    source: &LogSourceConfig,
    cursor: &mut TailCursor,
    from_start: bool,
) -> Result<Vec<AccessLogEvent>> {
    let mut file = std::fs::File::open(&source.path)?;
    let identity = file_identity(&file)?;
    let len = file.metadata()?.len();
    match cursor.identity {
        None => cursor.offset = if from_start { 0 } else { len },
        Some(previous) if previous != identity || len < cursor.offset => {
            cursor.offset = 0;
            cursor.discarding_oversized = false;
        }
        _ => {}
    }
    cursor.identity = Some(identity);
    file.seek(SeekFrom::Start(cursor.offset))?;
    let mut reader = BufReader::new(file);
    read_records(source, cursor, &mut reader)
}

fn read_records(
    source: &LogSourceConfig,
    cursor: &mut TailCursor,
    reader: &mut impl BufRead,
) -> Result<Vec<AccessLogEvent>> {
    let mut events = Vec::new();
    cursor.full_batch = true;
    // Limit each filesystem operation so cancellation/backpressure stays responsive.
    let mut batch_bytes = 0;
    for _ in 0..256 {
        // Stop before the next record; at most one 64 KiB record can exceed this target.
        if batch_bytes >= 64 * 1024 {
            break;
        }
        let mut record = Vec::new();
        let bytes = match (&mut *reader)
            .take((MAX_LOG_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut record)
        {
            Ok(bytes) => bytes,
            Err(error) if events.is_empty() => return Err(error.into()),
            Err(error) => {
                // Already committed records must still reach the consumer. The
                // failed record's offset is unchanged, so the next poll retries it.
                cursor.full_batch = false;
                warn!(path = %source.path.display(), offset = cursor.offset, %error, "Read interrupted; delivering complete records before retry");
                break;
            }
        };
        if bytes == 0 {
            cursor.full_batch = false;
            break;
        }
        if cursor.discarding_oversized || bytes > MAX_LOG_RECORD_BYTES {
            cursor.offset += bytes as u64;
            cursor.discarding_oversized = !record.ends_with(b"\n");
            continue;
        }
        if !record.ends_with(b"\n") {
            cursor.full_batch = false;
            break;
        }
        cursor.offset += bytes as u64;
        let Ok(line) = std::str::from_utf8(&record) else {
            warn!(path = %source.path.display(), offset = cursor.offset, "Skipped access log record with invalid UTF-8");
            continue;
        };
        if let Some(event) = parse_log_line(line, source.format) {
            batch_bytes += bytes;
            events.push(event);
        } else if !line.trim().is_empty() && !line.trim_start().starts_with('#') {
            warn!(path = %source.path.display(), offset = cursor.offset, "Skipped malformed access log record");
        }
    }
    Ok(events)
}

/// Follow replacement files by identity and consume only complete records.
pub fn spawn_log_tailer(
    source: LogSourceConfig,
    tx: mpsc::Sender<AccessLogEvent>,
    read_from_start: bool,
) -> tokio::task::JoinHandle<()> {
    spawn_reader(source, LogSink::Channel(tx), read_from_start)
}

pub fn spawn_pipeline_tailer(
    source: LogSourceConfig,
    pipeline: crate::SecurityPipeline,
    read_from_start: bool,
) -> tokio::task::JoinHandle<()> {
    spawn_reader(source, LogSink::Pipeline(pipeline), read_from_start)
}

enum LogSink {
    Channel(mpsc::Sender<AccessLogEvent>),
    Pipeline(crate::SecurityPipeline),
}

fn spawn_reader(
    source: LogSourceConfig,
    sink: LogSink,
    read_from_start: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut cursor = TailCursor::default();
        loop {
            if matches!(&sink, LogSink::Channel(tx) if tx.is_closed()) {
                return;
            }
            let input = source.clone();
            let (next_cursor, result) = match tokio::task::spawn_blocking(move || {
                let result = read_available(&input, &mut cursor, read_from_start);
                (cursor, result)
            })
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    warn!(%error, "Log reader worker failed");
                    return;
                }
            };
            cursor = next_cursor;
            let mut full = false;
            match result {
                Ok(events) => {
                    full = cursor.full_batch;
                    for event in events {
                        let sent = match &sink {
                            LogSink::Channel(tx) => {
                                tx.send(event).await.map_err(anyhow::Error::from)
                            }
                            LogSink::Pipeline(pipeline) => pipeline.submit_log_event(event).await,
                        };
                        if sent.is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    warn!(path = %source.path.display(), %error, "Unable to read log source; will retry")
                }
            }
            if full {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_error_preserves_complete_records_and_retries_partial_record() {
        struct InterruptedReader {
            bytes: std::io::Cursor<Vec<u8>>,
        }
        impl std::io::Read for InterruptedReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = std::io::Read::read(&mut self.bytes, buffer)?;
                if count == 0 {
                    return Err(std::io::Error::other("injected read failure"));
                }
                Ok(count)
            }
        }
        let complete = b"{\"client_ip\":\"198.51.100.1\",\"uri\":\"/complete\"}\n";
        let mut bytes = complete.to_vec();
        bytes.extend_from_slice(b"{\"client_ip\":");
        let mut reader = BufReader::new(InterruptedReader {
            bytes: std::io::Cursor::new(bytes),
        });
        let source = LogSourceConfig {
            path: "unused".into(),
            format: LogFormat::Json,
        };
        let mut cursor = TailCursor::default();
        let events = read_records(&source, &mut cursor, &mut reader).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, "/complete");
        assert_eq!(
            cursor.offset,
            complete.len() as u64,
            "retry starts at the partial record"
        );
    }

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
