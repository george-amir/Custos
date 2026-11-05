use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Default)]
pub struct SourceHealth {
    pub parsed: AtomicU64,
    pub malformed: AtomicU64,
    pub oversized: AtomicU64,
    pub read_errors: AtomicU64,
    pub rotations: AtomicU64,
    pub backlog_bytes: AtomicU64,
    pub last_read_unix: AtomicU64,
    pub last_event_unix: AtomicU64,
}
#[derive(Serialize, serde::Deserialize)]
pub struct SourceStatus {
    pub source_id: usize,
    pub path: String,
    pub parsed: u64,
    pub malformed: u64,
    pub oversized: u64,
    pub read_errors: u64,
    pub rotations: u64,
    pub backlog_bytes: u64,
    pub last_read_unix: u64,
    pub last_event_unix: u64,
}
pub struct PipelineHealth {
    started: Instant,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub events_received: AtomicU64,
    pub already_banned: AtomicU64,
    pub new_bans: AtomicU64,
    pub ban_updates: AtomicU64,
    pub observed_crawler_allowed: AtomicU64,
    pub analysis_completed: AtomicU64,
    pub analysis_latency_ms_total: AtomicU64,
    pub analysis_latency_ms_max: AtomicU64,
    sources: Mutex<BTreeMap<String, Arc<SourceHealth>>>,
}
impl Default for PipelineHealth {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            started_at: chrono::Utc::now(),
            events_received: 0.into(),
            already_banned: 0.into(),
            new_bans: 0.into(),
            ban_updates: 0.into(),
            observed_crawler_allowed: 0.into(),
            analysis_completed: 0.into(),
            analysis_latency_ms_total: 0.into(),
            analysis_latency_ms_max: 0.into(),
            sources: Mutex::new(BTreeMap::new()),
        }
    }
}
impl PipelineHealth {
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn source_count(&self) -> usize {
        self.sources.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub fn source(&self, path: &Path) -> Option<Arc<SourceHealth>> {
        let path = path.to_string_lossy();
        if path.len() > 4096 {
            return None;
        }
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(source) = sources.get(path.as_ref()) {
            return Some(source.clone());
        }
        if sources.len() >= 16 {
            return None;
        }
        let source = Arc::new(SourceHealth::default());
        sources.insert(path.into_owned(), source.clone());
        Some(source)
    }
    pub fn sources(&self) -> Vec<SourceStatus> {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .enumerate()
            .map(|(source_id, (path, h))| SourceStatus {
                source_id,
                path: path.clone(),
                parsed: h.parsed.load(Ordering::Relaxed),
                malformed: h.malformed.load(Ordering::Relaxed),
                oversized: h.oversized.load(Ordering::Relaxed),
                read_errors: h.read_errors.load(Ordering::Relaxed),
                rotations: h.rotations.load(Ordering::Relaxed),
                backlog_bytes: h.backlog_bytes.load(Ordering::Relaxed),
                last_read_unix: h.last_read_unix.load(Ordering::Relaxed),
                last_event_unix: h.last_event_unix.load(Ordering::Relaxed),
            })
            .collect()
    }
}
