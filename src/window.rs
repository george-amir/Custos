use crate::config::WindowConfig;
use crate::sanitizer::{
    ActorStateSummary, MAX_SANITIZED_UA_LEN, MAX_SANITIZED_URI_LEN, decode_url, inspect_untrusted,
    redact_sensitive, sanitize_untrusted,
};
use crate::tailer::{AccessLogEvent, MAX_METHOD_BYTES, MAX_UA_BYTES, MAX_URI_BYTES, bounded_str};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use regex::Regex;
use std::collections::{BTreeSet, HashSet, VecDeque, hash_map::RandomState};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// High-value sensitive or exploit-probe path substrings that immediately raise L1 suspicion.
const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    "/.env",
    "/.git",
    "/wp-admin",
    "/wp-login",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/actuator",
    "/etc/passwd",
    "/proc/self",
    "../",
    "..%2f",
    "/cgi-bin",
    "/vendor/phpunit",
    "/admin/config",
];

/// Known offensive scanner User-Agent substrings.
const SCANNER_UA_PATTERNS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nuclei",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "ffuf",
    "wfuzz",
    "zgrab",
];

/// Outcome of processing a single `AccessLogEvent` through the L1 engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L1Disposition {
    /// No additional IP can be admitted without exceeding the configured bound.
    CapacityExceeded,
    /// Benign static asset or healthcheck; skipped to save memory and tokens.
    IgnoredStatic,
    /// Matched an auto-cached attack signature or volumetric flood threshold at L1.
    InstantBan {
        threat_class: String,
        reason: String,
    },
    /// Added to the IP's sliding behavioral window.
    Buffered { current_suspicion_score: u32 },
}

#[derive(Debug, Clone)]
struct IpWindowState {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    total_requests: usize,
    unique_paths: HashSet<u64>,
    status_2xx: usize,
    status_3xx: usize,
    status_401_403: usize,
    status_404: usize,
    status_5xx: usize,
    max_special_chars: usize,
    prompt_injection_flag: bool,
    suspicion_score: u32,
    suspicion_reasons: BTreeSet<String>,
    user_agents: BTreeSet<String>,
    sample_requests: Vec<(u32, String)>,
}

impl IpWindowState {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            first_seen: now,
            last_seen: now,
            total_requests: 0,
            unique_paths: HashSet::new(),
            status_2xx: 0,
            status_3xx: 0,
            status_401_403: 0,
            status_404: 0,
            status_5xx: 0,
            max_special_chars: 0,
            prompt_injection_flag: false,
            suspicion_score: 0,
            suspicion_reasons: BTreeSet::new(),
            user_agents: BTreeSet::new(),
            sample_requests: Vec::new(),
        }
    }
}

/// Telemetry counters for L1 filtering and windowing.
#[derive(Debug, Default)]
pub struct WindowMetrics {
    pub capacity_dropped: AtomicU64,
    pub expired_evidence_dropped: AtomicU64,
    pub events_processed: AtomicU64,
    pub static_ignored: AtomicU64,
    pub l1_instant_bans: AtomicU64,
    pub windows_promoted_to_jev: AtomicU64,
}

/// Manages per-IP sliding windows, L1 deterministic filtering, and auto-cached signatures.
pub struct SlidingWindowEngine {
    mutation: Mutex<()>,
    cfg: WindowConfig,
    limits: crate::limits::MemoryLimits,
    windows: DashMap<IpAddr, IpWindowState>,
    ready: Mutex<VecDeque<(IpAddr, IpWindowState)>>,
    path_hasher: RandomState,
    /// Auto-synthesized signatures `(method, normalized_path_prefix)` learned from high-confidence Jev verdicts.
    auto_signatures: DashMap<(String, String), (String, DateTime<Utc>)>,
    pub metrics: WindowMetrics,
}

impl SlidingWindowEngine {
    pub fn new(cfg: WindowConfig) -> Self {
        Self::with_limits(cfg, crate::limits::MemoryLimits::default())
    }

    pub fn with_limits(cfg: WindowConfig, limits: crate::limits::MemoryLimits) -> Self {
        Self {
            cfg,
            limits,
            mutation: Mutex::new(()),
            windows: DashMap::new(),
            ready: Mutex::new(VecDeque::new()),
            path_hasher: RandomState::new(),
            auto_signatures: DashMap::new(),
            metrics: WindowMetrics::default(),
        }
    }

    /// Registers a high-confidence attack signature discovered by Jev so repeat probes
    /// from other botnet IPs can be blocked at L1 with zero AI token cost.
    pub fn register_auto_signature(&self, method: &str, path: &str, threat_class: &str) {
        self.try_register_auto_signature(method, path, threat_class);
    }

    pub fn try_register_auto_signature(
        &self,
        method: &str,
        path: &str,
        threat_class: &str,
    ) -> bool {
        let _guard = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        if path.len() > crate::limits::MAX_SIGNATURE_BYTES
            || method.len() > MAX_METHOD_BYTES
            || threat_class.len() > crate::limits::MAX_THREAT_BYTES
        {
            return false;
        }
        let prefix = path.trim().to_string();
        if prefix.len() < 4 || prefix == "/" {
            return false;
        }
        let now = Utc::now();
        self.auto_signatures
            .retain(|_, (_, expires)| *expires > now);
        let key = (method.to_uppercase(), prefix);
        if !self.auto_signatures.contains_key(&key)
            && self.auto_signatures.len() >= self.limits.max_signatures
        {
            return false;
        }
        let expiry =
            now + chrono::TimeDelta::seconds(self.limits.hub_retention_secs.min(86400) as i64);
        self.auto_signatures
            .insert(key, (threat_class.to_string(), expiry));
        true
    }

    pub fn retained_window_counts(&self) -> (usize, usize) {
        let _guard = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        (
            self.windows.len(),
            self.ready.lock().unwrap_or_else(|e| e.into_inner()).len(),
        )
    }

    pub fn active_signature_count(&self) -> usize {
        self.auto_signatures
            .retain(|_, (_, expires)| *expires > Utc::now());
        self.auto_signatures.len()
    }

    /// Ingests one `AccessLogEvent` into the L1 filter and per-IP sliding window.
    pub fn ingest(&self, ev: &AccessLogEvent) -> L1Disposition {
        self.ingest_bounded(ev, false)
    }

    pub(crate) fn ingest_bounded(&self, ev: &AccessLogEvent, oversized: bool) -> L1Disposition {
        let _guard = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        self.metrics
            .events_processed
            .fetch_add(1, Ordering::Relaxed);

        // Never let provider backlogs extend a request-counting interval.
        // Preserve expired suspicious evidence separately, with a bounded backlog.
        let expired = self.windows.get(&ev.client_ip).is_some_and(|w| {
            (ev.timestamp - w.first_seen).num_seconds()
                >= self.cfg.window_secs.max(1).min(i64::MAX as u64) as i64
        });
        if expired
            && let Some((ip, old)) = self.windows.remove(&ev.client_ip)
            && old.suspicion_score >= self.cfg.min_suspicion_score
        {
            self.retain_expired(ip, old);
        }
        let path = bounded_str(&ev.path, MAX_URI_BYTES);
        let query = bounded_str(&ev.query, MAX_URI_BYTES.saturating_sub(path.len()));
        let ua = bounded_str(&ev.user_agent, MAX_UA_BYTES);
        let method = bounded_str(&ev.method, MAX_METHOD_BYTES);
        let oversized = oversized
            || path.len() != ev.path.len()
            || query.len() != ev.query.len()
            || ua.len() != ev.user_agent.len()
            || method.len() != ev.method.len();

        // 2. Check Auto-Cached Signatures from previous high-confidence Jev convictions
        let path_prefix = path.trim().to_string();
        if let Some(sig_threat) = self
            .auto_signatures
            .get(&(method.to_uppercase(), path_prefix.clone()))
            .filter(|s| s.value().1 > Utc::now())
        {
            self.metrics.l1_instant_bans.fetch_add(1, Ordering::Relaxed);
            return L1Disposition::InstantBan {
                threat_class: sig_threat.value().0.clone(),
                reason: format!(
                    "Matched cached Jev signature on {} {}",
                    ev.method, path_prefix
                ),
            };
        }

        // 3. Enforce bounded memory cap (`max_tracked_ips`) against spoofed-IP floods
        let max_ips = self.max_windows();
        if self.windows.len() >= max_ips && !self.windows.contains_key(&ev.client_ip) {
            // Idle clients must not pin all admission capacity during provider outages.
            let expired: Vec<_> = self
                .windows
                .iter()
                .filter(|w| {
                    (ev.timestamp - w.first_seen).num_seconds()
                        >= self.cfg.window_secs.max(1).min(i64::MAX as u64) as i64
                })
                .map(|w| *w.key())
                .collect();
            for ip in expired {
                if let Some((ip, old)) = self.windows.remove(&ip) {
                    self.retain_expired(ip, old);
                }
            }
            if self.windows.len() >= max_ips {
                self.evict_low_priority_windows(max_ips / 10 + 1);
            }
            if self.windows.len() >= max_ips {
                self.metrics
                    .capacity_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return L1Disposition::CapacityExceeded;
            }
        }

        let decoded_path = decode_url(path, false);
        let full_uri = if query.is_empty() {
            decoded_path.into_owned()
        } else {
            format!("{}?{}", decoded_path, decode_url(query, true))
        };
        let raw_uri = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        let (raw_special, raw_prompt) = inspect_untrusted(&raw_uri);
        let (decoded_special, decoded_prompt) = if raw_uri == full_uri {
            (raw_special, raw_prompt)
        } else {
            inspect_untrusted(&full_uri)
        };
        let special_count = raw_special.max(decoded_special);
        let sanitized_ua = sanitize_untrusted(ua, MAX_SANITIZED_UA_LEN);
        let ua_prompt = sanitized_ua.prompt_injection_suspected;
        let lower_uri = full_uri.to_ascii_lowercase();
        let lower_ua = ua.to_ascii_lowercase();
        let sensitive_path = SENSITIVE_PATH_PATTERNS
            .iter()
            .any(|pat| lower_uri.contains(pat));
        let sql = looks_like_sqli_or_xss(&lower_uri)
            || (raw_uri != full_uri && looks_like_sqli_or_xss(&raw_uri.to_ascii_lowercase()));
        let scanner = SCANNER_UA_PATTERNS.iter().any(|pat| lower_ua.contains(pat));
        let benign_static = !oversized
            && query.is_empty()
            && matches!(method, "GET" | "HEAD")
            && matches!(ev.status, 200 | 304)
            && is_benign_static(path)
            && !sensitive_path
            && !sql
            && !scanner
            && !raw_prompt
            && !decoded_prompt
            && !ua_prompt
            && special_count < 3;

        let mut entry = self
            .windows
            .entry(ev.client_ip)
            .or_insert_with(|| IpWindowState::new(ev.timestamp));
        let win = entry.value_mut();

        win.last_seen = win.last_seen.max(ev.timestamp);
        let previous_score = win.suspicion_score;
        win.total_requests += 1;
        if win.unique_paths.len() < self.cfg.l1_flood_threshold.clamp(1, MAX_UNIQUE_PATHS) {
            win.unique_paths.insert(self.path_hasher.hash_one(path));
        }
        // Count static traffic before skipping expensive evidence collection.
        if win.total_requests >= self.cfg.l1_flood_threshold.max(1) {
            let reason = format!(
                "Exceeded L1 volumetric threshold ({} requests in window)",
                win.total_requests
            );
            drop(entry);
            self.windows.remove(&ev.client_ip);
            self.metrics.l1_instant_bans.fetch_add(1, Ordering::Relaxed);
            return L1Disposition::InstantBan {
                threat_class: "layer7_dos".into(),
                reason,
            };
        }
        if benign_static {
            win.status_2xx += usize::from(ev.status == 200);
            win.status_3xx += usize::from(ev.status == 304);
            self.metrics.static_ignored.fetch_add(1, Ordering::Relaxed);
            return L1Disposition::IgnoredStatic;
        }
        if oversized {
            win.suspicion_score = win.suspicion_score.saturating_add(3);
            win.suspicion_reasons.insert("oversized_http_field".into());
        }

        match ev.status {
            200..=299 => win.status_2xx += 1,
            300..=399 => win.status_3xx += 1,
            401 | 403 => {
                win.status_401_403 += 1;
                win.suspicion_score += 1;
                if win.status_401_403 >= 3 {
                    win.suspicion_score += 2;
                    win.suspicion_reasons
                        .insert("repeated_auth_failures".into());
                }
            }
            404 => {
                win.status_404 += 1;
                if win.status_404 >= 3 {
                    win.suspicion_score += 2;
                    win.suspicion_reasons.insert("high_404_probe_rate".into());
                }
            }
            500..=599 => {
                win.status_5xx += 1;
                win.suspicion_score += 1;
                win.suspicion_reasons.insert("server_5xx_triggered".into());
            }
            _ => {}
        }

        if special_count > win.max_special_chars {
            win.max_special_chars = special_count;
        }
        if special_count >= 3 {
            win.suspicion_score += 3;
            win.suspicion_reasons
                .insert("high_special_char_density_in_uri".into());
        }

        if raw_prompt || decoded_prompt || ua_prompt {
            win.prompt_injection_flag = true;
            win.suspicion_score += 5;
            win.suspicion_reasons
                .insert("adversarial_prompt_injection_in_payload".into());
        }

        if sensitive_path {
            win.suspicion_score += 3;
            win.suspicion_reasons
                .insert("sensitive_or_exploit_path_probe".into());
        }

        if sql {
            win.suspicion_score += 4;
            win.suspicion_reasons
                .insert("sqli_or_xss_token_pattern".into());
        }

        if scanner {
            win.suspicion_score += 4;
            win.suspicion_reasons.insert("offensive_scanner_ua".into());
        }

        if win.user_agents.len() < 4 && !sanitized_ua.text.is_empty() {
            win.user_agents.insert(sanitized_ua.text);
        }

        let sample_limit = self.cfg.max_sample_requests.min(MAX_SAMPLES);
        if sample_limit > 0
            && (win.sample_requests.len() < sample_limit
                || win
                    .sample_requests
                    .iter()
                    .any(|(rank, _)| *rank < win.suspicion_score.saturating_sub(previous_score)))
        {
            let priority = win.suspicion_score.saturating_sub(previous_score);
            // Redact before taking an excerpt, so clipping cannot hide a credential key.
            let evidence = redact_sensitive(&decode_url(&redact_sensitive(&raw_uri), true));
            let lower = evidence.to_ascii_lowercase();
            let focus = if sql {
                SQL_EVIDENCE.find(&lower).map(|m| m.start())
            } else {
                SENSITIVE_PATH_PATTERNS
                    .iter()
                    .filter_map(|p| lower.find(p))
                    .min()
            }
            .unwrap_or(0);
            let start = if focus > MAX_SANITIZED_URI_LEN / 2 {
                focus.saturating_sub(24)
            } else {
                0
            };
            let mut start = start;
            while !evidence.is_char_boundary(start) {
                start -= 1;
            }
            let excerpt = sanitize_untrusted(&evidence[start..], MAX_SANITIZED_URI_LEN);
            let mut trace = format!(
                "{} {}{} -> {}",
                method,
                if start > 0 { "..." } else { "" },
                excerpt.text,
                ev.status
            );
            trace.shrink_to_fit();
            if let Some((rank, _)) = win.sample_requests.iter_mut().find(|(_, s)| s == &trace) {
                *rank = (*rank).max(priority);
            } else if win.sample_requests.len() < sample_limit {
                win.sample_requests.push((priority, trace));
            } else if let Some((idx, (lowest, _))) = win
                .sample_requests
                .iter()
                .enumerate()
                .min_by_key(|(_, (p, _))| *p)
                && priority > *lowest
            {
                win.sample_requests[idx] = (priority, trace);
            }
        }

        L1Disposition::Buffered {
            current_suspicion_score: win.suspicion_score,
        }
    }

    /// Drains all IP windows that have crossed `min_suspicion_score` (and either expired
    /// or `force_all` is true), packing them into sanitized `ActorStateSummary` structs
    /// ready for a bulk Jev `/v1/systemone` request.
    pub fn drain_suspicious_summaries(&self, force_all: bool) -> Vec<ActorStateSummary> {
        let _guard = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        let mut to_remove = Vec::new();
        let mut summaries = Vec::new();
        let mut ready = self.ready.lock().unwrap_or_else(|e| e.into_inner());
        for (ip, win) in ready.drain(..) {
            summaries.push(self.summary(ip, &win, summaries.len()));
        }
        drop(ready);

        for item in self.windows.iter() {
            let ip = *item.key();
            let win = item.value();
            let age_secs = (now - win.first_seen).num_seconds().max(1) as u64;
            let expired = age_secs >= self.cfg.window_secs;

            if force_all
                || expired
                || win.suspicion_score >= self.cfg.min_suspicion_score.saturating_mul(2)
            {
                to_remove.push(ip);
                if win.suspicion_score >= self.cfg.min_suspicion_score {
                    summaries.push(self.summary(ip, win, summaries.len()));
                }
            }
        }

        for ip in to_remove {
            self.windows.remove(&ip);
        }

        self.metrics
            .windows_promoted_to_jev
            .fetch_add(summaries.len() as u64, Ordering::Relaxed);
        summaries
    }

    // Caller holds `mutation`, shared with ingestion and draining.
    fn retain_expired(&self, ip: IpAddr, old: IpWindowState) {
        if old.suspicion_score < self.cfg.min_suspicion_score {
            return;
        }
        let mut ready = self.ready.lock().unwrap_or_else(|e| e.into_inner());
        if ready.len() >= self.max_windows() {
            ready.pop_front();
            self.metrics
                .expired_evidence_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        ready.push_back((ip, old));
    }

    fn max_windows(&self) -> usize {
        // Reserve heap overhead as well as the bounded sample and cardinality storage.
        let bytes = 2048
            + 4 * (MAX_SANITIZED_UA_LEN * 4 + 128)
            + self.cfg.max_sample_requests.min(MAX_SAMPLES) * (MAX_SANITIZED_URI_LEN * 4 + 128)
            + self.cfg.l1_flood_threshold.clamp(1, MAX_UNIQUE_PATHS) * 32;
        self.cfg
            .max_tracked_ips
            .max(1)
            .min((self.cfg.max_state_bytes / (2 * bytes)).max(1))
    }

    fn summary(&self, ip: IpAddr, win: &IpWindowState, idx: usize) -> ActorStateSummary {
        let error_count = win.status_401_403 + win.status_404 + win.status_5xx;
        let error_ratio = error_count as f64 / win.total_requests.max(1) as f64;
        let duration = (win.last_seen - win.first_seen).num_seconds().max(1) as u64;
        let req_per_sec = win.total_requests as f64 / duration as f64;
        ActorStateSummary {
            actor_key: format!("actor_{idx}"),
            client_ip: ip.to_string(),
            window_secs: duration,
            total_requests: win.total_requests,
            req_per_sec: (req_per_sec * 100.0).round() / 100.0,
            unique_paths: win.unique_paths.len(),
            status_2xx: win.status_2xx,
            status_3xx: win.status_3xx,
            status_401_403: win.status_401_403,
            status_404: win.status_404,
            status_5xx: win.status_5xx,
            error_ratio: (error_ratio * 100.0).round() / 100.0,
            max_special_chars_in_uri: win.max_special_chars,
            prompt_injection_flag: win.prompt_injection_flag,
            l1_suspicion_reasons: win.suspicion_reasons.iter().cloned().collect(),
            user_agents: win.user_agents.iter().cloned().collect(),
            sample_requests: win.sample_requests.iter().map(|(_, s)| s.clone()).collect(),
        }
    }

    fn evict_low_priority_windows(&self, target_to_evict: usize) {
        let mut candidates = Vec::new();
        for item in self.windows.iter() {
            if item.value().suspicion_score < self.cfg.min_suspicion_score {
                candidates.push(*item.key());
                if candidates.len() >= target_to_evict {
                    break;
                }
            }
        }
        for ip in candidates {
            self.windows.remove(&ip);
        }
    }
}

fn is_benign_static(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower == "/healthz" || lower == "/readyz" || lower == "/favicon.ico" {
        return true;
    }
    [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".webp", ".map",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

const MAX_UNIQUE_PATHS: usize = 1024;
const MAX_SAMPLES: usize = 32;
static SQL_EVIDENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"(?is)\bunion(?:\s|/\*.*?\*/)+select\b|<script|sleep\(|benchmark\(|information_schema|waitfor\s+delay|'\s*or\s*'|\bor\s+1\s*=\s*1"
).unwrap()
});
static SQL_COMMENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

fn normalize_sql(uri: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let stripped = if uri.contains("/*") {
        SQL_COMMENTS.replace_all(uri, " ")
    } else {
        Cow::Borrowed(uri)
    };
    if stripped.bytes().any(|b| b.is_ascii_whitespace()) {
        Cow::Owned(stripped.split_whitespace().collect::<Vec<_>>().join(" "))
    } else {
        stripped
    }
}

fn looks_like_sqli_or_xss(lower_uri: &str) -> bool {
    let normalized = normalize_sql(lower_uri);
    [
        "union select",
        "or 1=1",
        "waitfor delay",
        "union%20select",
        "union+select",
        "or%201=1",
        "'%20or%20'",
        "' or '1'='1",
        "<script",
        "%3cscript",
        "sleep(",
        "benchmark(",
        "information_schema",
        "waitfor%20delay",
    ]
    .iter()
    .any(|pat| lower_uri.contains(pat) || normalized.contains(pat))
}

pub fn normalize_path_prefix(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    let segments: Vec<&str> = trimmed
        .split('/')
        .filter(|s| !s.is_empty())
        .take(3)
        .collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogFormat, WindowConfig};
    use crate::tailer::parse_log_line;

    #[test]
    fn test_static_assets_ignored_and_attacks_flagged() {
        let engine = SlidingWindowEngine::new(WindowConfig::default());

        let static_line = r#"192.0.2.10 - - [29/Oct/2026:21:15:02 +0300] "GET /assets/app.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0""#;
        let ev_static = parse_log_line(static_line, LogFormat::NginxCombined).unwrap();
        assert_eq!(engine.ingest(&ev_static), L1Disposition::IgnoredStatic);

        let sqli_line = r#"198.51.100.77 - - [29/Oct/2026:21:15:03 +0300] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 210 "-" "Mozilla/5.0""#;
        let ev_sqli = parse_log_line(sqli_line, LogFormat::NginxCombined).unwrap();
        match engine.ingest(&ev_sqli) {
            L1Disposition::Buffered {
                current_suspicion_score,
            } => assert!(current_suspicion_score >= 4),
            other => panic!("Expected Buffered, got {:?}", other),
        }

        let summaries = engine.drain_suspicious_summaries(true);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].client_ip, "198.51.100.77");
        assert!(
            summaries[0]
                .l1_suspicion_reasons
                .contains(&"sqli_or_xss_token_pattern".to_string())
        );
    }
}
