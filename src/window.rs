use crate::config::WindowConfig;
use crate::sanitizer::{
    ActorStateSummary, MAX_SANITIZED_UA_LEN, MAX_SANITIZED_URI_LEN, sanitize_untrusted,
};
use crate::tailer::AccessLogEvent;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
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
    unique_paths: HashSet<String>,
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
    sample_requests: Vec<String>,
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
    pub events_processed: AtomicU64,
    pub static_ignored: AtomicU64,
    pub l1_instant_bans: AtomicU64,
    pub windows_promoted_to_jev: AtomicU64,
}

/// Manages per-IP sliding windows, L1 deterministic filtering, and auto-cached signatures.
pub struct SlidingWindowEngine {
    cfg: WindowConfig,
    windows: DashMap<IpAddr, IpWindowState>,
    /// Auto-synthesized signatures `(method, normalized_path_prefix)` learned from high-confidence Jev verdicts.
    auto_signatures: DashMap<(String, String), String>,
    pub metrics: WindowMetrics,
}

impl SlidingWindowEngine {
    pub fn new(cfg: WindowConfig) -> Self {
        Self {
            cfg,
            windows: DashMap::new(),
            auto_signatures: DashMap::new(),
            metrics: WindowMetrics::default(),
        }
    }

    /// Registers a high-confidence attack signature discovered by Jev so repeat probes
    /// from other botnet IPs can be blocked at L1 with zero AI token cost.
    pub fn register_auto_signature(&self, method: &str, path: &str, threat_class: &str) {
        let prefix = normalize_path_prefix(path);
        if prefix.len() >= 4 && prefix != "/" {
            self.auto_signatures
                .insert((method.to_uppercase(), prefix), threat_class.to_string());
        }
    }

    pub fn active_signature_count(&self) -> usize {
        self.auto_signatures.len()
    }

    /// Ingests one `AccessLogEvent` into the L1 filter and per-IP sliding window.
    pub fn ingest(&self, ev: &AccessLogEvent) -> L1Disposition {
        self.metrics
            .events_processed
            .fetch_add(1, Ordering::Relaxed);

        // 1. Fast Static Asset & Healthcheck Drop (only if status is 200/304 and no query string)
        if ev.query.is_empty()
            && (ev.status == 200 || ev.status == 304)
            && is_benign_static(&ev.path)
        {
            self.metrics.static_ignored.fetch_add(1, Ordering::Relaxed);
            return L1Disposition::IgnoredStatic;
        }

        // 2. Check Auto-Cached Signatures from previous high-confidence Jev convictions
        let path_prefix = normalize_path_prefix(&ev.path);
        if let Some(sig_threat) = self
            .auto_signatures
            .get(&(ev.method.to_uppercase(), path_prefix.clone()))
        {
            self.metrics.l1_instant_bans.fetch_add(1, Ordering::Relaxed);
            return L1Disposition::InstantBan {
                threat_class: sig_threat.value().clone(),
                reason: format!(
                    "Matched cached Jev signature on {} {}",
                    ev.method, path_prefix
                ),
            };
        }

        // 3. Enforce bounded memory cap (`max_tracked_ips`) against spoofed-IP floods
        let max_ips = self.cfg.max_tracked_ips.max(64);
        if self.windows.len() >= max_ips && !self.windows.contains_key(&ev.client_ip) {
            self.evict_low_priority_windows(max_ips / 10 + 1);
        }

        // 4. Sanitize URI & User-Agent and extract structural signals
        let full_uri = if ev.query.is_empty() {
            ev.path.clone()
        } else {
            format!("{}?{}", ev.path, ev.query)
        };
        let sanitized_uri = sanitize_untrusted(&full_uri, MAX_SANITIZED_URI_LEN);
        let sanitized_ua = sanitize_untrusted(&ev.user_agent, MAX_SANITIZED_UA_LEN);

        let mut entry = self
            .windows
            .entry(ev.client_ip)
            .or_insert_with(|| IpWindowState::new(ev.timestamp));
        let win = entry.value_mut();

        win.last_seen = ev.timestamp;
        win.total_requests += 1;
        win.unique_paths.insert(ev.path.clone());

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

        if sanitized_uri.special_char_count > win.max_special_chars {
            win.max_special_chars = sanitized_uri.special_char_count;
        }
        if sanitized_uri.special_char_count >= 3 {
            win.suspicion_score += 3;
            win.suspicion_reasons
                .insert("high_special_char_density_in_uri".into());
        }

        if sanitized_uri.prompt_injection_suspected || sanitized_ua.prompt_injection_suspected {
            win.prompt_injection_flag = true;
            win.suspicion_score += 5;
            win.suspicion_reasons
                .insert("adversarial_prompt_injection_in_payload".into());
        }

        let lower_uri = full_uri.to_ascii_lowercase();
        if SENSITIVE_PATH_PATTERNS
            .iter()
            .any(|pat| lower_uri.contains(pat))
        {
            win.suspicion_score += 3;
            win.suspicion_reasons
                .insert("sensitive_or_exploit_path_probe".into());
        }

        if looks_like_sqli_or_xss(&lower_uri) {
            win.suspicion_score += 4;
            win.suspicion_reasons
                .insert("sqli_or_xss_token_pattern".into());
        }

        let lower_ua = ev.user_agent.to_ascii_lowercase();
        if SCANNER_UA_PATTERNS.iter().any(|pat| lower_ua.contains(pat)) {
            win.suspicion_score += 4;
            win.suspicion_reasons.insert("offensive_scanner_ua".into());
        }

        if win.user_agents.len() < 4 && !sanitized_ua.text.is_empty() {
            win.user_agents.insert(sanitized_ua.text);
        }

        if win.sample_requests.len() < self.cfg.max_sample_requests {
            let trace = format!("{} {} -> {}", ev.method, sanitized_uri.text, ev.status);
            if !win.sample_requests.contains(&trace) {
                win.sample_requests.push(trace);
            }
        }

        // 4. Check L1 Volumetric Flood Instant-Ban
        if win.total_requests >= self.cfg.l1_flood_threshold {
            let reason = format!(
                "Exceeded L1 volumetric threshold ({} requests in window)",
                win.total_requests
            );
            drop(entry);
            self.windows.remove(&ev.client_ip);
            self.metrics.l1_instant_bans.fetch_add(1, Ordering::Relaxed);
            return L1Disposition::InstantBan {
                threat_class: "layer7_dos".to_string(),
                reason,
            };
        }

        L1Disposition::Buffered {
            current_suspicion_score: win.suspicion_score,
        }
    }

    /// Drains all IP windows that have crossed `min_suspicion_score` (and either expired
    /// or `force_all` is true), packing them into sanitized `ActorStateSummary` structs
    /// ready for a bulk Jev `/v1/systemone` request.
    pub fn drain_suspicious_summaries(&self, force_all: bool) -> Vec<ActorStateSummary> {
        let now = Utc::now();
        let mut to_remove = Vec::new();
        let mut summaries = Vec::new();

        for item in self.windows.iter() {
            let ip = *item.key();
            let win = item.value();
            let age_secs = (now - win.first_seen).num_seconds().max(1) as u64;
            let expired = age_secs >= self.cfg.window_secs;

            if force_all || expired || win.suspicion_score >= self.cfg.min_suspicion_score * 2 {
                to_remove.push(ip);
                if win.suspicion_score >= self.cfg.min_suspicion_score {
                    let idx = summaries.len();
                    let error_count = win.status_401_403 + win.status_404 + win.status_5xx;
                    let error_ratio = (error_count as f64) / (win.total_requests.max(1) as f64);
                    let duration = ((win.last_seen - win.first_seen).num_seconds().max(1)) as u64;
                    let req_per_sec = (win.total_requests as f64) / (duration as f64);

                    summaries.push(ActorStateSummary {
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
                        sample_requests: win.sample_requests.clone(),
                    });
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

fn looks_like_sqli_or_xss(lower_uri: &str) -> bool {
    [
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
    .any(|pat| lower_uri.contains(pat))
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
