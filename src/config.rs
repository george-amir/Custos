use crate::firewall::FirewallBackend;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub logs: Vec<LogSourceConfig>,
    #[serde(default)]
    pub window: WindowConfig,
    #[serde(default)]
    pub jev: JevConfig,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub hub: HubConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_hub_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_hub_listen")]
    pub listen: String,
    #[serde(default = "default_node_id")]
    pub node_id: String,
    #[serde(default)]
    pub api_token: String,
    #[serde(default = "default_quorum_min_nodes")]
    pub quorum_min_nodes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_firewall_enabled")]
    pub enabled: bool,
    #[serde(default = "default_firewall_backend")]
    pub backend: FirewallBackend,
    #[serde(default = "default_firewall_dry_run")]
    pub dry_run: bool,
    #[serde(default = "default_firewall_table")]
    pub table_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_bouncer_listen")]
    pub bouncer_listen: String,
    #[serde(default = "default_decisions_file")]
    pub decisions_file: PathBuf,
    #[serde(default = "default_ban_ttl_secs")]
    pub default_ban_ttl_secs: u64,
    #[serde(default)]
    pub api_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    NginxCombined,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSourceConfig {
    pub path: PathBuf,
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_l1_flood_threshold")]
    pub l1_flood_threshold: usize,
    #[serde(default = "default_min_suspicion_score")]
    pub min_suspicion_score: u32,
    #[serde(default = "default_max_sample_requests")]
    pub max_sample_requests: usize,
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JevConfig {
    #[serde(default = "default_jev_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_jev_model")]
    pub model: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_max_actors_per_batch")]
    pub max_actors_per_batch: usize,
    #[serde(default = "default_noul_ban_threshold")]
    pub noul_ban_threshold: f64,
    #[serde(default = "default_choice_confidence_threshold")]
    pub choice_confidence_threshold: f64,
    #[serde(default = "default_auto_sig_threshold")]
    pub auto_signature_confidence_threshold: f64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_hub_endpoint() -> String {
    "http://127.0.0.1:50051".to_string()
}
fn default_hub_listen() -> String {
    "127.0.0.1:50051".to_string()
}
fn default_node_id() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "custos-node-1".to_string())
}
fn default_quorum_min_nodes() -> usize {
    1
}
fn default_firewall_enabled() -> bool {
    true
}
fn default_firewall_backend() -> FirewallBackend {
    FirewallBackend::Auto
}
fn default_firewall_dry_run() -> bool {
    true
}
fn default_firewall_table() -> String {
    "custos_block".to_string()
}
fn default_bouncer_listen() -> String {
    "127.0.0.1:8085".to_string()
}
fn default_decisions_file() -> PathBuf {
    PathBuf::from("decisions.jsonl")
}
fn default_ban_ttl_secs() -> u64 {
    3600
}
fn default_log_format() -> LogFormat {
    LogFormat::NginxCombined
}
fn default_window_secs() -> u64 {
    15
}
fn default_flush_interval_ms() -> u64 {
    2500
}
fn default_l1_flood_threshold() -> usize {
    120
}
fn default_min_suspicion_score() -> u32 {
    2
}
fn default_max_sample_requests() -> usize {
    10
}
fn default_max_tracked_ips() -> usize {
    50_000
}
fn default_jev_endpoint() -> String {
    "https://api.typesafe.ai/v1/systemone".to_string()
}
fn default_jev_model() -> String {
    "jev-latest".to_string()
}
fn default_max_actors_per_batch() -> usize {
    25
}
fn default_noul_ban_threshold() -> f64 {
    0.80
}
fn default_choice_confidence_threshold() -> f64 {
    0.70
}
fn default_auto_sig_threshold() -> f64 {
    0.92
}
fn default_timeout_ms() -> u64 {
    5000
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_hub_endpoint(),
            listen: default_hub_listen(),
            node_id: default_node_id(),
            api_token: std::env::var("CUSTOS_HUB_TOKEN").unwrap_or_default(),
            quorum_min_nodes: default_quorum_min_nodes(),
        }
    }
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: default_firewall_enabled(),
            backend: default_firewall_backend(),
            dry_run: default_firewall_dry_run(),
            table_name: default_firewall_table(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bouncer_listen: default_bouncer_listen(),
            decisions_file: default_decisions_file(),
            default_ban_ttl_secs: default_ban_ttl_secs(),
            api_token: std::env::var("CUSTOS_API_TOKEN").unwrap_or_default(),
        }
    }
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            window_secs: default_window_secs(),
            flush_interval_ms: default_flush_interval_ms(),
            l1_flood_threshold: default_l1_flood_threshold(),
            min_suspicion_score: default_min_suspicion_score(),
            max_sample_requests: default_max_sample_requests(),
            max_tracked_ips: default_max_tracked_ips(),
        }
    }
}

impl Default for JevConfig {
    fn default() -> Self {
        Self {
            endpoint: default_jev_endpoint(),
            model: default_jev_model(),
            api_key: std::env::var("TYPESAFE_API_KEY").unwrap_or_default(),
            max_actors_per_batch: default_max_actors_per_batch(),
            noul_ban_threshold: default_noul_ban_threshold(),
            choice_confidence_threshold: default_choice_confidence_threshold(),
            auto_signature_confidence_threshold: default_auto_sig_threshold(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig::default(),
            logs: Vec::new(),
            window: WindowConfig::default(),
            jev: JevConfig::default(),
            firewall: FirewallConfig::default(),
            hub: HubConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        let mut cfg = if let Some(p) = path {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("Failed to read config file {}", p.display()))?;
            toml::from_str::<AppConfig>(&raw)
                .with_context(|| format!("Failed to parse TOML config {}", p.display()))?
        } else if Path::new("config.toml").exists() {
            let raw = std::fs::read_to_string("config.toml")?;
            toml::from_str::<AppConfig>(&raw)?
        } else if Path::new("/etc/custos/config.toml").exists() {
            let raw = std::fs::read_to_string("/etc/custos/config.toml")?;
            toml::from_str::<AppConfig>(&raw)?
        } else {
            AppConfig::default()
        };

        if cfg.jev.api_key.trim().is_empty() {
            if let Ok(env_key) = std::env::var("TYPESAFE_API_KEY") {
                cfg.jev.api_key = env_key;
            }
        }
        if cfg.daemon.api_token.trim().is_empty() {
            if let Ok(tok) = std::env::var("CUSTOS_API_TOKEN") {
                cfg.daemon.api_token = tok;
            }
        }
        if cfg.hub.api_token.trim().is_empty() {
            if let Ok(tok) = std::env::var("CUSTOS_HUB_TOKEN") {
                cfg.hub.api_token = tok;
            }
        }
        Ok(cfg)
    }

    /// Auto-discovers standard web-server access logs present on the host system
    /// (Nginx, Caddy, Apache/HTTPD across Linux, macOS Homebrew, BSD, and Windows).
    pub fn discover_system_logs() -> Vec<LogSourceConfig> {
        let candidates: &[(&str, LogFormat)] = &[
            ("/var/log/nginx/access.log", LogFormat::NginxCombined),
            (
                "/opt/homebrew/var/log/nginx/access.log",
                LogFormat::NginxCombined,
            ),
            (
                "/usr/local/var/log/nginx/access.log",
                LogFormat::NginxCombined,
            ),
            ("/var/log/caddy/access.log", LogFormat::Json),
            ("/var/log/apache2/access.log", LogFormat::NginxCombined),
            ("/var/log/httpd/access_log", LogFormat::NginxCombined),
            ("C:\\nginx\\logs\\access.log", LogFormat::NginxCombined),
        ];

        let mut found = Vec::new();
        for (path_str, format) in candidates {
            let p = Path::new(path_str);
            if p.exists() {
                found.push(LogSourceConfig {
                    path: p.to_path_buf(),
                    format: *format,
                });
            }
        }
        found
    }
}
