pub mod bouncer_api;
pub mod config;
pub mod firewall;
pub mod hub;
pub mod hub_proto;
pub mod jev;
pub mod middleware;
pub mod sanitizer;
pub mod service;
pub mod store;
pub mod tailer;
pub mod window;

use crate::config::{AppConfig, FirewallConfig, JevConfig, WindowConfig};
use crate::firewall::{FirewallBackend, FirewallBouncer};
use crate::jev::{ActorVerdict, JevBatchAnalyzer};
use crate::store::{DecisionSource, DecisionStore};
use crate::tailer::AccessLogEvent;
use crate::window::{L1Disposition, SlidingWindowEngine};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Ergonomic builder for embedding `Custos` (`SecurityPipeline`) as a Rust library.
#[derive(Debug, Clone, Default)]
pub struct CustosBuilder {
    config: AppConfig,
    mock_jev: bool,
}

impl CustosBuilder {
    pub fn new() -> Self {
        Self {
            config: AppConfig::default(),
            mock_jev: false,
        }
    }

    pub fn with_config(mut self, config: AppConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_decisions_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.daemon.decisions_file = path.into();
        self
    }

    pub fn with_typesafe_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.config.jev.api_key = api_key.into();
        self
    }

    pub fn with_mock_jev(mut self, mock_jev: bool) -> Self {
        self.mock_jev = mock_jev;
        self
    }

    pub fn with_firewall_backend(mut self, backend: FirewallBackend, dry_run: bool) -> Self {
        self.config.firewall.backend = backend;
        self.config.firewall.dry_run = dry_run;
        self
    }

    pub fn with_window_config(mut self, window: WindowConfig) -> Self {
        self.config.window = window;
        self
    }

    pub fn with_jev_config(mut self, jev: JevConfig) -> Self {
        self.config.jev = jev;
        self
    }

    pub fn with_firewall_config(mut self, firewall: FirewallConfig) -> Self {
        self.config.firewall = firewall;
        self
    }

    pub fn build(self) -> Result<SecurityPipeline> {
        let use_mock = self.mock_jev || self.config.jev.api_key.trim().is_empty();
        let store = Arc::new(DecisionStore::open(
            self.config.daemon.decisions_file,
            self.config.daemon.default_ban_ttl_secs,
        )?);
        let window = Arc::new(SlidingWindowEngine::new(self.config.window));
        let jev = Arc::new(JevBatchAnalyzer::new(self.config.jev, use_mock)?);
        let firewall = Arc::new(FirewallBouncer::new(self.config.firewall));
        Ok(SecurityPipeline::new(store, window, jev, firewall))
    }
}

/// Coordinates the 3-stage pipeline:
/// 1. Ingests `AccessLogEvent` through `SlidingWindowEngine` (skipping already-banned IPs and benign static hits).
/// 2. Records instant L1 bans (volumetric floods or cached Jev signatures) and enforces OS firewall rules.
/// 3. Flushes suspicious IP windows in batches to `JevBatchAnalyzer` (`/v1/systemone`),
///    updating `DecisionStore`, enforcing OS firewall rules, and caching high-confidence attack signatures.
#[derive(Clone)]
pub struct SecurityPipeline {
    pub store: Arc<DecisionStore>,
    pub window: Arc<SlidingWindowEngine>,
    pub jev: Arc<JevBatchAnalyzer>,
    pub firewall: Arc<FirewallBouncer>,
}

impl SecurityPipeline {
    pub fn builder() -> CustosBuilder {
        CustosBuilder::new()
    }

    pub fn new(
        store: Arc<DecisionStore>,
        window: Arc<SlidingWindowEngine>,
        jev: Arc<JevBatchAnalyzer>,
        firewall: Arc<FirewallBouncer>,
    ) -> Self {
        let _ = firewall.init_backend();
        Self {
            store,
            window,
            jev,
            firewall,
        }
    }

    /// Processes a single incoming log event through L1 check and window buffering.
    pub fn process_event(&self, ev: &AccessLogEvent) -> Result<()> {
        // Fast path: if IP is already actively banned, skip windowing/token cost
        if self.store.check_ip(&ev.client_ip).is_some() {
            return Ok(());
        }

        match self.window.ingest(ev) {
            L1Disposition::IgnoredStatic | L1Disposition::Buffered { .. } => {}
            L1Disposition::InstantBan {
                threat_class,
                reason,
            } => {
                let source = if reason.contains("cached Jev signature") {
                    DecisionSource::L1AutoSignature
                } else {
                    DecisionSource::L1Deterministic
                };
                let decision = self.store.upsert_ban(
                    ev.client_ip,
                    threat_class,
                    source,
                    1.0,
                    1.0,
                    reason,
                    None,
                )?;
                let ttl = (decision.expires_at - decision.created_at)
                    .num_seconds()
                    .max(1) as u64;
                let _ = self.firewall.ban_ip(ev.client_ip, ttl);
            }
        }
        Ok(())
    }

    /// Drains suspicious IP behavioral windows and evaluates them in a bulk Jev `/v1/systemone` call.
    pub async fn flush_and_analyze(&self, force_all: bool) -> Result<Vec<ActorVerdict>> {
        let summaries = self.window.drain_suspicious_summaries(force_all);
        if summaries.is_empty() {
            return Ok(Vec::new());
        }

        let verdicts = self.jev.analyze_summaries(&summaries).await?;
        for v in &verdicts {
            if v.should_ban {
                let reason = format!(
                    "Jev /v1/systemone verdict: class={} (noul={:.2}, confidence={:.2})",
                    v.threat_class, v.noul_malicious_prob, v.choice_confidence
                );
                let decision = self.store.upsert_ban(
                    v.client_ip,
                    v.threat_class.clone(),
                    DecisionSource::JevSystemOne,
                    v.noul_malicious_prob,
                    v.choice_confidence,
                    reason,
                    None,
                )?;
                let ttl = (decision.expires_at - decision.created_at)
                    .num_seconds()
                    .max(1) as u64;
                let _ = self.firewall.ban_ip(v.client_ip, ttl);

                if v.recommend_auto_signature
                    && let Some((method, path)) = extract_first_method_and_path(&v.sample_requests)
                {
                    self.window
                        .register_auto_signature(&method, &path, &v.threat_class);
                    info!(
                        method = %method,
                        path = %path,
                        threat_class = %v.threat_class,
                        "Cached high-confidence Jev attack signature for L1 zero-token blocking"
                    );
                }
            }
        }

        Ok(verdicts)
    }
}

fn extract_first_method_and_path(samples: &[String]) -> Option<(String, String)> {
    let first = samples.first()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let uri = parts.next()?;
    let path = uri.split('?').next().unwrap_or(uri).to_string();
    Some((method, path))
}
