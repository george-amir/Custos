pub mod bouncer_api;
pub mod config;
pub mod firewall;
pub mod hub;
#[allow(clippy::all)]
pub mod hub_proto;
pub mod jev;
pub mod middleware;
pub mod sanitizer;
pub mod service;
pub mod store;
pub mod tailer;
pub mod window;
pub mod windows_service;

use crate::config::{AppConfig, FirewallConfig, JevConfig, WindowConfig};
use crate::firewall::{FirewallBackend, FirewallBouncer};
use crate::jev::{ActorVerdict, JevBatchAnalyzer};
use crate::sanitizer::ActorStateSummary;
use crate::store::{BanDecision, DecisionSource, DecisionStore};
use crate::tailer::AccessLogEvent;
use crate::window::{L1Disposition, SlidingWindowEngine};
use anyhow::Result;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{info, warn};

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
        let mut pipeline = SecurityPipeline::new(store, window, jev, firewall)?;
        pipeline.trusted_proxies = Arc::new(self.config.daemon.trusted_proxies);
        Ok(pipeline)
    }
}

/// Coordinates the 3-stage pipeline:
/// 1. Ingests `AccessLogEvent` through `SlidingWindowEngine` (skipping already-banned IPs and benign static hits).
/// 2. Records instant L1 bans (volumetric floods or cached Jev signatures) and enforces OS firewall rules.
/// 3. Flushes suspicious IP windows in batches to `JevBatchAnalyzer` (`/v1/systemone`),
///    updating `DecisionStore`, enforcing OS firewall rules, and caching high-confidence attack signatures.
enum IngestionMessage {
    Event(AccessLogEvent),
    Barrier(tokio::sync::oneshot::Sender<()>),
}

pub struct EventPermit(tokio::sync::mpsc::OwnedPermit<IngestionMessage>);
impl EventPermit {
    pub fn send(self, event: AccessLogEvent) {
        self.0.send(IngestionMessage::Event(event));
    }
}

#[derive(Clone)]
pub struct SecurityPipeline {
    pub store: Arc<DecisionStore>,
    pub window: Arc<SlidingWindowEngine>,
    pub jev: Arc<JevBatchAnalyzer>,
    pub firewall: Arc<FirewallBouncer>,
    pub trusted_proxies: Arc<Vec<IpAddr>>,
    enforcement: Arc<Mutex<()>>,
    pending: Arc<tokio::sync::Mutex<VecDeque<ActorStateSummary>>>,
    ingestion: Option<tokio::sync::mpsc::Sender<IngestionMessage>>,
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
    ) -> Result<Self> {
        firewall.init_backend()?;
        let mut pipeline = Self {
            store,
            window,
            jev,
            firewall,
            trusted_proxies: Arc::new(Vec::new()),
            enforcement: Arc::new(Mutex::new(())),
            pending: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            ingestion: None,
        };
        pipeline.reconcile_firewall()?;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
        // The worker owns no sender, so dropping all public pipelines closes it.
        let worker = pipeline.clone();
        std::thread::Builder::new()
            .name("custos-ingestion".into())
            .spawn(move || {
                while let Some(message) = rx.blocking_recv() {
                    match message {
                        IngestionMessage::Event(event) => {
                            if let Err(error) = worker.process_event(&event) {
                                warn!(%error, "Failed to ingest queued request");
                            }
                        }
                        IngestionMessage::Barrier(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })?;
        pipeline.ingestion = Some(tx);
        Ok(pipeline)
    }

    pub(crate) fn enforcement_guard(&self) -> Result<MutexGuard<'_, ()>> {
        self.enforcement
            .lock()
            .map_err(|_| anyhow::anyhow!("Enforcement lock poisoned"))
    }

    /// Reserve bounded ingestion capacity before executing an HTTP handler.
    pub fn reserve_event(&self) -> Result<EventPermit> {
        self.ingestion
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ingestion worker unavailable"))?
            .clone()
            .try_reserve_owned()
            .map(EventPermit)
            .map_err(|e| anyhow::anyhow!("Ingestion unavailable: {e}"))
    }

    pub async fn submit_event(&self, event: AccessLogEvent) -> Result<()> {
        self.ingestion
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ingestion unavailable"))?
            .send(IngestionMessage::Event(event))
            .await
            .map_err(|e| anyhow::anyhow!("Ingestion worker stopped: {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_ban(
        &self,
        ip: IpAddr,
        threat: String,
        source: DecisionSource,
        noul: f64,
        confidence: f64,
        reason: String,
        ttl: Option<u64>,
    ) -> Result<BanDecision> {
        let _guard = self.enforcement_guard()?;
        let decision = self
            .store
            .upsert_ban(ip, threat, source, noul, confidence, reason, ttl)?;
        self.firewall.ban_ip(ip, remaining_ttl(&decision))?;
        Ok(decision)
    }

    pub fn remove_ban(&self, ip: &IpAddr) -> Result<bool> {
        let _guard = self.enforcement_guard()?;
        let removed = self.store.remove_ban(ip)?;
        // Retry an earlier failed removal as well as a newly removed decision.
        if removed || self.store.sweep_expired().contains(ip) {
            self.firewall.unban_ip(*ip)?;
            self.store.acknowledge_cleanup(ip)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Retry desired enforcement and retain failed cleanup obligations for the next pass.
    pub fn reconcile_firewall(&self) -> Result<()> {
        let _guard = self.enforcement_guard()?;
        let mut failures = Vec::new();
        for ip in self.store.sweep_expired() {
            if self.store.check_ip(&ip).is_none() {
                match self
                    .firewall
                    .unban_ip(ip)
                    .and_then(|_| self.store.acknowledge_cleanup(&ip).map(|_| ()))
                {
                    Ok(()) => {}
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }
        let entries: Vec<_> = self
            .store
            .list_active()
            .iter()
            .map(|d| (d.ip, remaining_ttl(d)))
            .collect();
        if let Err(error) = self.firewall.ban_ips_batch(&entries) {
            failures.push(error.to_string());
        }
        if !failures.is_empty() {
            anyhow::bail!("Firewall reconciliation failed: {}", failures.join("; "));
        }
        Ok(())
    }

    pub fn process_event(&self, ev: &AccessLogEvent) -> Result<()> {
        if self.store.check_ip(&ev.client_ip).is_some() {
            return Ok(());
        }
        match self.window.ingest(ev) {
            L1Disposition::IgnoredStatic | L1Disposition::Buffered { .. } => {}
            L1Disposition::CapacityExceeded => anyhow::bail!("IP window capacity reached"),
            L1Disposition::InstantBan {
                threat_class,
                reason,
            } => {
                let source = if reason.contains("cached Jev signature") {
                    DecisionSource::L1AutoSignature
                } else {
                    DecisionSource::L1Deterministic
                };
                self.record_ban(ev.client_ip, threat_class, source, 1.0, 1.0, reason, None)?;
            }
        }
        Ok(())
    }

    fn apply_verdicts(&self, verdicts: &[ActorVerdict]) -> Result<()> {
        for v in verdicts.iter().filter(|v| v.should_ban) {
            if self.store.check_ip(&v.client_ip).is_none() {
                self.record_ban(
                    v.client_ip,
                    v.threat_class.clone(),
                    DecisionSource::JevSystemOne,
                    v.noul_malicious_prob,
                    v.choice_confidence,
                    format!(
                        "Jev verdict: {} (noul={:.2}, confidence={:.2})",
                        v.threat_class, v.noul_malicious_prob, v.choice_confidence
                    ),
                    None,
                )?;
            } else {
                // A prior attempt may have persisted the ban before enforcement failed.
                self.reconcile_firewall()?;
            }
            if let Some((method, path)) = proven_signature_for_verdict(v) {
                self.window
                    .register_auto_signature(&method, &path, &v.threat_class);
                info!(%method, %path, "Cached validated exploit signature");
            }
        }
        Ok(())
    }

    /// Acknowledge each successful batch independently; retain failed actors for retry.
    pub async fn flush_and_analyze(&self, force_all: bool) -> Result<Vec<ActorVerdict>> {
        if force_all {
            let (done, drained) = tokio::sync::oneshot::channel();
            self.ingestion
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Ingestion unavailable"))?
                .send(IngestionMessage::Barrier(done))
                .await?;
            drained.await?;
        }
        let mut pending = self.pending.lock().await;
        let mut completed = Vec::new();
        let mut drained_current_windows = false;
        loop {
            if pending.is_empty() {
                if drained_current_windows {
                    break;
                }
                pending.extend(self.window.drain_suspicious_summaries(force_all));
                drained_current_windows = true;
                if pending.is_empty() {
                    break;
                }
            }
            let chunk: Vec<_> = pending
                .iter()
                .take(self.jev.max_actors_per_batch())
                .cloned()
                .collect();
            let result = self.jev.analyze_summaries(&chunk).await;
            let verdicts = match result {
                Ok(verdicts) => verdicts,
                Err(error) if completed.is_empty() => return Err(error),
                Err(error) => {
                    warn!(%error, "Retained failed analysis batch for retry");
                    break;
                }
            };
            let worker = self.clone();
            let apply = verdicts.clone();
            let result = tokio::task::spawn_blocking(move || worker.apply_verdicts(&apply)).await?;
            if let Err(error) = result {
                if completed.is_empty() {
                    return Err(error);
                }
                warn!(%error, "Retained unapplied verdict batch for retry");
                break;
            }
            pending.drain(..chunk.len());
            completed.extend(verdicts);
        }
        Ok(completed)
    }
}

fn remaining_ttl(decision: &BanDecision) -> u64 {
    (decision.expires_at - chrono::Utc::now())
        .num_seconds()
        .max(1) as u64
}

/// Only intrinsic exploit paths are eligible. Actor confidence is not evidence that
/// an ordinary route, query string, or arbitrary first sample is malicious.
pub fn proven_signature_for_verdict(v: &ActorVerdict) -> Option<(String, String)> {
    if !v.should_ban || !v.recommend_auto_signature {
        return None;
    }
    for sample in &v.sample_requests {
        let mut parts = sample.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;
        if !matches!(method, "GET" | "POST" | "HEAD") || path.contains('?') {
            continue;
        }
        // Deliberately do not learn normal auth/admin or application routes.
        if matches!(
            path,
            "/.env"
                | "/.git/config"
                | "/.git/HEAD"
                | "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        ) {
            return Some((method.to_string(), path.to_string()));
        }
    }
    None
}
