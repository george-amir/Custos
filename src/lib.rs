pub mod analysis;
pub mod bouncer_api;
mod cleanup;
pub mod config;
pub mod crawlers;
pub mod evidence;
pub mod firewall;
pub mod health;
pub mod hub;
#[allow(clippy::all)]
pub mod hub_proto;
pub mod jev;
pub mod limits;
pub mod middleware;
pub mod sanitizer;
pub mod service;
pub mod store;
pub mod tailer;
pub mod update;
pub mod window;
pub mod windows_service;

use crate::config::{AppConfig, DecisionCapacityPolicy, FirewallConfig, JevConfig, WindowConfig};
use crate::firewall::{FirewallBackend, FirewallBouncer};
use crate::jev::{ActorVerdict, JevBatchAnalyzer};
use crate::store::{BanDecision, DecisionSource, DecisionStore};
use crate::tailer::AccessLogEvent;
use crate::window::{L1Disposition, SlidingWindowEngine};
use anyhow::Result;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{info, warn};

/// Resolve existing ancestors even when the state file has not been created yet.
/// Reject ambiguous missing-parent traversal instead of risking journal replacement.
fn storage_path_identity(path: &std::path::Path) -> Result<PathBuf> {
    let mut existing = std::path::absolute(path)?;
    let mut missing = Vec::new();
    while !existing.try_exists()? {
        missing.push(
            existing
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Storage path requires an unambiguous file name"))?
                .to_owned(),
        );
        anyhow::ensure!(existing.pop(), "Storage path has no existing ancestor");
    }
    let mut resolved = existing.canonicalize()?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    // Windows and default macOS volumes compare file names without case. Being
    // conservative also rejects case-only aliases on case-sensitive volumes.
    #[cfg(any(windows, target_os = "macos"))]
    let resolved = PathBuf::from(resolved.to_string_lossy().to_lowercase());
    Ok(resolved)
}

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
        self.config.memory.validate()?;
        self.config.window.validate()?;
        let limits = self.config.memory;
        let use_mock = self.mock_jev || self.config.jev.api_key.trim().is_empty();
        let store = Arc::new(DecisionStore::open_with_limit(
            self.config.daemon.decisions_file,
            self.config.daemon.default_ban_ttl_secs,
            limits.max_decisions,
        )?);
        let window = Arc::new(SlidingWindowEngine::with_limits(
            self.config.window,
            limits.clone(),
        ));
        let jev = Arc::new(JevBatchAnalyzer::with_response_limit(
            self.config.jev,
            use_mock,
            limits.max_provider_response_bytes,
        )?);
        let firewall = Arc::new(FirewallBouncer::new(self.config.firewall));
        let mut pipeline = SecurityPipeline::new_with_crawlers(
            store,
            window,
            jev,
            firewall,
            limits,
            self.config.crawlers,
        )?;
        pipeline.trusted_proxies = Arc::new(self.config.daemon.trusted_proxies);
        pipeline.on_decision_capacity = self.config.daemon.on_decision_capacity;
        Ok(pipeline)
    }
}

/// Coordinates the 3-stage pipeline:
/// 1. Ingests `AccessLogEvent` through `SlidingWindowEngine` (skipping already-banned IPs and benign static hits).
/// 2. Applies short HTTP-only volume throttles; records cached-signature or explicitly opted-in strict L1 bans.
/// 3. Flushes suspicious IP windows in batches to `JevBatchAnalyzer` (`/v1/systemone`),
///    updating `DecisionStore`, enforcing OS firewall rules, and caching high-confidence attack signatures.
enum IngestionMessage {
    Event(AccessLogEvent, bool, tokio::sync::OwnedSemaphorePermit),
    Barrier(tokio::sync::oneshot::Sender<()>),
}

pub struct EventPermit(
    tokio::sync::mpsc::OwnedPermit<IngestionMessage>,
    tokio::sync::OwnedSemaphorePermit,
);
impl EventPermit {
    pub fn send(self, event: AccessLogEvent) {
        let (event, oversized) = tailer::bound_event(event);
        self.0
            .send(IngestionMessage::Event(event, oversized, self.1));
    }
}

#[derive(Clone)]
pub struct SecurityPipeline {
    pub crawlers: Arc<crawlers::CrawlerRegistry>,
    pub health: Arc<health::PipelineHealth>,
    crawler_mutation: Arc<Mutex<()>>,
    pub store: Arc<DecisionStore>,
    pub window: Arc<SlidingWindowEngine>,
    pub jev: Arc<JevBatchAnalyzer>,
    pub firewall: Arc<FirewallBouncer>,
    pub trusted_proxies: Arc<Vec<IpAddr>>,
    pub on_decision_capacity: DecisionCapacityPolicy,
    enforcement: Arc<Mutex<()>>,
    cleanup: Option<cleanup::CleanupWorker>,
    pub capacity_allowed: Arc<std::sync::atomic::AtomicU64>,
    pub capacity_blocked: Arc<std::sync::atomic::AtomicU64>,
    queue_budget: Arc<tokio::sync::Semaphore>,
    pub queue_rejected: Arc<std::sync::atomic::AtomicU64>,
    pending: Arc<tokio::sync::Mutex<analysis::PendingQueue>>,
    limits: Arc<limits::MemoryLimits>,
    pub analysis_metrics: Arc<analysis::AnalysisMetrics>,
    analysis_work: Arc<tokio::sync::Semaphore>,
    ingestion: Option<tokio::sync::mpsc::Sender<IngestionMessage>>,
}

impl SecurityPipeline {
    /// Policy is durable before cleanup. Failed removals remain in the ban ledger for retry.
    pub fn set_crawler_policy(&self, id: &str, policy: crawlers::CrawlerPolicy) -> Result<usize> {
        self.set_crawler_policies(&[id.to_owned()], policy)
    }

    pub fn set_crawler_policies(
        &self,
        ids: &[String],
        policy: crawlers::CrawlerPolicy,
    ) -> Result<usize> {
        let _operation = self
            .crawler_mutation
            .try_lock()
            .map_err(|_| anyhow::anyhow!("Crawler policy update already in progress"))?;
        {
            let _guard = self.enforcement_guard()?;
            self.crawlers.set_policies(ids, policy)?;
        }
        let mut removed = 0;
        let mut errors = Vec::new();
        if policy != crawlers::CrawlerPolicy::Block {
            let ips = self.store.active_ips();
            for group in ips.chunks(self.firewall.cleanup_chunk_size()) {
                let mut cleanup = Vec::new();
                {
                    let _guard = self.enforcement_guard()?;
                    for ip in group {
                        let Some(decision) = self.store.check_ip(ip) else {
                            continue;
                        };
                        if self
                            .crawlers
                            .identify(*ip)
                            .is_none_or(|identity| !ids.contains(&identity.id))
                        {
                            continue;
                        }
                        let relaxable = decision.source == DecisionSource::CrawlerPolicy
                            || (policy == crawlers::CrawlerPolicy::Allow
                                && matches!(
                                    decision.source,
                                    DecisionSource::JevSystemOne | DecisionSource::L1Deterministic
                                )
                                && matches!(
                                    decision.threat_class.as_str(),
                                    "vulnerability_scanner" | "api_enumeration_idor"
                                )
                                && !decision.evidence.as_ref().is_some_and(|e| e.has_exploit()));
                        if relaxable {
                            match self.store.remove_ban(ip) {
                                Ok(true) => cleanup.push(*ip),
                                Ok(false) => {}
                                Err(error) => {
                                    if errors.len() < 4 {
                                        errors.push(error.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                if !cleanup.is_empty() {
                    match cleanup::cleanup_group(
                        &self.store,
                        &self.firewall,
                        &self.enforcement,
                        &cleanup,
                    ) {
                        Ok(()) => removed += cleanup.len(),
                        Err(error) => {
                            if errors.len() < 4 {
                                errors.push(error.to_string());
                            }
                        }
                    }
                }
            }
        }
        if !errors.is_empty() {
            self.request_cleanup();
        }
        anyhow::ensure!(
            errors.is_empty(),
            "Crawler policy saved, but cleanup is pending: {}",
            errors.first().unwrap_or(&String::new())
        );
        Ok(removed)
    }
    pub fn builder() -> CustosBuilder {
        CustosBuilder::new()
    }

    pub fn new(
        store: Arc<DecisionStore>,
        window: Arc<SlidingWindowEngine>,
        jev: Arc<JevBatchAnalyzer>,
        firewall: Arc<FirewallBouncer>,
    ) -> Result<Self> {
        Self::new_with_limits(
            store,
            window,
            jev,
            firewall,
            limits::MemoryLimits::default(),
        )
    }

    pub fn new_with_limits(
        store: Arc<DecisionStore>,
        window: Arc<SlidingWindowEngine>,
        jev: Arc<JevBatchAnalyzer>,
        firewall: Arc<FirewallBouncer>,
        limits: limits::MemoryLimits,
    ) -> Result<Self> {
        Self::new_with_crawlers(store, window, jev, firewall, limits, Default::default())
    }

    pub fn new_with_crawlers(
        store: Arc<DecisionStore>,
        window: Arc<SlidingWindowEngine>,
        jev: Arc<JevBatchAnalyzer>,
        firewall: Arc<FirewallBouncer>,
        limits: limits::MemoryLimits,
        config: crawlers::CrawlerConfig,
    ) -> Result<Self> {
        let path = store.persistence_path().with_extension("crawlers.json");
        anyhow::ensure!(
            storage_path_identity(config.state_file.as_ref().unwrap_or(&path))?
                != storage_path_identity(store.persistence_path())?,
            "Crawler state must not overwrite the decision journal"
        );
        let crawlers = Arc::new(crawlers::CrawlerRegistry::open(config, Some(path))?);
        limits.validate()?;
        firewall.init_backend()?;
        let mut pipeline = Self {
            crawlers,
            health: Arc::new(health::PipelineHealth::default()),
            crawler_mutation: Arc::new(Mutex::new(())),
            store,
            window,
            jev,
            firewall,
            trusted_proxies: Arc::new(Vec::new()),
            on_decision_capacity: DecisionCapacityPolicy::default(),
            enforcement: Arc::new(Mutex::new(())),
            cleanup: None,
            capacity_allowed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            capacity_blocked: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            queue_budget: Arc::new(tokio::sync::Semaphore::new(limits.event_queue_bytes)),
            queue_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending: Arc::new(tokio::sync::Mutex::new(analysis::PendingQueue::default())),
            limits: Arc::new(limits.clone()),
            analysis_metrics: Arc::new(analysis::AnalysisMetrics::default()),
            analysis_work: Arc::new(tokio::sync::Semaphore::new(1)),
            ingestion: None,
        };
        pipeline.reconcile_firewall()?;
        pipeline.firewall.sample_counters();
        pipeline.cleanup = Some(cleanup::CleanupWorker::start(
            pipeline.store.clone(),
            pipeline.firewall.clone(),
            pipeline.enforcement.clone(),
        )?);
        let (tx, mut rx) = tokio::sync::mpsc::channel(limits.event_queue_capacity);
        // The worker owns no sender, so dropping all public pipelines closes it.
        let worker = pipeline.clone();
        std::thread::Builder::new()
            .name("custos-ingestion".into())
            .spawn(move || {
                while let Some(message) = rx.blocking_recv() {
                    match message {
                        IngestionMessage::Event(event, oversized, _memory) => {
                            if let Err(error) = worker.process_event_bounded(&event, oversized)
                                && !error.is::<store::DecisionCapacityExceeded>()
                            {
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
        if !self.capacity_allows_traffic() {
            anyhow::bail!("Decision capacity reached");
        }
        let result = (|| {
            let memory = self
                .queue_budget
                .clone()
                .try_acquire_many_owned(limits::EVENT_RESERVATION_BYTES as u32)?;
            let slot = self
                .ingestion
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Ingestion unavailable"))?
                .clone()
                .try_reserve_owned()?;
            Ok(EventPermit(slot, memory))
        })();
        if result.is_err() {
            self.queue_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Capacity policy is independent of ingestion and request concurrency limits.
    pub fn capacity_allows_traffic(&self) -> bool {
        if !self.store.is_at_capacity() {
            return true;
        }
        self.request_cleanup();
        let allowed = self.on_decision_capacity == DecisionCapacityPolicy::EnforceExisting;
        let metric = if allowed {
            &self.capacity_allowed
        } else {
            &self.capacity_blocked
        };
        metric.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        allowed
    }

    pub fn request_cleanup(&self) {
        if let Some(worker) = &self.cleanup {
            worker.request();
        }
    }

    /// Nonblocking admission: overload returns an error instead of retaining waiting producers.
    pub async fn submit_event(&self, event: AccessLogEvent) -> Result<()> {
        self.reserve_event()?.send(event);
        Ok(())
    }

    /// File readers backpressure on the original file, holding one bounded read batch.
    pub(crate) async fn submit_log_event(&self, event: AccessLogEvent) -> Result<()> {
        let (event, oversized) = tailer::bound_event(event);
        let memory = self
            .queue_budget
            .clone()
            .acquire_many_owned(limits::EVENT_RESERVATION_BYTES as u32)
            .await?;
        self.ingestion
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ingestion unavailable"))?
            .send(IngestionMessage::Event(event, oversized, memory))
            .await?;
        Ok(())
    }

    pub fn available_queue_bytes(&self) -> usize {
        self.queue_budget.available_permits()
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
        // A full ledger can reject new identities without waiting behind a slow
        // firewall command. upsert_ban rechecks under its mutation lock.
        if let Err(error) = self.store.admit(&ip) {
            self.request_cleanup();
            return Err(error);
        }
        let _guard = self.enforcement_guard()?;
        self.record_ban_locked(ip, threat, source, noul, confidence, reason, ttl)
    }

    /// Caller holds enforcement_guard across persistence and the OS command.
    #[allow(clippy::too_many_arguments)]
    fn record_ban_locked(
        &self,
        ip: IpAddr,
        threat: String,
        source: DecisionSource,
        noul: f64,
        confidence: f64,
        reason: String,
        ttl: Option<u64>,
    ) -> Result<BanDecision> {
        self.record_ban_with_evidence_locked(
            ip, threat, source, noul, confidence, reason, ttl, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_ban_with_evidence_locked(
        &self,
        ip: IpAddr,
        threat: String,
        source: DecisionSource,
        noul: f64,
        confidence: f64,
        reason: String,
        ttl: Option<u64>,
        evidence: Option<evidence::DecisionEvidence>,
    ) -> Result<BanDecision> {
        let was_active = self.store.check_ip(&ip).is_some();
        let result = self.store.upsert_ban_with_context(
            ip,
            threat,
            source,
            noul,
            confidence,
            reason,
            ttl,
            self.firewall.is_enabled() && !self.firewall.is_dry_run(),
            evidence,
            self.crawlers.identify(ip),
        );
        if result.is_err() && self.store.is_at_capacity() {
            self.request_cleanup();
        }
        let decision = result?;
        if was_active {
            &self.health.ban_updates
        } else {
            &self.health.new_bans
        }
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Err(error) = self.firewall.ban_ip(ip, remaining_ttl(&decision)) {
            if let Some(worker) = &self.cleanup {
                worker.retry_enforcement();
            }
            return Err(error);
        }
        Ok(decision)
    }

    pub fn remove_ban(&self, ip: &IpAddr) -> Result<bool> {
        let _guard = self.enforcement_guard()?;
        let removed = self.store.remove_ban(ip)?;
        // Retry an earlier failed removal as well as a newly removed decision.
        if removed || self.store.sweep_expired().contains(ip) {
            if self.store.cleanup_requires_kernel(ip) {
                anyhow::ensure!(
                    self.firewall.is_enabled() && !self.firewall.is_dry_run(),
                    "Live or legacy kernel cleanup retained: enable live firewall enforcement to confirm removal"
                );
                self.firewall.unban_ip(*ip)?;
            }
            self.store.acknowledge_cleanup(ip)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Retry desired enforcement and retain failed cleanup obligations for the next pass.
    pub fn reconcile_firewall(&self) -> Result<()> {
        let mut failures = Vec::new();
        for group in self
            .store
            .sweep_expired()
            .chunks(self.firewall.cleanup_chunk_size())
        {
            if let Err(error) =
                cleanup::cleanup_group(&self.store, &self.firewall, &self.enforcement, group)
            {
                failures.push(error.to_string());
            }
        }
        let active = self.store.active_ips();
        for group in active.chunks(self.firewall.enforcement_chunk_size()) {
            let _guard = self.enforcement_guard()?;
            let entries: Vec<_> = group
                .iter()
                .filter_map(|ip| self.store.check_ip(ip))
                .map(|d| (d.ip, remaining_ttl(&d)))
                .collect();
            if self.firewall.is_enabled() && !self.firewall.is_dry_run() {
                self.store.require_kernel_cleanup(
                    &entries.iter().map(|(ip, _)| *ip).collect::<Vec<_>>(),
                )?;
            }
            if let Err(error) = self.firewall.ban_ips_batch(&entries) {
                failures.push(error.to_string());
            } else {
                self.firewall
                    .metrics
                    .ban_refreshes
                    .fetch_add(entries.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if !failures.is_empty() {
            anyhow::bail!("Firewall reconciliation failed: {}", failures.join("; "));
        }
        Ok(())
    }

    pub fn process_event(&self, ev: &AccessLogEvent) -> Result<()> {
        self.process_event_bounded(ev, false)
    }

    fn process_event_bounded(&self, ev: &AccessLogEvent, oversized: bool) -> Result<()> {
        self.health
            .events_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.store.check_ip(&ev.client_ip).is_some() {
            self.health
                .already_banned
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        let mut identity = self.crawlers.identify(ev.client_ip);
        if identity
            .as_ref()
            .is_some_and(|identity| identity.policy == crawlers::CrawlerPolicy::Block)
        {
            let _guard = self.enforcement_guard()?;
            // A policy may change while this event waits for kernel enforcement.
            identity = self.crawlers.identify(ev.client_ip);
            if identity
                .as_ref()
                .is_some_and(|identity| identity.policy == crawlers::CrawlerPolicy::Block)
            {
                self.record_ban_with_evidence_locked(
                    ev.client_ip,
                    "crawler_policy".into(),
                    DecisionSource::CrawlerPolicy,
                    0.0,
                    0.0,
                    format!(
                        "Operator blocked verified crawler {}",
                        identity.as_ref().unwrap().id
                    ),
                    None,
                    Some(evidence::DecisionEvidence::from_event(
                        ev,
                        "crawler_policy_block",
                    )),
                )?;
                return Ok(());
            }
        }
        let allowed =
            identity.is_some_and(|identity| identity.policy == crawlers::CrawlerPolicy::Allow);
        if allowed {
            self.health
                .observed_crawler_allowed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        match self.window.ingest_verified_crawler(ev, oversized, allowed) {
            L1Disposition::IgnoredStatic
            | L1Disposition::Buffered { .. }
            | L1Disposition::Throttled { .. } => {}
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
                let _guard = self.enforcement_guard()?;
                let signal = if source == DecisionSource::L1AutoSignature {
                    "cached_exploit_signature"
                } else {
                    "strict_volume_opt_in"
                };
                self.record_ban_with_evidence_locked(
                    ev.client_ip,
                    threat_class,
                    source,
                    1.0,
                    1.0,
                    reason,
                    None,
                    Some(evidence::DecisionEvidence::from_event(ev, signal)),
                )?;
            }
        }
        Ok(())
    }

    fn apply_verdict(
        &self,
        v: &ActorVerdict,
        expires: std::time::Instant,
        evidence: evidence::DecisionEvidence,
    ) -> Result<bool> {
        let _policy_guard = self
            .crawler_mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("Crawler mutation lock poisoned"))?;
        if !v.should_ban {
            return Ok(false);
        }
        if self
            .crawlers
            .identify(v.client_ip)
            .is_some_and(|identity| identity.policy == crawlers::CrawlerPolicy::Allow)
            && !evidence.has_exploit()
        {
            return Ok(false);
        }
        anyhow::ensure!(
            std::time::Instant::now() < expires,
            "Analysis evidence expired before application"
        );
        if let Some((method, path)) = proven_signature_for_verdict(v) {
            self.window
                .register_auto_signature(&method, &path, &v.threat_class);
            info!(%method, %path, "Cached validated exploit signature");
        }
        if self.store.check_ip(&v.client_ip).is_none()
            && let Err(error) = self.store.admit(&v.client_ip)
        {
            self.request_cleanup();
            return Err(error);
        }
        let _guard = self.enforcement_guard()?;
        anyhow::ensure!(
            std::time::Instant::now() < expires,
            "Analysis evidence expired while waiting for enforcement"
        );
        if let Some(decision) = self.store.check_ip(&v.client_ip) {
            if self.firewall.is_enabled() && !self.firewall.is_dry_run() {
                self.store.require_kernel_cleanup(&[v.client_ip])?;
            }
            if let Err(error) = self.firewall.ban_ip(v.client_ip, remaining_ttl(&decision)) {
                if let Some(worker) = &self.cleanup {
                    worker.retry_enforcement();
                }
                return Err(error);
            }
        } else {
            self.record_ban_with_evidence_locked(
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
                Some(evidence),
            )?;
        }
        Ok(true)
    }

    /// Analyze bounded fresh and retry work fairly. Forced flushing bypasses retry
    /// delays, but never the age, count, byte, or per-call work limits.
    pub async fn flush_and_analyze(&self, force_all: bool) -> Result<Vec<ActorVerdict>> {
        let mut work_permit = Some(
            self.analysis_work
                .clone()
                .try_acquire_owned()
                .map_err(|_| anyhow::anyhow!("Analysis application still in progress"))?,
        );
        let mut pending = self
            .pending
            .try_lock()
            .map_err(|_| anyhow::anyhow!("Analysis flush already in progress"))?;
        if force_all {
            let (done, drained) = tokio::sync::oneshot::channel();
            self.ingestion
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Ingestion unavailable"))?
                .send(IngestionMessage::Barrier(done))
                .await?;
            drained.await?;
        }
        pending.expire(&self.analysis_metrics);
        for (summary, observed) in self.window.drain_suspicious_work(force_all) {
            pending.admit(summary, observed, &self.limits, &self.analysis_metrics);
        }
        pending.publish(&self.analysis_metrics);
        let mut completed = Vec::new();
        let mut seen = HashSet::new();
        let mut first_error = None;
        for _ in 0..self.limits.analysis_batches_per_flush {
            let ids = pending.select(&seen, self.jev.max_actors_per_batch(), force_all);
            if ids.is_empty() {
                break;
            }
            seen.extend(ids.iter().copied());
            let cached = pending
                .items
                .iter()
                .find(|item| item.id == ids[0])
                .and_then(|item| item.verdict.clone());
            let verdicts = if let Some(verdict) = cached {
                vec![verdict]
            } else {
                let chunk: Vec<_> = ids
                    .iter()
                    .enumerate()
                    .map(|(idx, id)| {
                        let mut summary = pending
                            .items
                            .iter()
                            .find(|item| item.id == *id)
                            .expect("selected actor")
                            .summary
                            .clone();
                        // Every outgoing batch gets unique keys, including merged drains.
                        summary.actor_key = format!("actor_{idx}");
                        summary
                    })
                    .collect();
                match self.jev.analyze_summaries(&chunk).await {
                    Ok(verdicts) => verdicts,
                    Err(error) => {
                        pending.retry(&ids, &self.limits, &self.analysis_metrics);
                        first_error.get_or_insert(error);
                        continue;
                    }
                }
            };
            let mut apply_ids = Vec::new();
            let mut apply = Vec::new();
            for (id, mut verdict) in ids.iter().zip(verdicts) {
                let item = pending
                    .items
                    .iter_mut()
                    .find(|item| item.id == *id)
                    .expect("selected actor");
                if item.expires <= std::time::Instant::now() {
                    continue;
                }
                let evidence = evidence::DecisionEvidence::from_summary(&item.summary);
                if self
                    .crawlers
                    .identify(verdict.client_ip)
                    .is_some_and(|identity| identity.policy == crawlers::CrawlerPolicy::Allow)
                    && !evidence.has_exploit()
                {
                    verdict.should_ban = false;
                    verdict.recommend_auto_signature = false;
                }
                item.verdict = Some(verdict.clone());
                apply_ids.push(*id);
                apply.push((verdict, item.expires, evidence));
            }
            let worker = self.clone();
            let permit = work_permit.take().expect("analysis work permit");
            let (results, permit) = tokio::task::spawn_blocking(move || {
                let results = apply
                    .into_iter()
                    .map(|(mut verdict, expires, evidence)| {
                        let result = if std::time::Instant::now() >= expires {
                            Err(anyhow::anyhow!(
                                "Analysis evidence expired before application"
                            ))
                        } else {
                            worker
                                .apply_verdict(&verdict, expires, evidence)
                                .map(|applied| {
                                    if !applied {
                                        verdict.should_ban = false;
                                        verdict.recommend_auto_signature = false;
                                    }
                                })
                        };
                        (verdict, result)
                    })
                    .collect::<Vec<_>>();
                (results, permit)
            })
            .await?;
            work_permit = Some(permit);
            for (id, (verdict, result)) in apply_ids.into_iter().zip(results) {
                match result {
                    Ok(()) => {
                        let latency = self
                            .limits
                            .analysis_ttl_secs
                            .saturating_mul(1000)
                            .saturating_sub(
                                pending
                                    .items
                                    .iter()
                                    .find(|item| item.id == id)
                                    .map(|item| {
                                        item.expires
                                            .saturating_duration_since(std::time::Instant::now())
                                            .as_millis()
                                            as u64
                                    })
                                    .unwrap_or(0),
                            );
                        self.health
                            .analysis_completed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.health
                            .analysis_latency_ms_total
                            .fetch_add(latency, std::sync::atomic::Ordering::Relaxed);
                        self.health
                            .analysis_latency_ms_max
                            .fetch_max(latency, std::sync::atomic::Ordering::Relaxed);
                        pending.remove(id);
                        completed.push(verdict);
                    }
                    Err(error) => {
                        // A persisted ban is now durable enforcement work. The background
                        // worker retries it even if its original analysis evidence expires.
                        if verdict.should_ban && self.store.check_ip(&verdict.client_ip).is_some() {
                            pending.remove(id);
                            warn!(%error, ip=%verdict.client_ip, "Durable ban awaits firewall retry");
                            completed.push(verdict);
                        } else {
                            pending.retry(&[id], &self.limits, &self.analysis_metrics);
                            first_error.get_or_insert(error);
                        }
                    }
                }
            }
            pending.expire(&self.analysis_metrics);
            pending.publish(&self.analysis_metrics);
        }
        pending.expire(&self.analysis_metrics);
        pending.publish(&self.analysis_metrics);
        if completed.is_empty() {
            if let Some(error) = first_error {
                return Err(error);
            }
            if !pending.items.is_empty() {
                anyhow::bail!("Analysis retries deferred or per-flush work budget reached");
            }
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
