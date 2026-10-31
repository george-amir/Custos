pub mod analysis;
pub mod bouncer_api;
mod cleanup;
pub mod config;
pub mod firewall;
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
        let mut pipeline = SecurityPipeline::new_with_limits(store, window, jev, firewall, limits)?;
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
        limits.validate()?;
        firewall.init_backend()?;
        let mut pipeline = Self {
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
        let result = self.store.upsert_ban_with_kernel(
            ip,
            threat,
            source,
            noul,
            confidence,
            reason,
            ttl,
            self.firewall.is_enabled() && !self.firewall.is_dry_run(),
        );
        if result.is_err() && self.store.is_at_capacity() {
            self.request_cleanup();
        }
        let decision = result?;
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
        let active = self.store.list_active();
        for group in active.chunks(self.firewall.enforcement_chunk_size()) {
            let _guard = self.enforcement_guard()?;
            let entries: Vec<_> = group
                .iter()
                .filter_map(|old| self.store.check_ip(&old.ip))
                .map(|d| (d.ip, remaining_ttl(&d)))
                .collect();
            if self.firewall.is_enabled() && !self.firewall.is_dry_run() {
                self.store.require_kernel_cleanup(
                    &entries.iter().map(|(ip, _)| *ip).collect::<Vec<_>>(),
                )?;
            }
            if let Err(error) = self.firewall.ban_ips_batch(&entries) {
                failures.push(error.to_string());
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
        if self.store.check_ip(&ev.client_ip).is_some() {
            return Ok(());
        }
        match self.window.ingest_bounded(ev, oversized) {
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
                self.record_ban(ev.client_ip, threat_class, source, 1.0, 1.0, reason, None)?;
            }
        }
        Ok(())
    }

    fn apply_verdict(&self, v: &ActorVerdict, expires: std::time::Instant) -> Result<()> {
        if !v.should_ban {
            return Ok(());
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
            self.record_ban_locked(
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
        }
        Ok(())
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
            for (id, verdict) in ids.iter().zip(verdicts) {
                let item = pending
                    .items
                    .iter_mut()
                    .find(|item| item.id == *id)
                    .expect("selected actor");
                if item.expires <= std::time::Instant::now() {
                    continue;
                }
                item.verdict = Some(verdict.clone());
                apply_ids.push(*id);
                apply.push((verdict, item.expires));
            }
            let worker = self.clone();
            let permit = work_permit.take().expect("analysis work permit");
            let (results, permit) = tokio::task::spawn_blocking(move || {
                let results = apply
                    .into_iter()
                    .map(|(verdict, expires)| {
                        let result = if std::time::Instant::now() >= expires {
                            Err(anyhow::anyhow!(
                                "Analysis evidence expired before application"
                            ))
                        } else {
                            worker.apply_verdict(&verdict, expires)
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
