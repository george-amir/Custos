pub mod bouncer_api;
pub mod config;
pub mod firewall;
pub mod jev;
pub mod sanitizer;
pub mod store;
pub mod tailer;
pub mod window;

use crate::firewall::FirewallBouncer;
use crate::jev::{ActorVerdict, JevBatchAnalyzer};
use crate::store::{DecisionSource, DecisionStore};
use crate::tailer::AccessLogEvent;
use crate::window::{L1Disposition, SlidingWindowEngine};
use anyhow::Result;
use std::sync::Arc;
use tracing::info;

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

                if v.recommend_auto_signature {
                    if let Some((method, path)) = extract_first_method_and_path(&v.sample_requests)
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
