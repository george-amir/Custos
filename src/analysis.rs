//! Bounded, expiring analysis evidence. Durable enforcement lives in DecisionStore.
use crate::{jev::ActorVerdict, limits::MemoryLimits, sanitizer::ActorStateSummary};
use std::{
    collections::{HashSet, VecDeque},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct AnalysisMetrics {
    pub expired: AtomicU64,
    pub capacity_dropped: AtomicU64,
    pub retried: AtomicU64,
    pub pending_actors: AtomicUsize,
    pub pending_bytes: AtomicUsize,
}

pub(crate) struct PendingActor {
    pub id: u64,
    pub summary: ActorStateSummary,
    pub verdict: Option<ActorVerdict>,
    pub expires: Instant,
    pub retry_at: Instant,
    pub attempts: u32,
    bytes: usize,
}

#[derive(Default)]
pub(crate) struct PendingQueue {
    pub items: VecDeque<PendingActor>,
    bytes: usize,
    next_id: u64,
    prefer_retry: bool,
}

impl PendingQueue {
    pub fn publish(&self, metrics: &AnalysisMetrics) {
        metrics
            .pending_actors
            .store(self.items.len(), Ordering::Relaxed);
        metrics.pending_bytes.store(self.bytes, Ordering::Relaxed);
    }

    pub fn expire(&mut self, metrics: &AnalysisMetrics) {
        let now = Instant::now();
        self.items.retain(|item| {
            if item.expires > now {
                return true;
            }
            self.bytes -= item.bytes;
            metrics.expired.fetch_add(1, Ordering::Relaxed);
            false
        });
    }

    pub fn admit(
        &mut self,
        summary: ActorStateSummary,
        observed: Instant,
        limits: &MemoryLimits,
        metrics: &AnalysisMetrics,
    ) {
        let age = observed.elapsed();
        let ttl = Duration::from_secs(limits.analysis_ttl_secs).saturating_sub(age);
        if ttl.is_zero() {
            metrics.expired.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Reserve both evidence and a cached verdict, including owned string/vector
        // capacities and queue overhead. In-flight provider buffers are separately bounded.
        let strings = [
            &summary.l1_suspicion_reasons,
            &summary.user_agents,
            &summary.sample_requests,
        ];
        let heap = summary.actor_key.capacity()
            + summary.client_ip.capacity()
            + strings
                .iter()
                .map(|values| {
                    values.capacity() * std::mem::size_of::<String>()
                        + values.iter().map(String::capacity).sum::<usize>()
                })
                .sum::<usize>();
        let bytes = 2 * (heap + std::mem::size_of::<ActorStateSummary>()) + 512;
        if bytes > limits.max_pending_bytes {
            metrics.capacity_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        while self.items.len() >= limits.max_pending_actors
            || self.bytes + bytes > limits.max_pending_bytes
        {
            if let Some(old) = self.items.pop_front() {
                self.bytes -= old.bytes;
            }
            metrics.capacity_dropped.fetch_add(1, Ordering::Relaxed);
        }
        let now = Instant::now();
        self.items.push_back(PendingActor {
            id: self.next_id,
            summary,
            verdict: None,
            expires: now + ttl,
            retry_at: now,
            attempts: 0,
            bytes,
        });
        self.next_id = self.next_id.wrapping_add(1);
        self.bytes += bytes;
    }

    pub fn select(&mut self, seen: &HashSet<u64>, batch_size: usize, force: bool) -> Vec<u64> {
        let now = Instant::now();
        let eligible = |item: &&PendingActor| {
            !seen.contains(&item.id) && item.expires > now && (force || item.retry_at <= now)
        };
        let has_fresh = self
            .items
            .iter()
            .filter(eligible)
            .any(|item| item.attempts == 0);
        let has_retry = self
            .items
            .iter()
            .filter(eligible)
            .any(|item| item.attempts > 0);
        let retry = has_retry && (self.prefer_retry || !has_fresh);
        self.prefer_retry = !retry;
        // Retry actors individually: one malformed actor cannot poison a healthy
        // actor forever merely because they first shared a provider batch.
        self.items
            .iter()
            .filter(eligible)
            .filter(|item| (item.attempts > 0) == retry)
            .take(if retry { 1 } else { batch_size })
            .map(|item| item.id)
            .collect()
    }

    pub fn remove(&mut self, id: u64) {
        if let Some(index) = self.items.iter().position(|item| item.id == id)
            && let Some(item) = self.items.remove(index)
        {
            self.bytes -= item.bytes;
        }
    }

    pub fn retry(&mut self, ids: &[u64], limits: &MemoryLimits, metrics: &AnalysisMetrics) {
        for item in self.items.iter_mut().filter(|item| ids.contains(&item.id)) {
            item.attempts = item.attempts.saturating_add(1);
            let seconds = limits
                .analysis_retry_secs
                .saturating_mul(1u64 << item.attempts.saturating_sub(1).min(5))
                .min(60);
            item.retry_at = Instant::now() + Duration::from_secs(seconds);
            metrics.retried.fetch_add(1, Ordering::Relaxed);
        }
    }
}
