//! Resource admission limits. These bound retained library state, not process RSS.
use serde::{Deserialize, Serialize};

pub const EVENT_RESERVATION_BYTES: usize = 12 * 1024;
pub const MAX_REASON_BYTES: usize = 512;
pub const MAX_THREAT_BYTES: usize = 64;
pub const MAX_SIGNATURE_BYTES: usize = 256;
pub const MAX_HUB_BATCH: usize = 256;
pub const MAX_HUB_VOTERS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryLimits {
    pub max_decisions: usize,
    pub event_queue_bytes: usize,
    pub event_queue_capacity: usize,
    pub max_provider_response_bytes: usize,
    pub hub_max_entries: usize,
    pub max_signatures: usize,
    pub hub_retention_secs: u64,
    pub hub_max_streams: usize,
    pub max_pending_actors: usize,
    pub max_pending_bytes: usize,
    pub analysis_ttl_secs: u64,
    pub analysis_retry_secs: u64,
    pub analysis_batches_per_flush: usize,
    pub hub_max_pending_entries: usize,
    pub hub_max_pending_signatures: usize,
    pub hub_max_pending_per_node: usize,
    pub hub_vote_ttl_secs: u64,
}
impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            max_decisions: 10_000,
            event_queue_bytes: 8 * 1024 * 1024,
            event_queue_capacity: 1024,
            max_provider_response_bytes: 256 * 1024,
            hub_max_entries: 10_000,
            max_signatures: 1024,
            hub_retention_secs: 3600,
            hub_max_streams: 16,
            max_pending_actors: 4096,
            max_pending_bytes: 16 * 1024 * 1024,
            analysis_ttl_secs: 300,
            analysis_retry_secs: 1,
            analysis_batches_per_flush: 16,
            hub_max_pending_entries: 2500,
            hub_max_pending_signatures: 256,
            hub_max_pending_per_node: 1000,
            hub_vote_ttl_secs: 60,
        }
    }
}
impl MemoryLimits {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_decisions > 0
                && self.event_queue_capacity > 0
                && self.hub_max_entries > 0
                && self.max_signatures > 0
                && self.max_provider_response_bytes > 0
                && self.hub_max_streams > 0
                && self.hub_retention_secs > 0
                && self.max_pending_actors > 0
                && self.max_pending_bytes > 0
                && self.analysis_ttl_secs > 0
                && self.analysis_retry_secs > 0
                && self.analysis_batches_per_flush > 0
                && self.hub_max_pending_entries > 0
                && self.hub_max_pending_signatures > 0
                && self.hub_max_pending_per_node > 0
                && self.hub_vote_ttl_secs > 0,
            "Memory limits must be positive"
        );
        anyhow::ensure!(
            self.analysis_ttl_secs <= 86400,
            "analysis_ttl_secs must be at most 86400"
        );
        anyhow::ensure!(
            (EVENT_RESERVATION_BYTES..=u32::MAX as usize).contains(&self.event_queue_bytes),
            "event_queue_bytes must fit at least one 12 KiB event and be at most 4 GiB - 1"
        );
        Ok(())
    }
}
