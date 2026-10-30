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
                && self.hub_retention_secs > 0,
            "Memory limits must be positive"
        );
        anyhow::ensure!(
            (EVENT_RESERVATION_BYTES..=u32::MAX as usize).contains(&self.event_queue_bytes),
            "event_queue_bytes must fit at least one 12 KiB event and be at most 4 GiB - 1"
        );
        Ok(())
    }
}
