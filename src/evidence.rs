use crate::{
    sanitizer::{ActorStateSummary, redact_sensitive},
    tailer::{AccessLogEvent, bounded_str},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Small, redacted audit excerpt; never retains full logs, credentials, or bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionEvidence {
    pub observed_at: DateTime<Utc>,
    pub window_secs: u64,
    pub total_requests: usize,
    pub status_404: usize,
    pub unique_404_paths: usize,
    pub signals: Vec<String>,
    pub samples: Vec<String>,
}
impl DecisionEvidence {
    pub fn from_summary(summary: &ActorStateSummary) -> Self {
        Self {
            observed_at: Utc::now(),
            window_secs: summary.window_secs,
            total_requests: summary.total_requests,
            status_404: summary.status_404,
            unique_404_paths: summary.unique_404_paths,
            signals: summary
                .l1_suspicion_reasons
                .iter()
                .take(16)
                .map(|s| bounded_str(s, 64).to_owned())
                .collect(),
            samples: summary
                .sample_requests
                .iter()
                .take(3)
                .map(|s| {
                    bounded_str(
                        &redact_sensitive(bounded_str(s, crate::tailer::MAX_URI_BYTES)),
                        256,
                    )
                    .to_owned()
                })
                .collect(),
        }
    }
    pub fn from_event(event: &AccessLogEvent, signal: &str) -> Self {
        Self {
            observed_at: event.timestamp,
            window_secs: 0,
            total_requests: 1,
            status_404: usize::from(event.status == 404),
            unique_404_paths: usize::from(event.status == 404),
            signals: vec![bounded_str(signal, 64).to_owned()],
            samples: vec![
                bounded_str(
                    &redact_sensitive(&format!(
                        "{} {} -> {}",
                        bounded_str(&event.method, crate::tailer::MAX_METHOD_BYTES),
                        bounded_str(&event.path, crate::tailer::MAX_URI_BYTES),
                        event.status
                    )),
                    256,
                )
                .to_owned(),
            ],
        }
    }
    pub fn has_exploit(&self) -> bool {
        signals_have_exploit(&self.signals)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.signals.len() <= 16
                && self.samples.len() <= 3
                && self.signals.iter().all(|s| s.len() <= 64)
                && self.samples.iter().all(|s| s.len() <= 256),
            "Decision evidence exceeds budget"
        );
        Ok(())
    }
}

pub fn signals_have_exploit(signals: &[String]) -> bool {
    signals.iter().any(|s| {
        matches!(
            s.as_str(),
            "sqli_or_xss_token_pattern"
                | "path_traversal_pattern"
                | "intrinsic_exploit_path"
                | "adversarial_prompt_injection_in_payload"
                | "cached_exploit_signature"
        )
    })
}
