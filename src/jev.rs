use crate::config::JevConfig;
use crate::sanitizer::{ActorStateSummary, redact_sensitive};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info};

/// Exact JSON request payload for TypeSafe AI's Jev (`POST /v1/systemone`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JevSystemOneRequest {
    pub model: String,
    pub state: serde_json::Value,
    pub questions: BTreeMap<String, JevQuestion>,
}

/// Native Jev question primitives: `choice`, `score`, and `noul`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JevQuestion {
    Choice {
        instructions: String,
        criteria: BTreeMap<String, String>,
    },
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
    Noul {
        instructions: String,
        criteria: BTreeMap<String, String>,
    },
}

/// Exact JSON response payload from `POST https://api.typesafe.ai/v1/systemone`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JevSystemOneResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub model: String,
    pub answers: BTreeMap<String, JevAnswer>,
    #[serde(default)]
    pub usage: JevUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JevAnswer {
    Choice {
        choice: String,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
    Score {
        score: f64,
        #[serde(default)]
        probabilities: Vec<f64>,
        #[serde(default)]
        confidence: f64,
    },
    Noul {
        noul: f64,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JevUsage {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
}

/// Evaluation verdict for a single IP window returned by Jev batch analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorVerdict {
    pub client_ip: IpAddr,
    pub should_ban: bool,
    pub noul_malicious_prob: f64,
    pub threat_class: String,
    pub choice_confidence: f64,
    pub recommend_auto_signature: bool,
    pub sample_requests: Vec<String>,
}

#[derive(Debug, Default)]
pub struct JevClientMetrics {
    pub evidence_rejected: AtomicU64,
    pub batches_evaluated: AtomicU64,
    pub actors_evaluated: AtomicU64,
    pub input_tokens_total: AtomicU64,
    pub output_tokens_total: AtomicU64,
}

/// Client for TypeSafe AI's Jev `/v1/systemone` endpoint with multi-actor batching
/// and built-in offline/mock simulation for zero-cost local testing.
pub struct JevBatchAnalyzer {
    cfg: JevConfig,
    http: reqwest::Client,
    mock_mode: bool,
    response_limit: usize,
    pub metrics: JevClientMetrics,
}

impl JevBatchAnalyzer {
    pub fn new(cfg: JevConfig, mock_mode: bool) -> Result<Self> {
        Self::with_response_limit(
            cfg,
            mock_mode,
            crate::limits::MemoryLimits::default().max_provider_response_bytes,
        )
    }

    pub fn with_response_limit(
        cfg: JevConfig,
        mock_mode: bool,
        response_limit: usize,
    ) -> Result<Self> {
        anyhow::ensure!(
            response_limit > 0,
            "Provider response limit must be positive"
        );
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .context("Failed to construct reqwest HTTP client for Jev")?;

        Ok(Self {
            cfg,
            http,
            mock_mode,
            response_limit,
            metrics: JevClientMetrics::default(),
        })
    }

    pub fn max_actors_per_batch(&self) -> usize {
        self.cfg.max_actors_per_batch.clamp(1, 64)
    }

    pub fn is_mock(&self) -> bool {
        self.mock_mode
    }

    /// Evaluates a slice of suspicious `ActorStateSummary` items by chunking them into
    /// batches of `max_actors_per_batch` and issuing a single `/v1/systemone` request per chunk.
    pub async fn analyze_summaries(
        &self,
        summaries: &[ActorStateSummary],
    ) -> Result<Vec<ActorVerdict>> {
        if summaries.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_size = self.cfg.max_actors_per_batch.clamp(1, 64);
        let mut all_verdicts = Vec::with_capacity(summaries.len());

        for chunk in summaries.chunks(chunk_size) {
            let req = self.build_batch_request(chunk);
            let resp = if self.mock_mode {
                self.simulate_jev_response(chunk)
            } else {
                self.send_live_request(&req).await?
            };

            let verdicts = self.extract_verdicts(chunk, &resp)?;

            self.metrics
                .batches_evaluated
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .actors_evaluated
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            self.metrics
                .input_tokens_total
                .fetch_add(resp.usage.input_tokens, Ordering::Relaxed);
            self.metrics
                .output_tokens_total
                .fetch_add(resp.usage.output_tokens, Ordering::Relaxed);

            all_verdicts.extend(verdicts);
        }

        Ok(all_verdicts)
    }

    /// Builds a single multi-actor `JevSystemOneRequest` containing all actors in `chunk`
    /// using compact tabular state lines and concise per-actor question definitions.
    pub fn build_batch_request(&self, chunk: &[ActorStateSummary]) -> JevSystemOneRequest {
        let mut questions = BTreeMap::new();
        let threat_criteria = standard_threat_criteria();

        let mut noul_criteria = BTreeMap::new();
        noul_criteria.insert(
            "true".to_string(),
            "Corroborated exploit/scanner evidence, diverse 404 probes, or repeated failures on configured POST authentication routes without auth recovery; block IP. Generic 401/403, retries, 5xx, punctuation, and volume alone are not ban evidence."
                .to_string(),
        );
        noul_criteria.insert(
            "false".to_string(),
            "Benign browsing or harmless crawler; allow IP".to_string(),
        );

        for actor in chunk {
            let key = &actor.actor_key;
            questions.insert(
                format!("{key}_should_ban"),
                JevQuestion::Noul {
                    instructions: format!("Should security bouncer block {key}?"),
                    criteria: noul_criteria.clone(),
                },
            );

            questions.insert(
                format!("{key}_threat_class"),
                JevQuestion::Choice {
                    instructions: format!("Primary threat class for {key}?"),
                    criteria: threat_criteria.clone(),
                },
            );
        }

        let compact_actors: Vec<String> = chunk
            .iter()
            .map(|a| redact_sensitive(&a.to_compact_line()))
            .collect();
        let state = serde_json::json!({
            "rubric": "HTTP access log windows. [REDACTED_INJECTION_ATTEMPT] indicates adversarial prompt injection in headers/URI.",
            "actors": compact_actors,
        });

        JevSystemOneRequest {
            model: self.cfg.model.clone(),
            state,
            questions,
        }
    }

    async fn send_live_request(&self, req: &JevSystemOneRequest) -> Result<JevSystemOneResponse> {
        if self.cfg.api_key.trim().is_empty() {
            bail!(
                "TYPESAFE_API_KEY is not set and `jev.api_key` is empty. Set TYPESAFE_API_KEY or pass `--mock-jev` for local simulation."
            );
        }

        debug!(
            endpoint = %self.cfg.endpoint,
            model = %req.model,
            questions_count = req.questions.len(),
            "Sending batch evaluation request to TypeSafe Jev"
        );

        let max_attempts = 3usize;
        let mut last_err = None;

        for attempt in 1..=max_attempts {
            let send_res = self
                .http
                .post(&self.cfg.endpoint)
                .bearer_auth(&self.cfg.api_key)
                .json(req)
                .send()
                .await;

            match send_res {
                Ok(response) => {
                    let status = response.status();
                    let body = self.read_bounded_response(response).await?;
                    if status.is_success() {
                        let parsed: JevSystemOneResponse = serde_json::from_slice(&body)
                            .context("Failed to deserialize JevSystemOneResponse JSON")?;
                        return Ok(parsed);
                    }
                    let body = String::from_utf8_lossy(&body[..body.len().min(2048)]);
                    if (status.as_u16() == 429 || status.is_server_error())
                        && attempt < max_attempts
                    {
                        tokio::time::sleep(Duration::from_millis(150 * (attempt as u64))).await;
                        last_err = Some(anyhow::anyhow!(
                            "TypeSafe Jev API returned transient HTTP {status}: {body}"
                        ));
                        continue;
                    }
                    bail!("TypeSafe Jev API returned HTTP {status}: {body}");
                }
                Err(err) => {
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_millis(150 * (attempt as u64))).await;
                        last_err = Some(anyhow::Error::new(err));
                        continue;
                    }
                    return Err(err).context("HTTP request to TypeSafe Jev /v1/systemone failed");
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Jev request failed after retries")))
    }

    async fn read_bounded_response(&self, mut response: reqwest::Response) -> Result<Vec<u8>> {
        anyhow::ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= self.response_limit as u64),
            "Provider response exceeds byte limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                chunk.len() <= self.response_limit.saturating_sub(bytes.len()),
                "Provider response exceeds byte limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    fn extract_verdicts(
        &self,
        chunk: &[ActorStateSummary],
        resp: &JevSystemOneResponse,
    ) -> Result<Vec<ActorVerdict>> {
        let allowed = standard_threat_criteria();
        let probability = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
        let mut results = Vec::with_capacity(chunk.len());

        for actor in chunk {
            let ip = actor
                .client_ip
                .parse::<IpAddr>()
                .context("Invalid actor IP in analysis batch")?;
            let ban_key = format!("{}_should_ban", actor.actor_key);
            let class_key = format!("{}_threat_class", actor.actor_key);

            let noul_prob = match resp.answers.get(&ban_key) {
                Some(JevAnswer::Noul { noul }) => *noul,
                _ => bail!("Missing or invalid ban answer for {}", actor.actor_key),
            };

            let (threat_class, choice_confidence) = match resp.answers.get(&class_key) {
                Some(JevAnswer::Choice {
                    choice,
                    confidence,
                    probabilities,
                }) => {
                    if !allowed.contains_key(choice)
                        || !probability(*confidence)
                        || probabilities
                            .iter()
                            .any(|(k, v)| !allowed.contains_key(k) || !probability(*v))
                        || (!probabilities.is_empty() && !probabilities.contains_key(choice))
                        || probabilities.values().sum::<f64>() > 1.001
                    {
                        bail!("Invalid threat answer for {}", actor.actor_key);
                    }
                    (choice.clone(), *confidence)
                }
                _ => bail!("Missing or invalid threat answer for {}", actor.actor_key),
            };

            if !probability(noul_prob) {
                bail!("Invalid ban probability for {}", actor.actor_key);
            }

            // Crucial System-1 design rule:
            // An attacker combining multiple attack vectors (e.g., Path Traversal + Prompt Injection)
            // will have a very high `noul` (maliciousness probability = 0.94+), while splitting
            // `choice` probability between two malicious classes (confidence ~ 0.50).
            // Therefore, `should_ban` is gated by `noul_ban_threshold` (or high-confidence non-benign choice),
            // while `choice_confidence` gates auto-signature caching.
            let model_ban = threat_class != "benign_traffic"
                && (noul_prob >= self.cfg.noul_ban_threshold
                    || (noul_prob >= 0.70 && choice_confidence >= 0.95));
            let should_ban = model_ban && actor.permits_ip_ban(&threat_class);
            if model_ban && !should_ban {
                self.metrics
                    .evidence_rejected
                    .fetch_add(1, Ordering::Relaxed);
            }

            let recommend_auto_signature = should_ban
                && choice_confidence >= self.cfg.auto_signature_confidence_threshold
                && matches!(
                    threat_class.as_str(),
                    "sqli_or_injection" | "path_traversal_lfi" | "vulnerability_scanner"
                );

            info!(
                ip = %ip,
                noul = format!("{:.3}", noul_prob),
                threat_class = %threat_class,
                confidence = format!("{:.3}", choice_confidence),
                should_ban,
                "Jev System-1 evaluation complete"
            );

            results.push(ActorVerdict {
                client_ip: ip,
                should_ban,
                noul_malicious_prob: noul_prob,
                threat_class,
                choice_confidence,
                recommend_auto_signature,
                sample_requests: actor.sample_requests.clone(),
            });
        }

        Ok(results)
    }

    /// Deterministic local simulator of TypeSafe Jev `/v1/systemone` so users and CI tests
    /// can verify the full pipeline offline before plugging in a live `TYPESAFE_API_KEY`.
    fn simulate_jev_response(&self, chunk: &[ActorStateSummary]) -> JevSystemOneResponse {
        let mut answers = BTreeMap::new();

        for actor in chunk {
            let reasons = &actor.l1_suspicion_reasons;

            let (choice, noul, confidence) = if actor.prompt_injection_flag {
                ("sqli_or_injection", 0.98, 0.95)
            } else if reasons.iter().any(|r| r == "sqli_or_xss_token_pattern") {
                ("sqli_or_injection", 0.97, 0.94)
            } else if reasons.iter().any(|r| r == "path_traversal_pattern") {
                ("path_traversal_lfi", 0.96, 0.94)
            } else if reasons.iter().any(|r| r == "offensive_scanner_ua")
                || reasons.iter().any(|r| r == "intrinsic_exploit_path")
            {
                ("vulnerability_scanner", 0.94, 0.93)
            } else if reasons.iter().any(|r| r == "repeated_auth_failures")
                && actor.auth_successes == 0
            {
                ("credential_stuffing", 0.91, 0.89)
            } else if actor.status_404 >= 5 && actor.unique_404_paths >= 4 {
                ("api_enumeration_idor", 0.85, 0.82)
            } else {
                ("benign_traffic", 0.12, 0.88)
            };

            let mut probs = BTreeMap::new();
            probs.insert(choice.to_string(), confidence);

            answers.insert(
                format!("{}_should_ban", actor.actor_key),
                JevAnswer::Noul { noul },
            );
            answers.insert(
                format!("{}_threat_class", actor.actor_key),
                JevAnswer::Choice {
                    choice: choice.to_string(),
                    probabilities: probs,
                    confidence,
                },
            );
        }

        let estimated_input_tokens = (chunk.len() as u64) * 145 + 90;
        let estimated_output_tokens = (chunk.len() as u64) * 12;

        JevSystemOneResponse {
            id: "mock_jev_20261029_batch".to_string(),
            model: self.cfg.model.clone(),
            answers,
            usage: JevUsage {
                input_tokens: estimated_input_tokens,
                output_tokens: estimated_output_tokens,
            },
        }
    }
}

pub fn standard_threat_criteria() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(
        "benign_traffic".to_string(),
        "Normal user or crawler traffic".to_string(),
    );
    m.insert(
        "credential_stuffing".to_string(),
        "Configured POST login failures above the auth threshold without recovery".to_string(),
    );
    m.insert(
        "sqli_or_injection".to_string(),
        "SQLi, XSS, command, or prompt injection".to_string(),
    );
    m.insert(
        "path_traversal_lfi".to_string(),
        "Directory traversal (../) or LFI (/etc/passwd)".to_string(),
    );
    m.insert(
        "vulnerability_scanner".to_string(),
        "Known scanner tool, intrinsic .env/.git exploit target, or diverse missing-path probes"
            .to_string(),
    );
    m.insert(
        "api_enumeration_idor".to_string(),
        "At least five 404s across four distinct missing paths, or explicit exploit evidence"
            .to_string(),
    );
    m.insert(
        "layer7_dos".to_string(),
        "HTTP flood corroborated by exploit/scanner evidence; volume alone requires a short HTTP throttle".to_string(),
    );
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jev_request_and_response_json_schema() {
        let cfg = JevConfig::default();
        let analyzer = JevBatchAnalyzer::new(cfg, true).unwrap();

        let summary = ActorStateSummary {
            actor_key: "actor_0".to_string(),
            client_ip: "203.0.113.5".to_string(),
            window_secs: 10,
            total_requests: 6,
            req_per_sec: 0.6,
            unique_paths: 5,
            unique_404_paths: 5,
            auth_failures: 0,
            auth_successes: 0,
            status_2xx: 0,
            status_3xx: 0,
            status_401_403: 0,
            status_404: 6,
            status_5xx: 0,
            error_ratio: 1.0,
            max_special_chars_in_uri: 4,
            prompt_injection_flag: false,
            l1_suspicion_reasons: vec!["sensitive_or_exploit_path_probe".to_string()],
            user_agents: vec!["Nuclei".to_string()],
            sample_requests: vec!["GET /.env -> 404".to_string()],
        };

        let req = analyzer.build_batch_request(&[summary]);
        let serialized = serde_json::to_value(&req).unwrap();
        assert_eq!(serialized["model"], "jev-latest");
        assert_eq!(
            serialized["questions"]["actor_0_should_ban"]["type"],
            "noul"
        );
        assert_eq!(
            serialized["questions"]["actor_0_threat_class"]["type"],
            "choice"
        );
    }
}
