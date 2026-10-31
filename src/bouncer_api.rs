use crate::store::{BanDecision, DecisionSource};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

#[derive(Clone)]
pub struct AppState {
    pub pipeline: crate::SecurityPipeline,
    pub api_token: String,
}

impl std::ops::Deref for AppState {
    type Target = crate::SecurityPipeline;
    fn deref(&self) -> &Self::Target {
        &self.pipeline
    }
}

async fn require_admin(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if state.api_token.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin API disabled: configure daemon.api_token",
        )
            .into_response();
    }
    let authorized = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|token| token == state.api_token);
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

#[derive(Debug, Deserialize)]
pub struct CheckQuery {
    /// Nginx auth_request accepts only 2xx/401/403. Proxy maps this 403 to 429.
    #[serde(default)]
    pub auth_request: bool,
    pub ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BouncerCheckResponse {
    pub ip: String,
    pub action: String,
    pub threat_class: Option<String>,
    pub reason: Option<String>,
    pub noul_probability: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManualBanRequest {
    pub ip: IpAddr,
    #[serde(default = "default_manual_threat")]
    pub threat_class: String,
    #[serde(default = "default_manual_reason")]
    pub reason: String,
    pub ttl_secs: Option<u64>,
}

fn default_manual_threat() -> String {
    "manual_block".to_string()
}
fn default_manual_reason() -> String {
    "Manually banned via JevSec API/CLI".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub events_processed: u64,
    pub static_ignored: u64,
    pub l1_instant_bans: u64,
    pub windows_promoted_to_jev: u64,
    pub jev_batches_evaluated: u64,
    pub jev_actors_evaluated: u64,
    pub jev_input_tokens: u64,
    pub jev_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub active_bans: usize,
    pub auto_cached_signatures: usize,
    pub jev_mock_mode: bool,
    pub firewall_backend: String,
    pub firewall_dry_run: bool,
    pub firewall_rules_applied: u64,
    pub firewall_rules_removed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallStatusResponse {
    pub enabled: bool,
    pub resolved_backend: String,
    pub dry_run: bool,
    pub rules_applied: u64,
    pub rules_removed: u64,
    pub command_errors: u64,
    pub recent_commands: Vec<String>,
}

pub fn build_bouncer_router(state: AppState) -> Router {
    let mutations = Router::new()
        .route("/v1/decisions", axum::routing::post(handle_create_decision))
        .route("/v1/decisions/{ip}", delete(handle_delete_decision))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ));
    let requests = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    Router::new()
        .route("/v1/bouncer/check", get(handle_bouncer_check))
        .route("/v1/decisions", get(handle_list_decisions))
        .route("/v1/firewall", get(handle_firewall_status))
        .route("/v1/stats", get(handle_stats))
        .route("/metrics", get(handle_prometheus_metrics))
        .merge(mutations)
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let requests = requests.clone();
                async move {
                    let Ok(permit) = requests.try_acquire_owned() else {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Security API capacity reached",
                        )
                            .into_response();
                    };
                    let response = next.run(request).await;
                    let (parts, body) = response.into_parts();
                    let guarded =
                        tokio_stream::StreamExt::map(body.into_data_stream(), move |chunk| {
                            let _ = &permit;
                            chunk
                        });
                    axum::response::Response::from_parts(
                        parts,
                        axum::body::Body::from_stream(guarded),
                    )
                }
            },
        ))
        .with_state(state)
}

/// Sub-millisecond endpoint compatible with Nginx `auth_request`, Caddy `forward_auth`,
/// Traefik `ForwardAuth`, or custom firewall bouncers.
async fn handle_bouncer_check(
    State(state): State<AppState>,
    Query(query): Query<CheckQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let raw_ip = query
        .ip
        .clone()
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
        });

    let Some(raw_ip) = raw_ip else {
        return (
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(BouncerCheckResponse {
                ip: String::new(),
                action: "error_missing_ip".to_string(),
                threat_class: None,
                reason: Some("Provide ?ip=<IP> or X-Real-IP / X-Forwarded-For header".to_string()),
                noul_probability: None,
            }),
        );
    };

    let Ok(ip) = raw_ip.parse::<IpAddr>() else {
        return (
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(BouncerCheckResponse {
                ip: raw_ip,
                action: "error_invalid_ip".to_string(),
                threat_class: None,
                reason: Some("Invalid IP address format".to_string()),
                noul_probability: None,
            }),
        );
    };

    if let Some(decision) = state.store.check_ip(&ip) {
        let mut resp_headers = HeaderMap::new();
        if let Ok(val) = HeaderValue::from_str(&decision.threat_class) {
            resp_headers.insert("x-custos-threat", val.clone());
            resp_headers.insert("x-jevsec-threat", val);
        }
        (
            StatusCode::FORBIDDEN,
            resp_headers,
            Json(BouncerCheckResponse {
                ip: ip.to_string(),
                action: "block".to_string(),
                threat_class: Some(decision.threat_class),
                reason: Some(decision.reason),
                noul_probability: Some(decision.noul_probability),
            }),
        )
    } else if let Some(threat) = original_request_signature(&state, &query, &headers) {
        let (status, action, reason) = match threat {
            Ok(threat) => (StatusCode::FORBIDDEN, "block", threat),
            Err(()) => (
                StatusCode::BAD_REQUEST,
                "error_invalid_request",
                "Invalid original method/URI metadata".into(),
            ),
        };
        (
            status,
            HeaderMap::new(),
            Json(BouncerCheckResponse {
                ip: ip.to_string(),
                action: action.into(),
                threat_class: (status == StatusCode::FORBIDDEN).then_some(reason.clone()),
                reason: Some(reason),
                noul_probability: None,
            }),
        )
    } else if let Some(seconds) = state.window.retry_after_secs(&ip) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "retry-after",
            HeaderValue::from_str(&seconds.to_string()).expect("bounded integer"),
        );
        headers.insert("x-custos-action", HeaderValue::from_static("throttle"));
        (
            if query.auth_request {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::TOO_MANY_REQUESTS
            },
            headers,
            Json(BouncerCheckResponse {
                ip: ip.to_string(),
                action: "throttle".into(),
                threat_class: None,
                reason: Some("Temporary request rate limit".into()),
                noul_probability: None,
            }),
        )
    } else if !state.capacity_allows_traffic() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            Json(BouncerCheckResponse {
                ip: ip.to_string(),
                action: "block".into(),
                threat_class: None,
                reason: Some("Security decision capacity reached".into()),
                noul_probability: None,
            }),
        )
    } else {
        (
            StatusCode::OK,
            HeaderMap::new(),
            Json(BouncerCheckResponse {
                ip: ip.to_string(),
                action: "allow".to_string(),
                threat_class: None,
                reason: None,
                noul_probability: None,
            }),
        )
    }
}

// Only a trusted proxy should reach the standalone checker. It must overwrite
// these headers with original request metadata, just as it supplies client IP.
fn original_request_signature(
    state: &AppState,
    query: &CheckQuery,
    headers: &HeaderMap,
) -> Option<Result<String, ()>> {
    let header = |name: &str| -> Result<Option<&str>, ()> {
        if headers.get_all(name).iter().count() > 1 {
            return Err(());
        }
        headers
            .get(name)
            .map(|value| value.to_str().map_err(|_| ()))
            .transpose()
    };
    let metadata = (|| -> Result<Option<(String, axum::http::Uri)>, ()> {
        let method = header("x-original-method")?.or(query.method.as_deref());
        let uri = header("x-original-uri")?.or(query.uri.as_deref());
        let (method, uri) = match (method, uri) {
            (None, None) => return Ok(None),
            (Some(method), Some(uri)) => (method, uri),
            _ => return Err(()),
        };
        if method.len() > crate::tailer::MAX_METHOD_BYTES
            || uri.len() > crate::tailer::MAX_URI_BYTES
            || !uri.starts_with('/')
        {
            return Err(());
        }
        let method = method.parse::<axum::http::Method>().map_err(|_| ())?;
        let uri = uri.parse::<axum::http::Uri>().map_err(|_| ())?;
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err(());
        }
        Ok(Some((method.to_string(), uri)))
    })();
    match metadata {
        Err(()) => Some(Err(())),
        Ok(Some((method, uri))) => state.window.cached_signature(&method, uri.path()).map(Ok),
        Ok(None) => None,
    }
}

async fn handle_list_decisions(State(state): State<AppState>) -> Json<Vec<BanDecision>> {
    Json(state.store.list_active())
}

async fn handle_create_decision(
    State(state): State<AppState>,
    Json(req): Json<ManualBanRequest>,
) -> Result<(StatusCode, Json<BanDecision>), (StatusCode, String)> {
    let pipeline = state.pipeline.clone();
    let decision = tokio::task::spawn_blocking(move || {
        pipeline.record_ban(
            req.ip,
            req.threat_class,
            DecisionSource::ManualAdmin,
            1.0,
            1.0,
            req.reason,
            req.ttl_secs,
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| {
        (
            if state.store.is_at_capacity() {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            e.to_string(),
        )
    })?;
    Ok((StatusCode::CREATED, Json(decision)))
}

async fn handle_delete_decision(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> axum::response::Response {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return (StatusCode::BAD_REQUEST, "Invalid IP address").into_response();
    };
    let pipeline = state.pipeline.clone();
    match tokio::task::spawn_blocking(move || pipeline.remove_ban(&ip)).await {
        Ok(Ok(removed)) => (
            if removed {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            },
            Json(serde_json::json!({"ip": ip, "removed": removed})),
        )
            .into_response(),
        Ok(Err(error)) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn handle_firewall_status(State(state): State<AppState>) -> Json<FirewallStatusResponse> {
    Json(FirewallStatusResponse {
        enabled: state.firewall.is_enabled(),
        resolved_backend: state.firewall.resolved_backend().as_str().to_string(),
        dry_run: state.firewall.is_dry_run(),
        rules_applied: state.firewall.metrics.rules_applied.load(Ordering::Relaxed),
        rules_removed: state.firewall.metrics.rules_removed.load(Ordering::Relaxed),
        command_errors: state
            .firewall
            .metrics
            .command_errors
            .load(Ordering::Relaxed),
        recent_commands: state.firewall.recent_commands(),
    })
}

async fn handle_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let input_tokens = state.jev.metrics.input_tokens_total.load(Ordering::Relaxed);
    let output_tokens = state
        .jev
        .metrics
        .output_tokens_total
        .load(Ordering::Relaxed);
    let estimated_cost_usd = (input_tokens as f64 / 1_000_000.0) * 0.042;

    Json(StatsResponse {
        events_processed: state
            .window
            .metrics
            .events_processed
            .load(Ordering::Relaxed),
        static_ignored: state.window.metrics.static_ignored.load(Ordering::Relaxed),
        l1_instant_bans: state.window.metrics.l1_instant_bans.load(Ordering::Relaxed),
        windows_promoted_to_jev: state
            .window
            .metrics
            .windows_promoted_to_jev
            .load(Ordering::Relaxed),
        jev_batches_evaluated: state.jev.metrics.batches_evaluated.load(Ordering::Relaxed),
        jev_actors_evaluated: state.jev.metrics.actors_evaluated.load(Ordering::Relaxed),
        jev_input_tokens: input_tokens,
        jev_output_tokens: output_tokens,
        estimated_cost_usd: (estimated_cost_usd * 1_000_000.0).round() / 1_000_000.0,
        active_bans: state.store.active_count(),
        auto_cached_signatures: state.window.active_signature_count(),
        jev_mock_mode: state.jev.is_mock(),
        firewall_backend: state.firewall.resolved_backend().as_str().to_string(),
        firewall_dry_run: state.firewall.is_dry_run(),
        firewall_rules_applied: state.firewall.metrics.rules_applied.load(Ordering::Relaxed),
        firewall_rules_removed: state.firewall.metrics.rules_removed.load(Ordering::Relaxed),
    })
}

/// Prometheus OpenMetrics exposition endpoint (`GET /metrics`).
async fn handle_prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let events = state
        .window
        .metrics
        .events_processed
        .load(Ordering::Relaxed);
    let queue_rejected = state.queue_rejected.load(Ordering::Relaxed);
    let decision_rejected = state.store.capacity_rejected.load(Ordering::Relaxed);
    let queue_available = state.available_queue_bytes();
    let capacity_dropped = state
        .window
        .metrics
        .capacity_dropped
        .load(Ordering::Relaxed);
    let expired_dropped = state
        .window
        .metrics
        .expired_evidence_dropped
        .load(Ordering::Relaxed);
    let static_ignored = state.window.metrics.static_ignored.load(Ordering::Relaxed);
    let l1_bans = state.window.metrics.l1_instant_bans.load(Ordering::Relaxed);
    let http_throttles = state.window.metrics.http_throttles.load(Ordering::Relaxed);
    let retained_throttles = state.window.retained_throttle_count();
    let evidence_rejected = state.jev.metrics.evidence_rejected.load(Ordering::Relaxed);
    let promoted = state
        .window
        .metrics
        .windows_promoted_to_jev
        .load(Ordering::Relaxed);
    let batches = state.jev.metrics.batches_evaluated.load(Ordering::Relaxed);
    let actors = state.jev.metrics.actors_evaluated.load(Ordering::Relaxed);
    let in_tokens = state.jev.metrics.input_tokens_total.load(Ordering::Relaxed);
    let active_bans = state.store.active_count();
    let signatures = state.window.active_signature_count();
    let fw_applied = state.firewall.metrics.rules_applied.load(Ordering::Relaxed);
    let fw_removed = state.firewall.metrics.rules_removed.load(Ordering::Relaxed);
    let fw_errors = state
        .firewall
        .metrics
        .command_errors
        .load(Ordering::Relaxed);

    let retained = state.store.retained_count();
    let cleanup_pending = state.store.sweep_expired().len();
    let saturated = usize::from(state.store.is_at_capacity());
    let capacity_allowed = state.capacity_allowed.load(Ordering::Relaxed);
    let capacity_blocked = state.capacity_blocked.load(Ordering::Relaxed);
    let analysis_actors = state
        .analysis_metrics
        .pending_actors
        .load(Ordering::Relaxed);
    let analysis_bytes = state.analysis_metrics.pending_bytes.load(Ordering::Relaxed);
    let analysis_expired = state.analysis_metrics.expired.load(Ordering::Relaxed);
    let analysis_dropped = state
        .analysis_metrics
        .capacity_dropped
        .load(Ordering::Relaxed);
    let analysis_retried = state.analysis_metrics.retried.load(Ordering::Relaxed);
    let body = format!(
        "# HELP custos_events_processed_total Total HTTP access log events ingested.\n\
         # TYPE custos_events_processed_total counter\n\
         custos_events_processed_total {events}\n\
         # HELP custos_static_ignored_total Total benign static asset requests ignored at L1.\n\
         # TYPE custos_static_ignored_total counter\n\
         custos_static_ignored_total {static_ignored}\n\
         # HELP custos_queue_rejected_total Events rejected at ingestion admission.\n\
         # TYPE custos_queue_rejected_total counter\n\
         custos_queue_rejected_total {queue_rejected}\n\
         # HELP custos_decision_capacity_rejected_total Bans rejected at retained decision capacity.\n\
         # TYPE custos_decision_capacity_rejected_total counter\n\
         custos_decision_capacity_rejected_total {decision_rejected}\n\
         # HELP custos_queue_available_bytes Unreserved ingestion budget.\n\
         # TYPE custos_queue_available_bytes gauge\n\
         custos_queue_available_bytes {queue_available}\n\
         # HELP custos_capacity_dropped_total Events rejected at active window capacity.\n\
         # TYPE custos_capacity_dropped_total counter\n\
         custos_capacity_dropped_total {capacity_dropped}\n\
         # HELP custos_expired_evidence_dropped_total Oldest expired evidence dropped at backlog capacity.\n\
         # TYPE custos_expired_evidence_dropped_total counter\n\
         custos_expired_evidence_dropped_total {expired_dropped}\n\
         # HELP custos_l1_instant_bans_total Cached-signature bans or explicitly opted-in strict volume bans.\n\
         # TYPE custos_l1_instant_bans_total counter\n\
         custos_l1_instant_bans_total {l1_bans}\n\
         # HELP custos_http_throttles_total Short HTTP-only rate limits created.\n\
         # TYPE custos_http_throttles_total counter\n\
         custos_http_throttles_total {http_throttles}\n\
         # TYPE custos_http_throttles_retained gauge\n\
         custos_http_throttles_retained {retained_throttles}\n\
         # HELP custos_jev_evidence_rejected_total Model convictions rejected by runtime evidence policy.\n\
         # TYPE custos_jev_evidence_rejected_total counter\n\
         custos_jev_evidence_rejected_total {evidence_rejected}\n\
         # HELP custos_windows_promoted_total Suspicious IP windows promoted to TypeSafe Jev L2.\n\
         # TYPE custos_windows_promoted_total counter\n\
         custos_windows_promoted_total {promoted}\n\
         # HELP custos_jev_batches_total Total multi-actor batch requests sent to TypeSafe Jev /v1/systemone.\n\
         # TYPE custos_jev_batches_total counter\n\
         custos_jev_batches_total {batches}\n\
         # HELP custos_jev_actors_evaluated_total Total suspicious actors evaluated by Jev.\n\
         # TYPE custos_jev_actors_evaluated_total counter\n\
         custos_jev_actors_evaluated_total {actors}\n\
         # HELP custos_jev_input_tokens_total Total Jev input tokens consumed.\n\
         # TYPE custos_jev_input_tokens_total counter\n\
         custos_jev_input_tokens_total {in_tokens}\n\
         # HELP custos_active_bans Current active IP bans in DecisionStore.\n\
         # TYPE custos_active_bans gauge\n\
         custos_active_bans {active_bans}\n\
         # HELP custos_auto_cached_signatures Current zero-day L1 signatures cached in memory.\n\
         # TYPE custos_auto_cached_signatures gauge\n\
         custos_auto_cached_signatures {signatures}\n\
         # HELP custos_firewall_rules_applied_total Total OS kernel firewall rules applied.\n\
         # TYPE custos_firewall_rules_applied_total counter\n\
         custos_firewall_rules_applied_total {fw_applied}\n\
         # HELP custos_firewall_rules_removed_total Total OS kernel firewall rules removed.\n\
         # TYPE custos_firewall_rules_removed_total counter\n\
         custos_firewall_rules_removed_total {fw_removed}\n\
         # HELP custos_firewall_command_errors_total Total OS firewall execution errors.\n\
         # TYPE custos_firewall_command_errors_total counter\n\
         custos_firewall_command_errors_total {fw_errors}\n\
         # TYPE custos_decision_retained gauge\n\
         custos_decision_retained {retained}\n\
         # TYPE custos_decision_cleanup_pending gauge\n\
         custos_decision_cleanup_pending {cleanup_pending}\n\
         # TYPE custos_decision_saturated gauge\n\
         custos_decision_saturated {saturated}\n\
         # TYPE custos_decision_capacity_allowed_total counter\n\
         custos_decision_capacity_allowed_total {capacity_allowed}\n\
         # TYPE custos_decision_capacity_blocked_total counter\n\
         custos_decision_capacity_blocked_total {capacity_blocked}\n\
         # TYPE custos_analysis_pending_actors gauge\n\
         custos_analysis_pending_actors {analysis_actors}\n\
         # TYPE custos_analysis_pending_bytes gauge\n\
         custos_analysis_pending_bytes {analysis_bytes}\n\
         # TYPE custos_analysis_expired_total counter\n\
         custos_analysis_expired_total {analysis_expired}\n\
         # TYPE custos_analysis_capacity_dropped_total counter\n\
         custos_analysis_capacity_dropped_total {analysis_dropped}\n\
         # TYPE custos_analysis_retried_total counter\n\
         custos_analysis_retried_total {analysis_retried}\n"
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, body)
}
