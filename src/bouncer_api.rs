use crate::firewall::FirewallBouncer;
use crate::jev::JevBatchAnalyzer;
use crate::store::{BanDecision, DecisionSource, DecisionStore};
use crate::window::SlidingWindowEngine;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<DecisionStore>,
    pub window: Arc<SlidingWindowEngine>,
    pub jev: Arc<JevBatchAnalyzer>,
    pub firewall: Arc<FirewallBouncer>,
}

#[derive(Debug, Deserialize)]
pub struct CheckQuery {
    pub ip: Option<String>,
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
    Router::new()
        .route("/v1/bouncer/check", get(handle_bouncer_check))
        .route(
            "/v1/decisions",
            get(handle_list_decisions).post(handle_create_decision),
        )
        .route("/v1/decisions/{ip}", delete(handle_delete_decision))
        .route("/v1/firewall", get(handle_firewall_status))
        .route("/v1/stats", get(handle_stats))
        .route("/metrics", get(handle_prometheus_metrics))
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

async fn handle_list_decisions(State(state): State<AppState>) -> Json<Vec<BanDecision>> {
    Json(state.store.list_active())
}

async fn handle_create_decision(
    State(state): State<AppState>,
    Json(req): Json<ManualBanRequest>,
) -> Result<(StatusCode, Json<BanDecision>), (StatusCode, String)> {
    let decision = state
        .store
        .upsert_ban(
            req.ip,
            req.threat_class,
            DecisionSource::ManualAdmin,
            1.0,
            1.0,
            req.reason,
            req.ttl_secs,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let ttl = (decision.expires_at - decision.created_at)
        .num_seconds()
        .max(1) as u64;
    let _ = state.firewall.ban_ip(req.ip, ttl);

    Ok((StatusCode::CREATED, Json(decision)))
}

async fn handle_delete_decision(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> impl IntoResponse {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid IP address" })),
        );
    };
    let removed = state.store.remove_ban(&ip);
    if removed {
        let _ = state.firewall.unban_ip(ip);
        (
            StatusCode::OK,
            Json(serde_json::json!({ "ip": ip, "removed": true })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ip": ip, "removed": false })),
        )
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
    let static_ignored = state.window.metrics.static_ignored.load(Ordering::Relaxed);
    let l1_bans = state.window.metrics.l1_instant_bans.load(Ordering::Relaxed);
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

    let body = format!(
        "# HELP custos_events_processed_total Total HTTP access log events ingested.\n\
         # TYPE custos_events_processed_total counter\n\
         custos_events_processed_total {events}\n\
         # HELP custos_static_ignored_total Total benign static asset requests ignored at L1.\n\
         # TYPE custos_static_ignored_total counter\n\
         custos_static_ignored_total {static_ignored}\n\
         # HELP custos_l1_instant_bans_total Instant bans triggered by L1 flood or auto-signature cache.\n\
         # TYPE custos_l1_instant_bans_total counter\n\
         custos_l1_instant_bans_total {l1_bans}\n\
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
         custos_firewall_command_errors_total {fw_errors}\n"
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, body)
}
