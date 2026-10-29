use crate::SecurityPipeline;
use crate::tailer::AccessLogEvent;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use std::net::IpAddr;

/// Embedded Axum middleware function that integrates `Custos` (`SecurityPipeline`) directly
/// into an application's HTTP request pipeline:
/// 1. Extracts the client IP from `X-Real-IP` or `X-Forwarded-For` (falling back to `127.0.0.1`).
/// 2. Checks `DecisionStore::check_ip` in sub-microsecond time and short-circuits with `403 Forbidden`
///    (plus `x-custos-threat` header) if the IP is actively banned.
/// 3. Executes the downstream handler, then feeds the resulting `AccessLogEvent` asynchronously
///    into `SecurityPipeline::process_event`.
pub async fn custos_bouncer_middleware(
    State(pipeline): State<SecurityPipeline>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(&req);

    // 1. Sub-microsecond check against active bans
    if let Some(decision) = pipeline.store.check_ip(&client_ip) {
        let mut resp = (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "ip": client_ip,
                "action": "block",
                "threat_class": decision.threat_class,
                "reason": decision.reason,
            })),
        )
            .into_response();
        if let Ok(val) = HeaderValue::from_str(&decision.threat_class) {
            resp.headers_mut().insert("x-custos-threat", val);
        }
        return resp;
    }

    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let referer = req
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // 2. Run downstream handler
    let response = next.run(req).await;
    let status = response.status().as_u16();

    // 3. Feed behavioral event into Custos L1 & sliding window engine
    let ev = AccessLogEvent {
        timestamp: Utc::now(),
        client_ip,
        method,
        path,
        query,
        status,
        bytes_sent: 0,
        referer,
        user_agent,
    };
    let _ = pipeline.process_event(&ev);

    response
}

fn extract_client_ip(req: &Request<Body>) -> IpAddr {
    let headers = req.headers();
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    IpAddr::from([127, 0, 0, 1])
}
