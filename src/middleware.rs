use crate::SecurityPipeline;
use crate::tailer::AccessLogEvent;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use std::net::{IpAddr, SocketAddr};

/// Embedded Axum middleware function that integrates `Custos` (`SecurityPipeline`) directly
/// into an application's HTTP request pipeline:
/// 1. Uses the socket peer, accepting forwarded identity only from configured proxies.
/// 2. Checks `DecisionStore::check_ip` in sub-microsecond time and short-circuits with `403 Forbidden`
///    (plus `x-custos-threat` header) if the IP is actively banned.
/// 3. Rejects validated cached signatures before the handler, including at ledger capacity.
/// 4. Executes the downstream handler, then feeds the resulting `AccessLogEvent` asynchronously
///    into `SecurityPipeline::process_event`.
pub async fn custos_bouncer_middleware(
    State(pipeline): State<SecurityPipeline>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(client_ip) = extract_client_ip(&req, &pipeline.trusted_proxies) else {
        return (
            StatusCode::BAD_REQUEST,
            "Missing connection identity or invalid forwarding header",
        )
            .into_response();
    };

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

    if let Some(threat) = pipeline
        .window
        .cached_signature(req.method().as_str(), req.uri().path())
    {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "ip": client_ip, "action": "block", "threat_class": threat,
                "reason": "Matched cached Jev signature",
            })),
        )
            .into_response();
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

    // Reserve capacity before downstream side effects; never block a Tokio worker.
    let Ok(permit) = pipeline.reserve_event() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Security ingestion queue unavailable",
        )
            .into_response();
    };
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
    permit.send(ev);

    response
}

fn extract_client_ip(req: &Request<Body>, trusted: &[IpAddr]) -> Option<IpAddr> {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>()?.0.ip();
    if !trusted.contains(&peer) {
        return Some(peer);
    }
    let headers = req.headers();
    if headers.contains_key("x-forwarded-for") {
        let mut chain = Vec::<IpAddr>::new();
        for field in headers.get_all("x-forwarded-for") {
            for part in field.to_str().ok()?.split(',') {
                chain.push(part.trim().parse().ok()?);
            }
        }
        // Walk away from the authenticated proxy; ignore spoofed leftmost entries.
        return chain
            .iter()
            .rev()
            .find(|ip| !trusted.contains(ip))
            .copied()
            .or_else(|| chain.first().copied());
    }
    if headers.get_all("x-real-ip").iter().count() > 1 {
        return None;
    }
    if let Some(real) = headers.get("x-real-ip") {
        return real.to_str().ok()?.trim().parse().ok();
    }
    Some(peer)
}
