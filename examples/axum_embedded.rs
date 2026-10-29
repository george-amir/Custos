//! Example: Embedding `custos` directly inside an Axum web application.
//!
//! Run with:
//! ```bash
//! cargo run --example axum_embedded
//! ```

use axum::routing::get;
use axum::{Router, middleware};
use custos::SecurityPipeline;
use custos::firewall::FirewallBackend;
use custos::middleware::custos_bouncer_middleware;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Build an embedded Custos pipeline using the ergonomic builder API
    let pipeline = SecurityPipeline::builder()
        .with_decisions_file("decisions.jsonl")
        .with_firewall_backend(FirewallBackend::Auto, true)
        .with_mock_jev(true) // Set false + TYPESAFE_API_KEY for live TypeSafe Jev (/v1/systemone)
        .build()?;

    // 2. Spawn background periodic flush to evaluate suspicious IP windows via Jev
    let bg_pipeline = pipeline.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let _ = bg_pipeline.flush_and_analyze(false).await;
        }
    });

    // 3. Attach `custos_bouncer_middleware` to any Axum router
    let _app: Router = Router::new()
        .route("/api/v1/items", get(|| async { "protected content" }))
        .layer(middleware::from_fn_with_state(
            pipeline.clone(),
            custos_bouncer_middleware,
        ));

    println!(
        "Custos embedded Axum router initialized (firewall backend = {})",
        pipeline.firewall.resolved_backend().as_str()
    );
    Ok(())
}
