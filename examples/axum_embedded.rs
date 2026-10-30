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
            if let Err(error) = bg_pipeline.flush_and_analyze(false).await {
                eprintln!("Analysis failed; retained work will retry: {error}");
            }
        }
    });

    let maintenance = pipeline.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let worker = maintenance.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || worker.reconcile_firewall())
                .await
                .unwrap_or_else(|e| Err(e.into()))
            {
                eprintln!("Enforcement reconciliation failed; will retry: {error}");
            }
        }
    });

    // 3. Attach `custos_bouncer_middleware` to any Axum router
    let app: Router = Router::new()
        .route("/api/v1/items", get(|| async { "protected content" }))
        .layer(middleware::from_fn_with_state(
            pipeline.clone(),
            custos_bouncer_middleware,
        ));

    println!(
        "Custos embedded Axum router initialized (firewall backend = {})",
        pipeline.firewall.resolved_backend().as_str()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
