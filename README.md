# Custos (`custos`)

**Custos** (*Latin: "The Guardian / Sentinel"*) is an open-source, lightweight, single-binary Rust behavioral security engine and cross-platform firewall bouncer inspired by CrowdSec, powered by **TypeSafe AI's Jev (`POST https://api.typesafe.ai/v1/systemone`)** System-1 decision model.

Unlike traditional regex-only WAFs or heavy multi-daemon stacks, **Custos** operates both as an **embeddable Rust library (`custos`)** and a **single standalone binary** with **zero external `protoc` build requirement**:

1. **Tier 0 — Out-of-Band Log Tailer or Embedded Axum Middleware**: Tails Nginx Combined or JSON access logs asynchronously (or runs in-process via `custos_bouncer_middleware`) with zero latency impact on live user traffic.
2. **Tier 1 — L1 Fast Filter & Sliding Behavioral Windows**: Drops benign static asset hits, blocks volumetric floods at $0 token cost, caps tracked IPs (`max_tracked_ips = 50_000`) to prevent memory exhaustion under spoofed-IP DDoS, and aggregates per-IP sliding behavioral windows.
3. **Adversarial Log Sanitization**: Strips control characters and neutralizes prompt-injection payloads (`ignore previous instructions`, `"noul": 0.0`, etc.) in `User-Agent` and `URI` fields before building the Jev state.
4. **Tier 2 — Multi-Actor Jev (`/v1/systemone`) Batch Evaluation**: Evaluates up to 16 suspicious IP windows in a **single** `/v1/systemone` API call using native `noul` (ban conviction probability) and `choice` (threat classification) primitives with exponential-backoff retry.
5. **Dual Bouncers (HTTP Reverse-Proxy + Cross-Platform OS Kernel Firewall)**:
   - **HTTP Bouncer & Prometheus Telemetry**: Sub-millisecond `GET /v1/bouncer/check` for Nginx `auth_request` / Caddy `forward_auth` / Traefik `ForwardAuth`, plus OpenMetrics `GET /metrics`.
   - **Cross-Platform OS Firewall Bouncer**: Translates active bans into native kernel firewall rules across **macOS / BSD (`pfctl`)**, **Linux (`nftables` and `ipset`)**, and **Windows (`netsh advfirewall`)** with **single-command batched execution** (`ban_ips_batch`).
6. **Tier 3 — CustosHub gRPC Threat-Intelligence Fleet Sync (`tonic` + `prost` HTTP/2)**:
   - Multiplexed HTTP/2 binary Protobuf streaming (`StreamIntel`, `PushSignals`, `PullDeltas`).
   - **Canary Anti-Poisoning Guardrail**: Rejects private RFC1918, loopback, link-local, CGNAT, and critical public DNS/CDN IPs (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`).
   - **Multi-Node Quorum Consensus** & **Monotonic Sequence Cursors (`seq`)**.

---

## Quick Start (CLI)

### 1. Replay & Analyze Access Logs (Offline or Live Jev)
```bash
# Offline deterministic simulation (--mock-jev)
cargo run -- replay --log tests/fixtures/sample_access.log --mock-jev

# Live TypeSafe Jev (/v1/systemone) evaluation
export TYPESAFE_API_KEY="ts_live_..."
cargo run -- replay --log tests/fixtures/sample_access.log
```

### 2. Cross-Platform OS Firewall Preview & Live Kernel Enforcement
```bash
# Preview batched commands for macOS/BSD pf, Linux nftables, Linux ipset, and Windows netsh
cargo run -- firewall --backend all

# Enforce active bans in the live macOS Packet Filter (`pf`) kernel table
sudo cargo run -- firewall --backend pf --live
sudo pfctl -t custos_block -T show
```

### 3. Multi-Node gRPC Threat-Intelligence Hub (`CustosHubService`)
```bash
# Terminal 1: Start the gRPC Hub server
cargo run -- hub --listen 127.0.0.1:50051 --quorum 1

# Terminal 2: Replay logs on Node A and push convicted signals + L1 signatures to the Hub
cargo run -- replay --log tests/fixtures/sample_access.log --mock-jev --hub http://127.0.0.1:50051 --node-id node-a

# Terminal 2: Pull incremental binary deltas on Node B and apply in 1 batched OS firewall call
cargo run -- hub-sync --hub http://127.0.0.1:50051 --since-seq 0
```

---

## Embedding `custos` as a Rust Library

Because `custos` vendors its generated Protobuf/gRPC bindings (`src/hub_proto.rs`), downstream Rust applications can depend on `custos` with **zero `protoc` system requirement**:

```rust
use axum::{Router, middleware, routing::get};
use custos::SecurityPipeline;
use custos::firewall::FirewallBackend;
use custos::middleware::custos_bouncer_middleware;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pipeline = SecurityPipeline::builder()
        .with_decisions_file("decisions.jsonl")
        .with_firewall_backend(FirewallBackend::Auto, true)
        .with_mock_jev(true)
        .build()?;

    let app = Router::new()
        .route("/api/v1/items", get(|| async { "protected content" }))
        .layer(middleware::from_fn_with_state(
            pipeline,
            custos_bouncer_middleware,
        ));
    # drop(app);
    Ok(())
}
```

Run the included example:
```bash
cargo run --example axum_embedded
```

---

## License

MIT License — see [LICENSE](LICENSE).
