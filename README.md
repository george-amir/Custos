# JevSec (`jevsec`)

An open-source, lightweight, single-binary Rust behavioral security engine inspired by CrowdSec, purpose-built around **TypeSafe AI’s Jev (`POST https://api.typesafe.ai/v1/systemone`)** System-1 decision model.

## Why JevSec?

Traditional WAFs rely on brittle static regexes, while generative LLMs are too slow and expensive to analyze HTTP access logs at scale. **JevSec** combines deterministic L1 filtering with **compacted multi-actor batch evaluation** on TypeSafe's Jev model:

1. **Zero Request Latency (Out-of-Band Log Tailing)**: Tails Nginx, Apache, or Caddy access logs (combined or JSON format) asynchronously with inode/rotation awareness.
2. **L1 Fast Filter & Sliding IP Windows**: Drops benign static assets (`.css`, `.js`, `.png`, `/healthz`), triggers instant L1 bans on volumetric floods, and groups traffic into per-IP behavioral windows.
3. **Sanitized Multi-Actor Batching for Jev**: Packs up to 25 suspicious IP windows into a single `POST https://api.typesafe.ai/v1/systemone` call using native `noul` (calibrated maliciousness probability `0.0–1.0`) and `choice` (threat classification + confidence) questions.
4. **Prompt-Injection Hardened**: Strips control characters, truncates untrusted URIs/User-Agents, and flags adversarial prompt-injection attempts inside HTTP headers.
5. **Auto-Signature Caching**: When Jev convicts an exploit pattern with high confidence (`>= 0.92`), JevSec caches the normalized `(method, path_prefix)` signature locally so subsequent botnet peers are blocked at L1 with **0 AI tokens**.
6. **Built-in Bouncer HTTP API**: Sub-millisecond IP checks (`GET /v1/bouncer/check?ip=<IP>`) ready for Nginx `auth_request`, Caddy `forward_auth`, or firewall sync scripts.

---

## Quick Start

### 1. Replay & Analyze a Sample Access Log (Offline / Mock Jev Mode)

```bash
cargo run -- replay --log tests/fixtures/sample_access.log --mock-jev
```

### 2. Run with Live TypeSafe Jev API

```bash
export TYPESAFE_API_KEY="ts_live_..."
cargo run -- replay --log tests/fixtures/sample_access.log
```

### 3. Run the Real-Time Daemon + Bouncer HTTP Server

```bash
cp config.example.toml config.toml
cargo run -- run --config config.toml --from-start
```

Query active bans, bouncer status, or pipeline telemetry from another terminal:

```bash
cargo run -- decisions
cargo run -- check 198.51.100.44
cargo run -- stats
```

---

## Nginx `auth_request` Bouncer Integration

```nginx
location = /_jevsec_bouncer {
    internal;
    proxy_pass http://127.0.0.1:8085/v1/bouncer/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $remote_addr;
}

server {
    listen 80;
    auth_request /_jevsec_bouncer;
    # ...
}
```
