# Security Policy

As an autonomous behavioral security engine and OS firewall bouncer, **Custos** treats security vulnerabilities with the highest priority.

## Supported Versions

Only the latest minor release series receives security patches and advisories:

| Version | Supported          |
| ------- | ------------------ |
| `0.2.x` | :white_check_mark: |
| `< 0.2` | :x:                |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report vulnerabilities privately using **GitHub Private Vulnerability Reporting**:
- **Report Privately**: [https://github.com/george-amir/Custos/security/advisories/new](https://github.com/george-amir/Custos/security/advisories/new)

### What to Include in Your Report
To help us triage and reproduce the issue quickly, please include:
1. **Affected Component**: (`firewall`, `sanitizer`, `window`, `jev`, `hub`, `bouncer_api`, or `service`).
2. **Reproduction Steps / PoC**: A minimal log payload, HTTP/gRPC request, or `config.toml` that triggers the issue.
3. **Impact Assessment**: What an attacker can achieve (e.g., command injection, ban evasion, false-positive self-DoS, memory exhaustion).

### Response Timeline & SLA
- **Acknowledgment**: Within **48 hours** of submission.
- **Triage & Severity Assessment**: Within **5 business days**.
- **Patch & Coordinated Disclosure**: Critical patches are targeted within **7–14 days**, followed by a GitHub Security Advisory (GHSA) and credit to the reporter (unless anonymity is requested).

---

## In-Scope Security Areas

We are especially interested in reports covering the following threat surfaces:

1. **OS Firewall Command Execution (`src/firewall.rs`)**
   - Any bypass of `std::net::IpAddr` validation or table-name sanitization that could lead to arbitrary command or argument injection in `pfctl`, `nft`, `ipset`, or `netsh.exe`.
2. **Adversarial Log & Prompt-Injection Bypass (`src/sanitizer.rs` & `src/jev.rs`)**
   - Crafted HTTP paths, query strings, or `User-Agent` headers that bypass control-character stripping and prompt-injection detection to trick the Jev `/v1/systemone` model into returning `benign` on malicious traffic or poisoning L1 auto-signatures.
3. **CustosHub Fleet Poisoning & Canary Bypass (`src/hub.rs`)**
   - Bypassing `CUSTOS_HUB_TOKEN` authentication, `quorum_min_nodes` consensus, or the Canary/RFC1918/loopback IP guardrail to trigger fleet-wide false-positive bans.
4. **Resource Exhaustion / Denial of Service (`src/window.rs` & `src/tailer.rs`)**
   - Bypassing the `max_tracked_ips` cap (`50,000` default) or line-length truncation to cause OOM crashes or CPU starvation during high-volume spoofed-IP floods.
5. **Bouncer API Authorization Bypass (`src/bouncer_api.rs`)**
   - Mutating `/v1/decisions` (`POST`/`DELETE`) without a valid `Authorization: Bearer <CUSTOS_API_TOKEN>`.

---

## Out of Scope

- Denial of Service caused by intentionally misconfiguring `max_tracked_ips` to an unbounded value or exposing an unauthenticated `bouncer_listen` port (`0.0.0.0:9480`) to the public internet without setting `CUSTOS_API_TOKEN`.
- Rate limiting or availability of the upstream TypeSafe AI API (`https://api.typesafe.ai/v1/systemone`).

---

## Operator Hardening Checklist

When deploying `custos` in production, we strongly recommend:
1. **Bind Bouncer API Locally**: Keep `bouncer_listen = "127.0.0.1:9480"` so only local reverse proxies (NGINX, Caddy, Envoy) can query `/v1/bouncer/check`.
2. **Enforce Bearer Tokens**: Always set `CUSTOS_API_TOKEN` (for local admin mutations) and `CUSTOS_HUB_TOKEN` (for multi-node gRPC `CustosHub` sync).
3. **Least-Privilege Linux Capabilities**: Use `sudo custos service install` on Linux so `systemd` runs `custos` with bounded `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` and `ProtectSystem=strict`.
4. **Multi-Node Quorum**: In multi-server `CustosHub` deployments, set `quorum_min_nodes = 2` (or higher) so a single compromised edge node cannot unilaterally broadcast global bans.
