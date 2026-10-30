pub use crate::hub_proto as proto;

use crate::SecurityPipeline;
use crate::jev::ActorVerdict;
use crate::store::DecisionSource;
use crate::window::normalize_path_prefix;
use anyhow::{Context, Result};
use dashmap::DashMap;
use proto::custos_hub_service_client::CustosHubServiceClient;
use proto::custos_hub_service_server::{CustosHubService, CustosHubServiceServer};
use proto::{
    HubDeltaBatch, IpBanDelta, IpSignal, NodeStreamMessage, PullRequest, PushAck, SignalBatch,
    SignatureDelta, SignatureSignal, ThreatClassProto,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

/// Encodes an `IpAddr` into compact binary form (4 bytes for IPv4, 16 bytes for IPv6).
pub fn ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Decodes a compact 4-byte or 16-byte slice back into an `IpAddr`.
pub fn bytes_to_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(arr)))
        }
        16 => {
            let arr: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => None,
    }
}

pub fn threat_str_to_proto(threat: &str) -> ThreatClassProto {
    match threat {
        "benign_traffic" => ThreatClassProto::BenignTraffic,
        "credential_stuffing" => ThreatClassProto::CredentialStuffing,
        "sqli_or_injection" => ThreatClassProto::SqliOrInjection,
        "path_traversal_lfi" => ThreatClassProto::PathTraversalLfi,
        "vulnerability_scanner" => ThreatClassProto::VulnerabilityScanner,
        "api_enumeration_idor" => ThreatClassProto::ApiEnumerationIdor,
        "layer7_dos" => ThreatClassProto::Layer7Dos,
        _ => ThreatClassProto::ThreatClassUnspecified,
    }
}

pub fn proto_to_threat_str(proto: ThreatClassProto) -> &'static str {
    match proto {
        ThreatClassProto::BenignTraffic => "benign_traffic",
        ThreatClassProto::CredentialStuffing => "credential_stuffing",
        ThreatClassProto::SqliOrInjection => "sqli_or_injection",
        ThreatClassProto::PathTraversalLfi => "path_traversal_lfi",
        ThreatClassProto::VulnerabilityScanner => "vulnerability_scanner",
        ThreatClassProto::ApiEnumerationIdor => "api_enumeration_idor",
        ThreatClassProto::Layer7Dos => "layer7_dos",
        ThreatClassProto::ThreatClassUnspecified => "unknown_threat",
    }
}

/// Canary Anti-Poisoning Guardrail:
/// Rejects loopback, private RFC1918, link-local, CGNAT, multicast, and critical public
/// DNS/CDN infrastructure IPs so a misconfigured or malicious node can never poison the Hub.
pub fn is_protected_canary_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
            {
                return true;
            }
            // CGNAT 100.64.0.0/10
            if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
                return true;
            }
            // Critical public DNS resolvers (Cloudflare 1.1.1.1/1.0.0.1, Google 8.8.8.8/8.8.4.4, Quad9 9.9.9.9)
            matches!(
                octets,
                [1, 1, 1, 1]
                    | [1, 0, 0, 1]
                    | [8, 8, 8, 8]
                    | [8, 8, 4, 4]
                    | [9, 9, 9, 9]
                    | [149, 112, 112, 112]
            )
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || v6.is_unique_local()
        }
    }
}

/// Prevents generic root or authentication routes from being globally auto-blocked by path prefix alone.
pub fn is_protected_route_prefix(path: &str) -> bool {
    let lower = path.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "" | "/"
            | "/login"
            | "/signin"
            | "/signup"
            | "/logout"
            | "/api"
            | "/api/v1"
            | "/health"
            | "/healthz"
            | "/readyz"
            | "/metrics"
    )
}

#[derive(Debug, Clone)]
enum DeltaEntry {
    Ip(IpBanDelta),
    Signature(SignatureDelta),
}

impl DeltaEntry {
    fn seq(&self) -> u64 {
        match self {
            Self::Ip(d) => d.seq,
            Self::Signature(s) => s.seq,
        }
    }
}

/// Core consensus and monotonic delta engine for `jevsec hub`.
pub struct HubEngine {
    quorum_min_nodes: usize,
    next_seq: AtomicU64,
    ip_voters: DashMap<IpAddr, HashSet<String>>,
    promoted_ips: DashMap<IpAddr, u64>,
    sig_voters: DashMap<(String, String), HashSet<String>>,
    promoted_sigs: DashMap<(String, String), u64>,
    delta_log: RwLock<Vec<DeltaEntry>>,
    broadcaster: broadcast::Sender<HubDeltaBatch>,
}

impl HubEngine {
    pub fn new(quorum_min_nodes: usize) -> Self {
        let (broadcaster, _) = broadcast::channel(1024);
        Self {
            quorum_min_nodes: quorum_min_nodes.max(1),
            next_seq: AtomicU64::new(1),
            ip_voters: DashMap::new(),
            promoted_ips: DashMap::new(),
            sig_voters: DashMap::new(),
            promoted_sigs: DashMap::new(),
            delta_log: RwLock::new(Vec::new()),
            broadcaster,
        }
    }

    pub fn latest_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HubDeltaBatch> {
        self.broadcaster.subscribe()
    }

    /// Ingests a `SignalBatch` from an edge node, applies canary anti-poisoning checks,
    /// updates multi-node quorum sets, appends newly promoted items to the monotonic delta log,
    /// and broadcasts real-time updates to all active gRPC stream subscribers.
    pub fn ingest_batch(&self, batch: SignalBatch) -> PushAck {
        let node_id = if batch.node_id.trim().is_empty() {
            "anonymous-node".to_string()
        } else {
            batch.node_id.trim().to_string()
        };

        let mut accepted_ips = 0u32;
        let mut accepted_signatures = 0u32;
        let mut rejected_canary = 0u32;
        let mut new_ip_deltas = Vec::new();
        let mut new_sig_deltas = Vec::new();

        for sig in batch.ip_signals {
            let Some(ip) = bytes_to_ip(&sig.ip) else {
                continue;
            };
            if is_protected_canary_ip(&ip) {
                rejected_canary += 1;
                warn!(node_id = %node_id, ip = %ip, "Rejected canary/protected IP signal from node");
                continue;
            }
            accepted_ips += 1;

            if self.promoted_ips.contains_key(&ip) {
                continue;
            }

            let mut voters = self.ip_voters.entry(ip).or_default();
            voters.insert(node_id.clone());
            let vote_count = voters.len();
            drop(voters);

            if vote_count >= self.quorum_min_nodes {
                let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
                self.promoted_ips.insert(ip, seq);
                let delta = IpBanDelta {
                    seq,
                    ip: ip_to_bytes(ip),
                    threat: sig.threat,
                    noul: sig.noul,
                    confidence: sig.confidence,
                    ttl_secs: sig.suggested_ttl_secs.max(300),
                };
                new_ip_deltas.push(delta);
                info!(
                    seq,
                    ip = %ip,
                    voters = vote_count,
                    "Promoted IP ban to global JevHub delta feed"
                );
            }
        }

        for sig in batch.signature_signals {
            let method = sig.method.trim().to_uppercase();
            let prefix = normalize_path_prefix(&sig.path_prefix);
            if is_protected_route_prefix(&prefix) {
                rejected_canary += 1;
                warn!(
                    node_id = %node_id,
                    path = %prefix,
                    "Rejected protected route prefix from global L1 signature feed"
                );
                continue;
            }
            accepted_signatures += 1;

            let key = (method.clone(), prefix.clone());
            if self.promoted_sigs.contains_key(&key) {
                continue;
            }

            let mut voters = self.sig_voters.entry(key.clone()).or_default();
            voters.insert(node_id.clone());
            let vote_count = voters.len();
            drop(voters);

            if vote_count >= self.quorum_min_nodes {
                let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
                self.promoted_sigs.insert(key, seq);
                let delta = SignatureDelta {
                    seq,
                    method: method.clone(),
                    path_prefix: prefix.clone(),
                    threat: sig.threat,
                };
                new_sig_deltas.push(delta);
                info!(
                    seq,
                    method = %method,
                    path_prefix = %prefix,
                    voters = vote_count,
                    "Promoted zero-day L1 signature to global JevHub delta feed"
                );
            }
        }

        if !new_ip_deltas.is_empty() || !new_sig_deltas.is_empty() {
            if let Ok(mut guard) = self.delta_log.write() {
                for d in &new_ip_deltas {
                    guard.push(DeltaEntry::Ip(d.clone()));
                }
                for s in &new_sig_deltas {
                    guard.push(DeltaEntry::Signature(s.clone()));
                }
            }

            let latest_seq = self.latest_seq();
            let push_batch = HubDeltaBatch {
                latest_seq,
                ip_deltas: new_ip_deltas,
                signature_deltas: new_sig_deltas,
            };
            let _ = self.broadcaster.send(push_batch);
        }

        PushAck {
            accepted_ips,
            accepted_signatures,
            rejected_canary,
            latest_seq: self.latest_seq(),
        }
    }

    /// Returns all delta items with `seq > since_seq`.
    pub fn pull_since(&self, since_seq: u64) -> HubDeltaBatch {
        let mut ip_deltas = Vec::new();
        let mut signature_deltas = Vec::new();

        if let Ok(guard) = self.delta_log.read() {
            for entry in guard.iter() {
                if entry.seq() > since_seq {
                    match entry {
                        DeltaEntry::Ip(d) => ip_deltas.push(d.clone()),
                        DeltaEntry::Signature(s) => signature_deltas.push(s.clone()),
                    }
                }
            }
        }

        HubDeltaBatch {
            latest_seq: self.latest_seq(),
            ip_deltas,
            signature_deltas,
        }
    }
}

/// gRPC server implementation of `CustosHubService`.
#[derive(Clone)]
pub struct CustosHubGrpcService {
    pub engine: Arc<HubEngine>,
}

/// Backwards-compatible alias for `CustosHubGrpcService`.
pub type JevHubGrpcService = CustosHubGrpcService;

impl CustosHubGrpcService {
    pub fn new(engine: Arc<HubEngine>) -> Self {
        Self { engine }
    }

    pub fn into_server(self) -> CustosHubServiceServer<Self> {
        CustosHubServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl CustosHubService for CustosHubGrpcService {
    async fn push_signals(
        &self,
        request: Request<SignalBatch>,
    ) -> Result<Response<PushAck>, Status> {
        let ack = self.engine.ingest_batch(request.into_inner());
        Ok(Response::new(ack))
    }

    async fn pull_deltas(
        &self,
        request: Request<PullRequest>,
    ) -> Result<Response<HubDeltaBatch>, Status> {
        let req = request.into_inner();
        let deltas = self.engine.pull_since(req.since_seq);
        Ok(Response::new(deltas))
    }

    type StreamIntelStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<HubDeltaBatch, Status>> + Send + 'static>>;

    async fn stream_intel(
        &self,
        request: Request<Streaming<NodeStreamMessage>>,
    ) -> Result<Response<Self::StreamIntelStream>, Status> {
        let mut inbound = request.into_inner();
        let engine = self.engine.clone();
        let mut broadcast_rx = engine.subscribe();
        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            let mut initialized_catchup = false;

            loop {
                tokio::select! {
                    msg_opt = inbound.next() => {
                        match msg_opt {
                            Some(Ok(msg)) => {
                                if !initialized_catchup {
                                    initialized_catchup = true;
                                    let catchup = engine.pull_since(msg.since_seq);
                                    if (!catchup.ip_deltas.is_empty() || !catchup.signature_deltas.is_empty())
                                        && tx.send(Ok(catchup)).await.is_err()
                                    {
                                        break;
                                    }
                                }
                                if let Some(signals) = msg.signals
                                    && (!signals.ip_signals.is_empty() || !signals.signature_signals.is_empty())
                                {
                                    engine.ingest_batch(signals);
                                }
                            }
                            Some(Err(err)) => {
                                debug!(error = %err, "Node gRPC stream closed with error");
                                break;
                            }
                            None => break,
                        }
                    }
                    bcast = broadcast_rx.recv() => {
                        if let Ok(delta_batch) = bcast
                            && tx.send(Ok(delta_batch)).await.is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output_stream)))
    }
}

/// Converts a slice of local `ActorVerdict`s from Jev into a compact Protobuf `SignalBatch`.
pub fn build_signal_batch_from_verdicts(
    node_id: &str,
    api_token: &str,
    verdicts: &[ActorVerdict],
    default_ttl_secs: u64,
) -> SignalBatch {
    let mut ip_signals = Vec::new();
    let mut signature_signals = Vec::new();

    for v in verdicts {
        if !v.should_ban {
            continue;
        }
        let threat_proto = threat_str_to_proto(&v.threat_class);
        ip_signals.push(IpSignal {
            ip: ip_to_bytes(v.client_ip),
            threat: threat_proto as i32,
            noul: v.noul_malicious_prob as f32,
            confidence: v.choice_confidence as f32,
            suggested_ttl_secs: default_ttl_secs as u32,
        });

        if v.recommend_auto_signature
            && let Some(first) = v.sample_requests.first()
        {
            let mut parts = first.split_whitespace();
            if let (Some(method), Some(uri)) = (parts.next(), parts.next()) {
                let path = uri.split('?').next().unwrap_or(uri);
                let prefix = normalize_path_prefix(path);
                signature_signals.push(SignatureSignal {
                    method: method.to_uppercase(),
                    path_prefix: prefix,
                    threat: threat_proto as i32,
                    confidence: v.choice_confidence as f32,
                });
            }
        }
    }

    SignalBatch {
        node_id: node_id.to_string(),
        api_token: api_token.to_string(),
        ip_signals,
        signature_signals,
    }
}

/// Applies a `HubDeltaBatch` received over gRPC to the local `SecurityPipeline`:
/// - Upserts all new IP bans into `DecisionStore`
/// - Registers all new L1 signatures in `SlidingWindowEngine`
/// - Executes a **single batched OS firewall command** (`ban_ips_batch`) for all new IPs
pub fn apply_hub_delta_to_pipeline(
    pipeline: &SecurityPipeline,
    delta: &HubDeltaBatch,
) -> Result<(usize, usize)> {
    let mut new_fw_entries: Vec<(IpAddr, u64)> = Vec::new();
    let mut applied_ips = 0usize;
    let mut applied_sigs = 0usize;

    for ip_delta in &delta.ip_deltas {
        let Some(ip) = bytes_to_ip(&ip_delta.ip) else {
            continue;
        };
        if pipeline.store.check_ip(&ip).is_some() {
            continue;
        }
        let threat_proto = ThreatClassProto::try_from(ip_delta.threat)
            .unwrap_or(ThreatClassProto::ThreatClassUnspecified);
        let threat_str = proto_to_threat_str(threat_proto).to_string();
        let ttl = (ip_delta.ttl_secs as u64).max(60);

        pipeline.store.upsert_ban(
            ip,
            threat_str,
            DecisionSource::HubCommunity,
            ip_delta.noul as f64,
            ip_delta.confidence as f64,
            format!("Synced from CustosHub (seq={})", ip_delta.seq),
            Some(ttl),
        )?;
        new_fw_entries.push((ip, ttl));
        applied_ips += 1;
    }

    for sig_delta in &delta.signature_deltas {
        let threat_proto = ThreatClassProto::try_from(sig_delta.threat)
            .unwrap_or(ThreatClassProto::ThreatClassUnspecified);
        let threat_str = proto_to_threat_str(threat_proto);
        pipeline.window.register_auto_signature(
            &sig_delta.method,
            &sig_delta.path_prefix,
            threat_str,
        );
        applied_sigs += 1;
    }

    // Apply all newly learned Hub IPs in a single batched OS firewall invocation
    if !new_fw_entries.is_empty() {
        let _ = pipeline.firewall.ban_ips_batch(&new_fw_entries);
    }

    Ok((applied_ips, applied_sigs))
}

/// High-level gRPC client helper for pushing signals and pulling/streaming deltas from CustosHub.
pub async fn push_verdicts_via_grpc(
    endpoint: &str,
    node_id: &str,
    api_token: &str,
    verdicts: &[ActorVerdict],
    default_ttl_secs: u64,
) -> Result<PushAck> {
    let batch = build_signal_batch_from_verdicts(node_id, api_token, verdicts, default_ttl_secs);
    let mut client = CustosHubServiceClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("Failed to connect to CustosHub gRPC server at {endpoint}"))?;
    let resp = client.push_signals(Request::new(batch)).await?;
    Ok(resp.into_inner())
}

pub async fn pull_and_apply_via_grpc(
    endpoint: &str,
    node_id: &str,
    since_seq: u64,
    pipeline: &SecurityPipeline,
) -> Result<(u64, usize, usize)> {
    let mut client = CustosHubServiceClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("Failed to connect to CustosHub gRPC server at {endpoint}"))?;
    let resp = client
        .pull_deltas(Request::new(PullRequest {
            node_id: node_id.to_string(),
            since_seq,
        }))
        .await?;
    let delta = resp.into_inner();
    let (ips, sigs) = apply_hub_delta_to_pipeline(pipeline, &delta)?;
    Ok((delta.latest_seq, ips, sigs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_guardrail_blocks_private_and_dns_ips() {
        assert!(is_protected_canary_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_protected_canary_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_protected_canary_ip(&"192.168.1.50".parse().unwrap()));
        assert!(is_protected_canary_ip(&"1.1.1.1".parse().unwrap()));
        assert!(is_protected_canary_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_protected_canary_ip(&"198.51.100.44".parse().unwrap()));
        assert!(!is_protected_canary_ip(&"203.0.113.88".parse().unwrap()));
    }

    #[test]
    fn test_hub_quorum_consensus_and_monotonic_delta_seq() {
        let engine = HubEngine::new(2); // Require 2 distinct nodes for consensus
        let bad_ip: IpAddr = "198.51.100.44".parse().unwrap();

        // Node 1 reports `198.51.100.44` -> should NOT promote yet (1 < 2)
        let ack1 = engine.ingest_batch(SignalBatch {
            node_id: "node-1".to_string(),
            api_token: String::new(),
            ip_signals: vec![IpSignal {
                ip: ip_to_bytes(bad_ip),
                threat: ThreatClassProto::SqliOrInjection as i32,
                noul: 0.97,
                confidence: 1.0,
                suggested_ttl_secs: 3600,
            }],
            signature_signals: vec![],
        });
        assert_eq!(ack1.accepted_ips, 1);
        assert_eq!(ack1.latest_seq, 0);
        assert!(engine.pull_since(0).ip_deltas.is_empty());

        // Same Node 1 reports again -> still 1 unique voter, no promotion
        engine.ingest_batch(SignalBatch {
            node_id: "node-1".to_string(),
            api_token: String::new(),
            ip_signals: vec![IpSignal {
                ip: ip_to_bytes(bad_ip),
                threat: ThreatClassProto::SqliOrInjection as i32,
                noul: 0.97,
                confidence: 1.0,
                suggested_ttl_secs: 3600,
            }],
            signature_signals: vec![],
        });
        assert_eq!(engine.latest_seq(), 0);

        // Independent Node 2 reports `198.51.100.44` -> reaches quorum (2 >= 2), promoted with seq=1!
        let ack2 = engine.ingest_batch(SignalBatch {
            node_id: "node-2".to_string(),
            api_token: String::new(),
            ip_signals: vec![IpSignal {
                ip: ip_to_bytes(bad_ip),
                threat: ThreatClassProto::SqliOrInjection as i32,
                noul: 0.96,
                confidence: 0.98,
                suggested_ttl_secs: 3600,
            }],
            signature_signals: vec![],
        });
        assert_eq!(ack2.latest_seq, 1);

        let delta = engine.pull_since(0);
        assert_eq!(delta.ip_deltas.len(), 1);
        assert_eq!(bytes_to_ip(&delta.ip_deltas[0].ip).unwrap(), bad_ip);
    }
}
