pub use crate::hub_proto as proto;

use crate::jev::ActorVerdict;
use crate::limits::{MAX_HUB_BATCH, MAX_HUB_VOTERS, MAX_SIGNATURE_BYTES, MemoryLimits};
use crate::store::DecisionSource;
use crate::{SecurityPipeline, proven_signature_for_verdict};
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};

use proto::custos_hub_service_client::CustosHubServiceClient;
use proto::custos_hub_service_server::{CustosHubService, CustosHubServiceServer};
use proto::{
    HubDeltaBatch, IpBanDelta, IpSignal, NodeStreamMessage, PullRequest, PushAck, SignalBatch,
    SignatureDelta, SignatureSignal, ThreatClassProto,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::warn;

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

/// State and its cursor are committed under one lock. A published cursor never
/// refers to an entry that a reader could not have observed.
#[derive(Default)]
struct Votes {
    nodes: HashSet<String>,
    expires: i64,
}

#[derive(Default)]
struct HubState {
    latest_seq: u64,
    last_expire: i64,
    ip_voters: HashMap<IpAddr, Votes>,
    promoted_ips: HashMap<IpAddr, i64>,
    sig_voters: HashMap<(String, String), Votes>,
    promoted_sigs: HashMap<(String, String), i64>,
    delta_log: Vec<DeltaEntry>,
}

impl HubState {
    fn expire(&mut self, now: i64) {
        if self.last_expire == now {
            return;
        }
        self.last_expire = now;
        self.promoted_ips.retain(|_, expiry| *expiry > now);
        self.promoted_sigs.retain(|_, expiry| *expiry > now);
        self.ip_voters.retain(|_, votes| votes.expires > now);
        self.sig_voters.retain(|_, votes| votes.expires > now);
        self.delta_log.retain(|entry| match entry {
            DeltaEntry::Ip(delta) => delta.expires_at_unix_secs > now,
            DeltaEntry::Signature(delta) => self
                .promoted_sigs
                .contains_key(&(delta.method.clone(), delta.path_prefix.clone())),
        });
    }
}

/// Core consensus engine. Callers of ingest_batch must provide an authenticated
/// node identity; network callers are authenticated by CustosHubGrpcService.
pub struct HubEngine {
    quorum_min_nodes: usize,
    limits: MemoryLimits,
    pub capacity_rejected: AtomicU64,
    state: Mutex<HubState>,
    broadcaster: broadcast::Sender<HubDeltaBatch>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl HubEngine {
    pub fn new(quorum_min_nodes: usize) -> Self {
        Self::with_clock(
            quorum_min_nodes,
            Arc::new(|| chrono::Utc::now().timestamp()),
        )
    }

    /// Clock injection permits deterministic expiry checks by embedders and tests.
    pub fn with_clock(quorum_min_nodes: usize, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self::with_limits_and_clock(quorum_min_nodes, MemoryLimits::default(), clock)
    }

    pub fn with_limits(quorum_min_nodes: usize, limits: MemoryLimits) -> Self {
        Self::with_limits_and_clock(
            quorum_min_nodes,
            limits,
            Arc::new(|| chrono::Utc::now().timestamp()),
        )
    }

    pub fn with_limits_and_clock(
        quorum_min_nodes: usize,
        limits: MemoryLimits,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        let (broadcaster, _) = broadcast::channel(16);
        Self {
            quorum_min_nodes: quorum_min_nodes.max(1),
            limits,
            capacity_rejected: AtomicU64::new(0),
            state: Mutex::new(HubState::default()),
            broadcaster,
            clock,
        }
    }

    pub fn latest_seq(&self) -> u64 {
        self.state
            .lock()
            .expect("Hub state lock poisoned")
            .latest_seq
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HubDeltaBatch> {
        self.broadcaster.subscribe()
    }

    pub fn ingest_batch(&self, batch: SignalBatch) -> PushAck {
        let now = (self.clock)();
        let mut state = self.state.lock().expect("Hub state lock poisoned");
        state.expire(now);
        let mut ack = PushAck::default();
        if validate_batch(&batch).is_err() {
            ack.rejected_invalid = 1;
            ack.latest_seq = state.latest_seq;
            return ack;
        }
        let vote_expiry =
            now.saturating_add(self.limits.hub_retention_secs.min(i64::MAX as u64) as i64);
        let mut ip_deltas = Vec::new();
        let mut signature_deltas = Vec::new();
        for signal in batch.ip_signals {
            let Some(ip) = bytes_to_ip(&signal.ip) else {
                continue;
            };
            if is_protected_canary_ip(&ip) {
                ack.rejected_canary += 1;
                continue;
            }
            if state.promoted_ips.contains_key(&ip) {
                ack.accepted_ips += 1;
                continue;
            }
            if !state.ip_voters.contains_key(&ip)
                && state.ip_voters.len() + state.promoted_ips.len() >= self.limits.hub_max_entries
            {
                ack.rejected_capacity += 1;
                continue;
            }
            let voters = state.ip_voters.entry(ip).or_insert_with(|| Votes {
                nodes: HashSet::new(),
                expires: vote_expiry,
            });
            if !voters.nodes.contains(&batch.node_id) && voters.nodes.len() >= MAX_HUB_VOTERS {
                ack.rejected_capacity += 1;
                continue;
            }
            voters.nodes.insert(batch.node_id.clone());
            ack.accepted_ips += 1;
            if voters.nodes.len() >= self.quorum_min_nodes {
                state.latest_seq += 1;
                let ttl_secs = signal.suggested_ttl_secs.clamp(1, 86400);
                let expires_at_unix_secs = now.saturating_add(i64::from(ttl_secs));
                let delta = IpBanDelta {
                    seq: state.latest_seq,
                    ip: ip_to_bytes(ip),
                    threat: signal.threat,
                    noul: signal.noul,
                    confidence: signal.confidence,
                    ttl_secs,
                    expires_at_unix_secs,
                };
                state.ip_voters.remove(&ip);
                state.promoted_ips.insert(ip, expires_at_unix_secs);
                state.delta_log.push(DeltaEntry::Ip(delta.clone()));
                ip_deltas.push(delta);
            }
        }
        for signal in batch.signature_signals {
            let key = (
                signal.method.trim().to_uppercase(),
                signal.path_prefix.trim().to_string(),
            );
            if is_protected_route_prefix(&key.1) {
                ack.rejected_canary += 1;
                continue;
            }
            if state.promoted_sigs.contains_key(&key) {
                ack.accepted_signatures += 1;
                continue;
            }
            if !state.sig_voters.contains_key(&key)
                && state.sig_voters.len() + state.promoted_sigs.len() >= self.limits.max_signatures
            {
                ack.rejected_capacity += 1;
                continue;
            }
            let voters = state
                .sig_voters
                .entry(key.clone())
                .or_insert_with(|| Votes {
                    nodes: HashSet::new(),
                    expires: vote_expiry,
                });
            if !voters.nodes.contains(&batch.node_id) && voters.nodes.len() >= MAX_HUB_VOTERS {
                ack.rejected_capacity += 1;
                continue;
            }
            voters.nodes.insert(batch.node_id.clone());
            ack.accepted_signatures += 1;
            if voters.nodes.len() >= self.quorum_min_nodes {
                state.latest_seq += 1;
                let delta = SignatureDelta {
                    seq: state.latest_seq,
                    method: key.0.clone(),
                    path_prefix: key.1.clone(),
                    threat: signal.threat,
                };
                state.sig_voters.remove(&key);
                state.promoted_sigs.insert(key, vote_expiry);
                state.delta_log.push(DeltaEntry::Signature(delta.clone()));
                signature_deltas.push(delta);
            }
        }
        self.capacity_rejected
            .fetch_add(ack.rejected_capacity as u64, Ordering::Relaxed);
        ack.latest_seq = state.latest_seq;
        if !ip_deltas.is_empty() || !signature_deltas.is_empty() {
            // Sending while locked preserves publication order between concurrent writers.
            let _ = self.broadcaster.send(HubDeltaBatch {
                latest_seq: state.latest_seq,
                ip_deltas,
                signature_deltas,
            });
        }
        ack
    }

    /// (IP entries, signature entries, retained deltas). Includes votes below quorum.
    pub fn retained_counts(&self) -> (usize, usize, usize) {
        let mut state = self.state.lock().expect("Hub state lock poisoned");
        state.expire((self.clock)());
        (
            state.ip_voters.len() + state.promoted_ips.len(),
            state.sig_voters.len() + state.promoted_sigs.len(),
            state.delta_log.len(),
        )
    }

    pub fn pull_since(&self, since_seq: u64) -> HubDeltaBatch {
        let now = (self.clock)();
        let mut state = self.state.lock().expect("Hub state lock poisoned");
        state.expire(now);
        let since_seq = if since_seq > state.latest_seq {
            0
        } else {
            since_seq
        };
        let mut result = HubDeltaBatch {
            latest_seq: state.latest_seq,
            ..HubDeltaBatch::default()
        };
        for entry in &state.delta_log {
            if entry.seq() > since_seq {
                match entry {
                    DeltaEntry::Ip(delta) => {
                        let mut delta = delta.clone();
                        delta.ttl_secs = (delta.expires_at_unix_secs - now) as u32;
                        result.ip_deltas.push(delta);
                    }
                    DeltaEntry::Signature(delta) => result.signature_deltas.push(delta.clone()),
                }
            }
        }
        result
    }
}

fn validate_batch(batch: &SignalBatch) -> Result<(), &'static str> {
    use prost::Message;
    if batch.encoded_len() > 256 * 1024
        || batch.node_id.len() > 128
        || batch.ip_signals.len() + batch.signature_signals.len() > MAX_HUB_BATCH
        || batch
            .signature_signals
            .iter()
            .any(|s| s.method.len() > 32 || s.path_prefix.len() > MAX_SIGNATURE_BYTES)
    {
        return Err("Hub batch exceeds admission limits");
    }
    Ok(())
}

/// Every network RPC requires a credential. Distinct quorum voters require
/// distinct per-node tokens; a shared token represents exactly one voter.
#[derive(Clone)]
pub struct CustosHubGrpcService {
    pub engine: Arc<HubEngine>,
    shared_token: String,
    node_tokens: BTreeMap<String, String>,
    streams: Arc<tokio::sync::Semaphore>,
}

pub type JevHubGrpcService = CustosHubGrpcService;

impl CustosHubGrpcService {
    /// Constructs a deny-all service until explicit credentials are supplied.
    pub fn new(engine: Arc<HubEngine>) -> Self {
        let streams = Arc::new(tokio::sync::Semaphore::new(engine.limits.hub_max_streams));
        Self {
            engine,
            streams,
            shared_token: String::new(),
            node_tokens: BTreeMap::new(),
        }
    }

    pub fn with_auth(
        engine: Arc<HubEngine>,
        shared_token: String,
        node_tokens: BTreeMap<String, String>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !shared_token.is_empty() || !node_tokens.is_empty(),
            "Configure hub.api_token or hub.node_tokens before starting the Hub"
        );
        anyhow::ensure!(
            engine.quorum_min_nodes <= MAX_HUB_VOTERS,
            "Hub quorum exceeds the 64-voter bound"
        );
        anyhow::ensure!(
            node_tokens.keys().all(|node| node.len() <= 120),
            "Hub node identity exceeds 120 bytes"
        );
        let mut unique = HashSet::new();
        if !shared_token.is_empty() {
            unique.insert(shared_token.clone());
        }
        for (node, token) in &node_tokens {
            anyhow::ensure!(
                !node.trim().is_empty() && !token.is_empty(),
                "Hub node identities and credentials must be nonempty"
            );
            anyhow::ensure!(
                unique.insert(token.clone()),
                "Hub node credentials must be distinct"
            );
        }
        let streams = Arc::new(tokio::sync::Semaphore::new(engine.limits.hub_max_streams));
        Ok(Self {
            engine,
            streams,
            shared_token,
            node_tokens,
        })
    }

    fn authenticate(&self, node: &str, token: &str) -> Option<String> {
        if node.len() > 120 {
            return None;
        }
        if !self.shared_token.is_empty() && constant_time_eq(token, &self.shared_token) {
            return Some("shared-fleet-credential".to_string());
        }
        if let Some(expected) = self.node_tokens.get(node)
            && constant_time_eq(token, expected)
        {
            return Some(format!("node:{node}"));
        }
        None
    }

    fn authenticate_metadata<T>(&self, request: &Request<T>, node: &str) -> Option<String> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        self.authenticate(node, token)
    }

    pub fn into_server(self) -> CustosHubServiceServer<Self> {
        CustosHubServiceServer::new(self)
            .max_decoding_message_size(256 * 1024)
            .max_encoding_message_size(4 * 1024 * 1024)
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[tonic::async_trait]
impl CustosHubService for CustosHubGrpcService {
    async fn push_signals(
        &self,
        request: Request<SignalBatch>,
    ) -> Result<Response<PushAck>, Status> {
        let mut batch = request.into_inner();
        batch.node_id = self
            .authenticate(&batch.node_id, &batch.api_token)
            .ok_or_else(|| Status::unauthenticated("Invalid Hub credentials"))?;
        validate_batch(&batch).map_err(Status::resource_exhausted)?;
        Ok(Response::new(self.engine.ingest_batch(batch)))
    }

    async fn pull_deltas(
        &self,
        request: Request<PullRequest>,
    ) -> Result<Response<HubDeltaBatch>, Status> {
        self.authenticate_metadata(&request, &request.get_ref().node_id)
            .ok_or_else(|| Status::unauthenticated("Invalid Hub credentials"))?;
        Ok(Response::new(
            self.engine.pull_since(request.into_inner().since_seq),
        ))
    }

    type StreamIntelStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<HubDeltaBatch, Status>> + Send + 'static>>;

    async fn stream_intel(
        &self,
        request: Request<Streaming<NodeStreamMessage>>,
    ) -> Result<Response<Self::StreamIntelStream>, Status> {
        let node = request
            .metadata()
            .get("x-custos-node")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let authenticated_node = self
            .authenticate_metadata(&request, node)
            .ok_or_else(|| Status::unauthenticated("Invalid Hub credentials"))?;
        let stream_permit = self
            .streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("Hub stream capacity reached"))?;
        let mut inbound = request.into_inner();
        let engine = self.engine.clone();
        let broadcast_rx = engine.subscribe();
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let Ok(Some(Ok(first))) =
                tokio::time::timeout(Duration::from_secs(5), inbound.next()).await
            else {
                return;
            };
            // Every new connection starts with an active-state snapshot. Absolute
            // expiration makes this safe even after the Hub itself has restarted.
            let mut subscription = HubSubscription {
                engine: engine.clone(),
                receiver: broadcast_rx,
                cursor: 0,
            };
            let snapshot = engine.pull_since(0);
            subscription.cursor = snapshot.latest_seq;
            if tx.send(Ok(snapshot)).await.is_err() {
                return;
            }
            if let Some(mut signals) = first.signals {
                signals.node_id = authenticated_node.clone();
                let ack = engine.ingest_batch(signals);
                if ack.rejected_capacity > 0 || ack.rejected_invalid > 0 {
                    let _ = tx
                        .send(Err(Status::resource_exhausted(
                            "Hub signal capacity reached",
                        )))
                        .await;
                    return;
                }
            }
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    incoming = inbound.next() => match incoming {
                        Some(Ok(msg)) => if let Some(mut signals) = msg.signals {
                            signals.node_id = authenticated_node.clone();
                            let ack = engine.ingest_batch(signals);
                            if ack.rejected_capacity > 0 || ack.rejected_invalid > 0 {
                                let _ = tx.send(Err(Status::resource_exhausted("Hub signal capacity reached"))).await;
                                break;
                            }
                        },
                        _ => break,
                    },
                    delta = subscription.next() => match delta {
                        Some(delta) => if tx.send(Ok(delta)).await.is_err() { break; },
                        None => break,
                    }
                }
            }
        });
        // Tonic requires Result<_, Status>; this adapter only holds the permit and forwards items.
        #[allow(clippy::result_large_err)]
        let guarded = ReceiverStream::new(rx).map(move |item| {
            let _ = &stream_permit;
            item
        });
        Ok(Response::new(Box::pin(guarded)))
    }
}

/// Cursor-based delivery uses notifications only as a wakeup. The committed log
/// is authoritative, so lagging or coalesced notifications cannot lose deltas.
pub struct HubSubscription {
    engine: Arc<HubEngine>,
    receiver: broadcast::Receiver<HubDeltaBatch>,
    cursor: u64,
}

impl HubSubscription {
    pub fn new(engine: Arc<HubEngine>, since_seq: u64) -> Self {
        let receiver = engine.subscribe();
        Self {
            engine,
            receiver,
            cursor: since_seq,
        }
    }

    pub async fn next(&mut self) -> Option<HubDeltaBatch> {
        loop {
            let snapshot = self.engine.pull_since(self.cursor);
            if snapshot.latest_seq != self.cursor {
                self.cursor = snapshot.latest_seq;
                return Some(snapshot);
            }
            match self.receiver.recv().await {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Coalesce old notifications before reading the log again.
                    while let Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) =
                        self.receiver.try_recv()
                    {}
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
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

        if let Some((method, path_prefix)) = proven_signature_for_verdict(v) {
            signature_signals.push(SignatureSignal {
                method,
                path_prefix,
                threat: threat_proto as i32,
                confidence: v.choice_confidence as f32,
            });
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
    let _enforcement = pipeline.enforcement_guard()?;
    let mut new_fw_entries: Vec<(IpAddr, u64)> = Vec::new();
    let mut applied_ips = 0usize;
    let mut applied_sigs = 0usize;

    for ip_delta in &delta.ip_deltas {
        let Some(ip) = bytes_to_ip(&ip_delta.ip) else {
            continue;
        };
        if let Some(existing) = pipeline.store.check_ip(&ip) {
            // A persisted decision is desired state, not proof that the kernel
            // accepted a previous command. Reconcile it on every snapshot retry.
            let ttl = (existing.expires_at - chrono::Utc::now()).num_seconds();
            if ttl > 0 {
                new_fw_entries.push((ip, ttl as u64));
            }
            continue;
        }
        let threat_proto = ThreatClassProto::try_from(ip_delta.threat)
            .unwrap_or(ThreatClassProto::ThreatClassUnspecified);
        let threat_str = proto_to_threat_str(threat_proto).to_string();
        let remaining = chrono::DateTime::from_timestamp(ip_delta.expires_at_unix_secs, 0)
            .map(|deadline| (deadline - chrono::Utc::now()).num_seconds())
            .unwrap_or(0);
        // Legacy deltas without an absolute expiry cannot safely be replayed.
        if remaining <= 0 {
            continue;
        }
        let ttl = remaining as u64;

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
        anyhow::ensure!(
            pipeline.window.try_register_auto_signature(
                &sig_delta.method,
                &sig_delta.path_prefix,
                threat_str
            ),
            "Local signature capacity reached"
        );
        applied_sigs += 1;
    }

    // Apply all newly learned Hub IPs in a single batched OS firewall invocation
    if !new_fw_entries.is_empty() {
        pipeline.firewall.ban_ips_batch(&new_fw_entries)?;
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
    let mut client = CustosHubServiceClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("Failed to connect to CustosHub gRPC server at {endpoint}"))?;
    let mut total = PushAck::default();
    for chunk in verdicts.chunks(MAX_HUB_BATCH) {
        let batch = build_signal_batch_from_verdicts(node_id, api_token, chunk, default_ttl_secs);
        validate_batch(&batch).map_err(anyhow::Error::msg)?;
        let ack = client.push_signals(Request::new(batch)).await?.into_inner();
        total.accepted_ips = total.accepted_ips.saturating_add(ack.accepted_ips);
        total.accepted_signatures = total
            .accepted_signatures
            .saturating_add(ack.accepted_signatures);
        total.rejected_canary = total.rejected_canary.saturating_add(ack.rejected_canary);
        total.rejected_capacity = total
            .rejected_capacity
            .saturating_add(ack.rejected_capacity);
        total.rejected_invalid = total.rejected_invalid.saturating_add(ack.rejected_invalid);
        total.latest_seq = ack.latest_seq;
        if ack.rejected_capacity > 0 || ack.rejected_invalid > 0 {
            break;
        }
    }
    Ok(total)
}

pub async fn pull_and_apply_via_grpc(
    endpoint: &str,
    node_id: &str,
    api_token: &str,
    since_seq: u64,
    pipeline: &SecurityPipeline,
) -> Result<(u64, usize, usize)> {
    let mut client = CustosHubServiceClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("Failed to connect to CustosHub gRPC server at {endpoint}"))?;
    let resp = client
        .pull_deltas(authenticated_request(
            PullRequest {
                node_id: node_id.to_string(),
                since_seq,
            },
            node_id,
            api_token,
        )?)
        .await?;
    let delta = resp.into_inner();
    let (ips, sigs) = apply_hub_delta_to_pipeline(pipeline, &delta)?;
    Ok((delta.latest_seq, ips, sigs))
}

fn authenticated_request<T>(body: T, node_id: &str, token: &str) -> Result<Request<T>> {
    let mut request = Request::new(body);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .context("Invalid Hub token metadata")?,
    );
    request.metadata_mut().insert(
        "x-custos-node",
        node_id
            .parse()
            .context("Invalid Hub node identity metadata")?,
    );
    Ok(request)
}

/// Reconnects until the producer closes or this future is cancelled. Outbound
/// batches stay pending until PushSignals acknowledges them. Duplicate retries
/// are safe because votes are sets of authenticated identities.
pub async fn run_hub_sync(
    endpoint: String,
    node_id: String,
    api_token: String,
    pipeline: SecurityPipeline,
    mut signals: mpsc::Receiver<SignalBatch>,
) -> Result<()> {
    anyhow::ensure!(
        !api_token.is_empty(),
        "Configure hub.api_token before connecting to the Hub"
    );
    authenticated_request((), &node_id, &api_token)?;
    let endpoint = tonic::transport::Endpoint::from_shared(endpoint)?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    let mut pending: Option<SignalBatch> = None;
    let mut retry_delay = Duration::from_millis(100);
    loop {
        if signals.is_closed() && signals.is_empty() && pending.is_none() {
            return Ok(());
        }
        let result = async {
            let channel = endpoint.connect().await?;
            let mut client = CustosHubServiceClient::new(channel);
            let (handshake_tx, handshake_rx) = mpsc::channel(1);
            handshake_tx.send(NodeStreamMessage { node_id: node_id.clone(), since_seq: 0, signals: None }).await?;
            let request = authenticated_request(ReceiverStream::new(handshake_rx), &node_id, &api_token)?;
            let mut inbound = client.stream_intel(request).await?.into_inner();
            // Keep the outgoing half open until the session ends.
            let _handshake_tx = handshake_tx;
            loop {
                if let Some(batch) = pending.as_ref() {
                    validate_batch(batch).map_err(anyhow::Error::msg)?;
                    let mut batch = batch.clone();
                    batch.node_id = node_id.clone();
                    batch.api_token = api_token.clone();
                    validate_batch(&batch).map_err(anyhow::Error::msg)?;
                    let ack = client.push_signals(Request::new(batch)).await?.into_inner();
                    anyhow::ensure!(ack.rejected_capacity == 0 && ack.rejected_invalid == 0, "Hub admission rejected signals; retaining batch for retry");
                    pending = None;
                }
                tokio::select! {
                    delta = inbound.message() => {
                        let delta = delta?.context("Hub stream closed")?;
                        let pipeline = pipeline.clone();
                        tokio::task::spawn_blocking(move || apply_hub_delta_to_pipeline(&pipeline, &delta)).await??;
                        retry_delay = Duration::from_millis(100);
                    },
                    batch = signals.recv() => match batch {
                        Some(batch) => { validate_batch(&batch).map_err(anyhow::Error::msg)?; pending = Some(batch); },
                        None => return Ok::<bool, anyhow::Error>(true),
                    }
                }
            }
        }.await;
        match result {
            Ok(true) => return Ok(()),
            Err(error) => {
                if error.downcast_ref::<Status>().is_some_and(|status| {
                    matches!(
                        status.code(),
                        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                    )
                }) {
                    return Err(error).context("Hub credentials were rejected");
                }
                warn!(%error, "Hub connection interrupted; retaining pending signals and reconnecting")
            }
            _ => {}
        }
        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
    }
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
