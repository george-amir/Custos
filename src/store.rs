use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Source tier that produced a `BanDecision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    L1Deterministic,
    L1AutoSignature,
    JevSystemOne,
    HubCommunity,
    ManualAdmin,
}

/// Active remediation decision stored in memory and persisted to `decisions.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanDecision {
    pub ip: IpAddr,
    pub threat_class: String,
    pub source: DecisionSource,
    pub noul_probability: f64,
    pub confidence: f64,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl BanDecision {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Thread-safe store of active IP bans backed by an append-only JSONL file.
pub struct DecisionStore {
    active_bans: DashMap<IpAddr, BanDecision>,
    persistence_path: PathBuf,
    default_ttl_secs: u64,
}

impl DecisionStore {
    pub fn open(persistence_path: PathBuf, default_ttl_secs: u64) -> Result<Self> {
        let store = Self {
            active_bans: DashMap::new(),
            persistence_path,
            default_ttl_secs,
        };
        store.load_existing()?;
        Ok(store)
    }

    fn load_existing(&self) -> Result<()> {
        if !Path::new(&self.persistence_path).exists() {
            return Ok(());
        }
        let file = std::fs::File::open(&self.persistence_path).with_context(|| {
            format!(
                "Failed to open persistence file {}",
                self.persistence_path.display()
            )
        })?;
        let reader = BufReader::new(file);
        let now = Utc::now();
        let mut loaded = 0usize;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(decision) = serde_json::from_str::<BanDecision>(&line) {
                if !decision.is_expired(now) {
                    self.active_bans.insert(decision.ip, decision);
                    loaded += 1;
                }
            }
        }
        if loaded > 0 {
            info!(
                loaded,
                path = %self.persistence_path.display(),
                "Restored active ban decisions from disk"
            );
        }
        Ok(())
    }

    /// Checks if `ip` is currently banned in sub-microsecond time.
    /// Automatically evicts the entry if its TTL has expired.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<BanDecision> {
        if let Some(entry) = self.active_bans.get(ip) {
            let now = Utc::now();
            if !entry.is_expired(now) {
                return Some(entry.value().clone());
            }
        } else {
            return None;
        }
        // Expired: remove outside read guard
        self.active_bans.remove(ip);
        None
    }

    /// Records a new `BanDecision` with the configured or custom TTL and appends it to disk.
    pub fn upsert_ban(
        &self,
        ip: IpAddr,
        threat_class: String,
        source: DecisionSource,
        noul_probability: f64,
        confidence: f64,
        reason: String,
        custom_ttl_secs: Option<u64>,
    ) -> Result<BanDecision> {
        let now = Utc::now();
        let ttl = custom_ttl_secs.unwrap_or(self.default_ttl_secs).max(1);
        let decision = BanDecision {
            ip,
            threat_class,
            source,
            noul_probability,
            confidence,
            reason,
            created_at: now,
            expires_at: now + Duration::seconds(ttl as i64),
        };

        self.active_bans.insert(ip, decision.clone());
        self.append_to_disk(&decision)?;
        Ok(decision)
    }

    pub fn remove_ban(&self, ip: &IpAddr) -> bool {
        self.active_bans.remove(ip).is_some()
    }

    pub fn list_active(&self) -> Vec<BanDecision> {
        let now = Utc::now();
        let mut list: Vec<BanDecision> = self
            .active_bans
            .iter()
            .filter(|e| !e.value().is_expired(now))
            .map(|e| e.value().clone())
            .collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }

    pub fn active_count(&self) -> usize {
        self.list_active().len()
    }

    /// Sweeps and evicts all expired bans from memory, returning the list of expired IPs
    /// so the daemon can remove them from `pf`/`netsh` OS firewall tables.
    pub fn sweep_expired(&self) -> Vec<IpAddr> {
        let now = Utc::now();
        let expired: Vec<IpAddr> = self
            .active_bans
            .iter()
            .filter(|e| e.value().is_expired(now))
            .map(|e| *e.key())
            .collect();
        for ip in &expired {
            self.active_bans.remove(ip);
        }
        expired
    }

    /// Compacts `decisions.jsonl` on disk so it only contains currently active, non-expired decisions.
    pub fn compact_persistence_file(&self) -> Result<()> {
        let active = self.list_active();
        if let Some(parent) = self.persistence_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.persistence_path)
            .with_context(|| {
                format!(
                    "Failed to compact decisions file {}",
                    self.persistence_path.display()
                )
            })?;
        for decision in &active {
            let serialized = serde_json::to_string(decision)?;
            writeln!(file, "{serialized}")?;
        }
        Ok(())
    }

    fn append_to_disk(&self, decision: &BanDecision) -> Result<()> {
        if let Some(parent) = self.persistence_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.persistence_path)
            .with_context(|| {
                format!(
                    "Failed to append to decisions file {}",
                    self.persistence_path.display()
                )
            })?;
        let serialized = serde_json::to_string(decision)?;
        writeln!(file, "{serialized}")?;
        debug!(ip = %decision.ip, threat = %decision.threat_class, "Persisted ban decision");
        Ok(())
    }
}
