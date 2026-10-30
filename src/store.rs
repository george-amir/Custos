use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum JournalOperation {
    Remove { ip: IpAddr },
    CleanupComplete { ip: IpAddr },
}

/// Concurrent reads with serialized, durable journal mutations. Expired entries
/// remain in the ledger until their OS firewall cleanup has been acknowledged.
pub struct DecisionStore {
    active_bans: DashMap<IpAddr, BanDecision>,
    pending_cleanup: DashMap<IpAddr, ()>,
    persistence_path: PathBuf,
    default_ttl_secs: u64,
    mutation_lock: Mutex<()>,
}

impl DecisionStore {
    pub fn open(persistence_path: PathBuf, default_ttl_secs: u64) -> Result<Self> {
        let store = Self {
            active_bans: DashMap::new(),
            pending_cleanup: DashMap::new(),
            persistence_path,
            default_ttl_secs,
            mutation_lock: Mutex::new(()),
        };
        store.load_existing()?;
        Ok(store)
    }

    fn load_existing(&self) -> Result<()> {
        if !self.persistence_path.exists() {
            return Ok(());
        }
        let reader = BufReader::new(File::open(&self.persistence_path).with_context(|| {
            format!(
                "Failed to open persistence file {}",
                self.persistence_path.display()
            )
        })?);
        for (index, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // Existing JSONL BanDecision records remain backwards compatible.
            if let Ok(decision) = serde_json::from_str::<BanDecision>(&line) {
                self.pending_cleanup.remove(&decision.ip);
                self.active_bans.insert(decision.ip, decision);
                continue;
            }
            let operation: JournalOperation = serde_json::from_str(&line).with_context(|| {
                format!(
                    "Invalid decision journal record at {}:{}",
                    self.persistence_path.display(),
                    index + 1
                )
            })?;
            match operation {
                JournalOperation::Remove { ip } => {
                    self.active_bans.remove(&ip);
                    self.pending_cleanup.insert(ip, ());
                }
                JournalOperation::CleanupComplete { ip } => {
                    self.active_bans.remove(&ip);
                    self.pending_cleanup.remove(&ip);
                }
            }
        }
        Ok(())
    }

    /// An expired decision is inactive, but reading it never destroys cleanup work.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<BanDecision> {
        self.active_bans
            .get(ip)
            .and_then(|entry| (!entry.is_expired(Utc::now())).then(|| entry.value().clone()))
    }

    #[allow(clippy::too_many_arguments)]
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
        let duration = i64::try_from(ttl)
            .ok()
            .and_then(Duration::try_seconds)
            .ok_or_else(|| anyhow!("Ban TTL is out of range"))?;
        let decision = BanDecision {
            ip,
            threat_class,
            source,
            noul_probability,
            confidence,
            reason,
            created_at: now,
            expires_at: now
                .checked_add_signed(duration)
                .ok_or_else(|| anyhow!("Ban expiry is out of range"))?,
        };
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow!("Decision journal lock poisoned"))?;
        self.append_record(&decision)?;
        self.pending_cleanup.remove(&ip);
        self.active_bans.insert(ip, decision.clone());
        Ok(decision)
    }

    /// Durably revokes a decision and records that the kernel rule still needs cleanup.
    pub fn remove_ban(&self, ip: &IpAddr) -> Result<bool> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow!("Decision journal lock poisoned"))?;
        if !self.active_bans.contains_key(ip) && !self.pending_cleanup.contains_key(ip) {
            return Ok(false);
        }
        self.append_record(&JournalOperation::Remove { ip: *ip })?;
        self.active_bans.remove(ip);
        self.pending_cleanup.insert(*ip, ());
        Ok(true)
    }

    pub fn list_active(&self) -> Vec<BanDecision> {
        let now = Utc::now();
        let mut list: Vec<_> = self
            .active_bans
            .iter()
            .filter(|entry| !entry.is_expired(now))
            .map(|entry| entry.value().clone())
            .collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        list
    }

    pub fn active_count(&self) -> usize {
        let now = Utc::now();
        self.active_bans
            .iter()
            .filter(|entry| !entry.is_expired(now))
            .count()
    }

    /// Returns cleanup obligations without consuming them. Retry after failures;
    /// call `acknowledge_cleanup` only after successful OS rule removal.
    pub fn sweep_expired(&self) -> Vec<IpAddr> {
        let now = Utc::now();
        let mut expired: Vec<_> = self
            .active_bans
            .iter()
            .filter(|entry| entry.is_expired(now))
            .map(|entry| *entry.key())
            .collect();
        expired.extend(self.pending_cleanup.iter().map(|entry| *entry.key()));
        expired.sort_unstable();
        expired.dedup();
        expired
    }

    /// The caller must serialize enforcement and cleanup so an old removal cannot
    /// race a newly applied ban. Active decisions are never acknowledged as cleaned.
    pub fn acknowledge_cleanup(&self, ip: &IpAddr) -> Result<bool> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow!("Decision journal lock poisoned"))?;
        if self.check_ip(ip).is_some() {
            return Ok(false);
        }
        if !self.active_bans.contains_key(ip) && !self.pending_cleanup.contains_key(ip) {
            return Ok(false);
        }
        self.append_record(&JournalOperation::CleanupComplete { ip: *ip })?;
        self.active_bans.remove(ip);
        self.pending_cleanup.remove(ip);
        Ok(true)
    }

    /// Atomically replaces the journal under the same lock as append operations.
    /// Pending removals and expired decisions are retained until kernel cleanup.
    pub fn compact_persistence_file(&self) -> Result<()> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow!("Decision journal lock poisoned"))?;
        let parent = self.parent_directory();
        std::fs::create_dir_all(parent)?;
        let temp_path = parent.join(format!(
            ".custos-journal-{}-{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut created_temp = false;
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path)?;
            created_temp = true;
            for decision in self.active_bans.iter() {
                write_record(&mut file, decision.value())?;
            }
            for ip in self.pending_cleanup.iter() {
                write_record(&mut file, &JournalOperation::Remove { ip: *ip.key() })?;
            }
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp_path, &self.persistence_path)?;
            sync_directory(parent)?;
            Ok(())
        })();
        if result.is_err() && created_temp {
            let _ = std::fs::remove_file(&temp_path);
        }
        result.with_context(|| {
            format!(
                "Failed to compact decisions file {}",
                self.persistence_path.display()
            )
        })
    }

    fn parent_directory(&self) -> &Path {
        self.persistence_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    // Called only with mutation_lock held; persistence succeeds before memory changes.
    fn append_record(&self, record: &impl Serialize) -> Result<()> {
        let parent = self.parent_directory();
        std::fs::create_dir_all(parent)?;
        let existed = self.persistence_path.exists();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.persistence_path).with_context(|| {
            format!(
                "Failed to append to decisions file {}",
                self.persistence_path.display()
            )
        })?;
        let original_length = file.metadata()?.len();
        let result =
            write_record(&mut file, record).and_then(|_| file.sync_all().map_err(Into::into));
        if let Err(error) = result {
            let _ = file.set_len(original_length);
            let _ = file.sync_all();
            return Err(error);
        }
        if !existed {
            sync_directory(parent)?;
        }
        Ok(())
    }
}

fn write_record(file: &mut File, record: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
