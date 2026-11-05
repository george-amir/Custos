//! Verified service identities. No DNS, HTTP, user-agent trust, or IP history on the request path.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
    net::IpAddr,
    path::PathBuf,
    sync::{LazyLock, RwLock},
    time::Duration,
};

pub const MAX_FEED_BYTES: usize = 512 * 1024;
pub const MAX_PREFIXES_PER_FEED: usize = 4096;
pub const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CrawlerPolicy {
    /// Existing behavioral analysis and enforcement.
    #[default]
    Normal,
    /// Permit ordinary crawling; explicit exploit evidence and manual bans still apply.
    Allow,
    /// Reject this verified service, independently of model classification.
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CrawlerConfig {
    pub policies: BTreeMap<String, CrawlerPolicy>,
    pub state_file: Option<PathBuf>,
    pub auto_refresh: bool,
    pub refresh_interval_secs: u64,
    pub max_feed_age_secs: u64,
}
impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            policies: BTreeMap::new(),
            state_file: None,
            auto_refresh: true,
            refresh_interval_secs: 86400,
            max_feed_age_secs: 7 * 86400,
        }
    }
}
impl CrawlerConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (3600..=7 * 86400).contains(&self.refresh_interval_secs),
            "Crawler refresh interval must be 1 hour to 7 days"
        );
        ensure!(
            (3600..=7 * 86400).contains(&self.max_feed_age_secs),
            "Crawler verification lifetime must be 1 hour to 7 days"
        );
        for id in self.policies.keys() {
            entry(id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerEntry {
    pub id: String,
    pub name: String,
    pub category: String,
    pub source_url: String,
    pub documentation_url: String,
}
pub static CATALOG: LazyLock<Vec<CrawlerEntry>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../data/crawler_catalog.json"))
        .expect("bundled crawler catalog")
});
fn entry(id: &str) -> Result<&'static CrawlerEntry> {
    CATALOG
        .iter()
        .find(|entry| entry.id == id)
        .context("Unknown crawler identity")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedCrawler {
    pub id: String,
    pub name: String,
    pub matched_prefix: String,
    pub verified_at: DateTime<Utc>,
    pub policy: CrawlerPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Feed {
    verified_at: DateTime<Utc>,
    prefixes: Vec<String>,
    #[serde(default)]
    last_error: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistentState {
    #[serde(default)]
    policies: BTreeMap<String, CrawlerPolicy>,
    feeds: BTreeMap<String, Feed>,
}

#[derive(Debug, Serialize)]
pub struct CrawlerStatus {
    #[serde(flatten)]
    pub entry: CrawlerEntry,
    pub policy: CrawlerPolicy,
    pub prefix_count: usize,
    pub verified_at: DateTime<Utc>,
    pub stale: bool,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy)]
struct Prefix {
    v6: bool,
    bits: u8,
    network: u128,
}
impl Prefix {
    fn parse(raw: &str) -> Result<Self> {
        let (address, bits) = raw.split_once('/').context("CIDR prefix required")?;
        let ip: IpAddr = address.parse()?;
        let bits: u8 = bits.parse()?;
        let (v6, value) = match ip {
            IpAddr::V4(ip) => {
                ensure!(
                    !ip.is_private()
                        && !ip.is_loopback()
                        && !ip.is_link_local()
                        && !ip.is_unspecified()
                        && !ip.is_multicast(),
                    "Non-public crawler prefix"
                );
                ensure!((8..=32).contains(&bits), "Overbroad IPv4 crawler prefix");
                (false, u32::from(ip) as u128)
            }
            IpAddr::V6(ip) => {
                ensure!(
                    !ip.is_unique_local()
                        && !ip.is_unicast_link_local()
                        && !ip.is_loopback()
                        && !ip.is_unspecified()
                        && !ip.is_multicast()
                        && ip.to_ipv4_mapped().is_none(),
                    "Non-public crawler prefix"
                );
                ensure!((16..=128).contains(&bits), "Overbroad IPv6 crawler prefix");
                (true, u128::from(ip))
            }
        };
        let prefix = Self {
            v6,
            bits,
            network: value,
        };
        ensure!(
            value & prefix.mask() == value,
            "Non-canonical crawler prefix"
        );
        Ok(prefix)
    }
    fn mask(self) -> u128 {
        u128::MAX << ((if self.v6 { 128 } else { 32 }) - self.bits)
    }
    fn text(self) -> String {
        let ip = if self.v6 {
            IpAddr::V6(self.network.into())
        } else {
            IpAddr::V4((self.network as u32).into())
        };
        format!("{ip}/{}", self.bits)
    }
}

struct PrefixGroup {
    prefix: Prefix,
    networks: HashMap<u128, u16>,
}
struct RegistryState {
    persistent: PersistentState,
    index: Vec<PrefixGroup>,
}
impl RegistryState {
    fn build(persistent: PersistentState) -> Result<Self> {
        ensure!(CATALOG.len() <= 16, "Crawler identity bit budget exceeded");
        for id in persistent.policies.keys() {
            entry(id)?;
        }
        ensure!(
            persistent.feeds.len() == CATALOG.len(),
            "Incomplete crawler catalog"
        );
        let mut groups: BTreeMap<(bool, u8), HashMap<u128, u16>> = BTreeMap::new();
        for (idx, catalog) in CATALOG.iter().enumerate() {
            let feed = persistent
                .feeds
                .get(&catalog.id)
                .context("Missing crawler feed")?;
            ensure!(
                !feed.prefixes.is_empty() && feed.prefixes.len() <= MAX_PREFIXES_PER_FEED,
                "Invalid crawler prefix count"
            );
            ensure!(
                feed.verified_at <= Utc::now() + chrono::Duration::minutes(5),
                "Crawler verification time is in the future"
            );
            for raw in &feed.prefixes {
                ensure!(raw.len() <= 64, "Crawler prefix too long");
                let p = Prefix::parse(raw)?;
                *groups
                    .entry((p.v6, p.bits))
                    .or_default()
                    .entry(p.network)
                    .or_default() |= 1 << idx;
            }
        }
        let index = groups
            .into_iter()
            .rev()
            .map(|((v6, bits), networks)| PrefixGroup {
                prefix: Prefix {
                    v6,
                    bits,
                    network: 0,
                },
                networks,
            })
            .collect();
        Ok(Self { persistent, index })
    }
}

pub struct CrawlerRegistry {
    state: RwLock<RegistryState>,
    path: Option<PathBuf>,
    pub config: CrawlerConfig,
    refresh: tokio::sync::Mutex<()>,
}
impl CrawlerRegistry {
    pub fn open(config: CrawlerConfig, default_path: Option<PathBuf>) -> Result<Self> {
        config.validate()?;
        let path = config.state_file.clone().or(default_path);
        let mut persistent: PersistentState =
            serde_json::from_str(include_str!("../data/crawler_ranges.json"))?;
        persistent.policies = config.policies.clone();
        if let Some(path) = path.as_ref().filter(|path| path.exists()) {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take((MAX_STATE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= MAX_STATE_BYTES,
                "Crawler state exceeds byte budget"
            );
            let saved: PersistentState = serde_json::from_slice(&bytes)?;
            // Older versions may lack newly added services. Validate saved feeds
            // against a complete bundled catalog before merging their timestamps.
            ensure!(
                saved
                    .feeds
                    .keys()
                    .all(|id| CATALOG.iter().any(|entry| &entry.id == id)),
                "Unknown cached crawler identity"
            );
            let mut complete = persistent.clone();
            complete.feeds.extend(saved.feeds.clone());
            complete.policies.extend(saved.policies.clone());
            RegistryState::build(complete)?;
            persistent.policies.extend(saved.policies);
            for (id, feed) in saved.feeds {
                if persistent
                    .feeds
                    .get(&id)
                    .is_some_and(|old| feed.verified_at > old.verified_at)
                {
                    persistent.feeds.insert(id, feed);
                }
            }
        }
        Ok(Self {
            state: RwLock::new(RegistryState::build(persistent)?),
            path,
            config,
            refresh: tokio::sync::Mutex::new(()),
        })
    }

    pub fn identify(&self, ip: IpAddr) -> Option<VerifiedCrawler> {
        self.identify_at(ip, Utc::now())
    }

    /// Evaluate snapshot freshness at a supplied audit time. Live enforcement uses identify().
    pub fn identify_at(&self, ip: IpAddr, now: DateTime<Utc>) -> Option<VerifiedCrawler> {
        let ip = match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let (v6, value) = match ip {
            IpAddr::V4(ip) => (false, u32::from(ip) as u128),
            IpAddr::V6(ip) => (true, u128::from(ip)),
        };
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut best: Option<(u8, VerifiedCrawler)> = None;
        for group in state.index.iter().filter(|group| group.prefix.v6 == v6) {
            let network = value & group.prefix.mask();
            let Some(identities) = group.networks.get(&network) else {
                continue;
            };
            for (idx, catalog) in CATALOG
                .iter()
                .enumerate()
                .filter(|(idx, _)| identities & (1 << idx) != 0)
            {
                let _ = idx;
                let feed = &state.persistent.feeds[&catalog.id];
                if !(-300..=self.config.max_feed_age_secs as i64)
                    .contains(&(now - feed.verified_at).num_seconds())
                {
                    continue;
                }
                let policy = state
                    .persistent
                    .policies
                    .get(&catalog.id)
                    .copied()
                    .unwrap_or_default();
                // Overlaps use the stricter action; an allow never overrides another service's block/normal policy.
                let rank = match policy {
                    CrawlerPolicy::Block => 3,
                    CrawlerPolicy::Normal => 2,
                    CrawlerPolicy::Allow => 1,
                };
                if best.as_ref().is_none_or(|(previous, _)| rank > *previous) {
                    best = Some((
                        rank,
                        VerifiedCrawler {
                            id: catalog.id.clone(),
                            name: catalog.name.clone(),
                            policy,
                            matched_prefix: Prefix {
                                network,
                                ..group.prefix
                            }
                            .text(),
                            verified_at: feed.verified_at,
                        },
                    ));
                }
            }
        }
        best.map(|(_, identity)| identity)
    }

    pub fn list(&self) -> Vec<CrawlerStatus> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        CATALOG
            .iter()
            .map(|entry| {
                let feed = &state.persistent.feeds[&entry.id];
                CrawlerStatus {
                    entry: entry.clone(),
                    policy: state
                        .persistent
                        .policies
                        .get(&entry.id)
                        .copied()
                        .unwrap_or_default(),
                    prefix_count: feed.prefixes.len(),
                    verified_at: feed.verified_at,
                    stale: !(-300..=self.config.max_feed_age_secs as i64)
                        .contains(&(Utc::now() - feed.verified_at).num_seconds()),
                    last_error: feed.last_error.clone(),
                }
            })
            .collect()
    }

    fn commit(&self, state: &mut RegistryState, next: PersistentState) -> Result<()> {
        let next = RegistryState::build(next)?;
        let bytes = serde_json::to_vec(&next.persistent)?;
        ensure!(
            bytes.len() <= MAX_STATE_BYTES,
            "Crawler state exceeds byte budget"
        );
        if let Some(path) = &self.path {
            crate::service::write_secret_file(path, &bytes)?;
        }
        *state = next;
        Ok(())
    }

    pub fn set_policy(&self, id: &str, policy: CrawlerPolicy) -> Result<()> {
        self.set_policies(&[id.to_owned()], policy)
    }

    /// Validate the whole selection and persist it in one atomic replacement.
    pub fn set_policies(&self, ids: &[String], policy: CrawlerPolicy) -> Result<()> {
        ensure!(
            !ids.is_empty() && ids.len() <= CATALOG.len(),
            "Invalid crawler selection size"
        );
        for id in ids {
            entry(id)?;
        }
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("Crawler registry lock poisoned"))?;
        let mut next = state.persistent.clone();
        for id in ids {
            next.policies.insert(id.clone(), policy);
        }
        self.commit(&mut state, next)
    }

    /// Only the compiled catalog supplies URLs. Concurrent refreshes are rejected, not queued.
    pub async fn refresh(&self) -> Result<Vec<CrawlerStatus>> {
        let _permit = self
            .refresh
            .try_lock()
            .map_err(|_| anyhow::anyhow!("Crawler refresh already in progress"))?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .user_agent("Custos crawler identity refresh")
            .build()?;
        let mut jobs = tokio::task::JoinSet::new();
        for catalog in CATALOG.iter() {
            let client = client.clone();
            let catalog = catalog.clone();
            jobs.spawn(async move {
                let result = async {
                    let mut response = client
                        .get(&catalog.source_url)
                        .send()
                        .await?
                        .error_for_status()?;
                    ensure!(
                        response
                            .content_length()
                            .is_none_or(|len| len <= MAX_FEED_BYTES as u64),
                        "Crawler feed exceeds byte budget"
                    );
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response.chunk().await? {
                        ensure!(
                            bytes.len() + chunk.len() <= MAX_FEED_BYTES,
                            "Crawler feed exceeds byte budget"
                        );
                        bytes.extend_from_slice(&chunk);
                    }
                    let prefixes = parse_feed(&bytes, catalog.id == "nokia_genome")?;
                    Ok::<_, anyhow::Error>(Feed {
                        verified_at: Utc::now(),
                        prefixes,
                        last_error: None,
                    })
                }
                .await;
                (catalog.id, result)
            });
        }
        let mut updates = Vec::new();
        while let Some(result) = jobs.join_next().await {
            updates.push(result?);
        }
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| anyhow::anyhow!("Crawler registry lock poisoned"))?;
            let mut next = state.persistent.clone();
            for (id, result) in updates {
                match result {
                    Ok(feed) => {
                        next.feeds.insert(id, feed);
                    }
                    Err(error) => {
                        next.feeds.get_mut(&id).expect("catalog feed").last_error =
                            Some(crate::tailer::bounded_str(&error.to_string(), 256).to_owned());
                    }
                }
            }
            self.commit(&mut state, next)?;
        }
        Ok(self.list())
    }
}

pub fn parse_feed(bytes: &[u8], plain_text: bool) -> Result<Vec<String>> {
    ensure!(
        bytes.len() <= MAX_FEED_BYTES,
        "Crawler feed exceeds byte budget"
    );
    let mut prefixes = if plain_text {
        std::str::from_utf8(bytes)?
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>()
    } else {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Range {
            #[serde(rename = "ipv4Prefix")]
            v4: Option<String>,
            #[serde(rename = "ipv6Prefix")]
            v6: Option<String>,
        }
        #[derive(Deserialize)]
        struct Response {
            prefixes: Vec<Range>,
        }
        let response: Response = serde_json::from_slice(bytes)?;
        let mut prefixes = Vec::new();
        for range in response.prefixes {
            ensure!(
                range.v4.is_some() ^ range.v6.is_some(),
                "Each crawler range requires one address family"
            );
            prefixes.push(range.v4.or(range.v6).expect("one range"));
        }
        prefixes
    };
    ensure!(
        !prefixes.is_empty() && prefixes.len() <= MAX_PREFIXES_PER_FEED,
        "Invalid crawler prefix count"
    );
    for prefix in &prefixes {
        Prefix::parse(prefix)?;
    }
    prefixes.sort();
    prefixes.dedup();
    Ok(prefixes)
}
