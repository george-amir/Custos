//! Coalesced, bounded expiry cleanup. No process or journal work runs on callers
//! of `request`, and this worker owns no sender (so it stops with the pipeline).
use crate::{firewall::FirewallBouncer, store::DecisionStore};
use anyhow::Result;
use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(crate) struct CleanupWorker {
    sender: mpsc::SyncSender<()>,
    retry_enforcement: Arc<AtomicBool>,
}

impl CleanupWorker {
    pub fn start(
        store: Arc<DecisionStore>,
        firewall: Arc<FirewallBouncer>,
        enforcement: Arc<Mutex<()>>,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel(1);
        let retry_enforcement = Arc::new(AtomicBool::new(false));
        let dirty = retry_enforcement.clone();
        std::thread::Builder::new()
            .name("custos-cleanup".into())
            .spawn(move || {
                run_worker(store, firewall, enforcement, rx, dirty);
            })?;
        Ok(Self {
            sender: tx,
            retry_enforcement,
        })
    }

    pub fn request(&self) {
        let _ = self.sender.try_send(());
    }

    pub fn retry_enforcement(&self) {
        self.retry_enforcement.store(true, Ordering::Relaxed);
        self.request();
    }
}

fn run_worker(
    store: Arc<DecisionStore>,
    firewall: Arc<FirewallBouncer>,
    enforcement: Arc<Mutex<()>>,
    rx: mpsc::Receiver<()>,
    dirty: Arc<AtomicBool>,
) {
    let interval = Duration::from_secs(1);
    let mut last_pass: Option<Instant> = None;
    let mut retry = false;
    let mut cursor = None;
    let mut refresh = std::collections::VecDeque::new();
    let mut next_refresh = Instant::now() + Duration::from_secs(60);
    loop {
        let wait = if retry || !refresh.is_empty() || dirty.load(Ordering::Relaxed) {
            interval
        } else {
            next_refresh.saturating_duration_since(Instant::now())
        };
        let signal = rx.recv_timeout(wait);
        if matches!(signal, Err(mpsc::RecvTimeoutError::Disconnected)) {
            break;
        }
        if let Some(previous) = last_pass {
            let remaining = interval.saturating_sub(previous.elapsed());
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }
        while rx.try_recv().is_ok() {}
        last_pass = Some(Instant::now());
        if (dirty.load(Ordering::Relaxed) || Instant::now() >= next_refresh) && refresh.is_empty() {
            dirty.store(false, Ordering::Relaxed);
            refresh.extend(store.list_active().into_iter().map(|decision| decision.ip));
            next_refresh = Instant::now() + Duration::from_secs(60);
        }
        let group: Vec<_> = refresh
            .drain(..refresh.len().min(firewall.enforcement_chunk_size()))
            .collect();
        if !group.is_empty() {
            let result = (|| -> Result<()> {
                let _guard = enforcement
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Enforcement lock poisoned"))?;
                let entries: Vec<_> = group
                    .iter()
                    .filter_map(|ip| store.check_ip(ip))
                    .map(|decision| (decision.ip, crate::remaining_ttl(&decision)))
                    .collect();
                if firewall.is_enabled() && !firewall.is_dry_run() {
                    store.require_kernel_cleanup(
                        &entries.iter().map(|(ip, _)| *ip).collect::<Vec<_>>(),
                    )?;
                }
                firewall.ban_ips_batch(&entries)?;
                Ok(())
            })();
            if let Err(error) = result {
                tracing::warn!(%error, "Durable firewall enforcement retained for retry");
                dirty.store(true, Ordering::Relaxed);
            }
        }
        let candidates = store.sweep_expired();
        if candidates.is_empty() {
            retry = false;
            cursor = None;
            continue;
        }
        // Round-robin failed removals so one failing address cannot starve
        // all later obligations. The snapshot is bounded by max_decisions.
        let start = cursor
            .map(|ip| candidates.partition_point(|candidate| *candidate <= ip))
            .unwrap_or(0);
        let start = if start == candidates.len() { 0 } else { start };
        let end = (start + firewall.cleanup_chunk_size()).min(candidates.len());
        let group = &candidates[start..end];
        if let Err(error) = cleanup_group(&store, &firewall, &enforcement, group) {
            tracing::warn!(%error, "Expiry cleanup retained for retry");
        }
        cursor = group.last().copied();
        retry = true;
    }
}

pub(crate) fn cleanup_group(
    store: &DecisionStore,
    firewall: &FirewallBouncer,
    enforcement: &Mutex<()>,
    ips: &[IpAddr],
) -> Result<()> {
    let _guard = enforcement
        .lock()
        .map_err(|_| anyhow::anyhow!("Enforcement lock poisoned"))?;
    // Recheck while serialized with record_ban: the snapshot may precede a re-ban.
    let eligible: Vec<_> = ips
        .iter()
        .copied()
        .filter(|ip| store.check_ip(ip).is_none())
        .collect();
    let (kernel, mut confirmed): (Vec<_>, Vec<_>) = eligible
        .into_iter()
        .partition(|ip| store.cleanup_requires_kernel(ip));
    if !kernel.is_empty() && (!firewall.is_enabled() || firewall.is_dry_run()) {
        store.acknowledge_cleanup_batch(&confirmed)?;
        anyhow::bail!(
            "Live or legacy kernel cleanup retained: enable live firewall enforcement to confirm removal"
        );
    }
    let result = firewall.unban_ips_batch(&kernel);
    confirmed.extend(result.confirmed);
    store.acknowledge_cleanup_batch(&confirmed)?;
    anyhow::ensure!(result.errors.is_empty(), "{}", result.errors.join("; "));
    Ok(())
}
