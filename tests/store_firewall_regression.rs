use custos::config::FirewallConfig;
use custos::firewall::{FirewallBackend, FirewallBouncer};
use custos::store::{BanDecision, DecisionSource, DecisionStore};
use std::net::IpAddr;
use std::sync::{Arc, Barrier};

fn ban(store: &DecisionStore, ip: IpAddr) -> BanDecision {
    store
        .upsert_ban(
            ip,
            "test".into(),
            DecisionSource::ManualAdmin,
            1.0,
            1.0,
            "test".into(),
            Some(3600),
        )
        .unwrap()
}

#[test]
fn concurrent_bans_and_compaction_survive_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    let store = Arc::new(DecisionStore::open(path.clone(), 3600).unwrap());
    let barrier = Arc::new(Barrier::new(5));
    let mut threads = Vec::new();
    for worker in 1..=4u8 {
        let store = store.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            for n in 0..100u8 {
                ban(&store, IpAddr::from([198, 51, worker, n]));
            }
        }));
    }
    let compact_store = store.clone();
    threads.push(std::thread::spawn(move || {
        barrier.wait();
        for _ in 0..20 {
            compact_store.compact_persistence_file().unwrap();
        }
    }));
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(store.active_count(), 400);
    assert_eq!(DecisionStore::open(path, 3600).unwrap().active_count(), 400);
}

#[test]
fn ipset_initialization_includes_both_packet_drop_rules() {
    let fw = FirewallBouncer::new(FirewallConfig {
        backend: FirewallBackend::Ipset,
        ..FirewallConfig::default()
    });
    let commands = fw.build_init_commands();
    for (program, set) in [
        ("iptables", "custos_block_v4"),
        ("ip6tables", "custos_block_v6"),
    ] {
        assert!(
            commands.iter().any(|cmd| cmd.program == program
                && cmd.args.iter().any(|a| a == set)
                && cmd.args.iter().any(|a| a == "DROP")),
            "missing {program} drop rule"
        );
    }
}

#[test]
fn manual_unban_remains_revoked_and_cleanup_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    let ip: IpAddr = "198.51.100.10".parse().unwrap();
    let store = DecisionStore::open(path.clone(), 3600).unwrap();
    ban(&store, ip);
    assert!(store.remove_ban(&ip).unwrap());
    store.compact_persistence_file().unwrap();
    drop(store);
    let store = DecisionStore::open(path.clone(), 3600).unwrap();
    assert!(store.check_ip(&ip).is_none());
    assert_eq!(store.sweep_expired(), vec![ip]);
    assert_eq!(
        store.sweep_expired(),
        vec![ip],
        "a failed firewall attempt must remain retryable"
    );
    assert!(store.acknowledge_cleanup(&ip).unwrap());
    assert!(
        DecisionStore::open(path, 3600)
            .unwrap()
            .sweep_expired()
            .is_empty()
    );
}

#[test]
fn reading_an_expired_ban_does_not_destroy_cleanup_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    let ip: IpAddr = "198.51.100.11".parse().unwrap();
    let store = DecisionStore::open(path.clone(), 3600).unwrap();
    let mut expired = ban(&store, ip);
    expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    drop(store);
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&expired).unwrap()),
    )
    .unwrap();
    let store = DecisionStore::open(path.clone(), 3600).unwrap();
    assert!(store.check_ip(&ip).is_none());
    assert_eq!(store.sweep_expired(), vec![ip]);
    store.compact_persistence_file().unwrap();
    assert_eq!(
        DecisionStore::open(path, 3600).unwrap().sweep_expired(),
        vec![ip]
    );
}

#[test]
fn new_ban_supersedes_pending_cleanup_and_cannot_be_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    let ip: IpAddr = "198.51.100.12".parse().unwrap();
    let store = DecisionStore::open(path.clone(), 3600).unwrap();
    ban(&store, ip);
    store.remove_ban(&ip).unwrap();
    ban(&store, ip);
    assert!(!store.acknowledge_cleanup(&ip).unwrap());
    assert!(store.sweep_expired().is_empty());
    assert!(
        DecisionStore::open(path, 3600)
            .unwrap()
            .check_ip(&ip)
            .is_some()
    );
}

#[test]
fn persistence_failure_does_not_publish_a_ban_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    let store = DecisionStore::open(path.clone(), 3600).unwrap();
    std::fs::create_dir(path).unwrap();
    let result = store.upsert_ban(
        "198.51.100.13".parse().unwrap(),
        "test".into(),
        DecisionSource::ManualAdmin,
        1.0,
        1.0,
        "test".into(),
        None,
    );
    assert!(result.is_err());
    assert_eq!(store.active_count(), 0);
}

#[test]
fn malformed_journal_is_reported_instead_of_silently_losing_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    std::fs::write(&path, "{broken\n").unwrap();
    assert!(DecisionStore::open(path, 3600).is_err());
}

#[cfg(unix)]
use custos::firewall::ProcessFirewallCommandRunner;
use custos::firewall::{FirewallCommandRunner, FirewallCommandSpec};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

struct Runner<F>(F);
impl<F: Fn(&FirewallCommandSpec, Duration) -> anyhow::Result<i32> + Send + Sync>
    FirewallCommandRunner for Runner<F>
{
    fn run(&self, command: &FirewallCommandSpec, timeout: Duration) -> anyhow::Result<i32> {
        (self.0)(command, timeout)
    }
}

fn live_config(backend: FirewallBackend) -> FirewallConfig {
    FirewallConfig {
        backend,
        dry_run: false,
        ..FirewallConfig::default()
    }
}

#[test]
fn failed_firewall_command_returns_error_without_claiming_enforcement() {
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Pf),
        Arc::new(Runner(|_: &FirewallCommandSpec, _: Duration| Ok(2))),
        Duration::from_millis(10),
    );
    let ip = "198.51.100.14".parse().unwrap();
    assert!(fw.ban_ip(ip, 300).is_err());
    assert!(fw.unban_ip(ip).is_err());
    assert_eq!(fw.metrics.rules_applied.load(Ordering::Relaxed), 0);
    assert_eq!(fw.metrics.rules_removed.load(Ordering::Relaxed), 0);
    assert_eq!(fw.metrics.command_errors.load(Ordering::Relaxed), 2);
}

#[test]
fn spawn_or_timeout_errors_are_propagated() {
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Nftables),
        Arc::new(Runner(|_: &FirewallCommandSpec, timeout: Duration| {
            assert_eq!(timeout, Duration::from_millis(7));
            anyhow::bail!("simulated timeout")
        })),
        Duration::from_millis(7),
    );
    assert!(fw.init_backend().is_err());
    assert_eq!(fw.metrics.command_errors.load(Ordering::Relaxed), 1);
}

#[test]
fn partial_batch_counts_only_successfully_enforced_addresses() {
    let count = Arc::new(AtomicUsize::new(0));
    let runner_count = count.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Nftables),
        Arc::new(Runner(move |_: &FirewallCommandSpec, _: Duration| {
            Ok(if runner_count.fetch_add(1, Ordering::Relaxed) == 0 {
                0
            } else {
                2
            })
        })),
        Duration::from_millis(10),
    );
    let entries = [
        ("198.51.100.1".parse().unwrap(), 300),
        ("198.51.100.2".parse().unwrap(), 300),
        ("2001:db8::1".parse().unwrap(), 300),
    ];
    assert!(fw.ban_ips_batch(&entries).is_err());
    assert_eq!(fw.metrics.rules_applied.load(Ordering::Relaxed), 2);
    assert_eq!(fw.metrics.command_errors.load(Ordering::Relaxed), 1);
}

#[test]
fn ipset_reinitialization_does_not_duplicate_drop_rules() {
    let inserted = Arc::new(Mutex::new(Vec::<String>::new()));
    let runner_inserted = inserted.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Ipset),
        Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
            if cmd.program == "ipset" {
                return Ok(0);
            }
            let mut inserted = runner_inserted.lock().unwrap();
            if cmd.args.iter().any(|arg| arg == "-C") {
                return Ok(if inserted.contains(&cmd.program) {
                    0
                } else {
                    1
                });
            }
            assert!(cmd.args.iter().any(|arg| arg == "-I"));
            assert!(cmd.args.iter().any(|arg| arg == "DROP"));
            inserted.push(cmd.program.clone());
            Ok(0)
        })),
        Duration::from_millis(10),
    );
    fw.init_backend().unwrap();
    fw.init_backend().unwrap();
    assert_eq!(*inserted.lock().unwrap(), vec!["iptables", "ip6tables"]);
    assert_eq!(fw.metrics.command_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn ipset_rule_check_operational_failure_does_not_insert_a_rule() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runner_calls = calls.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Ipset),
        Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
            runner_calls.lock().unwrap().push(cmd.clone());
            Ok(if cmd.program == "ipset" { 0 } else { 2 })
        })),
        Duration::from_millis(10),
    );
    assert!(fw.init_backend().is_err());
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|cmd| cmd.args.iter().any(|arg| arg == "-I"))
    );
}

#[cfg(unix)]
#[test]
fn production_runner_kills_a_command_at_its_deadline() {
    let runner = ProcessFirewallCommandRunner;
    let start = Instant::now();
    let result = runner.run(
        &FirewallCommandSpec::new("/bin/sleep", ["5"]),
        Duration::from_millis(20),
    );
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn windows_reenforcement_removes_the_owned_rule_before_adding_it() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runner_calls = calls.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::WindowsNetsh),
        Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
            runner_calls.lock().unwrap().push(cmd.clone());
            Ok(0)
        })),
        Duration::from_millis(10),
    );
    fw.ban_ip("198.51.100.15".parse().unwrap(), 300).unwrap();
    fw.ban_ip("198.51.100.15".parse().unwrap(), 300).unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .map(|cmd| cmd.program.as_str())
            .collect::<Vec<_>>(),
        ["powershell.exe", "netsh", "powershell.exe", "netsh"]
    );
    assert!(
        calls[0]
            .args
            .last()
            .unwrap()
            .contains("CmdletizationQuery_NotFound")
    );
}

#[test]
fn windows_removal_failure_is_not_ignored_as_a_missing_rule() {
    let calls = Arc::new(AtomicUsize::new(0));
    let runner_calls = calls.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::WindowsNetsh),
        Arc::new(Runner(move |_: &FirewallCommandSpec, _: Duration| {
            runner_calls.fetch_add(1, Ordering::Relaxed);
            Ok(1)
        })),
        Duration::from_millis(10),
    );
    assert!(fw.ban_ip("198.51.100.16".parse().unwrap(), 300).is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(fw.metrics.rules_applied.load(Ordering::Relaxed), 0);
}

#[test]
fn windows_missing_rule_match_accepts_both_error_ids_without_masking_other_failures() {
    let fw = FirewallBouncer::new(live_config(FirewallBackend::WindowsNetsh));
    let spec = fw.build_unban_command("198.51.100.17".parse().unwrap());
    let script = spec.args.last().unwrap();
    let pattern = script
        .split("-match '")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    let matcher = regex::Regex::new(pattern).unwrap();
    for error in [
        "CmdletizationQuery_NotFound,Get-NetFirewallRule",
        "CmdletizationQuery_NotFound_DisplayName,Get-NetFirewallRule",
    ] {
        assert!(
            matcher.is_match(error),
            "missing rule should succeed: {error}"
        );
    }
    for error in [
        "Windows System Error 5,Get-NetFirewallRule",
        "CmdletizationQuery_NotFound_DisplayName,Remove-NetFirewallRule",
        "CmdletizationQuery_NotFoundUnexpected,Get-NetFirewallRule",
    ] {
        assert!(
            !matcher.is_match(error),
            "operational error must propagate: {error}"
        );
    }
}

#[test]
fn pf_cleanup_recreates_a_missing_table_without_banning_an_address() {
    let table_exists = Arc::new(Mutex::new(false));
    let runner_table = table_exists.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let runner_calls = calls.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Pf),
        Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
            runner_calls.fetch_add(1, Ordering::Relaxed);
            let mut exists = runner_table.lock().unwrap();
            if cmd.args[3] == "add" {
                assert_eq!(cmd.args.len(), 4, "cleanup must not insert the IP first");
                *exists = true;
                return Ok(0);
            }
            assert_eq!(cmd.args[3], "delete");
            Ok(if *exists { 0 } else { 1 })
        })),
        Duration::from_millis(10),
    );
    fw.unban_ip("198.51.100.18".parse().unwrap()).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(fw.metrics.rules_removed.load(Ordering::Relaxed), 1);
    assert_eq!(fw.metrics.rules_applied.load(Ordering::Relaxed), 0);
}

#[test]
fn large_firewall_feeds_use_bounded_commands_in_builders_and_execution() {
    let entries: Vec<_> = (0..50_000u16)
        .map(|n| {
            (
                IpAddr::V6(std::net::Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, n,
                )),
                u64::MAX,
            )
        })
        .collect();
    for backend in [FirewallBackend::Pf, FirewallBackend::Nftables] {
        let calls = Arc::new(AtomicUsize::new(0));
        let runner_calls = calls.clone();
        let fw = FirewallBouncer::with_runner(
            live_config(backend),
            Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
                runner_calls.fetch_add(1, Ordering::Relaxed);
                let argv_bytes: usize = cmd.args.iter().map(|arg| arg.len() + 1).sum();
                assert!(
                    argv_bytes < 32_768,
                    "command exceeded conservative argv limit"
                );
                Ok(0)
            })),
            Duration::from_millis(10),
        );
        let commands = fw.build_batch_ban_commands(&entries);
        assert_eq!(commands.len(), 50_000usize.div_ceil(128));
        assert!(
            commands
                .iter()
                .all(|cmd| { cmd.args.iter().map(|arg| arg.len() + 1).sum::<usize>() < 32_768 })
        );
        fw.ban_ips_batch(&entries).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), commands.len());
        assert_eq!(fw.metrics.rules_applied.load(Ordering::Relaxed), 50_000);
    }
}

#[test]
fn mass_unbans_use_bounded_native_batches_and_confirm_all_successful_members() {
    let ips: Vec<_> = (0..5000u16)
        .map(|n| {
            IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, n,
            ))
        })
        .collect();
    for backend in [
        FirewallBackend::Pf,
        FirewallBackend::Nftables,
        FirewallBackend::Ipset,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let runner_calls = calls.clone();
        let fw = FirewallBouncer::with_runner(
            live_config(backend),
            Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
                runner_calls.fetch_add(1, Ordering::Relaxed);
                assert!(cmd.args.iter().map(|arg| arg.len() + 1).sum::<usize>() < 32768);
                if let Some(input) = &cmd.stdin {
                    assert!(input.len() < 16384);
                    assert!(input.lines().count() <= 128);
                }
                Ok(0)
            })),
            Duration::from_millis(10),
        );
        let expected = 5000usize.div_ceil(128) * if backend == FirewallBackend::Pf { 2 } else { 1 };
        assert_eq!(fw.build_batch_unban_commands(&ips).len(), expected);
        let result = fw.unban_ips_batch(&ips);
        assert!(result.errors.is_empty());
        assert_eq!(result.confirmed, ips);
        assert_eq!(calls.load(Ordering::Relaxed), expected);
        assert_eq!(fw.metrics.rules_removed.load(Ordering::Relaxed), 5000);
    }
}

#[test]
fn partially_applied_ipset_restore_is_unconfirmed_and_retry_is_idempotent() {
    use std::collections::HashSet;
    let ips: Vec<IpAddr> = (1..=128u8)
        .map(|n| IpAddr::from([198, 51, 100, n]))
        .collect();
    let live = Arc::new(Mutex::new(ips.iter().copied().collect::<HashSet<_>>()));
    let kernel = live.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::Ipset),
        Arc::new(Runner(move |cmd: &FirewallCommandSpec, _: Duration| {
            assert_eq!(cmd.args, ["restore", "-exist"]);
            let fail = count.fetch_add(1, Ordering::Relaxed) == 0;
            for (idx, line) in cmd.stdin.as_ref().unwrap().lines().enumerate() {
                if fail && idx == 32 {
                    return Ok(2);
                }
                let words: Vec<_> = line.split_whitespace().collect();
                assert_eq!(&words[..2], ["del", "custos_block_v4"]);
                kernel
                    .lock()
                    .unwrap()
                    .remove(&words[2].parse::<IpAddr>().unwrap());
            }
            Ok(0)
        })),
        Duration::from_millis(10),
    );
    let failed = fw.unban_ips_batch(&ips);
    assert!(failed.confirmed.is_empty());
    assert_eq!(failed.errors.len(), 1);
    assert_eq!(live.lock().unwrap().len(), 96);
    assert_eq!(fw.metrics.rules_removed.load(Ordering::Relaxed), 0);
    let retried = fw.unban_ips_batch(&ips);
    assert!(retried.errors.is_empty());
    assert_eq!(retried.confirmed, ips);
    assert!(live.lock().unwrap().is_empty());
}

#[test]
fn windows_cleanup_confirms_successful_addresses_without_acknowledging_later_failures() {
    let count = Arc::new(AtomicUsize::new(0));
    let attempts = count.clone();
    let fw = FirewallBouncer::with_runner(
        live_config(FirewallBackend::WindowsNetsh),
        Arc::new(Runner(move |_: &FirewallCommandSpec, _: Duration| {
            Ok(if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                0
            } else {
                2
            })
        })),
        Duration::from_millis(10),
    );
    let ips: Vec<_> = (1..=3).map(|n| IpAddr::from([198, 51, 100, n])).collect();
    let result = fw.unban_ips_batch(&ips);
    assert_eq!(result.confirmed, ips[..1]);
    assert_eq!(result.errors.len(), 2);
    assert_eq!(fw.metrics.rules_removed.load(Ordering::Relaxed), 1);
}

#[test]
fn batch_acknowledgment_deduplicates_cleanup_and_preserves_renewed_bans_durably() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let store = DecisionStore::open_with_limit(path.clone(), 3600, 3).unwrap();
    let ips: Vec<_> = (1..=3).map(|n| IpAddr::from([198, 51, 100, n])).collect();
    for ip in &ips {
        ban(&store, *ip);
        store.remove_ban(ip).unwrap();
    }
    ban(&store, ips[0]);
    assert_eq!(
        store
            .acknowledge_cleanup_batch(&[ips[0], ips[1], ips[1], ips[2]])
            .unwrap(),
        2
    );
    assert!(store.check_ip(&ips[0]).is_some());
    assert_eq!(store.retained_count(), 1);
    let reopened = DecisionStore::open_with_limit(path, 3600, 3).unwrap();
    assert!(reopened.check_ip(&ips[0]).is_some());
    assert!(reopened.sweep_expired().is_empty());
}

#[cfg(unix)]
#[test]
fn production_runner_deadline_also_covers_commands_that_never_read_stdin() {
    let mut command = FirewallCommandSpec::new("/bin/sleep", ["5"]);
    command.stdin = Some("x".repeat(512 * 1024));
    let start = Instant::now();
    assert!(
        ProcessFirewallCommandRunner
            .run(&command, Duration::from_millis(20))
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    let mut consumes = FirewallCommandSpec::new("/usr/bin/wc", ["-c"]);
    consumes.stdin = Some("x".repeat(128 * 1024));
    assert_eq!(
        ProcessFirewallCommandRunner
            .run(&consumes, Duration::from_secs(2))
            .unwrap(),
        0
    );
}
