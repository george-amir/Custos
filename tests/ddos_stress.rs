//! Run the longer profile with CUSTOS_STRESS_SECONDS=60 cargo test --test ddos_stress.
//! The worker is isolated so allocator/RSS measurements do not include parallel tests.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Metered;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn added(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Metered {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(p, layout, size) };
        if !out.is_null() {
            if size > layout.size() {
                added(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        out
    }
}
#[global_allocator]
static ALLOCATOR: Metered = Metered;

#[cfg(unix)]
fn rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let peak = unsafe { usage.assume_init() }.ru_maxrss as u64;
    #[cfg(target_os = "macos")]
    {
        peak
    }
    #[cfg(not(target_os = "macos"))]
    {
        peak * 1024
    }
}
#[cfg(windows)]
fn rss() -> u64 {
    #[repr(C)]
    struct Counters {
        cb: u32,
        faults: u32,
        sizes: [usize; 8],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(p: *mut std::ffi::c_void, info: *mut Counters, size: u32) -> i32;
    }
    let mut c = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        faults: 0,
        sizes: [0; 8],
    };
    assert_ne!(
        unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut c,
                std::mem::size_of::<Counters>() as u32,
            )
        },
        0
    );
    c.sizes[1] as u64
}
#[cfg(not(any(unix, windows)))]
fn rss() -> u64 {
    LIVE.load(Ordering::Relaxed) as u64
}

#[test]
fn sustained_ddos_memory_plateaus() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ddos_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn sustained_saturation_preserves_site_and_ledger() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "saturation_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
#[ignore = "isolated worker launched by sustained_saturation_preserves_site_and_ledger"]
fn saturation_worker() {
    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
        routing::get,
    };
    use custos::{
        SecurityPipeline,
        bouncer_api::{AppState, build_bouncer_router},
        config::{FirewallConfig, JevConfig, WindowConfig},
        firewall::{FirewallBackend, FirewallBouncer, FirewallCommandRunner, FirewallCommandSpec},
        hub::{
            HubEngine, ip_to_bytes,
            proto::{IpSignal, SignalBatch, SignatureSignal},
        },
        jev::JevBatchAnalyzer,
        limits::MemoryLimits,
        middleware::custos_bouncer_middleware,
        store::{DecisionSource, DecisionStore},
        tailer::AccessLogEvent,
        window::SlidingWindowEngine,
    };
    use std::{
        collections::HashSet,
        net::{IpAddr, SocketAddr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicI64},
        },
        time::{Duration, Instant},
    };
    use tower::ServiceExt;
    #[derive(Default)]
    struct Kernel {
        live: Mutex<HashSet<IpAddr>>,
        fail: AtomicBool,
        deletes: AtomicUsize,
    }
    impl FirewallCommandRunner for Kernel {
        fn run(&self, command: &FirewallCommandSpec, _: Duration) -> anyhow::Result<i32> {
            let addresses: Vec<IpAddr> = command.args[4..]
                .iter()
                .map(|ip| ip.parse().unwrap())
                .collect();
            if command.args[3] == "add" {
                self.live.lock().unwrap().extend(addresses);
            } else {
                self.deletes.fetch_add(1, Ordering::Relaxed);
                if self.fail.load(Ordering::Relaxed) {
                    return Ok(2);
                }
                let mut live = self.live.lock().unwrap();
                for ip in addresses {
                    live.remove(&ip);
                }
            }
            Ok(0)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let limits = MemoryLimits {
        max_decisions: 64,
        max_pending_actors: 64,
        max_pending_bytes: 256 * 1024,
        event_queue_bytes: 64 * 1024,
        event_queue_capacity: 64,
        hub_max_entries: 64,
        max_signatures: 32,
        hub_max_pending_entries: 32,
        hub_max_pending_signatures: 16,
        hub_max_pending_per_node: 8,
        hub_vote_ttl_secs: 2,
        hub_retention_secs: 2,
        analysis_ttl_secs: 2,
        analysis_batches_per_flush: 4,
        ..Default::default()
    };
    let kernel = Arc::new(Kernel::default());
    kernel.fail.store(true, Ordering::Relaxed);
    let p = SecurityPipeline::new_with_limits(
        Arc::new(DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 64).unwrap()),
        Arc::new(SlidingWindowEngine::with_limits(
            WindowConfig {
                max_state_bytes: 512 * 1024,
                max_tracked_ips: 128,
                ..Default::default()
            },
            limits.clone(),
        )),
        Arc::new(
            JevBatchAnalyzer::new(
                JevConfig {
                    api_key: String::new(),
                    ..Default::default()
                },
                false,
            )
            .unwrap(),
        ),
        Arc::new(FirewallBouncer::with_runner(
            FirewallConfig {
                backend: FirewallBackend::Pf,
                dry_run: false,
                ..Default::default()
            },
            kernel.clone(),
            Duration::from_secs(1),
        )),
        limits.clone(),
    )
    .unwrap();
    let address = |n| IpAddr::V4(std::net::Ipv4Addr::from(0xc6330000u32 + n));
    for n in 1..=64u32 {
        p.record_ban(
            address(n),
            "scanner".into(),
            DecisionSource::ManualAdmin,
            1.,
            1.,
            "stress".into(),
            None,
        )
        .unwrap();
        if n % 2 == 0 {
            p.store.remove_ban(&address(n)).unwrap();
        }
    }
    p.window.register_auto_signature("GET", "/.env", "scanner");
    let checker = build_bouncer_router(AppState {
        pipeline: p.clone(),
        api_token: String::new(),
    });
    let handlers = Arc::new(AtomicUsize::new(0));
    let hits = handlers.clone();
    let website = Router::new()
        .fallback(get(move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                "healthy"
            }
        }))
        .layer(axum::middleware::from_fn_with_state(
            p.clone(),
            custos_bouncer_middleware,
        ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let clock = Arc::new(AtomicI64::new(100));
    let now = clock.clone();
    let hub = HubEngine::with_limits_and_clock(
        2,
        limits.clone(),
        Arc::new(move || now.load(Ordering::Relaxed)),
    );
    let stopping = Arc::new(AtomicBool::new(false));
    let generated = Arc::new(AtomicUsize::new(0));
    let producers: Vec<_> = (0..2)
        .map(|_| {
            let p = p.clone();
            let stopping = stopping.clone();
            let generated = generated.clone();
            std::thread::spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    let n = generated.fetch_add(1, Ordering::Relaxed) as u32;
                    let event = AccessLogEvent {
                        timestamp: chrono::Utc::now(),
                        client_ip: IpAddr::V4(std::net::Ipv4Addr::from(
                            0xcb000000u32.wrapping_add(n),
                        )),
                        method: "GET".into(),
                        path: format!("/search/{}", "a".repeat(if n & 1 == 0 { 7900 } else { 32 })),
                        query: "q=1+UNION/**/SELECT+password".into(),
                        status: 500,
                        bytes_sent: 0,
                        referer: String::new(),
                        user_agent: "x".repeat(2048),
                    };
                    let _ = p.process_event(&event);
                }
            })
        })
        .collect();
    let seconds = std::env::var("CUSTOS_STRESS_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10)
        .max(1);
    let started = Instant::now();
    let mut waves = 0u32;
    let mut baseline = None;
    let mut max_heap = 0;
    let mut max_rss = 0;
    while started.elapsed() < Duration::from_secs(seconds) || waves < 32 {
        waves += 1;
        clock.fetch_add(3, Ordering::Relaxed);
        p.window.register_auto_signature("GET", "/.env", "scanner");
        for n in 1..=64 {
            let message = SignalBatch {
                node_id: "noisy".into(),
                api_token: String::new(),
                ip_signals: vec![IpSignal {
                    ip: ip_to_bytes(address(1000 + waves * 128 + n)),
                    threat: 3,
                    noul: 0.99,
                    confidence: 0.99,
                    suggested_ttl_secs: 2,
                }],
                signature_signals: vec![SignatureSignal {
                    method: "GET".into(),
                    path_prefix: format!("/exploit/{waves}/{n}"),
                    threat: 3,
                    confidence: 0.99,
                }],
            };
            hub.ingest_batch(message);
        }
        let quorum_ip = address(100_000 + waves);
        for node in ["honest-a", "honest-b"] {
            let ack = hub.ingest_batch(SignalBatch {
                node_id: node.into(),
                api_token: String::new(),
                ip_signals: vec![IpSignal {
                    ip: ip_to_bytes(quorum_ip),
                    threat: 3,
                    noul: 0.99,
                    confidence: 0.99,
                    suggested_ttl_secs: 2,
                }],
                signature_signals: vec![],
            });
            assert_eq!(
                ack.rejected_capacity, 0,
                "one noisy reporter starved independent quorum"
            );
        }
        assert_eq!(hub.pull_since(0).ip_deltas.len(), 1);
        if let Ok(verdicts) = runtime.block_on(p.flush_and_analyze(true)) {
            assert!(verdicts.is_empty());
        }
        assert_eq!(p.jev.metrics.actors_evaluated.load(Ordering::Relaxed), 0);
        runtime.block_on(async {
            for (n, expected) in [(100_000, StatusCode::OK), (1, StatusCode::FORBIDDEN)] {
                let response = checker
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/v1/bouncer/check?ip={}", address(n)))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected);
            }
            let signature = checker
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/bouncer/check?ip={}", address(100_000)))
                        .header("x-original-method", "GET")
                        .header("x-original-uri", "/.env")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(signature.status(), StatusCode::FORBIDDEN);
            drop(signature);
            for (n, path, expected) in [
                (100_000, "/products", StatusCode::OK),
                (1, "/products", StatusCode::FORBIDDEN),
                (100_000, "/.env", StatusCode::FORBIDDEN),
            ] {
                let mut request = Request::builder().uri(path).body(Body::empty()).unwrap();
                request
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::new(address(n), 12345)));
                assert_eq!(
                    website.clone().oneshot(request).await.unwrap().status(),
                    expected
                );
            }
        });
        assert!(
            p.record_ban(
                address(100_000 + waves),
                "new".into(),
                DecisionSource::ManualAdmin,
                1.,
                1.,
                "full".into(),
                None
            )
            .is_err()
        );
        assert_eq!(p.store.retained_count(), 64);
        assert_eq!(p.store.active_count(), 32);
        assert_eq!(p.store.sweep_expired().len(), 32);
        assert_eq!(kernel.live.lock().unwrap().len(), 64);
        assert!(
            p.analysis_metrics.pending_actors.load(Ordering::Relaxed) <= limits.max_pending_actors
        );
        assert!(
            p.analysis_metrics.pending_bytes.load(Ordering::Relaxed) <= limits.max_pending_bytes
        );
        let (active, ready) = p.window.retained_window_counts();
        assert!(active <= p.window.max_windows() && ready <= p.window.max_windows());
        let (ips, sigs, history) = hub.retained_counts();
        assert!(
            ips <= limits.hub_max_entries && sigs <= limits.max_signatures && history <= ips + sigs
        );
        let heap = LIVE.load(Ordering::Relaxed);
        let resident = rss();
        if waves == 16 {
            baseline = Some((heap, resident));
        }
        if let Some((warm_heap, warm_rss)) = baseline {
            max_heap = max_heap.max(heap);
            max_rss = max_rss.max(resident);
            assert!(
                heap <= warm_heap + 4 * 1024 * 1024,
                "saturated heap did not plateau: {heap} > {warm_heap}"
            );
            assert!(
                resident <= warm_rss + 24 * 1024 * 1024,
                "saturated RSS did not plateau: {resident} > {warm_rss}"
            );
        }
        assert!(resident < 128 * 1024 * 1024);
    }
    stopping.store(true, Ordering::Relaxed);
    for producer in producers {
        producer.join().unwrap();
    }
    assert_eq!(handlers.load(Ordering::Relaxed), waves as usize);
    assert!(
        kernel.deletes.load(Ordering::Relaxed) <= started.elapsed().as_secs() as usize + 2,
        "cleanup pressure was not coalesced"
    );
    p.store.compact_persistence_file().unwrap();
    let reopened = DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 64).unwrap();
    assert_eq!(reopened.active_count(), 32);
    assert_eq!(reopened.sweep_expired().len(), 32);
    for n in (1..=64).step_by(2) {
        assert!(reopened.check_ip(&address(n)).is_some());
    }
    kernel.fail.store(false, Ordering::Relaxed);
    p.reconcile_firewall().unwrap();
    assert_eq!(p.store.active_count(), 32);
    assert!(p.store.sweep_expired().is_empty());
    assert_eq!(kernel.live.lock().unwrap().len(), 32);
    assert_eq!(
        DecisionStore::open_with_limit(dir.path().join("ledger"), 3600, 64)
            .unwrap()
            .retained_count(),
        32
    );
    p.record_ban(
        address(200_000),
        "new".into(),
        DecisionSource::ManualAdmin,
        1.,
        1.,
        "recovered".into(),
        None,
    )
    .unwrap();
    println!(
        "{}",
        serde_json::json!({"profile":"site-saturation","seconds":started.elapsed().as_secs_f64(),"attack_events":generated.load(Ordering::Relaxed),
        "healthy_requests":waves * 2,"existing_ban_checks":waves * 2,"signature_checks":waves * 2,"steady_heap_max_bytes":max_heap,"steady_rss_max_bytes":max_rss,
        "warmup":baseline,"analysis_capacity_dropped":p.analysis_metrics.capacity_dropped.load(Ordering::Relaxed),"analysis_expired":p.analysis_metrics.expired.load(Ordering::Relaxed),
        "preserved_active_bans":32,"preserved_pending_cleanup_before_recovery":32,"retained_after_recovery":p.store.retained_count()})
    );
}

#[test]
#[ignore = "isolated worker launched by sustained_ddos_memory_plateaus"]
fn ddos_worker() {
    use chrono::{TimeDelta, Utc};
    use custos::{
        SecurityPipeline,
        config::{AppConfig, WindowConfig},
        hub::{
            HubEngine, ip_to_bytes,
            proto::{IpSignal, SignalBatch, SignatureSignal},
        },
        limits::MemoryLimits,
        store::{DecisionSource, DecisionStore},
        tailer::AccessLogEvent,
        window::SlidingWindowEngine,
    };
    use std::sync::{Arc, atomic::AtomicI64};
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let mut limits = MemoryLimits {
        max_decisions: 256,
        event_queue_bytes: 64 * 1024,
        event_queue_capacity: 64,
        hub_max_entries: 256,
        max_signatures: 64,
        hub_retention_secs: 2,
        ..Default::default()
    };
    let defaults = std::env::var_os("CUSTOS_STRESS_DEFAULTS").is_some();
    if defaults {
        limits = MemoryLimits::default();
    }
    let store = DecisionStore::open_with_limit(dir.path().join("bans"), 3600, limits.max_decisions)
        .unwrap();
    let window_cfg = if defaults {
        WindowConfig::default()
    } else {
        WindowConfig {
            max_state_bytes: 1024 * 1024,
            max_tracked_ips: 512,
            ..Default::default()
        }
    };
    let windows = SlidingWindowEngine::with_limits(window_cfg.clone(), limits.clone());
    let retries = SlidingWindowEngine::new(WindowConfig {
        max_tracked_ips: 128,
        max_state_bytes: 1024 * 1024,
        max_sample_requests: 0,
        l1_flood_threshold: 1,
        throttle_secs: 1,
        ..Default::default()
    });
    let clock = Arc::new(AtomicI64::new(1000));
    let clock_fn = clock.clone();
    let hub = HubEngine::with_limits_and_clock(
        2,
        limits.clone(),
        Arc::new(move || clock_fn.load(Ordering::Relaxed)),
    );
    let mut cfg = AppConfig::default();
    cfg.firewall.enabled = false;
    cfg.daemon.decisions_file = dir.path().join("pipeline");
    cfg.memory = limits.clone();
    cfg.window = window_cfg;
    let p = SecurityPipeline::new_with_limits(
        Arc::new(
            DecisionStore::open_with_limit(
                cfg.daemon.decisions_file.clone(),
                3600,
                limits.max_decisions,
            )
            .unwrap(),
        ),
        Arc::new(SlidingWindowEngine::with_limits(
            cfg.window.clone(),
            limits.clone(),
        )),
        Arc::new(
            custos::jev::JevBatchAnalyzer::with_response_limit(
                custos::config::JevConfig {
                    api_key: String::new(),
                    ..Default::default()
                },
                false,
                limits.max_provider_response_bytes,
            )
            .unwrap(),
        ),
        Arc::new(custos::firewall::FirewallBouncer::new(cfg.firewall.clone())),
        limits.clone(),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let seconds = std::env::var("CUSTOS_STRESS_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10)
        .max(1);
    let start = Instant::now();
    let event_start = Utc::now();
    let mut wave = 0;
    let mut requests = 0u32;
    let mut rejected = 0u64;
    let mut baseline = None;
    let mut steady_rss = 0;
    let mut steady_heap = 0;
    while start.elapsed() < Duration::from_secs(seconds) || wave < 12 {
        wave += 1;
        clock.fetch_add(3, Ordering::Relaxed);
        for _ in 0..2000 {
            requests += 1;
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(0xc6120000u32 + requests));
            let e = AccessLogEvent {
                timestamp: event_start + TimeDelta::seconds(wave * 20),
                client_ip: ip,
                method: "GET".into(),
                path: format!(
                    "/products/{}",
                    "a".repeat(if requests & 1 == 0 { 8000 } else { 80 })
                ),
                query: "id=1+UNION/**/SELECT+password".into(),
                status: 200,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: "x".repeat(2048),
            };
            windows.ingest(&e);
            let retry = AccessLogEvent {
                timestamp: e.timestamp,
                client_ip: ip,
                method: "GET".into(),
                path: "/api/feed".into(),
                query: String::new(),
                status: 200,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: format!("rotating-device-{requests}"),
            };
            assert!(matches!(
                retries.ingest(&retry),
                custos::window::L1Disposition::Throttled { .. }
            ));
            if requests & 7 == 0 {
                let _ = runtime.block_on(p.submit_event(e));
            }
            if store
                .upsert_ban(
                    ip,
                    "scanner".into(),
                    DecisionSource::L1Deterministic,
                    1.,
                    1.,
                    "stress".into(),
                    None,
                )
                .is_err()
            {
                rejected += 1;
            }
            let signals = SignalBatch {
                node_id: "a".into(),
                api_token: String::new(),
                ip_signals: vec![IpSignal {
                    ip: ip_to_bytes(ip),
                    threat: 3,
                    noul: 0.99,
                    confidence: 0.99,
                    suggested_ttl_secs: 2,
                }],
                signature_signals: vec![SignatureSignal {
                    method: "GET".into(),
                    path_prefix: format!("/probe/{requests}"),
                    threat: 3,
                    confidence: 0.99,
                }],
            };
            hub.ingest_batch(signals.clone());
            if requests & 15 == 0 {
                let mut quorum = signals;
                quorum.node_id = "b".into();
                hub.ingest_batch(quorum);
            }
            windows.try_register_auto_signature("GET", &format!("/probe/{requests}"), "scanner");
        }
        if wave == 9 {
            use std::io::Write;
            let path = dir.path().join("flood.log");
            let line =
                serde_json::json!({"ip":"198.51.100.20","uri":format!("/{}","a".repeat(2048))})
                    .to_string()
                    + "\n";
            let mut writer = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
            for _ in 0..20_000 {
                writer.write_all(line.as_bytes()).unwrap();
            }
            writer.flush().unwrap();
            drop(writer);
            let before = LIVE.load(Ordering::Relaxed);
            let earlier_peak = PEAK.swap(before, Ordering::Relaxed);
            assert_eq!(
                custos::tailer::visit_log_file(&path, custos::config::LogFormat::Json, |_| Ok(()))
                    .unwrap(),
                20_000
            );
            let replay_peak = PEAK.load(Ordering::Relaxed);
            assert!(
                replay_peak <= before + 2 * 1024 * 1024,
                "streaming replay retained the file: {replay_peak} > {before}"
            );
            PEAK.fetch_max(earlier_peak, Ordering::Relaxed);
        }
        assert!(
            runtime.block_on(p.flush_and_analyze(true)).is_err(),
            "provider outage must keep batches retryable"
        );
        assert!(store.retained_count() <= limits.max_decisions);
        let (ips, sigs, history) = hub.retained_counts();
        assert!(
            ips <= limits.hub_max_entries && sigs <= limits.max_signatures && history <= ips + sigs
        );
        assert!(windows.active_signature_count() <= limits.max_signatures);
        assert!(retries.retained_throttle_count() <= retries.max_windows());
        assert!(retries.drain_suspicious_summaries(true).is_empty());
        let (active, expired) = windows.retained_window_counts();
        assert!(
            active <= if defaults { 50_000 } else { 512 }
                && expired <= if defaults { 50_000 } else { 512 }
        );
        assert!(p.available_queue_bytes() <= limits.event_queue_bytes);
        let heap = LIVE.load(Ordering::Relaxed);
        let resident = rss();
        if wave == 8 {
            baseline = Some((heap, resident));
        }
        if let Some((warm_heap, warm_rss)) = baseline {
            steady_heap = steady_heap.max(heap);
            steady_rss = steady_rss.max(resident);
            assert!(
                heap <= warm_heap + 4 * 1024 * 1024,
                "heap kept growing after saturation: {heap} > {warm_heap}"
            );
            assert!(
                resident <= warm_rss + 24 * 1024 * 1024,
                "RSS kept growing after saturation: {resident} > {warm_rss}"
            );
        }
        assert!(
            resident < 256 * 1024 * 1024,
            "isolated stress profile exceeded 256 MiB RSS"
        );
    }
    assert!(rejected > 0 && hub.capacity_rejected.load(Ordering::Relaxed) > 0);
    assert_eq!(store.retained_count(), limits.max_decisions);
    println!(
        "{}",
        serde_json::json!({"default_limits":defaults,"seconds":start.elapsed().as_secs_f64(),"requests":requests,"waves":wave,
        "rejected_bans":rejected,"steady_heap_max_bytes":steady_heap,"steady_rss_max_bytes":steady_rss,
        "peak_rust_heap_bytes":PEAK.load(Ordering::Relaxed),"warmup":baseline,"retained_bans":store.retained_count(),
        "hub_retained":hub.retained_counts(),"window_retained":windows.retained_window_counts(),
        "http_throttles_retained":retries.retained_throttle_count(),"http_throttle_limit":retries.max_windows()})
    );
}
