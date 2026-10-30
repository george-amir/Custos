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
        "hub_retained":hub.retained_counts(),"window_retained":windows.retained_window_counts()})
    );
}
