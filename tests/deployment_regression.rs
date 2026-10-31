use custos::service::{generate_launchd_plist, generate_windows_sc_create_args};
use std::path::Path;

#[test]
fn cli_replay_drains_more_than_one_analysis_work_budget() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let ledger = dir.path().join("ledger");
    let mut cfg = custos::config::AppConfig::default();
    cfg.daemon.decisions_file = ledger.clone();
    cfg.firewall.enabled = false;
    cfg.jev.max_actors_per_batch = 1;
    cfg.window.auth_paths = vec!["/api/v1/auth/login".into()];
    cfg.window.auth_failure_threshold = 5;
    cfg.memory.analysis_batches_per_flush = 1;
    custos::service::write_secret_file(&config, toml::to_string(&cfg).unwrap().as_bytes()).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_custos"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "replay",
            "--log",
            "tests/fixtures/sample_access.log",
            "--mock-jev",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("Jev L2 Actor Verdicts (4)"));
    assert_eq!(
        custos::store::DecisionStore::open(ledger, 3600)
            .unwrap()
            .active_count(),
        4
    );
}

#[tokio::test]
async fn daemon_honors_both_decision_capacity_policies() {
    use custos::{
        config::{AppConfig, DecisionCapacityPolicy, LogFormat, LogSourceConfig},
        store::{DecisionSource, DecisionStore},
    };
    use std::{
        process::{Child, Command, Stdio},
        time::Duration,
    };
    struct Daemon(Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for (policy, expected) in [
        (DecisionCapacityPolicy::FailClosed, 503),
        (DecisionCapacityPolicy::EnforceExisting, 200),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger");
        let config = dir.path().join("config.toml");
        let log = dir.path().join("access.log");
        std::fs::write(&log, "").unwrap();
        let store = DecisionStore::open_with_limit(ledger.clone(), 3600, 1).unwrap();
        store
            .upsert_ban(
                "198.51.100.1".parse().unwrap(),
                "test".into(),
                DecisionSource::ManualAdmin,
                1.,
                1.,
                "test".into(),
                None,
            )
            .unwrap();
        drop(store);
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut cfg = AppConfig::default();
        cfg.daemon.decisions_file = ledger.clone();
        cfg.daemon.bouncer_listen = format!("127.0.0.1:{port}");
        cfg.daemon.on_decision_capacity = policy;
        cfg.memory.max_decisions = 1;
        cfg.firewall.enabled = false;
        cfg.logs = vec![LogSourceConfig {
            path: log,
            format: LogFormat::Json,
        }];
        custos::service::write_secret_file(&config, toml::to_string(&cfg).unwrap().as_bytes())
            .unwrap();
        let mut daemon = Daemon(
            Command::new(env!("CARGO_BIN_EXE_custos"))
                .args(["--config", config.to_str().unwrap(), "run", "--mock-jev"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();
        let check = format!("http://127.0.0.1:{port}/v1/bouncer/check");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    daemon.0.try_wait().unwrap().is_none(),
                    "daemon exited before serving requests"
                );
                if let Ok(response) = client
                    .get(&check)
                    .query(&[("ip", "198.51.100.2")])
                    .send()
                    .await
                {
                    assert_eq!(response.status().as_u16(), expected);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            client
                .get(&check)
                .query(&[("ip", "198.51.100.1")])
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            403
        );
        drop(daemon);
        assert_eq!(
            DecisionStore::open_with_limit(ledger, 3600, 1)
                .unwrap()
                .active_count(),
            1
        );
    }
}

#[test]
fn launchd_manifest_never_contains_api_credentials() {
    let plist = generate_launchd_plist(
        Path::new("/usr/local/bin/custos"),
        Path::new("/etc/custos/config.toml"),
        Path::new("/var/lib/custos"),
        Path::new("/var/log/custos"),
        Some("do-not-disclose-this-token"),
    );
    assert!(!plist.contains("do-not-disclose-this-token"));
    assert!(!plist.contains("TYPESAFE_API_KEY"));
}

#[test]
fn windows_service_registration_selects_the_scm_entry_point() {
    let args = generate_windows_sc_create_args(
        Path::new("C:\\Program Files\\Custos\\custos.exe"),
        Path::new("C:\\ProgramData\\Custos\\config.toml"),
    );
    let bin = args
        .iter()
        .position(|arg| arg == "binPath=")
        .expect("sc option name and value are separate arguments");
    assert!(args[bin + 1].contains("--windows-service"));
    assert!(args[bin + 1].starts_with('"'));
}

#[test]
fn private_credentials_survive_atomic_replacement_without_broad_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    custos::service::write_secret_file(&path, b"first-secret").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"first-secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Upgrading a legacy world-readable file must repair its permissions.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    custos::service::write_secret_file(&path, b"rotated-secret").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"rotated-secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn macos_stop_unloads_the_keepalive_job_and_start_loads_it_again() {
    use custos::service::{ServicePlatform, service_control_command};
    let (program, args) = service_control_command(ServicePlatform::Launchd, false);
    assert_eq!(program, "launchctl");
    assert_eq!(args, ["bootout", "system/ai.typesafe.custos"]);
    let (_, args) = service_control_command(ServicePlatform::Launchd, true);
    assert_eq!(
        args,
        [
            "bootstrap",
            "system",
            "/Library/LaunchDaemons/ai.typesafe.custos.plist"
        ]
    );
}

#[test]
fn docker_config_monitors_mounted_nginx_logs_and_enforces_bans() {
    let cfg: custos::config::AppConfig =
        toml::from_str(include_str!("../config.docker.toml")).unwrap();
    assert_eq!(cfg.logs.len(), 1);
    assert_eq!(cfg.logs[0].path, Path::new("/var/log/nginx/access.log"));
    // This path belongs to the Linux container, regardless of the test host OS.
    assert_eq!(
        cfg.daemon.decisions_file,
        Path::new("/var/lib/custos/decisions.jsonl")
    );
    assert!(cfg.firewall.enabled);
    assert!(!cfg.firewall.dry_run);
    assert_eq!(
        cfg.firewall.backend,
        custos::firewall::FirewallBackend::Nftables
    );
    assert!(
        include_str!("../Dockerfile").contains("COPY config.docker.toml /etc/custos/config.toml")
    );
}

#[test]
fn linux_arm64_installer_target_has_a_release_artifact() {
    let installer = include_str!("../install.sh");
    let releases = include_str!("../.github/workflows/release.yml");
    for target in [
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ] {
        assert!(installer.contains(target));
        assert!(
            releases.contains(&format!("target: {target}")),
            "installer target {target} must be published"
        );
    }
}

#[test]
fn init_writes_exported_tokens_privately_without_echoing_them() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("empty.toml");
    let output = dir.path().join("generated.toml");
    std::fs::write(&input, "").unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_custos"))
        .arg("--config")
        .arg(input)
        .arg("init")
        .arg("--output")
        .arg(&output)
        .env("TYPESAFE_API_KEY", "dummy-jev-secret")
        .env("CUSTOS_API_TOKEN", "dummy-admin-secret")
        .env("CUSTOS_HUB_TOKEN", "dummy-hub-secret")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(result.status.success());
    let cfg: custos::config::AppConfig =
        toml::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
    assert_eq!(cfg.jev.api_key, "dummy-jev-secret");
    assert_eq!(cfg.daemon.api_token, "dummy-admin-secret");
    assert_eq!(cfg.hub.api_token, "dummy-hub-secret");
    assert!(!String::from_utf8_lossy(&result.stdout).contains("secret"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
