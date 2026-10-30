use custos::service::{generate_launchd_plist, generate_windows_sc_create_args};
use std::path::Path;

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
