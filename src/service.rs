use crate::config::{AppConfig, LogFormat, LogSourceConfig};
use crate::firewall::FirewallBackend;
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SECRET_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Atomically writes credentials without exposing a readable intermediate file.
/// Replacing an existing file also tightens permissions left by older versions.
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .context("Secret file must have a filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SECRET_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<()> {
        let mut file = create_private_file(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        replace_private_file(&temporary, path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.with_context(|| format!("Failed to securely write {}", path.display()))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn create_private_file(_path: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Private credential files are not supported on this platform",
    ))
}

#[cfg(not(windows))]
fn replace_private_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
mod private_files {
    use std::{
        ffi::c_void,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        path::Path,
    };

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            path: *const u16,
            access: u32,
            sharing: u32,
            attributes: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
    }
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    pub(super) fn create(path: &Path) -> std::io::Result<std::fs::File> {
        // Protected DACL: SYSTEM, Administrators and the file owner only.
        let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let attrs = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor,
                inherit: 0,
            };
            let handle = CreateFileW(
                wide(path).as_ptr(),
                0x40000000,
                0,
                &attrs,
                1,
                0x80,
                std::ptr::null_mut(),
            );
            let error = std::io::Error::last_os_error();
            LocalFree(descriptor);
            if handle as isize == -1 {
                Err(error)
            } else {
                Ok(std::fs::File::from_raw_handle(handle))
            }
        }
    }
    pub(super) fn replace(source: &Path, destination: &Path) -> std::io::Result<()> {
        // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH; the private DACL follows the file.
        if unsafe { MoveFileExW(wide(source).as_ptr(), wide(destination).as_ptr(), 0x9) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    private_files::create(path)
}

#[cfg(windows)]
fn replace_private_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    private_files::replace(source, destination)
}

/// Supported native OS service managers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePlatform {
    /// Linux `systemd` (`/etc/systemd/system/custos.service`)
    Systemd,
    /// macOS `launchd` (`/Library/LaunchDaemons/ai.typesafe.custos.plist`)
    Launchd,
    /// Windows Service Control Manager (`sc.exe`)
    WindowsSc,
}

impl ServicePlatform {
    /// Detects the current host operating system's service manager.
    pub fn detect() -> Self {
        if cfg!(target_os = "linux") {
            Self::Systemd
        } else if cfg!(target_os = "macos") {
            Self::Launchd
        } else if cfg!(target_os = "windows") {
            Self::WindowsSc
        } else {
            Self::Systemd
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Systemd => "systemd (Linux)",
            Self::Launchd => "launchd (macOS)",
            Self::WindowsSc => "sc.exe (Windows Service)",
        }
    }
}

pub const MACOS_PLIST_LABEL: &str = "ai.typesafe.custos";
pub const MACOS_PLIST_PATH: &str = "/Library/LaunchDaemons/ai.typesafe.custos.plist";
pub const LINUX_UNIT_PATH: &str = "/etc/systemd/system/custos.service";

/// Generates the Linux `systemd` unit file content for `custos`.
pub fn generate_systemd_unit(
    bin_path: &Path,
    config_path: &Path,
    work_dir: &Path,
    env_file: &Path,
) -> String {
    format!(
        "[Unit]\n\
         Description=Custos Autonomous Behavioral Security Engine & Firewall Bouncer (TypeSafe Jev)\n\
         Documentation=https://github.com/george-amir/Custos\n\
         After=network-online.target nftables.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         WorkingDirectory={work_dir}\n\
         EnvironmentFile=-{env_file}\n\
         ExecStart={bin_path} --config {config_path} run\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n\
         CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH\n\
         NoNewPrivileges=true\n\
         ProtectSystem=full\n\
         ProtectHome=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        work_dir = work_dir.display(),
        env_file = env_file.display(),
        bin_path = bin_path.display(),
        config_path = config_path.display(),
    )
}

/// Generates the macOS `launchd` LaunchDaemon plist XML for `custos`.
pub fn generate_launchd_plist(
    bin_path: &Path,
    config_path: &Path,
    work_dir: &Path,
    log_dir: &Path,
    _typesafe_api_key: Option<&str>,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin_path}</string>
        <string>--config</string>
        <string>{config_path}</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{work_dir}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/custos.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/custos.err.log</string>
</dict>
</plist>
"#,
        label = MACOS_PLIST_LABEL,
        bin_path = xml_escape(&bin_path.to_string_lossy()),
        config_path = xml_escape(&config_path.to_string_lossy()),
        work_dir = xml_escape(&work_dir.to_string_lossy()),
        log_dir = xml_escape(&log_dir.to_string_lossy()),
    )
}

/// Generates the Windows `sc.exe` command arguments to register `Custos` as an auto-start service.
pub fn generate_windows_sc_create_args(bin_path: &Path, config_path: &Path) -> Vec<String> {
    let bin_arg = format!(
        "\"{}\" --windows-service --config \"{}\" run",
        bin_path.display(),
        config_path.display()
    );
    vec![
        "create".to_string(),
        "Custos".to_string(),
        "binPath=".to_string(),
        bin_arg,
        "start=".to_string(),
        "auto".to_string(),
        "DisplayName=".to_string(),
        "Custos Behavioral Security & Firewall Bouncer".to_string(),
    ]
}

/// Installs and starts `custos` as a persistent background OS service.
pub fn install_service(live_firewall: bool, dry_run: bool) -> Result<()> {
    let platform = ServicePlatform::detect();
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("custos"));
    let target_bin = if cfg!(target_os = "windows") {
        current_exe.clone()
    } else {
        PathBuf::from("/usr/local/bin/custos")
    };

    let config_dir = if cfg!(target_os = "windows") {
        PathBuf::from("C:\\ProgramData\\Custos")
    } else {
        PathBuf::from("/etc/custos")
    };
    let work_dir = if cfg!(target_os = "windows") {
        PathBuf::from("C:\\ProgramData\\Custos")
    } else {
        PathBuf::from("/var/lib/custos")
    };
    let log_dir = PathBuf::from("/var/log/custos");
    let config_path = config_dir.join("config.toml");
    let env_file = config_dir.join("custos.env");

    // Build default production config with auto-discovered logs
    let mut cfg = AppConfig::default();
    cfg.daemon.decisions_file = work_dir.join("decisions.jsonl");
    cfg.firewall.backend = FirewallBackend::Auto.resolve();
    cfg.firewall.dry_run = !live_firewall;
    let discovered = AppConfig::discover_system_logs();
    if discovered.is_empty() {
        cfg.logs.push(LogSourceConfig {
            path: PathBuf::from("/var/log/nginx/access.log"),
            format: LogFormat::NginxCombined,
        });
    } else {
        cfg.logs = discovered;
    }

    println!("=== Custos Service Installer ({}) ===", platform.as_str());
    println!("  Binary Path          : {}", target_bin.display());
    println!("  Config Path          : {}", config_path.display());
    println!("  State Directory      : {}", work_dir.display());
    println!(
        "  Firewall Backend     : {} (dry_run={})",
        cfg.firewall.backend.as_str(),
        cfg.firewall.dry_run
    );

    if dry_run {
        println!("\n[Dry-Run Mode] Generated Service Manifest:");
        match platform {
            ServicePlatform::Systemd => {
                println!(
                    "--- {} ---\n{}",
                    LINUX_UNIT_PATH,
                    generate_systemd_unit(&target_bin, &config_path, &work_dir, &env_file)
                );
            }
            ServicePlatform::Launchd => {
                println!(
                    "--- {} ---\n{}",
                    MACOS_PLIST_PATH,
                    generate_launchd_plist(&target_bin, &config_path, &work_dir, &log_dir, None)
                );
            }
            ServicePlatform::WindowsSc => {
                let args = generate_windows_sc_create_args(&target_bin, &config_path);
                println!("  $ sc.exe {}", args.join(" "));
                println!("  $ sc.exe start Custos");
            }
        }
        return Ok(());
    }

    // Create directories and write config if not already present
    std::fs::create_dir_all(&config_dir).with_context(|| {
        format!(
            "Failed to create {} (run with `sudo custos service install` or `--dry-run`)",
            config_dir.display()
        )
    })?;
    std::fs::create_dir_all(&work_dir)?;

    if !config_path.exists() {
        let toml_str = toml::to_string_pretty(&cfg)?;
        write_secret_file(&config_path, toml_str.as_bytes())?;
        println!("  Created Config       : {}", config_path.display());
    } else {
        // Repair permissions on credentials created by older installers.
        write_secret_file(&config_path, &std::fs::read(&config_path)?)?;
        println!(
            "  Preserved Config     : {} (already exists)",
            config_path.display()
        );
    }

    // Copy current binary to /usr/local/bin/custos on Unix if needed
    if !cfg!(target_os = "windows") && current_exe != target_bin {
        if let Some(parent) = target_bin.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&current_exe, &target_bin).with_context(|| {
            format!(
                "Failed to install binary to {} (ensure you run with sudo)",
                target_bin.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&target_bin, std::fs::Permissions::from_mode(0o755));
        }
    }

    match platform {
        ServicePlatform::Systemd => {
            if !env_file.exists() {
                write_secret_file(&env_file, b"RUST_LOG=info\n")?;
            } else {
                write_secret_file(&env_file, &std::fs::read(&env_file)?)?;
            }
            let unit = generate_systemd_unit(&target_bin, &config_path, &work_dir, &env_file);
            std::fs::write(LINUX_UNIT_PATH, unit)
                .with_context(|| format!("Failed to write {LINUX_UNIT_PATH} (run with sudo)"))?;
            run_cmd("systemctl", &["daemon-reload"])?;
            run_cmd("systemctl", &["enable", "--now", "custos"])?;
            println!("  Service Status       : enabled & started via systemd");
        }
        ServicePlatform::Launchd => {
            std::fs::create_dir_all(&log_dir)?;
            let plist =
                generate_launchd_plist(&target_bin, &config_path, &work_dir, &log_dir, None);
            std::fs::write(MACOS_PLIST_PATH, plist)
                .with_context(|| format!("Failed to write {MACOS_PLIST_PATH} (run with sudo)"))?;
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("system/{MACOS_PLIST_LABEL}")])
                .output();
            run_cmd("launchctl", &["bootstrap", "system", MACOS_PLIST_PATH])?;
            println!(
                "  Service Status       : loaded & started via launchd ({})",
                MACOS_PLIST_LABEL
            );
            println!("  Logs                 : /var/log/custos/custos.log");
        }
        ServicePlatform::WindowsSc => {
            let args = generate_windows_sc_create_args(&target_bin, &config_path);
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_cmd("sc.exe", &arg_refs)?;
            run_cmd("sc.exe", &["start", "Custos"])?;
            println!("  Service Status       : registered & started via Windows SCM");
        }
    }

    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Command plans are shared by execution and tests; stopping launchd unloads
/// the job so its KeepAlive policy cannot immediately restart it.
pub fn service_control_command(
    platform: ServicePlatform,
    start: bool,
) -> (&'static str, Vec<String>) {
    let (program, args): (&str, Vec<&str>) = match (platform, start) {
        (ServicePlatform::Systemd, true) => ("systemctl", vec!["start", "custos"]),
        (ServicePlatform::Systemd, false) => ("systemctl", vec!["stop", "custos"]),
        (ServicePlatform::Launchd, true) => {
            ("launchctl", vec!["bootstrap", "system", MACOS_PLIST_PATH])
        }
        (ServicePlatform::Launchd, false) => {
            ("launchctl", vec!["bootout", "system/ai.typesafe.custos"])
        }
        (ServicePlatform::WindowsSc, true) => ("sc.exe", vec!["start", "Custos"]),
        (ServicePlatform::WindowsSc, false) => ("sc.exe", vec!["stop", "Custos"]),
    };
    (program, args.into_iter().map(String::from).collect())
}

pub fn start_service() -> Result<()> {
    let (program, args) = service_control_command(ServicePlatform::detect(), true);
    run_cmd(
        program,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

pub fn stop_service() -> Result<()> {
    let (program, args) = service_control_command(ServicePlatform::detect(), false);
    run_cmd(
        program,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

pub fn uninstall_service() -> Result<()> {
    match ServicePlatform::detect() {
        ServicePlatform::Systemd => {
            let _ = run_cmd("systemctl", &["disable", "--now", "custos"]);
            if Path::new(LINUX_UNIT_PATH).exists() {
                std::fs::remove_file(LINUX_UNIT_PATH)?;
            }
            let _ = run_cmd("systemctl", &["daemon-reload"]);
            println!("Removed systemd service {LINUX_UNIT_PATH}");
        }
        ServicePlatform::Launchd => {
            if Path::new(MACOS_PLIST_PATH).exists() {
                let _ = run_cmd("launchctl", &["bootout", "system/ai.typesafe.custos"]);
                std::fs::remove_file(MACOS_PLIST_PATH)?;
            }
            println!("Removed macOS LaunchDaemon {MACOS_PLIST_PATH}");
        }
        ServicePlatform::WindowsSc => {
            let _ = run_cmd("sc.exe", &["stop", "Custos"]);
            run_cmd("sc.exe", &["delete", "Custos"])?;
            println!("Removed Windows Service 'Custos'");
        }
    }
    Ok(())
}

pub fn status_service() -> Result<()> {
    let platform = ServicePlatform::detect();
    println!("=== Custos Service Status ({}) ===", platform.as_str());
    match platform {
        ServicePlatform::Systemd => {
            let out = Command::new("systemctl")
                .args(["status", "custos", "--no-pager"])
                .output();
            match out {
                Ok(o) => println!("{}", String::from_utf8_lossy(&o.stdout)),
                Err(e) => println!("systemctl check failed: {e}"),
            }
        }
        ServicePlatform::Launchd => {
            let plist_exists = Path::new(MACOS_PLIST_PATH).exists();
            println!(
                "  Plist Installed      : {} ({})",
                plist_exists, MACOS_PLIST_PATH
            );
            if let Ok(out) = Command::new("launchctl")
                .args(["list", MACOS_PLIST_LABEL])
                .output()
            {
                if out.status.success() {
                    println!("  launchctl state      : running");
                    println!("{}", String::from_utf8_lossy(&out.stdout).trim());
                } else {
                    println!("  launchctl state      : not loaded");
                }
            }
        }
        ServicePlatform::WindowsSc => {
            if let Ok(out) = Command::new("sc.exe").args(["query", "Custos"]).output() {
                println!("{}", String::from_utf8_lossy(&out.stdout));
            }
        }
    }
    Ok(())
}

fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute `{program} {}`", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{program} {}` exited with {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_systemd_unit_and_launchd_plist() {
        let unit = generate_systemd_unit(
            Path::new("/usr/local/bin/custos"),
            Path::new("/etc/custos/config.toml"),
            Path::new("/var/lib/custos"),
            Path::new("/etc/custos/custos.env"),
        );
        assert!(
            unit.contains("ExecStart=/usr/local/bin/custos --config /etc/custos/config.toml run")
        );
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"));

        let plist = generate_launchd_plist(
            Path::new("/usr/local/bin/custos"),
            Path::new("/etc/custos/config.toml"),
            Path::new("/var/lib/custos"),
            Path::new("/var/log/custos"),
            Some("ts_test_123"),
        );
        assert!(plist.contains("<string>ai.typesafe.custos</string>"));
        assert!(plist.contains("<string>/usr/local/bin/custos</string>"));
        assert!(!plist.contains("ts_test_123"));

        let win_args = generate_windows_sc_create_args(
            Path::new("C:\\Program Files\\Custos\\custos.exe"),
            Path::new("C:\\ProgramData\\Custos\\config.toml"),
        );
        assert_eq!(win_args[0], "create");
        assert_eq!(win_args[1], "Custos");
    }
}
