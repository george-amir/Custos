use std::process::Command;

#[test]
fn short_version_flags_work_without_loading_configuration() {
    for flag in ["-v", "-V", "--version"] {
        let result = Command::new(env!("CARGO_BIN_EXE_custos"))
            .args(["--config", "does-not-exist.toml", flag])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            String::from_utf8(result.stdout).unwrap().trim(),
            concat!("custos ", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn help_and_version_flags_work_on_nested_commands() {
    for args in [
        vec!["update", "--help"],
        vec!["crawlers", "block", "--help"],
        vec!["crawlers", "-v"],
        vec!["run", "--help"],
        vec!["replay", "--help"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_custos"))
            .args(&args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
