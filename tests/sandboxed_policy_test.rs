use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn command(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chimera"))
        .args(args)
        .arg("--root")
        .arg(root)
        .output()
        .unwrap()
}

fn snapshot(root: &Path) -> Vec<(String, u64, u64, Vec<u8>)> {
    let mut entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let metadata = entry.metadata().unwrap();
            let bytes = if metadata.is_file() {
                fs::read(entry.path()).unwrap()
            } else {
                Vec::new()
            };
            (name, metadata.dev(), metadata.ino(), bytes)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

#[test]
fn doctor_missing_config_is_error_and_does_not_create_it() {
    let root = TempDir::new().unwrap();
    let before = snapshot(root.path());
    let output = command(root.path(), &["doctor", "--json"]);
    assert!(!output.status.success());
    assert!(!root.path().join("config.toml").exists());
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn doctor_json_is_read_only_and_never_claims_activation() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("config.toml"), "").unwrap();
    let before = snapshot(root.path());
    let output = command(root.path(), &["doctor", "--json"]);
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["activation_available"], false);
    assert_eq!(report["checks"].as_array().unwrap().len(), 7);
    assert_eq!(report["checks"][6]["id"], "activation");
    assert_eq!(report["checks"][6]["status"], "failed");
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn install_policy_only_renders_and_does_not_write_root() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("config.toml"),
        "[execution.network]\nproduction_cidrs = []\n",
    )
    .unwrap();
    let before = snapshot(root.path());
    let output = command(root.path(), &["install-policy", "--render"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("activation_available: false"));
    assert!(stdout.contains("IPAddressDeny="));
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn install_policy_rejects_unrequested_apply_modes() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("config.toml"),
        "[execution.network]\nproduction_cidrs = []\n",
    )
    .unwrap();
    let before = snapshot(root.path());
    for args in [
        vec!["install-policy"],
        vec!["install-policy", "--render", "--apply"],
    ] {
        let output = command(root.path(), &args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(snapshot(root.path()), before);
    }
}

#[test]
fn malformed_config_does_not_echo_secret() {
    let root = TempDir::new().unwrap();
    let secret = "synthetic_secret_do_not_echo_987";
    fs::write(
        root.path().join("config.toml"),
        format!("[execution.network]\nproduction_cidrs = [\"{secret}\"]\n"),
    )
    .unwrap();
    let output = command(root.path(), &["doctor", "--json"]);
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(secret));
    assert!(combined.contains("config"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn doctor_on_non_linux_reports_failed_platform() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("config.toml"), "").unwrap();
    let output = command(root.path(), &["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["checks"][0]["id"], "platform");
    assert_eq!(report["checks"][0]["status"], "failed");
}
