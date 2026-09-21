use super::catalog::{Reason, ScenarioId, validate_coverage};
use super::host::{NativeConfig, NativeLease, acquire_fixture};
use super::report::{EvidenceMode, QualificationReport, Verdict, qualifies};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    temp: tempfile::TempDir,
    config: NativeConfig,
    boot: uuid::Uuid,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let mut config: NativeConfig =
            serde_json::from_str(include_str!("../fixtures/qualification/config.json")).unwrap();
        config.root = base.join("qualification");
        config.report_root = config.root.join("reports");
        config.driver = base.join("driver");
        fs::create_dir(&config.root).unwrap();
        fs::create_dir(&config.report_root).unwrap();
        Self {
            temp,
            config,
            boot: uuid::Uuid::new_v4(),
        }
    }
    fn base(&self) -> PathBuf {
        self.temp.path().canonicalize().unwrap()
    }
    fn acquire(&self) -> Result<NativeLease, Reason> {
        let run = uuid::Uuid::new_v4();
        super::host_test::after_transient_host_busy(|| {
            acquire_fixture(
                &self.config,
                run,
                self.boot,
                &self.base().join("lock"),
                &self.base().join("active"),
            )
        })
    }
    fn driver(&self) {
        fs::write(
            &self.config.driver,
            "#!/bin/sh\nprintf invoked > \"$0.invoked\"\nexit 99\n",
        )
        .unwrap();
        fs::set_permissions(&self.config.driver, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn assert_blocked(report: &QualificationReport) {
    validate_coverage(&report.results).unwrap();
    assert_eq!(
        report
            .results
            .iter()
            .map(|row| row.key.scenario)
            .collect::<std::collections::BTreeSet<_>>(),
        ScenarioId::ALL.into_iter().collect()
    );
    assert!(
        report
            .results
            .iter()
            .all(|row| row.verdict == Verdict::Blocked
                && row.reason == Some(Reason::BackendUnavailable)
                && row.checks.is_empty())
    );
    assert!(report.driver_digest.is_empty());
    assert!(report.resource_summaries.is_empty());
    assert!(!report.activation_available);
    assert!(!qualifies(report));
}

#[test]
fn orchestrator_blocked_report_never_asserts_unknown_cleanup() {
    for mode in [
        EvidenceMode::Fixture,
        EvidenceMode::NestedSmoke,
        EvidenceMode::NativeDebian,
    ] {
        let mut identity = super::report_test::identity();
        identity.mode = mode;
        let report = super::blocked_report(identity, Reason::BackendUnavailable);
        assert_blocked(&report);
        assert!(!report.cleanup_confirmed);
    }
}

#[test]
fn orchestrator_missing_and_present_driver_publish_complete_nonqualifying_reports() {
    for present in [false, true] {
        let fixture = Fixture::new();
        if present {
            fixture.driver();
        }
        let lease = fixture.acquire().unwrap();
        let directory = lease.run_directory().to_owned();
        let report = super::publish_unavailable(lease, "a".repeat(40)).unwrap();
        assert_blocked(&report);
        assert_eq!(report.identity.mode, EvidenceMode::Fixture);
        assert_eq!(
            report.identity.config_digest,
            fixture.config.digest().unwrap()
        );
        assert!(report.cleanup_confirmed); // No workload was ever started.
        let saved: QualificationReport =
            serde_json::from_slice(&fs::read(directory.join("report.json")).unwrap()).unwrap();
        assert_eq!(report, saved);
        assert!(
            fs::read_to_string(directory.join("report.md"))
                .unwrap()
                .contains("BackendUnavailable")
        );
        assert!(!fixture.base().join("active").exists());
        assert!(!fixture.config.driver.with_extension("invoked").exists());
        drop(fixture.acquire().unwrap());
    }
}

#[test]
fn orchestrator_report_write_failure_keeps_marker_and_blocks_next_run() {
    let fixture = Fixture::new();
    fixture.driver();
    let lease = fixture.acquire().unwrap();
    fs::create_dir(lease.run_directory().join("report.json")).unwrap();
    assert_eq!(
        super::publish_unavailable(lease, "a".repeat(40)),
        Err(Reason::CleanupUnconfirmed)
    );
    assert!(fixture.base().join("active").exists());
    assert!(matches!(fixture.acquire(), Err(Reason::UnfinishedRun)));
    assert!(!fixture.config.driver.with_extension("invoked").exists());
}

#[test]
fn orchestrator_crash_after_durable_marker_blocks_next_invocation() {
    let fixture = Fixture::new();
    fixture.driver();
    let path = fixture.base().join("config.json");
    fs::write(&path, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "qualification::orchestrator_test::orchestrator_crash_child",
            "--ignored",
        ])
        .env("CHIMERA_E0_CRASH_FIXTURE", &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fixture.base().join("ready").exists() && Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready = fixture.base().join("ready").exists();
    let _ = child.kill();
    child.wait().unwrap();
    assert!(
        ready,
        "child did not acknowledge marker fsync before deadline"
    );
    assert!(matches!(fixture.acquire(), Err(Reason::UnfinishedRun)));
    assert!(!fixture.config.driver.with_extension("invoked").exists());
    assert_eq!(
        fs::read_dir(&fixture.config.report_root).unwrap().count(),
        1
    );
}

#[test]
#[ignore = "inert fixture subprocess only"]
fn orchestrator_crash_child() {
    let Some(path) = std::env::var_os("CHIMERA_E0_CRASH_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    let config = super::read_native_config(&path).unwrap();
    let base = path.parent().unwrap();
    let lease = acquire_fixture(
        &config,
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        &base.join("lock"),
        &base.join("active"),
    )
    .unwrap();
    fs::write(base.join("ready"), b"marker fsynced").unwrap();
    let mut byte = [0];
    let _ = std::io::Read::read(&mut std::io::stdin(), &mut byte);
    super::publish_unavailable(lease, "a".repeat(40)).unwrap();
}

#[tokio::test]
async fn orchestrator_invalid_config_has_no_output_side_effects() {
    let mut fixture = Fixture::new();
    fixture.config.max_case_ms = 0;
    assert_eq!(
        super::run_native(fixture.config.clone()).await,
        Err(Reason::InvalidConfig)
    );
    assert_eq!(
        fs::read_dir(&fixture.config.report_root).unwrap().count(),
        0
    );
    assert!(!fixture.base().join("active").exists());
}

#[test]
fn orchestrator_config_reader_rejects_relative_symlink_nonregular_and_malformed_input() {
    let fixture = Fixture::new();
    let path = fixture.base().join("config.json");
    fs::write(&path, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    assert_eq!(
        super::read_native_config(&path).unwrap().digest(),
        fixture.config.digest()
    );
    let link = fixture.base().join("link.json");
    symlink(&path, &link).unwrap();
    for invalid in [Path::new("relative.json"), &link, fixture.temp.path()] {
        assert!(matches!(
            super::read_native_config(invalid),
            Err(Reason::InvalidConfig)
        ));
    }
    fs::write(&path, b"synthetic-secret-invalid-json").unwrap();
    assert!(matches!(
        super::read_native_config(&path),
        Err(Reason::InvalidConfig)
    ));
    fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(matches!(
        super::read_native_config(&path),
        Err(Reason::InvalidConfig)
    ));
    assert_eq!(
        fs::read_dir(&fixture.config.report_root).unwrap().count(),
        0
    );
}

#[test]
fn orchestrator_production_start_rejects_sandboxed_without_side_effects() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.config.root.join("cache")).unwrap();
    fs::write(fixture.config.root.join("cache/canary"), b"preserve").unwrap();
    fs::write(
        fixture.config.root.join("config.toml"),
        "runners = ['synthetic-never-online']\n[execution]\nprofile = 'sandboxed'\n",
    )
    .unwrap();
    // Daemon::load always takes the existing storage lock before profile validation.
    fs::write(fixture.config.root.join(".chimera.lock"), b"").unwrap();
    fs::set_permissions(
        fixture.config.root.join(".chimera.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fn snapshot(path: &Path) -> Vec<(PathBuf, u64, u64, u32, Vec<u8>)> {
        let mut result = vec![];
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            result.push((
                path.clone(),
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                if path.is_file() {
                    fs::read(&path).unwrap()
                } else {
                    vec![]
                },
            ));
            if path.is_dir() {
                result.extend(snapshot(&path));
            }
        }
        result.sort();
        result
    }
    let before = snapshot(&fixture.config.root);
    let output = Command::new(env!("CARGO_BIN_EXE_chimera"))
        .args(["start", "--root"])
        .arg(&fixture.config.root)
        .env(
            "CHIMERA_QUALIFICATION_CONFIG",
            fixture.base().join("config.json"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("sandboxed execution profile is not available in this build"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(snapshot(&fixture.config.root), before);
}

#[test]
fn orchestrator_native_script_rejects_bad_paths_and_propagates_serial_cargo_failure() {
    let fixture = Fixture::new();
    let script = copy_native_script(&fixture);
    let config = fixture.base().join("config.json");
    fs::write(&config, b"{}").unwrap();
    let link = fixture.base().join("link");
    symlink(&config, &link).unwrap();
    let fake_bin = fixture.base().join("bin");
    fs::create_dir(&fake_bin).unwrap();
    fs::write(fake_bin.join("cargo"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CALLS\"\nprintf '%s\\n' \"$CHIMERA_QUALIFICATION_CONFIG\" \"$TMPDIR\" >> \"$CALLS\"\nexit 23\n").unwrap();
    fs::set_permissions(fake_bin.join("cargo"), fs::Permissions::from_mode(0o700)).unwrap();
    let calls = fixture.base().join("calls");
    let run = |args: &[&Path]| {
        Command::new("/bin/bash")
            .arg(&script)
            .args(args)
            .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
            .env("CALLS", &calls)
            .current_dir(fixture.base())
            .output()
            .unwrap()
    };
    for args in [
        vec![],
        vec![Path::new("relative")],
        vec![&link],
        vec![fixture.temp.path()],
        vec![&config, &config],
    ] {
        assert!(!run(&args).status.success());
        assert!(!calls.exists());
    }
    assert_eq!(run(&[&config]).status.code(), Some(23));
    let arguments = fs::read_to_string(calls).unwrap();
    assert!(arguments.starts_with("test\n--features\nacceptance-tests\n--test\nsandboxed_qualification_test\nnative_sandboxed_release_qualification\n--\n--ignored\n--exact\n--test-threads=1\n"));
    assert!(arguments.contains(config.to_str().unwrap()));
}

fn copy_native_script(fixture: &Fixture) -> PathBuf {
    let script = fixture
        .base()
        .join("checkout/scripts/qualification/native.sh");
    fs::create_dir_all(script.parent().unwrap()).unwrap();
    fs::write(
        &script,
        include_bytes!("../../scripts/qualification/native.sh"),
    )
    .unwrap();
    script
}

fn shell_run(
    fixture: &Fixture,
    script: &Path,
    cargo: &str,
    mktemp: Option<&str>,
) -> std::process::Output {
    let bin = fixture.base().join("bin");
    fs::create_dir_all(&bin).unwrap();
    for (name, contents) in [("cargo", Some(cargo)), ("mktemp", mktemp)] {
        if let Some(contents) = contents {
            fs::write(bin.join(name), contents).unwrap();
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let config = fixture.base().join("config.json");
    fs::write(&config, b"{}").unwrap();
    Command::new("/bin/bash")
        .arg(script)
        .arg(config)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("CALLS", fixture.base().join("calls"))
        .env("VICTIM", fixture.base().join("active-marker"))
        .output()
        .unwrap()
}

#[test]
fn orchestrator_native_script_rejects_symlink_and_writable_output_ancestry() {
    for component in [
        "checkout",
        "checkout/target",
        "checkout/target/chimera-tests",
    ] {
        for link in [false, true] {
            let fixture = Fixture::new();
            let script = copy_native_script(&fixture);
            let path = fixture.base().join(component);
            fs::create_dir_all(&path).unwrap();
            let retained = path.with_extension("retained");
            if link {
                fs::rename(&path, &retained).unwrap();
                symlink(&retained, &path).unwrap();
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
            }
            let output = shell_run(
                &fixture,
                &script,
                "#!/bin/sh\nprintf invoked > \"$CALLS\"\n",
                None,
            );
            assert!(
                !output.status.success(),
                "accepted {component}, symlink={link}"
            );
            assert!(!fixture.base().join("calls").exists());
            let checked_directory = if link { &retained } else { &path };
            match component {
                "checkout" => assert!(!checked_directory.join("target").exists()),
                "checkout/target" => assert!(!checked_directory.join("chimera-tests").exists()),
                _ => {}
            }
            if component.ends_with("chimera-tests") {
                assert_eq!(fs::read_dir(checked_directory).unwrap().count(), 0);
            }
        }
    }
}

#[test]
fn orchestrator_native_script_rejects_newline_paths_before_creating_output() {
    let fixture = Fixture::new();
    let source = copy_native_script(&fixture);
    let prefix = fixture.base().join("prefix");
    fs::create_dir(&prefix).unwrap();
    let unsafe_parent = fixture.base().join("prefix\n/unsafe");
    let script = unsafe_parent.join("checkout/scripts/qualification/native.sh");
    fs::create_dir_all(script.parent().unwrap()).unwrap();
    fs::copy(source, &script).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    let output = shell_run(
        &fixture,
        &script,
        "#!/bin/sh\nprintf invoked > \"$CALLS\"\n",
        None,
    );
    assert!(!output.status.success());
    assert!(!fixture.base().join("calls").exists());
    assert!(!unsafe_parent.join("checkout/target").exists());
}

#[test]
fn orchestrator_native_script_exclusive_log_open_rejects_preplaced_link() {
    let fixture = Fixture::new();
    let script = copy_native_script(&fixture);
    let victim = fixture.base().join("active-marker");
    fs::write(&victim, b"preserve active marker").unwrap();
    let output = shell_run(
        &fixture,
        &script,
        "#!/bin/sh\nprintf invoked > \"$CALLS\"\n",
        Some(
            "#!/bin/sh\ncreated=$(/usr/bin/mktemp \"$@\") || exit\nif test -d \"$created\"; then\n  ln -s \"$VICTIM\" \"$created/cargo.log\"\nelse\n  mv \"$created\" \"$created.original\"\n  ln -s \"$VICTIM\" \"$created\"\nfi\nprintf '%s\\n' \"$created\"\n",
        ),
    );
    assert!(!output.status.success());
    assert_eq!(fs::read(&victim).unwrap(), b"preserve active marker");
    assert!(!fixture.base().join("calls").exists());
}

#[test]
fn orchestrator_native_script_retains_log_descriptor_after_path_replacement() {
    let fixture = Fixture::new();
    let script = copy_native_script(&fixture);
    let victim = fixture.base().join("active-marker");
    fs::write(&victim, b"preserve active marker").unwrap();
    let output = shell_run(
        &fixture,
        &script,
        "#!/bin/sh\ntest -d \"$TMPDIR\" || exit 90\ntest -f \"$TMPDIR/cargo.log\" || exit 91\nls -i \"$TMPDIR/cargo.log\" > \"$CALLS.inode\"\nmv \"$TMPDIR/cargo.log\" \"$TMPDIR/retained.log\"\nln -s \"$VICTIM\" \"$TMPDIR/cargo.log\"\nprintf '%s\\n' \"$TMPDIR\" > \"$CALLS\"\nprintf 'fixture stdout\\n'\nprintf 'fixture stderr\\n' >&2\nexit 23\n",
        None,
    );
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(fs::read(&victim).unwrap(), b"preserve active marker");
    let invocation = PathBuf::from(
        fs::read_to_string(fixture.base().join("calls"))
            .unwrap()
            .trim(),
    );
    assert_eq!(fs::metadata(&invocation).unwrap().mode() & 0o777, 0o700);
    let retained = invocation.join("retained.log");
    let inode: u64 = fs::read_to_string(fixture.base().join("calls.inode"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(fs::metadata(&retained).unwrap().ino(), inode);
    assert_eq!(fs::metadata(&retained).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::read(retained).unwrap(),
        b"fixture stdout\nfixture stderr\n"
    );
}
