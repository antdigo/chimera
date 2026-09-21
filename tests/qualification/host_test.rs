use super::catalog::{Reason, required_cases};
use super::host::*;
use super::report::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    _temp: tempfile::TempDir,
    config: NativeConfig,
    lock: PathBuf,
    marker: PathBuf,
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
        config.driver = PathBuf::from("/usr/bin/true");
        fs::create_dir(&config.root).unwrap();
        fs::create_dir(&config.report_root).unwrap();
        Self {
            _temp: temp,
            config,
            lock: base.join("lock"),
            marker: base.join("active"),
            boot: uuid::Uuid::new_v4(),
        }
    }
    fn acquire(&self, run: uuid::Uuid) -> Result<NativeLease, Reason> {
        acquire_fixture(&self.config, run, self.boot, &self.lock, &self.marker)
    }
    fn report(&self, run: uuid::Uuid) -> QualificationReport {
        fixture_report(&self.config, self.boot, run)
    }
}
fn fixture_report(config: &NativeConfig, boot: uuid::Uuid, run: uuid::Uuid) -> QualificationReport {
    let identity = RunIdentity {
        run_id: run,
        commit: "a".repeat(40),
        config_digest: config.digest().unwrap(),
        host_boot_id: boot,
        mode: EvidenceMode::Fixture,
    };
    let results = required_cases()
        .into_iter()
        .map(|key| CaseResult {
            provenance: EvidenceProvenance {
                identity: identity.clone(),
                key: key.clone(),
                driver_commit: identity.commit.clone(),
                driver_digest: String::new(),
            },
            key,
            verdict: Verdict::Blocked,
            reason: Some(Reason::BackendUnavailable),
            checks: vec![],
            duration_ms: 0,
        })
        .collect();
    QualificationReport {
        schema_version: 1,
        identity,
        driver_digest: String::new(),
        activation_available: false,
        results,
        cleanup_confirmed: true,
    }
}

#[test]
fn exclusive_lock_cannot_be_bypassed_by_a_second_output_directory() {
    let fixture = Fixture::new();
    let first = lock_exclusive(&fixture.lock).unwrap();
    assert!(matches!(
        lock_exclusive(&fixture.lock),
        Err(Reason::HostBusy)
    ));
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "qualification::host_test::host_lock_child",
            "--ignored",
        ])
        .env("E0_LOCK", &fixture.lock)
        .current_dir(&fixture.config.report_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    drop(first);
    assert!(lock_exclusive(&fixture.lock).is_ok());
}

#[test]
#[ignore = "fixture subprocess only"]
fn host_lock_child() {
    let Some(path) = std::env::var_os("E0_LOCK") else {
        return;
    };
    assert!(matches!(
        lock_exclusive(&PathBuf::from(path)),
        Err(Reason::HostBusy)
    ));
}

#[test]
fn host_lock_rejects_symlinks_hardlinks_and_shared_parent() {
    let fixture = Fixture::new();
    fs::write(fixture.lock.with_extension("target"), b"untouched").unwrap();
    symlink(fixture.lock.with_extension("target"), &fixture.lock).unwrap();
    assert!(lock_exclusive(&fixture.lock).is_err());
    fs::remove_file(&fixture.lock).unwrap();
    let lock = lock_exclusive(&fixture.lock).unwrap();
    drop(lock);
    fs::hard_link(&fixture.lock, fixture.lock.with_extension("link")).unwrap();
    assert!(lock_exclusive(&fixture.lock).is_err());
    fs::remove_file(fixture.lock.with_extension("link")).unwrap();
    fs::set_permissions(
        fixture.lock.parent().unwrap(),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(lock_exclusive(&fixture.lock).is_err());
    fs::set_permissions(
        fixture.lock.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

#[test]
fn host_configuration_is_strict_and_resource_digest_uses_production_validation() {
    let fixture = Fixture::new();
    fixture.config.validate().unwrap();
    let original = fixture.config.digest().unwrap();
    let mut equivalent = fixture.config.clone();
    equivalent.execution_resources.global.memory_high = "1048576".into();
    assert_eq!(equivalent.digest().unwrap(), original);
    equivalent.execution_resources.global.memory_high = "512 KiB".into();
    assert_ne!(equivalent.digest().unwrap(), original);
    let mut json = serde_json::to_value(&fixture.config).unwrap();
    json["unexpected"] = true.into();
    assert!(serde_json::from_value::<NativeConfig>(json).is_err());
    let mut json = serde_json::to_value(&fixture.config).unwrap();
    json["negative_sentinels"][0]["unexpected"] = true.into();
    assert!(serde_json::from_value::<NativeConfig>(json).is_err());
    for change in 0..12 {
        let mut config = fixture.config.clone();
        match change {
            0 => config.max_case_ms = 0,
            1 => config.cleanup_deadline_ms = config.max_case_ms + 1,
            2 => config.max_parallel_builds = 41,
            3 => config.minimum_production_memory_bytes = 0,
            4 => config.maximum_chimera_pids = 0,
            5 => config.negative_sentinels.pop().map(|_| ()).unwrap(),
            6 => config.public_registry_url = "http://example.com".into(),
            7 => config.public_registry_url = "https://user:secret@example.com".into(),
            8 => config.public_registry_url = "https://example.com?token=secret".into(),
            9 => config.lock_file = fixture.lock.clone(),
            10 => config.active_marker = fixture.marker.clone(),
            _ => config.execution_resources.global.memory_max = "max".into(),
        }
        assert!(
            matches!(config.validate(), Err(Reason::InvalidConfig)),
            "change {change}"
        );
    }
}

#[test]
fn host_rejects_empty_url_userinfo_and_noncanonical_machine_paths() {
    let fixture = Fixture::new();
    let mut config = fixture.config.clone();
    config.public_registry_url = "https://@registry.example.com/v2/".into();
    assert_eq!(config.validate(), Err(Reason::InvalidConfig));
    config = fixture.config.clone();
    config.lock_file = PathBuf::from("/run//lock/chimera-qualification.lock");
    assert_eq!(config.validate(), Err(Reason::InvalidConfig));
}

#[test]
fn host_rejects_driver_in_shared_writable_parent() {
    let mut fixture = Fixture::new();
    let parent = fixture.lock.parent().unwrap().join("shared-driver");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    fixture.config.driver = parent.join("driver");
    fs::write(
        &fixture.config.driver,
        "synthetic executable, never invoked",
    )
    .unwrap();
    fs::set_permissions(&fixture.config.driver, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        fixture.acquire(uuid::Uuid::new_v4()),
        Err(Reason::InvalidConfig)
    ));
    assert!(!fixture.marker.exists());
}

#[test]
fn host_missing_driver_leaf_can_publish_blocked_but_symlink_cannot() {
    let mut fixture = Fixture::new();
    fixture.config.driver = fixture.lock.parent().unwrap().join("missing-driver");
    let run = uuid::Uuid::new_v4();
    let lease = fixture.acquire(run).unwrap();
    lease
        .publish_blocked_and_release(&fixture.report(run))
        .unwrap();
    assert!(!fixture.marker.exists());
    symlink("missing-target", &fixture.config.driver).unwrap();
    assert!(matches!(
        fixture.acquire(uuid::Uuid::new_v4()),
        Err(Reason::InvalidConfig)
    ));
    assert!(!fixture.marker.exists());
}

#[test]
fn host_rejects_unowned_root_before_any_directory_creation() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    assert!(matches!(
        private_directory(std::path::Path::new("/usr")),
        Err(Reason::InvalidConfig)
    ));
}

#[test]
fn host_report_directory_replacement_cannot_redirect_publication() {
    let fixture = Fixture::new();
    let run = uuid::Uuid::new_v4();
    let lease = fixture.acquire(run).unwrap();
    let original = lease.run_directory().with_extension("original");
    fs::rename(lease.run_directory(), &original).unwrap();
    fs::create_dir(lease.run_directory()).unwrap();
    let replacement = lease.run_directory().to_owned();
    assert_eq!(
        lease.publish_blocked_and_release(&fixture.report(run)),
        Err(Reason::CleanupUnconfirmed)
    );
    assert!(!replacement.join("report.json").exists());
    assert!(fixture.marker.exists());
}

#[test]
fn host_report_ancestry_replacement_before_and_after_write_preserves_quarantine() {
    for stage in [PublicationStage::BeforeWrite, PublicationStage::AfterWrite] {
        for replace_root in [false, true] {
            let fixture = Fixture::new();
            let run = uuid::Uuid::new_v4();
            let lease = fixture.acquire(run).unwrap();
            let target = if replace_root {
                &fixture.config.root
            } else {
                &fixture.config.report_root
            };
            let result = lease.publish_with_hook(&fixture.report(run), |point| {
                if point == stage {
                    fs::rename(target, target.with_extension("moved")).unwrap();
                    fs::create_dir(target).unwrap();
                }
            });
            assert_eq!(result, Err(Reason::CleanupUnconfirmed));
            assert!(fixture.marker.exists());
            assert_eq!(
                recover_fixture(&fixture.lock, &fixture.marker),
                Err(Reason::UnfinishedRun)
            );
        }
    }
}

#[test]
fn host_report_directory_becoming_shared_writable_blocks_release() {
    let fixture = Fixture::new();
    let run = uuid::Uuid::new_v4();
    let lease = fixture.acquire(run).unwrap();
    fs::set_permissions(lease.run_directory(), fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        lease.publish_blocked_and_release(&fixture.report(run)),
        Err(Reason::CleanupUnconfirmed)
    );
    assert!(fixture.marker.exists());
}

#[test]
fn host_marker_replacement_at_claim_is_preserved_and_blocks_next_run() {
    let fixture = Fixture::new();
    let run = uuid::Uuid::new_v4();
    let lease = fixture.acquire(run).unwrap();
    let result = lease.publish_with_hook(&fixture.report(run), |stage| {
        if stage == PublicationStage::BeforeClaim {
            fs::rename(&fixture.marker, fixture.marker.with_extension("original")).unwrap();
            fs::write(&fixture.marker, b"unexpected replacement").unwrap();
        }
    });
    assert_eq!(result, Err(Reason::CleanupUnconfirmed));
    assert_eq!(
        fs::read(fixture.marker.with_extension("claim").join("marker")).unwrap(),
        b"unexpected replacement"
    );
    assert!(matches!(
        fixture.acquire(uuid::Uuid::new_v4()),
        Err(Reason::UnfinishedRun)
    ));
}

#[test]
fn host_completed_claim_is_retained_without_overwriting_an_existing_archive() {
    for collision in [false, true] {
        let fixture = Fixture::new();
        let run = uuid::Uuid::new_v4();
        let lease = fixture.acquire(run).unwrap();
        let bytes = fs::read(&fixture.marker).unwrap();
        let archive = fixture.marker.with_extension(format!("completed.{run}"));
        if collision {
            fs::create_dir(&archive).unwrap();
        }
        let original_archive = fs::metadata(&archive).ok().map(|metadata| metadata.ino());
        let result = lease.publish_blocked_and_release(&fixture.report(run));
        if collision {
            assert_eq!(result, Err(Reason::CleanupUnconfirmed));
            // An ordinary rename would replace this empty directory. Its inode
            // must survive, proving atomic no-replace rather than ENOTEMPTY.
            assert_eq!(
                Some(fs::metadata(&archive).unwrap().ino()),
                original_archive
            );
            assert_eq!(fs::read_dir(&archive).unwrap().count(), 0);
            assert_eq!(
                recover_fixture(&fixture.lock, &fixture.marker),
                Err(Reason::UnfinishedRun)
            );
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(fs::read(archive.join("marker")).unwrap(), bytes);
            assert_eq!(recover_fixture(&fixture.lock, &fixture.marker), Ok(()));
        }
    }
}

#[test]
fn host_rejects_unsafe_workspace_paths_without_creating_a_marker() {
    for change in 0..9 {
        let mut fixture = Fixture::new();
        match change {
            0 => fixture.config.root = PathBuf::from("/"),
            1 => fixture.config.root = PathBuf::from("/tmp"),
            2 => fixture.config.root = dirs::home_dir().unwrap(),
            3 => fs::set_permissions(&fixture.config.root, fs::Permissions::from_mode(0o777))
                .unwrap(),
            4 => {
                let original = fixture.config.root.clone();
                fixture.config.root = original.with_extension("link");
                fixture.config.report_root = fixture.config.root.join("reports");
                symlink(original, &fixture.config.root).unwrap();
            }
            5 => {
                let original = fixture.config.report_root.clone();
                fixture.config.report_root = original.with_extension("link");
                symlink(original, &fixture.config.report_root).unwrap();
            }
            6 => fixture.config.report_root = fixture.lock.parent().unwrap().to_owned(),
            7 => {
                fixture.config.driver = fixture.config.root.join("driver");
                fs::write(&fixture.config.driver, "fixture").unwrap();
            }
            _ => fixture.config.root = fixture.config.root.join("..").join("qualification"),
        }
        assert!(
            matches!(
                fixture.acquire(uuid::Uuid::new_v4()),
                Err(Reason::InvalidConfig)
            ),
            "change {change}"
        );
        assert!(!fixture.marker.exists());
    }
}

#[test]
fn host_refuses_preexisting_run_and_keeps_marker_on_drop() {
    let fixture = Fixture::new();
    let run = uuid::Uuid::new_v4();
    fs::create_dir(fixture.config.root.join(run.to_string())).unwrap();
    assert!(matches!(fixture.acquire(run), Err(Reason::InvalidConfig)));
    let lease = fixture.acquire(uuid::Uuid::new_v4()).unwrap();
    drop(lease);
    assert!(matches!(
        fixture.acquire(uuid::Uuid::new_v4()),
        Err(Reason::UnfinishedRun)
    ));
    assert_eq!(
        recover_fixture(&fixture.lock, &fixture.marker),
        Err(Reason::UnfinishedRun)
    );
}

#[test]
fn host_clean_blocked_report_is_synced_before_releasing_marker() {
    let fixture = Fixture::new();
    let run = uuid::Uuid::new_v4();
    let lease = fixture.acquire(run).unwrap();
    let directory = lease.run_directory().to_owned();
    let marker: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.marker).unwrap()).unwrap();
    assert!(marker["cgroup"].is_null());
    assert!(
        !String::from_utf8(fs::read(&fixture.marker).unwrap())
            .unwrap()
            .contains(fixture.config.root.to_str().unwrap())
    );
    lease
        .publish_blocked_and_release(&fixture.report(run))
        .unwrap();
    assert!(!fixture.marker.exists());
    let report: QualificationReport =
        serde_json::from_slice(&fs::read(directory.join("report.json")).unwrap()).unwrap();
    assert_eq!(report.results.len(), required_cases().len());
    assert!(!qualifies(&report));
    assert_eq!(recover_fixture(&fixture.lock, &fixture.marker), Ok(()));
    assert!(fixture.acquire(uuid::Uuid::new_v4()).is_ok());
}

#[test]
fn host_failed_or_untrusted_publication_preserves_marker() {
    for change in 0..7 {
        let fixture = Fixture::new();
        let run = uuid::Uuid::new_v4();
        let lease = fixture.acquire(run).unwrap();
        let mut report = fixture.report(run);
        match change {
            0 => fs::create_dir(lease.run_directory().join("report.json")).unwrap(),
            1 => report.results.pop().map(|_| ()).unwrap(),
            2 => report.results[0].verdict = Verdict::Passed,
            3 => report.identity.run_id = uuid::Uuid::new_v4(),
            4 => {
                fs::rename(&fixture.marker, fixture.marker.with_extension("old")).unwrap();
                fs::write(&fixture.marker, b"replacement").unwrap();
            }
            5 => fs::write(&fixture.marker, b"mutated in place").unwrap(),
            _ => report.identity.config_digest = "d".repeat(64),
        }
        assert_eq!(
            lease.publish_blocked_and_release(&report),
            Err(Reason::CleanupUnconfirmed),
            "change {change}"
        );
        assert!(fixture.marker.exists());
        assert_eq!(
            recover_fixture(&fixture.lock, &fixture.marker),
            Err(Reason::UnfinishedRun)
        );
    }
}

#[test]
fn host_killed_harness_leaves_durable_marker_and_never_recovers_by_pid() {
    let fixture = Fixture::new();
    let mut child = start_fixture_harness(&fixture, "marker", Duration::from_secs(3)).unwrap();
    child.0.kill().unwrap(); // Child handle, no stored/reused PID or process group.
    child.0.wait().unwrap();
    let before = fs::read(&fixture.marker).unwrap();
    assert!(matches!(
        fixture.acquire(uuid::Uuid::new_v4()),
        Err(Reason::UnfinishedRun)
    ));
    assert_eq!(
        recover_fixture(&fixture.lock, &fixture.marker),
        Err(Reason::UnfinishedRun)
    );
    assert_eq!(fs::read(&fixture.marker).unwrap(), before);
    fs::write(
        &fixture.marker,
        b"{\"boot_id\":\"changed\",\"supervisor\":\"stale\"}",
    )
    .unwrap();
    assert_eq!(
        recover_fixture(&fixture.lock, &fixture.marker),
        Err(Reason::UnfinishedRun)
    );
    assert!(fixture.marker.exists());
}

#[test]
fn host_claim_crash_blocks_even_when_active_name_has_moved() {
    let fixture = Fixture::new();
    let mut child = start_fixture_harness(&fixture, "claim", Duration::from_secs(3)).unwrap();
    assert!(!fixture.marker.exists());
    assert!(
        fixture
            .marker
            .with_extension("claim")
            .join("marker")
            .exists()
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(matches!(
        fixture.acquire(uuid::Uuid::new_v4()),
        Err(Reason::UnfinishedRun)
    ));
    assert_eq!(
        recover_fixture(&fixture.lock, &fixture.marker),
        Err(Reason::UnfinishedRun)
    );
}

#[test]
fn host_silent_fixture_readiness_is_bounded_and_child_reaped() {
    let fixture = Fixture::new();
    let start = Instant::now();
    let result = start_fixture_harness(&fixture, "silent", Duration::from_millis(500));
    assert_eq!(result.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_millis(1500));
    assert!(fixture.marker.exists()); // Child acquired the lock before becoming silent.
    assert!(lock_exclusive(&fixture.lock).is_ok()); // Its guard killed and reaped it.
}

struct FixtureChild(std::process::Child);
impl Drop for FixtureChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start_fixture_harness(
    fixture: &Fixture,
    mode: &str,
    timeout: Duration,
) -> std::io::Result<FixtureChild> {
    let mut child = FixtureChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "qualification::host_test::host_marker_child",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "E0_FIXTURE_CONFIG",
                serde_json::to_string(&fixture.config).unwrap(),
            )
            .env("E0_LOCK", &fixture.lock)
            .env("E0_MARKER", &fixture.marker)
            .env("E0_CHILD_MODE", mode)
            .stdout(Stdio::piped())
            .spawn()?,
    );
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut stdout = child.0.stdout.take().unwrap();
    let deadline = Instant::now() + timeout;
    let mut captured = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(std::io::ErrorKind::TimedOut)?;
        let mut descriptor = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let waited = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if waited == 0 {
            continue;
        }
        let mut bytes = [0; 1024];
        let count = stdout.read(&mut bytes)?;
        if count == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        captured.extend_from_slice(&bytes[..count]);
        if captured.len() > 16 * 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        if captured
            .windows(b"E0_MARKER_SYNCED".len())
            .any(|window| window == b"E0_MARKER_SYNCED")
        {
            return Ok(child);
        }
    }
}

#[test]
#[ignore = "fixture subprocess only"]
fn host_marker_child() {
    let Ok(json) = std::env::var("E0_FIXTURE_CONFIG") else {
        return;
    };
    let config = serde_json::from_str(&json).unwrap();
    let run = uuid::Uuid::new_v4();
    let boot = uuid::Uuid::new_v4();
    let lease = acquire_fixture(
        &config,
        run,
        boot,
        &PathBuf::from(std::env::var_os("E0_LOCK").unwrap()),
        &PathBuf::from(std::env::var_os("E0_MARKER").unwrap()),
    )
    .unwrap();
    match std::env::var("E0_CHILD_MODE").unwrap_or_default().as_str() {
        "silent" => std::thread::sleep(Duration::from_secs(2)),
        "claim" => {
            lease
                .publish_with_hook(&fixture_report(&config, boot, run), |stage| {
                    if stage == PublicationStage::AfterClaim {
                        signal_ready_and_wait();
                    }
                })
                .unwrap();
        }
        _ => signal_ready_and_wait(),
    }
}

fn signal_ready_and_wait() {
    println!("E0_MARKER_SYNCED");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn host_native_platform_rejection_cannot_touch_machine_lock() {
    let fixture = Fixture::new();
    assert!(matches!(
        acquire_native(&fixture.config, uuid::Uuid::new_v4()),
        Err(Reason::PlatformUnsupported)
    ));
    assert!(matches!(inspect_host(), Err(Reason::PlatformUnsupported)));
    assert_eq!(
        recover_unfinished(&fixture.config),
        Err(Reason::PlatformUnsupported)
    );
}
