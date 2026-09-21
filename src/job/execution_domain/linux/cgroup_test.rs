use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory};
use super::cgroup::{CgroupFilesystem, CgroupRoot, KernelCgroupFs};
use super::cgroup::{CgroupOperation, creation_operations, validate_controllers};
use crate::config::resources::{IoMax, ResourceLimits, ValidatedLimits};
use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// This fixture emulates only cgroup file effects, never enforcement. All opens,
// binding checks, driver ordering and admission decisions use the real backend.
#[derive(Default)]
struct FixtureFs {
    failure: Mutex<Option<(String, String)>>,
    skip_failures: Mutex<usize>,
    corrupt_write: Mutex<Option<String>>,
    wrong_filesystem: Mutex<bool>,
    omit_domain_membership: Mutex<bool>,
    read_delay: Mutex<Option<ReadDelay>>,
    readonly_child_control: Mutex<Option<(String, String)>>,
    omit_child_control: Mutex<bool>,
    visited_directories: Mutex<HashSet<PathBuf>>,
    scan_gate: Mutex<Option<ScanGate>>,
    observed: Mutex<Vec<(String, String)>>,
}

struct ScanGate {
    started: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

struct ReadDelay {
    tick: Arc<AtomicBool>,
    observed_tick: Arc<AtomicBool>,
}

impl FixtureFs {
    fn at(&self, operation: &str, name: &CStr) -> io::Result<()> {
        let pair = (operation.to_owned(), name.to_string_lossy().into_owned());
        self.observed.lock().unwrap().push(pair.clone());
        if self.failure.lock().unwrap().as_ref() == Some(&pair) {
            let mut skip = self.skip_failures.lock().unwrap();
            if *skip > 0 {
                *skip -= 1;
                return Ok(());
            }
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }
}

fn fd_path(fd: RawFd) -> PathBuf {
    fs::read_link(format!("/proc/self/fd/{fd}")).unwrap()
}

fn seed(path: &Path, limits: &ValidatedLimits) {
    for (name, value) in [
        ("cgroup.controllers", "cpu memory pids io"),
        ("cgroup.type", "domain"),
        ("cgroup.subtree_control", ""),
        ("cgroup.procs", ""),
        ("cgroup.events", "populated 0\nfrozen 0\n"),
        ("cgroup.kill", ""),
    ] {
        fs::write(path.join(name), value).unwrap();
    }
    let mut io_lines = String::new();
    for (name, value) in limits.writes() {
        if name == "io.max" {
            io_lines.push_str(&value);
            io_lines.push('\n');
        } else {
            fs::write(path.join(name), value).unwrap();
        }
    }
    fs::write(path.join("io.max"), io_lines).unwrap();
}

impl CgroupFilesystem for FixtureFs {
    fn verify_filesystem(&self, fd: RawFd) -> io::Result<()> {
        let path = fd_path(fd);
        if path.is_dir() {
            self.visited_directories.lock().unwrap().insert(path);
            if let Some(gate) = self.scan_gate.lock().unwrap().take() {
                gate.started.store(true, Ordering::Release);
                while !gate.release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if *self.wrong_filesystem.lock().unwrap() {
            Err(io::Error::from_raw_os_error(libc::ENODEV))
        } else {
            Ok(())
        }
    }

    fn create(&self, parent: RawFd, name: &CStr) -> io::Result<()> {
        self.at("mkdir", name)?;
        KernelCgroupFs.create(parent, name)?;
        seed(&fd_path(parent).join(name.to_str().unwrap()), &limits());
        if name == c"domain" && *self.omit_domain_membership.lock().unwrap() {
            fs::remove_file(fd_path(parent).join("domain/cgroup.procs"))?;
        }
        if let Some((group, control)) = self.readonly_child_control.lock().unwrap().as_ref() {
            let component = name.to_str().unwrap();
            if component == group || group == "attempt" && component.starts_with("attempt-") {
                let path = fd_path(parent).join(component).join(control);
                if *self.omit_child_control.lock().unwrap() {
                    fs::remove_file(path)?;
                } else {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
                }
            }
        }
        Ok(())
    }

    fn read(&self, file: &mut File, name: &CStr) -> io::Result<String> {
        self.at("read", name)?;
        if name == c"cgroup.events" {
            let delay = self.read_delay.lock().unwrap().take();
            if let Some(delay) = delay {
                std::thread::sleep(Duration::from_millis(80));
                delay
                    .observed_tick
                    .store(delay.tick.load(Ordering::Acquire), Ordering::Release);
            }
        }
        KernelCgroupFs.read(file, name)
    }

    fn write(&self, file: &mut File, name: &CStr, value: &str) -> io::Result<()> {
        self.at("write", name)?;
        let path = fd_path(file.as_raw_fd());
        let directory = path.parent().unwrap();
        let value = if self.corrupt_write.lock().unwrap().as_deref() == name.to_str().ok() {
            "invalid-readback".to_owned()
        } else if name == c"cgroup.subtree_control" {
            value.replace('+', "")
        } else if name == c"cgroup.procs" && value == "0" {
            // Emulate process-group migration for this dedicated regular-file root.
            assert_eq!(directory.file_name().unwrap(), "supervisor");
            fs::write(directory.parent().unwrap().join("cgroup.procs"), "")?;
            unsafe { libc::getpid() }.to_string()
        } else if name == c"io.max" {
            let old = fs::read_to_string(&path)?;
            let device = value.split_whitespace().next().unwrap();
            let mut lines: Vec<_> = old
                .lines()
                .filter(|line| line.split_whitespace().next() != Some(device))
                .map(str::to_owned)
                .collect();
            lines.push(value.to_owned());
            lines.join("\n")
        } else {
            value.to_owned()
        };
        file.set_len(0)?;
        KernelCgroupFs.write(file, name, &value)
    }

    fn remove(&self, parent: RawFd, name: &CStr, child: RawFd) -> io::Result<()> {
        if self.failure.lock().unwrap().as_ref()
            == Some(&("remove".into(), name.to_string_lossy().into_owned()))
        {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.at("remove", name)?;
        for entry in fs::read_dir(fd_path(child))? {
            let entry = entry?;
            assert!(entry.file_type()?.is_file());
            fs::remove_file(entry.path())?;
        }
        KernelCgroupFs.remove(parent, name, child)
    }
}

#[test]
fn delegated_root_controls_can_be_read_only_for_the_service_user() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run the Linux fixture as its unprivileged UID"
    );
    for kill_mode in [0o444, 0o000] {
        let fixture = Fixture::new();
        fs::set_permissions(
            fixture.temp.path().join("cgroup.kill"),
            fs::Permissions::from_mode(kill_mode),
        )
        .unwrap();
        fs::set_permissions(
            fixture.temp.path().join("memory.swap.max"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        let root = fixture.ready();
        root.create_attempt(AttemptIdentity::new(), &limits())
            .unwrap();
    }
}

#[test]
fn owned_attempt_and_domain_controls_must_still_be_writable() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run the Linux fixture as its unprivileged UID"
    );
    for group in ["attempt", "domain"] {
        for control in [
            "cgroup.kill",
            "memory.swap.max",
            "memory.max",
            "cpu.max",
            "pids.max",
            "io.max",
        ] {
            for missing in [false, true] {
                let fixture = Fixture::new();
                let root = fixture.ready();
                *fixture.fs.readonly_child_control.lock().unwrap() =
                    Some((group.into(), control.into()));
                *fixture.fs.omit_child_control.lock().unwrap() = missing;
                let attempt = AttemptIdentity::new();
                assert!(
                    root.create_attempt(attempt, &limits()).is_err(),
                    "{group}/{control}, missing={missing}"
                );
                assert!(
                    !fixture.attempt_path(attempt).exists(),
                    "partial cgroup survived: {group}/{control}, missing={missing}"
                );
            }
        }
    }
}

#[tokio::test]
async fn wide_inventory_stops_before_opening_over_budget_children() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let domain = fixture.attempt_path(id).join("domain");
    for index in 0..4200 {
        fs::create_dir(domain.join(format!("child-{index}"))).unwrap();
    }
    fixture.fs.visited_directories.lock().unwrap().clear();
    assert!(attempt.wait_empty(Duration::from_secs(10)).await.is_err());
    let count = fixture.fs.visited_directories.lock().unwrap().len();
    assert!(
        count <= 4096,
        "opened {count} groups before enforcing the 4096-node budget"
    );
}

#[tokio::test]
async fn deep_inventory_stops_before_opening_over_depth_children() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let mut path = fixture.attempt_path(id).join("domain");
    for _ in 0..80 {
        path.push("child");
        fs::create_dir(&path).unwrap();
    }
    fixture.fs.visited_directories.lock().unwrap().clear();
    assert!(attempt.wait_empty(Duration::from_secs(10)).await.is_err());
    let count = fixture.fs.visited_directories.lock().unwrap().len();
    assert!(
        count <= 64,
        "opened {count} groups before enforcing the 64-level budget"
    );
}

#[tokio::test]
async fn timed_out_inventory_is_joined_and_hard_bounded() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let domain = fixture.attempt_path(id).join("domain");
    for index in 0..4200 {
        fs::create_dir(domain.join(format!("child-{index}"))).unwrap();
    }
    fixture.fs.visited_directories.lock().unwrap().clear();
    let started = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    *fixture.fs.scan_gate.lock().unwrap() = Some(ScanGate {
        started: started.clone(),
        release: release.clone(),
    });
    let references = Arc::strong_count(&fixture.fs);
    let (result, ()) = tokio::join!(attempt.wait_empty(Duration::from_millis(30)), async {
        while !started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        release.store(true, Ordering::Release);
    });
    assert!(started.load(Ordering::Acquire));
    assert!(matches!(
        result,
        Err(ExecutionDomainError::Backend {
            category: FailureCategory::Timeout,
            ..
        })
    ));
    let visited = fixture.fs.visited_directories.lock().unwrap().len();
    assert!(visited <= 4096, "timed-out worker opened {visited} groups");
    assert_eq!(
        Arc::strong_count(&fixture.fs),
        references,
        "wait_empty returned while a proof worker still retained authority"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn emptiness_scan_does_not_block_the_async_executor() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let attempt = root
        .create_attempt(AttemptIdentity::new(), &limits())
        .unwrap();
    let tick = Arc::new(AtomicBool::new(false));
    let observed_tick = Arc::new(AtomicBool::new(false));
    *fixture.fs.read_delay.lock().unwrap() = Some(ReadDelay {
        tick: tick.clone(),
        observed_tick: observed_tick.clone(),
    });
    let (result, ()) = tokio::join!(attempt.wait_empty(Duration::from_secs(1)), async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        tick.store(true, Ordering::Release);
    });
    result.unwrap();
    assert!(
        observed_tick.load(Ordering::Acquire),
        "blocking cgroup reads must run outside the async executor"
    );
}

fn limits() -> ValidatedLimits {
    ResourceLimits {
        memory_high: "384 MiB".into(),
        memory_max: "512 MiB".into(),
        memory_swap_max: "0".into(),
        cpu_quota: "150%".into(),
        cpu_weight: 100,
        pids_max: "256".into(),
        io_weight: 100,
        io_max: vec![
            IoMax {
                device: "8:0".into(),
                read_bytes_per_second: "1 MiB".into(),
                write_bytes_per_second: "2 MiB".into(),
                read_iops: 10,
                write_iops: 20,
            },
            IoMax {
                device: "8:16".into(),
                read_bytes_per_second: "3 MiB".into(),
                write_bytes_per_second: "4 MiB".into(),
                read_iops: 30,
                write_iops: 40,
            },
        ],
    }
    .validate()
    .unwrap()
}

struct Fixture {
    temp: tempfile::TempDir,
    fs: Arc<FixtureFs>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        seed(temp.path(), &limits());
        fs::write(
            temp.path().join("cgroup.procs"),
            unsafe { libc::getpid() }.to_string(),
        )
        .unwrap();
        Self {
            temp,
            fs: Arc::new(FixtureFs::default()),
        }
    }

    fn root(&self) -> CgroupRoot<FixtureFs> {
        CgroupRoot::open_with_filesystem(self.temp.path(), Arc::clone(&self.fs)).unwrap()
    }

    fn ready(&self) -> CgroupRoot<FixtureFs> {
        let mut root = self.root();
        root.prepare_supervisor(&limits()).unwrap();
        self.fs.observed.lock().unwrap().clear();
        root
    }

    fn attempt_path(&self, attempt: AttemptIdentity) -> PathBuf {
        self.temp
            .path()
            .join(format!("attempt-{}", attempt.component()))
    }

    fn fail(&self, operation: &str, name: &str) {
        *self.fs.failure.lock().unwrap() = Some((operation.into(), name.into()));
    }
}

#[test]
fn cgroup_order_sets_limits_before_admitting_processes() {
    let writes = vec![
        ("memory.max", "536870912".to_owned()),
        ("pids.max", "256".to_owned()),
    ];
    let operations = creation_operations(&writes);
    assert_eq!(
        operations,
        vec![
            CgroupOperation::CreateAttempt,
            CgroupOperation::WriteLimit("memory.max".into(), "536870912".into()),
            CgroupOperation::WriteLimit("pids.max".into(), "256".into()),
            CgroupOperation::VerifyLimits,
            CgroupOperation::EnableControllers,
            CgroupOperation::CreateDomain,
            CgroupOperation::OpenMembership,
        ]
    );
}

#[test]
fn launcher_checks_bound_rootfs_before_spawning() {
    use super::launcher::{LaunchSpec, NetworkLaunch, launch};
    let fixture = Fixture::new();
    let root = fixture.ready();
    let identity = AttemptIdentity::new();
    let attempt = root.create_attempt(identity, &limits()).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let staging = temp.path().join("rootfs");
    fs::create_dir(&staging).unwrap();
    let bound_rootfs = super::dirfd::BoundDir::open_root(&staging).unwrap();
    let spec = LaunchSpec {
        attempt: identity,
        rootfs: super::rootfs::RootfsPlan {
            inputs: vec![],
            staging_root: staging.clone(),
        },
        bound_rootfs,
        executable: fs::canonicalize("/bin/false").unwrap(),
        rootlesskit: fs::canonicalize("/bin/true").unwrap(),
        state_directory: temp.path().to_owned(),
        hostname: "test".into(),
        network: NetworkLaunch::Disconnected,
    };
    fs::rename(&staging, temp.path().join("old")).unwrap();
    fs::create_dir(&staging).unwrap();
    assert!(launch(&attempt, &spec).is_err());
}

#[test]
fn missing_controller_is_a_preflight_error() {
    assert!(validate_controllers("cpu memory pids").is_err());
    assert!(validate_controllers("cpuset cpu io memory pids").is_ok());
}

#[test]
fn real_preflight_refuses_regular_files_without_mutating_them() {
    let fixture = Fixture::new();
    assert!(CgroupRoot::open_delegated(fixture.temp.path()).is_err());
    assert!(!fixture.temp.path().join("supervisor").exists());
}

#[test]
fn admission_requires_global_readback_and_supervisor_migration() {
    let fixture = Fixture::new();
    let mut root = fixture.root();
    assert!(
        root.create_attempt(AttemptIdentity::new(), &limits())
            .is_err()
    );
    fs::write(fixture.temp.path().join("memory.max"), "max").unwrap();
    assert!(root.prepare_supervisor(&limits()).is_err());
    assert!(!fixture.temp.path().join("supervisor").exists());
}

#[test]
fn supervisor_migration_precedes_enabling_controllers() {
    let fixture = Fixture::new();
    let mut root = fixture.root();
    root.prepare_supervisor(&limits()).unwrap();
    let events = fixture.fs.observed.lock().unwrap();
    let migration = events
        .iter()
        .position(|event| event == &("write".into(), "cgroup.procs".into()))
        .unwrap();
    let enable = events
        .iter()
        .position(|event| event == &("write".into(), "cgroup.subtree_control".into()))
        .unwrap();
    assert!(migration < enable);
    assert_eq!(
        fs::read_to_string(fixture.temp.path().join("cgroup.procs")).unwrap(),
        ""
    );
    assert_eq!(
        fs::read_to_string(fixture.temp.path().join("supervisor/cgroup.procs"))
            .unwrap()
            .trim(),
        unsafe { libc::getpid() }.to_string()
    );
}

#[test]
fn root_with_other_processes_is_refused_before_migration() {
    let fixture = Fixture::new();
    fs::write(fixture.temp.path().join("cgroup.procs"), "2147483647\n").unwrap();
    assert!(fixture.root().prepare_supervisor(&limits()).is_err());
    assert!(!fixture.temp.path().join("supervisor").exists());
}

#[test]
fn missing_kill_swap_or_controller_refuses_preflight() {
    for name in ["cgroup.kill", "memory.swap.max", "cgroup.controllers"] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.temp.path().join(name)).unwrap();
        assert!(
            CgroupRoot::open_with_filesystem(fixture.temp.path(), fixture.fs.clone()).is_err(),
            "{name}"
        );
    }
}

#[test]
fn attempt_is_deterministic_and_readback_precedes_launch_fd() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::from_uuid(uuid::Uuid::from_u128(7)).unwrap();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    assert_eq!(
        fd_path(attempt.launch_membership_fd().as_raw_fd()),
        fixture
            .temp
            .path()
            .join("attempt-00000000000000000000000000000007/domain/cgroup.procs")
    );
    attempt.limits_match().unwrap();
    assert!(root.create_attempt(id, &limits()).is_err());
    assert_eq!(
        fs::read_to_string(fixture.attempt_path(id).join("cpu.max"))
            .unwrap()
            .trim(),
        "150000 100000"
    );
    assert_eq!(
        fs::read_to_string(fixture.attempt_path(id).join("memory.max"))
            .unwrap()
            .trim(),
        "536870912"
    );
    let events = fixture.fs.observed.lock().unwrap();
    let write = events
        .iter()
        .position(|event| event == &("write".into(), "memory.max".into()))
        .unwrap();
    let read = events
        .iter()
        .enumerate()
        .find(|(index, event)| *index > write && *event == &("read".into(), "memory.max".into()))
        .unwrap()
        .0;
    let domain = events
        .iter()
        .position(|event| event == &("mkdir".into(), "domain".into()))
        .unwrap();
    assert!(write < read && read < domain);
}

#[test]
fn every_limit_write_and_read_error_refuses_launcher() {
    for operation in ["read", "write"] {
        for (name, _) in limits().writes() {
            let fixture = Fixture::new();
            let root = fixture.ready();
            fixture.fail(operation, name);
            // Skip the complete global verification; fail the attempt's own
            // readback, after every limit write, before creating its domain.
            if operation == "read" {
                *fixture.fs.skip_failures.lock().unwrap() = limits()
                    .writes()
                    .iter()
                    .filter(|(key, _)| *key == name)
                    .count();
            }
            let id = AttemptIdentity::new();
            assert!(
                root.create_attempt(id, &limits()).is_err(),
                "{operation} {name}"
            );
            assert!(!fixture.attempt_path(id).join("domain").exists());
            assert!(
                !fixture.attempt_path(id).exists(),
                "partial cgroup must roll back before returning: {operation} {name}"
            );
            if operation == "read" {
                assert!(
                    fixture
                        .fs
                        .observed
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|event| event == &("write".into(), "io.max".into()))
                );
            }
        }
    }
}

#[test]
fn each_incorrect_limit_readback_refuses_launcher() {
    for (name, _) in limits().writes() {
        let fixture = Fixture::new();
        let root = fixture.ready();
        *fixture.fs.corrupt_write.lock().unwrap() = Some(name.into());
        let id = AttemptIdentity::new();
        assert!(root.create_attempt(id, &limits()).is_err(), "{name}");
        assert!(!fixture.attempt_path(id).join("domain").exists());
    }
}

#[test]
fn each_startup_write_read_and_readback_failure_keeps_admission_closed() {
    for (operation, name, skip) in [
        ("write", "cgroup.procs", 0),
        ("read", "cgroup.procs", 2),
        ("write", "cgroup.subtree_control", 0),
        ("read", "cgroup.subtree_control", 0),
    ] {
        let fixture = Fixture::new();
        let mut root = fixture.root();
        fixture.fail(operation, name);
        *fixture.fs.skip_failures.lock().unwrap() = skip;
        assert!(
            root.prepare_supervisor(&limits()).is_err(),
            "{operation} {name}"
        );
        assert!(
            root.create_attempt(AttemptIdentity::new(), &limits())
                .is_err()
        );
    }
    let fixture = Fixture::new();
    let mut root = fixture.root();
    *fixture.fs.corrupt_write.lock().unwrap() = Some("cgroup.procs".into());
    assert!(root.prepare_supervisor(&limits()).is_err());
    assert!(
        root.create_attempt(AttemptIdentity::new(), &limits())
            .is_err()
    );
}

#[tokio::test]
async fn filesystem_change_refuses_kill_wait_and_remove() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    *fixture.fs.wrong_filesystem.lock().unwrap() = true;
    assert!(attempt.kill().is_err());
    assert!(
        attempt
            .wait_empty(Duration::from_millis(100))
            .await
            .is_err()
    );
    assert!(attempt.remove().is_err());
    assert!(fixture.attempt_path(id).join("domain").exists());
}

#[tokio::test]
async fn malformed_events_and_membership_never_prove_empty() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    for text in [
        "",
        "populated 2",
        "populated 0\npopulated 0",
        "populated 0 extra",
    ] {
        fs::write(fixture.attempt_path(id).join("cgroup.events"), text).unwrap();
        assert!(
            matches!(
                attempt.wait_empty(Duration::from_millis(100)).await,
                Err(ExecutionDomainError::Backend {
                    category: FailureCategory::IdentityMismatch,
                    ..
                })
            ),
            "{text}"
        );
    }
    fs::write(
        fixture.attempt_path(id).join("cgroup.events"),
        "populated 0",
    )
    .unwrap();
    for text in ["0", "-1", "not-a-pid", "999999999999999999"] {
        fs::write(fixture.attempt_path(id).join("domain/cgroup.procs"), text).unwrap();
        assert!(
            matches!(
                attempt.wait_empty(Duration::from_millis(100)).await,
                Err(ExecutionDomainError::Backend {
                    category: FailureCategory::IdentityMismatch,
                    ..
                })
            ),
            "{text}"
        );
    }
}

#[test]
fn failed_kill_uses_pidfd_for_only_the_owned_fixture_child() {
    use std::process::{Command, Stdio};
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut sentinel = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fs::write(
        fixture.attempt_path(id).join("domain/cgroup.procs"),
        child.id().to_string(),
    )
    .unwrap();
    fixture.fail("write", "cgroup.kill");
    let result = attempt.kill();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let terminated = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let sentinel_alive = sentinel.try_wait().unwrap().is_none();
    if !terminated {
        child.kill().unwrap();
    }
    child.wait().unwrap();
    sentinel.kill().unwrap();
    sentinel.wait().unwrap();
    assert!(result.is_err());
    assert!(terminated, "pidfd fallback must kill the child we own");
    assert!(sentinel_alive);
}

#[test]
fn subtree_write_read_and_domain_creation_fail_closed() {
    for (operation, name) in [
        ("write", "cgroup.subtree_control"),
        ("read", "cgroup.subtree_control"),
        ("mkdir", "domain"),
    ] {
        let fixture = Fixture::new();
        let root = fixture.ready();
        fixture.fail(operation, name);
        assert!(
            root.create_attempt(AttemptIdentity::new(), &limits())
                .is_err()
        );
    }
}

#[test]
fn membership_open_failure_never_returns_an_attempt() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    *fixture.fs.omit_domain_membership.lock().unwrap() = true;
    let id = AttemptIdentity::new();
    assert!(root.create_attempt(id, &limits()).is_err());
    assert!(fixture.attempt_path(id).join("domain").exists());
}

#[tokio::test]
async fn fifo_and_hardlinked_controls_fail_without_reading_outside_data() {
    use std::ffi::CString;
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let control = fixture.attempt_path(id).join("cgroup.events");
    fs::remove_file(&control).unwrap();
    let control_c = CString::new(control.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(control_c.as_ptr(), 0o600) }, 0);
    assert!(
        attempt
            .wait_empty(Duration::from_millis(100))
            .await
            .is_err()
    );
    fs::remove_file(&control).unwrap();
    let outside = fixture.temp.path().join("canary");
    fs::write(&outside, "populated 0\n").unwrap();
    fs::hard_link(&outside, &control).unwrap();
    assert!(
        attempt
            .wait_empty(Duration::from_millis(100))
            .await
            .is_err()
    );
    assert!(attempt.remove().is_err());
    assert_eq!(fs::read_to_string(outside).unwrap(), "populated 0\n");
}

#[test]
fn readback_detects_limit_tampering_and_accepts_io_field_reordering() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    fs::write(fixture.attempt_path(id).join("io.max"), "8:16 wiops=40 riops=30 wbps=4194304 rbps=3145728\n8:0 wiops=20 riops=10 wbps=2097152 rbps=1048576\n").unwrap();
    attempt.limits_match().unwrap();
    fs::write(fixture.attempt_path(id).join("pids.max"), "max").unwrap();
    assert!(attempt.limits_match().is_err());
}

#[test]
fn evacuation_requires_live_init_and_empty_domain() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    assert!(attempt.finish_evacuation().is_err());
    let domain = fixture.attempt_path(id).join("domain");
    fs::create_dir(domain.join("init")).unwrap();
    seed(&domain.join("init"), &limits());
    assert!(attempt.finish_evacuation().is_err());
    fs::write(domain.join("init/cgroup.procs"), "2147483647\n").unwrap();
    fs::write(domain.join("cgroup.procs"), "2147483646\n").unwrap();
    assert!(attempt.finish_evacuation().is_err());
    fs::write(domain.join("cgroup.procs"), "").unwrap();
    attempt.finish_evacuation().unwrap();
    assert_eq!(
        fs::read_to_string(domain.join("cgroup.subtree_control"))
            .unwrap()
            .trim(),
        "cpu memory pids io"
    );
}

#[tokio::test]
async fn emptiness_checks_nested_members_and_events_and_times_out() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let nested = fixture.attempt_path(id).join("domain/descendant");
    fs::create_dir(&nested).unwrap();
    seed(&nested, &limits());
    for (name, value) in [
        ("cgroup.procs", "2147483647"),
        ("cgroup.events", "populated 1\n"),
    ] {
        fs::write(nested.join(name), value).unwrap();
        assert!(matches!(
            attempt.wait_empty(Duration::from_millis(10)).await,
            Err(ExecutionDomainError::Backend {
                category: FailureCategory::Timeout,
                ..
            })
        ));
        assert!(attempt.remove().is_err());
        fs::write(
            nested.join(name),
            if name == "cgroup.procs" {
                ""
            } else {
                "populated 0\n"
            },
        )
        .unwrap();
    }
    attempt
        .wait_empty(Duration::from_millis(100))
        .await
        .unwrap();
    attempt.remove().unwrap();
    assert!(!fixture.attempt_path(id).exists());
    assert!(fixture.temp.path().join("supervisor").exists());
}

#[tokio::test]
async fn kill_failure_is_not_success_even_when_fallback_has_no_members() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    attempt.kill().unwrap();
    assert_eq!(
        fs::read_to_string(fixture.attempt_path(id).join("cgroup.kill")).unwrap(),
        "1\n"
    );
    fixture.fail("write", "cgroup.kill");
    assert!(attempt.kill().is_err());
    attempt
        .wait_empty(Duration::from_millis(100))
        .await
        .unwrap();
}

#[test]
fn busy_removal_preserves_attempt_and_outside_canary() {
    let fixture = Fixture::new();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("canary"), "safe").unwrap();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    fixture.fail("remove", "domain");
    assert!(matches!(
        attempt.remove(),
        Err(ExecutionDomainError::Backend {
            errno: Some(libc::EBUSY),
            ..
        })
    ));
    assert!(fixture.attempt_path(id).join("domain").exists());
    assert_eq!(
        fs::read_to_string(outside.path().join("canary")).unwrap(),
        "safe"
    );
}

#[tokio::test]
async fn replaced_directory_and_symlink_controls_are_refused() {
    let fixture = Fixture::new();
    let root = fixture.ready();
    let id = AttemptIdentity::new();
    let attempt = root.create_attempt(id, &limits()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let canary = outside.path().join("canary");
    fs::write(&canary, "safe").unwrap();
    fs::remove_file(fixture.attempt_path(id).join("cgroup.kill")).unwrap();
    symlink(&canary, fixture.attempt_path(id).join("cgroup.kill")).unwrap();
    assert!(attempt.kill().is_err());
    assert!(
        attempt
            .wait_empty(Duration::from_millis(100))
            .await
            .is_err()
    );
    assert!(attempt.remove().is_err());
    assert_eq!(fs::read_to_string(&canary).unwrap(), "safe");
    fs::rename(fixture.attempt_path(id), fixture.temp.path().join("moved")).unwrap();
    fs::create_dir(fixture.attempt_path(id)).unwrap();
    seed(&fixture.attempt_path(id), &limits());
    assert!(attempt.limits_match().is_err());
}

#[test]
fn kernel_write_uses_real_fd_and_bounded_read_refuses_oversize() {
    let mut file = tempfile::tempfile().unwrap();
    KernelCgroupFs
        .write(&mut file, c"cgroup.kill", "1")
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(
        KernelCgroupFs.read(&mut file, c"cgroup.kill").unwrap(),
        "1\n"
    );
    file.set_len(1024 * 1024 + 1).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    assert!(KernelCgroupFs.read(&mut file, c"cgroup.events").is_err());
}
