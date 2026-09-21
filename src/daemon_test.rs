use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tempfile::TempDir;

use super::*;
use crate::config::{
    ExecutionConfig, ExecutionProfile, ExecutionResources, NetworkPolicyConfig, ResourceLimits,
    StorageBoundConfig, StorageMechanism,
};
use crate::storage::{RootLock, RootLockError};

#[test]
fn sandboxed_profile_is_rejected_before_runtime_start() {
    let config = ChimeraConfig {
        execution: ExecutionConfig {
            profile: ExecutionProfile::Sandboxed,
            max_active_domains: NonZeroUsize::new(20).unwrap(),
            resources: None,
            ..ExecutionConfig::default()
        },
        ..Default::default()
    };

    let error = validate_execution_profile(&config).unwrap_err();

    assert_eq!(
        error.to_string(),
        "sandboxed execution profile is not available in this build"
    );
}

#[tokio::test]
async fn sandboxed_run_rejects_before_daemon_owned_side_effects() {
    let root = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(root.path().to_path_buf());
    let root_lock = RootLock::acquire(root.path()).unwrap();
    #[cfg(target_os = "linux")]
    let root_lock_proof = root_lock.reconciliation_proof().unwrap();
    let daemon = Daemon {
        paths: paths.clone(),
        config: ChimeraConfig {
            execution: ExecutionConfig {
                profile: ExecutionProfile::Sandboxed,
                max_active_domains: NonZeroUsize::new(20).unwrap(),
                resources: None,
                network: Some(NetworkPolicyConfig {
                    production_cidrs: vec!["203.0.113.0/24".parse().unwrap()],
                }),
                storage: Some(StorageBoundConfig {
                    mechanism: StorageMechanism::DedicatedFilesystem,
                    max_bytes: "1GiB".parse().unwrap(),
                }),
                ..ExecutionConfig::default()
            },
            runners: vec!["safety".into()],
            ..Default::default()
        },
        _root_lock: root_lock,
        #[cfg(target_os = "linux")]
        _root_lock_proof: root_lock_proof,
    };
    let before = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let error = daemon.run(shutdown_rx).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "sandboxed execution profile is not available in this build"
    );
    assert_eq!(
        std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>(),
        before
    );
    assert!(!paths.pid_file().exists());
    assert!(!paths.job_resources_dir().exists());
    assert!(!paths.cache_entries_dir().exists());
    assert!(!paths.state_file().exists());
    assert!(!paths.runner_dir("safety").exists());
}

#[test]
fn sandboxed_gate_precedes_resource_validation() {
    let invalid = ResourceLimits {
        memory_high: "2 MiB".into(),
        memory_max: "1 MiB".into(),
        memory_swap_max: "0".into(),
        cpu_quota: "0%".into(),
        cpu_weight: 0,
        pids_max: "0".into(),
        io_weight: 0,
        io_max: Vec::new(),
    };
    let config = ChimeraConfig {
        execution: ExecutionConfig {
            profile: ExecutionProfile::Sandboxed,
            max_active_domains: NonZeroUsize::new(20).unwrap(),
            resources: Some(ExecutionResources {
                global: invalid.clone(),
                attempt: invalid,
            }),
            ..ExecutionConfig::default()
        },
        ..Default::default()
    };

    let error = validate_execution_profile(&config).unwrap_err();

    assert_eq!(
        error.to_string(),
        "sandboxed execution profile is not available in this build"
    );
}

#[test]
fn daemon_load_refuses_busy_root_before_reading_config() {
    let root = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(root.path().to_path_buf());
    let config_path = paths.config_file();
    let _held = RootLock::acquire(root.path()).unwrap();

    let error = match Daemon::load(paths) {
        Ok(_) => panic!("daemon unexpectedly acquired a busy root"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("root storage is busy"));
    assert!(
        !config_path.exists(),
        "config was read/created before locking"
    );
}

#[test]
fn daemon_holds_root_lock_for_its_lifetime() {
    let root = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(root.path().to_path_buf());
    let daemon = Daemon::load(paths).unwrap();

    assert!(matches!(
        RootLock::acquire(root.path()).unwrap_err(),
        RootLockError::Busy
    ));
    drop(daemon);
    // A concurrently spawned child process (other tests spawn the test binary)
    // transiently duplicates the lock-holding fd until its exec completes, so
    // Busy can outlive drop(daemon) by milliseconds even though the daemon
    // released its lock. Poll until the lock is genuinely free.
    let deadline = Instant::now() + LOCK_TEST_TIMEOUT;
    loop {
        match RootLock::acquire(root.path()) {
            Ok(_released) => break,
            Err(RootLockError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("root lock not acquirable after daemon drop: {error:?}"),
        }
    }
}

#[test]
fn reconciliation_proof_keeps_the_exclusive_root_lock_live() {
    let root = TempDir::new().unwrap();
    let lock = RootLock::acquire(root.path()).unwrap();
    let proof = lock.reconciliation_proof().unwrap();
    let _pinned_root = proof.try_clone_root().unwrap();
    assert_eq!(proof.root_path(), root.path());
    drop(proof.lock_reconciliation());
    drop(lock);

    assert!(matches!(
        RootLock::acquire(root.path()),
        Err(RootLockError::Busy)
    ));
    drop(proof);
    assert!(RootLock::acquire(root.path()).is_ok());
}

#[test]
fn reconciliation_proof_serializes_same_process_recovery() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let root = TempDir::new().unwrap();
    let lock = RootLock::acquire(root.path()).unwrap();
    let first = lock.reconciliation_proof().unwrap();
    let second = lock.reconciliation_proof().unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let held = first.lock_reconciliation();

    std::thread::scope(|scope| {
        let thread_entered = Arc::clone(&entered);
        scope.spawn(move || {
            let _guard = second.lock_reconciliation();
            thread_entered.store(true, Ordering::Release);
        });
        std::thread::sleep(Duration::from_millis(20));
        assert!(!entered.load(Ordering::Acquire));
        drop(held);
    });
    assert!(entered.load(Ordering::Acquire));
}

const LOCK_TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct TestChild {
    child: Child,
}

impl TestChild {
    fn spawn(test_name: &str, path: &Path, control: &Path, id: &str) -> Self {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env("CHIMERA_PID_LOCK_TEST_PATH", path)
            .env("CHIMERA_PID_LOCK_TEST_CONTROL", control)
            .env("CHIMERA_PID_LOCK_TEST_ID", id)
            .spawn()
            .unwrap();
        Self { child }
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        self.child.wait().unwrap()
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + LOCK_TEST_TIMEOUT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_signal(control: &Path, name: &str) {
    wait_for_path(&control.join(name));
}

fn wait_for_result(control: &Path, name: &str) -> String {
    // Result files carry their signal in the content, and `fs::write` makes the
    // path visible before the content lands (a scheduled-out child can leave it
    // empty for milliseconds under load), so wait for non-empty content.
    let path = control.join(name);
    let deadline = Instant::now() + LOCK_TEST_TIMEOUT;
    loop {
        if let Ok(content) = std::fs::read_to_string(&path)
            && !content.is_empty()
        {
            return content;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

// --- PID lock tests ---

#[test]
fn acquire_lock_succeeds_when_no_file() {
    let tmp = TempDir::new().unwrap();
    let pid_path = tmp.path().join("chimera.pid");

    let lock = PidLock::acquire(&pid_path).unwrap();

    assert!(pid_path.exists());
    let content = std::fs::read_to_string(&pid_path).unwrap();
    assert_eq!(content.trim(), std::process::id().to_string());

    drop(lock);
}

#[test]
fn acquire_lock_fails_when_already_held() {
    let tmp = TempDir::new().unwrap();
    let pid_path = tmp.path().join("chimera.pid");

    // Write our own PID — process is alive
    std::fs::write(&pid_path, std::process::id().to_string()).unwrap();

    let result = PidLock::acquire(&pid_path);
    assert!(result.is_err());

    let err = result.unwrap_err().to_string();
    assert!(err.contains("already running"), "got: {err}");
}

#[test]
fn second_lock_cannot_replace_live_lock() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let first = PidLock::acquire(&path).unwrap();

    let second = PidLock::acquire(&path).unwrap_err();

    assert!(second.to_string().contains("already running"));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        std::process::id().to_string()
    );
    drop(first);
}

#[test]
fn pid_lock_holds_kernel_lock() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let control = temp.path().join("control");
    std::fs::create_dir(&control).unwrap();
    let mut child = TestChild::spawn(
        "daemon::daemon_test::pid_lock_holder_child",
        &path,
        &control,
        "holder",
    );

    wait_for_signal(&control, "holder.ready");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    let error = std::io::Error::last_os_error();
    if result == 0 {
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    assert_eq!(result, -1, "PID lock must be held by the child process");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

    std::fs::write(control.join("release"), []).unwrap();
    assert!(child.wait().success());
}

#[test]
fn pid_lock_holder_child() {
    let Some(path) = std::env::var_os("CHIMERA_PID_LOCK_TEST_PATH") else {
        return;
    };
    let control =
        std::path::PathBuf::from(std::env::var_os("CHIMERA_PID_LOCK_TEST_CONTROL").unwrap());
    let id = std::env::var("CHIMERA_PID_LOCK_TEST_ID").unwrap();
    let lock = PidLock::acquire(Path::new(&path)).unwrap();
    std::fs::write(control.join(format!("{id}.ready")), []).unwrap();

    wait_for_signal(&control, "release");
    drop(lock);
}

#[test]
fn fresh_pid_file_race_has_single_owner_and_valid_pid() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let control = temp.path().join("control");
    std::fs::create_dir(&control).unwrap();
    let mut creator = TestChild::spawn(
        "daemon::daemon_test::fresh_pid_file_race_child",
        &path,
        &control,
        "creator",
    );

    wait_for_signal(&control, "creator.opened");
    let mut contender = TestChild::spawn(
        "daemon::daemon_test::fresh_pid_file_race_child",
        &path,
        &control,
        "contender",
    );
    wait_for_signal(&control, "contender.locked");
    let creator_result = wait_for_result(&control, "creator.result");
    let contender_result = wait_for_result(&control, "contender.result");
    let results = [&creator_result, &contender_result];
    assert_eq!(
        results
            .iter()
            .filter(|result| result.starts_with("acquired:"))
            .count(),
        1
    );
    assert!(
        results
            .iter()
            .any(|result| result.starts_with("rejected:chimera daemon already running"))
    );

    let owner_pid = results
        .iter()
        .find_map(|result| result.strip_prefix("acquired:"))
        .unwrap();
    let published_pid = std::fs::read_to_string(&path).unwrap();
    assert_eq!(published_pid, owner_pid);
    assert!(published_pid.parse::<u32>().is_ok());

    std::fs::write(control.join("release"), []).unwrap();
    assert!(creator.wait().success());
    assert!(contender.wait().success());
    assert!(!path.exists());
}

#[test]
fn fresh_pid_file_race_child() {
    let Some(path) = std::env::var_os("CHIMERA_PID_LOCK_TEST_PATH") else {
        return;
    };
    let control =
        std::path::PathBuf::from(std::env::var_os("CHIMERA_PID_LOCK_TEST_CONTROL").unwrap());
    let id = std::env::var("CHIMERA_PID_LOCK_TEST_ID").unwrap();

    let result = PidLock::acquire_with_hooks(
        Path::new(&path),
        || {
            std::fs::write(control.join(format!("{id}.opened")), []).unwrap();
            if id == "creator" {
                wait_for_signal(&control, "contender.locked");
            }
        },
        || {
            std::fs::write(control.join(format!("{id}.locked")), []).unwrap();
            if id == "contender" {
                wait_for_signal(&control, "creator.result");
            }
        },
    );

    match result {
        Ok(lock) => {
            std::fs::write(
                control.join(format!("{id}.result")),
                format!("acquired:{}", std::process::id()),
            )
            .unwrap();
            wait_for_signal(&control, "release");
            drop(lock);
        }
        Err(error) => {
            std::fs::write(
                control.join(format!("{id}.result")),
                format!("rejected:{error}"),
            )
            .unwrap();
        }
    }
}

#[test]
fn concurrent_stale_lock_reclamation_has_single_owner() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let control = temp.path().join("control");
    std::fs::create_dir(&control).unwrap();
    std::fs::write(&path, "1000000000").unwrap();
    let mut first = TestChild::spawn(
        "daemon::daemon_test::stale_lock_reclamation_child",
        &path,
        &control,
        "first",
    );
    let mut second = TestChild::spawn(
        "daemon::daemon_test::stale_lock_reclamation_child",
        &path,
        &control,
        "second",
    );

    wait_for_signal(&control, "first.ready");
    wait_for_signal(&control, "second.ready");
    std::fs::write(control.join("start"), []).unwrap();
    let first_result = wait_for_result(&control, "first.result");
    let second_result = wait_for_result(&control, "second.result");
    let results = [&first_result, &second_result];
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == "acquired")
            .count(),
        1
    );
    assert!(
        results
            .iter()
            .any(|result| result.starts_with("rejected:chimera daemon already running"))
    );

    std::fs::write(control.join("release"), []).unwrap();
    assert!(first.wait().success());
    assert!(second.wait().success());
}

#[test]
fn stale_lock_reclamation_child() {
    let Some(path) = std::env::var_os("CHIMERA_PID_LOCK_TEST_PATH") else {
        return;
    };
    let control =
        std::path::PathBuf::from(std::env::var_os("CHIMERA_PID_LOCK_TEST_CONTROL").unwrap());
    let id = std::env::var("CHIMERA_PID_LOCK_TEST_ID").unwrap();
    std::fs::write(control.join(format!("{id}.ready")), []).unwrap();

    wait_for_signal(&control, "start");
    match PidLock::acquire(Path::new(&path)) {
        Ok(lock) => {
            std::fs::write(control.join(format!("{id}.result")), "acquired").unwrap();
            wait_for_signal(&control, "release");
            drop(lock);
        }
        Err(error) => {
            std::fs::write(
                control.join(format!("{id}.result")),
                format!("rejected:{error}"),
            )
            .unwrap();
        }
    }
}

#[test]
fn pid_lock_refuses_symlink_and_special_paths() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("target");
    std::fs::write(&target, "1000000000").unwrap();
    let symlink = temp.path().join("chimera.pid");
    std::os::unix::fs::symlink(&target, &symlink).unwrap();

    let symlink_error = PidLock::acquire(&symlink).unwrap_err();
    assert!(symlink_error.to_string().contains("unsafe PID lock path"));

    let directory = temp.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    let directory_error = PidLock::acquire(&directory).unwrap_err();
    assert!(directory_error.to_string().contains("unsafe PID lock path"));
}

#[test]
fn dropping_lock_does_not_remove_replacement_inode() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let lock = PidLock::acquire(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, "replacement").unwrap();

    drop(lock);

    assert_eq!(std::fs::read_to_string(path).unwrap(), "replacement");
}

#[test]
fn startup_preparation_rejects_stale_job_resources_without_deleting_them() {
    let temp = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());
    std::fs::create_dir_all(&paths.root).unwrap();
    let root = crate::job::execution_domain::ExecutionDomainRoot::prepare(
        &paths.job_resources_dir(),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let stale = futures::executor::block_on(async {
        root.reserve()
            .await?
            .provision(crate::job::execution_domain::AttemptIdentity::new())
            .await
    })
    .unwrap();
    let stale_dir = stale.attempt_dir().to_path_buf();

    let error = prepare_daemon_root(&paths, NonZeroUsize::new(1).unwrap()).unwrap_err();

    assert!(error.to_string().contains("stale-job-resources"));
    assert!(stale_dir.exists());
}

#[tokio::test]
async fn startup_preparation_enforces_supplied_domain_capacity() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = TempDir::new_in(test_root).unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());
    let (_lock, root) = prepare_daemon_root(&paths, NonZeroUsize::new(2).unwrap()).unwrap();
    let first = root.reserve().await.unwrap();
    let second = tokio::time::timeout(Duration::from_secs(1), root.reserve())
        .await
        .expect("second domain must be admitted")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), root.reserve())
            .await
            .is_err()
    );
    drop((first, second));
}

#[tokio::test]
async fn trusted_host_admits_every_runner_despite_sandboxed_capacity_limit() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = TempDir::new_in(test_root).unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());
    let config = ChimeraConfig {
        runners: vec!["first".into(), "second".into()],
        execution: crate::config::ExecutionConfig {
            max_active_domains: NonZeroUsize::new(1).unwrap(),
            ..Default::default()
        },
        cache: crate::cache::config::CacheConfig {
            cache_port: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    crate::config::save_config(&paths.config_file(), &config).unwrap();
    let rsa_params =
        crate::config::private_key_to_rsa_params(&crate::testing::test_private_key()).unwrap();
    let mut servers = Vec::new();
    for name in &config.runners {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-token", "expires_in": 7200
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessionId": name
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/message"))
            .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_secs(1)))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/session"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        crate::config::save_runner_credentials(
            &paths.runners_dir(),
            name,
            &crate::config::RunnerCredentials {
                info: crate::config::RunnerInfo {
                    agent_id: 1,
                    agent_name: name.clone(),
                    pool_id: 1,
                    server_url: server.uri(),
                    server_url_v2: server.uri(),
                    git_hub_url: server.uri(),
                    work_folder: "_work".into(),
                    use_v2_flow: true,
                },
                oauth: crate::config::OAuthCredentials {
                    scheme: "OAuth".into(),
                    client_id: name.clone(),
                    authorization_url: format!("{}/oauth2/token", server.uri()),
                },
                rsa_params: rsa_params.clone(),
            },
        )
        .unwrap();
        servers.push(server);
    }
    let daemon = Daemon::load(paths).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let run = tokio::spawn(daemon.run(shutdown_rx));
    let both_polling = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut polling = 0;
            for server in &servers {
                if server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|request| request.url.path() == "/message")
                {
                    polling += 1;
                }
            }
            if polling == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    both_polling.expect("both trusted-host runners must poll despite sandboxed capacity of one");
}

#[test]
fn startup_preparation_rejects_legacy_work_and_temp_canaries() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();

    for legacy_name in ["work", "tmp"] {
        let temp = TempDir::new_in(&test_root).unwrap();
        let paths = ChimeraPaths::new(temp.path().to_path_buf());
        let canary = paths.root.join(legacy_name).join("runner-0/canary");
        std::fs::create_dir_all(canary.parent().unwrap()).unwrap();
        std::fs::write(&canary, "secret from previous job").unwrap();

        let error = prepare_daemon_root(&paths, NonZeroUsize::new(1).unwrap()).unwrap_err();

        assert!(error.to_string().contains("stale-legacy-job-data"));
        assert!(canary.exists());
        assert!(!paths.job_resources_dir().exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn startup_rejects_chimera_root_under_host_tmp() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());

    let error = prepare_daemon_root(&paths, NonZeroUsize::new(1).unwrap()).unwrap_err();

    assert!(error.to_string().contains("chimera-root-under-host-tmp"));
    assert!(!paths.job_resources_dir().exists());
}

#[cfg(target_os = "linux")]
#[test]
fn startup_rejects_tmp_symlink_to_root_outside_host_tmp() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let target = TempDir::new_in(test_root).unwrap();
    let link = std::path::PathBuf::from(format!(
        "/tmp/chimera-root-link-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::os::unix::fs::symlink(target.path(), &link).unwrap();
    let paths = ChimeraPaths::new(link.clone());

    let result = prepare_daemon_root(&paths, NonZeroUsize::new(1).unwrap());
    let error = result.as_ref().err().map(ToString::to_string);
    drop(result);
    std::fs::remove_file(&link).unwrap();

    assert!(
        error
            .as_deref()
            .is_some_and(|message| message.contains("chimera-root-under-host-tmp"))
    );
    assert!(!target.path().join("job-resources").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_load_canonicalizes_root_with_intermediate_tmp_symlink() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let outside = TempDir::new_in(test_root).unwrap();
    let target_parent = outside.path().join("target-parent");
    let target_root = target_parent.join("root");
    std::fs::create_dir_all(&target_root).unwrap();
    let tmp_link = std::path::PathBuf::from(format!(
        "/tmp/chimera-intermediate-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::os::unix::fs::symlink(&target_parent, &tmp_link).unwrap();
    let outside_link = outside.path().join("through-tmp");
    std::os::unix::fs::symlink(&tmp_link, &outside_link).unwrap();
    let paths = ChimeraPaths::new(outside_link.join("root"));

    let daemon = Daemon::load(paths).unwrap();
    std::fs::remove_file(&tmp_link).unwrap();

    assert_eq!(daemon.paths.root, target_root.canonicalize().unwrap());
}

#[test]
fn poisoned_job_resource_error_requires_daemon_shutdown() {
    let poisoned = anyhow::Error::new(ExecutionDomainError::PoisonedRoot {
        path: "/synthetic/job-resources".into(),
    });
    let unrelated = anyhow::anyhow!("unrelated runner failure");

    assert!(is_fatal_job_resource_error(&poisoned));
    assert!(!is_fatal_job_resource_error(&unrelated));
}

#[test]
fn cleanup_fatal_error_requires_daemon_shutdown() {
    let fatal = anyhow::Error::new(ExecutionDomainCleanupFatalError {
        source: ExecutionDomainError::Cleanup {
            path: "/synthetic/job-resources/attempt".into(),
            source: std::io::Error::other("synthetic cleanup failure"),
        },
    });

    assert!(is_fatal_job_resource_error(&fatal));
}

#[test]
fn fatal_job_resource_errors_are_detected_through_wrapping_context() {
    let wrapped = anyhow::Error::new(ExecutionDomainError::PoisonedRoot {
        path: "/synthetic/job-resources".into(),
    })
    .context("runner exited");

    assert!(is_fatal_job_resource_error(&wrapped));
}

#[test]
fn acquire_lock_removes_stale_file() {
    let tmp = TempDir::new().unwrap();
    let pid_path = tmp.path().join("chimera.pid");

    // PID that almost certainly doesn't exist
    std::fs::write(&pid_path, "1000000000").unwrap();

    let lock = PidLock::acquire(&pid_path).unwrap();

    let content = std::fs::read_to_string(&pid_path).unwrap();
    assert_eq!(content.trim(), std::process::id().to_string());

    drop(lock);
}

#[test]
fn release_lock_removes_file() {
    let tmp = TempDir::new().unwrap();
    let pid_path = tmp.path().join("chimera.pid");

    {
        let _lock = PidLock::acquire(&pid_path).unwrap();
        assert!(pid_path.exists());
    }
    // Drop guard should have removed it
    assert!(!pid_path.exists());
}

#[test]
fn acquire_lock_fails_with_running_pid() {
    let tmp = TempDir::new().unwrap();
    let pid_path = tmp.path().join("chimera.pid");

    // PID 1 is init/launchd — always alive
    std::fs::write(&pid_path, "1").unwrap();

    let result = PidLock::acquire(&pid_path);
    assert!(result.is_err());

    let err = result.unwrap_err().to_string();
    assert!(err.contains("already running"), "got: {err}");
}

// --- State file tests ---

#[test]
fn state_file_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");

    let now = Utc::now();
    let mut runners = HashMap::new();
    runners.insert(
        "runner-0".to_string(),
        RunnerStatus {
            phase: RunnerPhase::Idle,
            current_job: None,
            last_error: None,
            started_at: now,
            phase_changed_at: now,
        },
    );
    runners.insert(
        "runner-1".to_string(),
        RunnerStatus {
            phase: RunnerPhase::Stopped,
            current_job: None,
            last_error: Some("bad credentials".into()),
            started_at: now,
            phase_changed_at: now,
        },
    );

    let snapshot = StateSnapshot {
        pid: 12345,
        started_at: now,
        runners,
    };

    write_state_file(&path, &snapshot).unwrap();
    let loaded = read_state_file(&path).unwrap();

    assert_eq!(loaded.pid, 12345);
    assert_eq!(loaded.runners.len(), 2);
    assert_eq!(loaded.runners["runner-0"].phase, RunnerPhase::Idle);
    assert_eq!(loaded.runners["runner-1"].phase, RunnerPhase::Stopped);
    assert_eq!(
        loaded.runners["runner-1"].last_error.as_deref(),
        Some("bad credentials")
    );
}

#[test]
fn state_file_atomic_write() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");

    let snapshot = StateSnapshot {
        pid: 1,
        started_at: Utc::now(),
        runners: HashMap::new(),
    };

    write_state_file(&path, &snapshot).unwrap();

    assert!(path.exists());
    assert!(!path.with_extension("json.tmp").exists());
}

#[test]
fn state_file_with_job_info() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");

    let now = Utc::now();
    let mut runners = HashMap::new();
    runners.insert(
        "runner-0".to_string(),
        RunnerStatus {
            phase: RunnerPhase::Running,
            current_job: Some(JobInfo {
                repo: "org/repo".into(),
                job_id: "job-123".into(),
                started_at: now,
            }),
            last_error: None,
            started_at: now,
            phase_changed_at: now,
        },
    );

    let snapshot = StateSnapshot {
        pid: 42,
        started_at: now,
        runners,
    };

    write_state_file(&path, &snapshot).unwrap();
    let loaded = read_state_file(&path).unwrap();

    let job = loaded.runners["runner-0"].current_job.as_ref().unwrap();
    assert_eq!(job.repo, "org/repo");
    assert_eq!(job.job_id, "job-123");
}

// --- RunnerStatus / phase transition tests ---

#[tokio::test]
async fn set_phase_updates_status() {
    let state = DaemonState::new(&["runner-0".into()]);

    state.set_phase("runner-0", RunnerPhase::Idle).await;

    let snapshot = state.snapshot().await;
    assert_eq!(snapshot.runners["runner-0"].phase, RunnerPhase::Idle);
}

#[tokio::test]
async fn set_job_clears_on_idle() {
    let state = DaemonState::new(&["runner-0".into()]);

    state
        .set_running(
            "runner-0",
            JobInfo {
                repo: "org/repo".into(),
                job_id: "j1".into(),
                started_at: Utc::now(),
            },
        )
        .await;

    let snapshot = state.snapshot().await;
    assert!(snapshot.runners["runner-0"].current_job.is_some());

    state.set_phase("runner-0", RunnerPhase::Idle).await;

    let snapshot = state.snapshot().await;
    assert_eq!(snapshot.runners["runner-0"].phase, RunnerPhase::Idle);
    assert!(snapshot.runners["runner-0"].current_job.is_none());
}

#[tokio::test]
async fn concurrent_phase_updates() {
    let names: Vec<String> = (0..10).map(|i| format!("runner-{i}")).collect();
    let state = Arc::new(DaemonState::new(&names));

    let mut handles = Vec::new();
    for name in &names {
        let state = Arc::clone(&state);
        let name = name.clone();
        handles.push(tokio::spawn(async move {
            state.set_phase(&name, RunnerPhase::Idle).await;
            state.set_phase(&name, RunnerPhase::Running).await;
            state.set_phase(&name, RunnerPhase::Idle).await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let snapshot = state.snapshot().await;
    for name in &names {
        assert_eq!(snapshot.runners[name].phase, RunnerPhase::Idle);
    }
}

// --- PID liveness check tests ---

#[test]
fn is_process_alive_for_current_process() {
    assert!(is_process_alive(std::process::id()));
}

#[test]
fn is_process_alive_for_dead_process() {
    assert!(!is_process_alive(1_000_000_000));
}

// --- Status display tests ---

#[test]
fn format_runner_status_idle() {
    let now = Utc::now();
    let status = RunnerStatus {
        phase: RunnerPhase::Idle,
        current_job: None,
        last_error: None,
        started_at: now,
        phase_changed_at: now,
    };

    let line = format_runner_line(&status);
    assert!(line.starts_with("Idle ("), "got: {line}");
}

#[test]
fn format_runner_status_running_job() {
    let now = Utc::now();
    let status = RunnerStatus {
        phase: RunnerPhase::Running,
        current_job: Some(JobInfo {
            repo: "org/repo".into(),
            job_id: "j1".into(),
            started_at: now,
        }),
        last_error: None,
        started_at: now,
        phase_changed_at: now,
    };

    let line = format_runner_line(&status);
    assert!(line.contains("org/repo"), "got: {line}");
    assert!(line.starts_with("Running job"), "got: {line}");
}

#[test]
fn format_runner_status_stopped_with_error() {
    let now = Utc::now();
    let status = RunnerStatus {
        phase: RunnerPhase::Stopped,
        current_job: None,
        last_error: Some("bad credentials".into()),
        started_at: now,
        phase_changed_at: now,
    };

    let line = format_runner_line(&status);
    assert!(line.contains("bad credentials"), "got: {line}");
    assert!(line.contains("Stopped"), "got: {line}");
}
