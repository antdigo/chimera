use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;
use uuid::Uuid;

use super::*;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn prepared_root() -> (TempDir, JobResourceRoot) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("job-resources");
    let root = JobResourceRoot::prepare(&path).unwrap();
    (temp, root)
}

struct ChildGuard {
    child: std::process::Child,
}

impl ChildGuard {
    fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn creates_private_empty_config() {
    let (_temp, root) = prepared_root();

    let config = root.create_docker_config().unwrap();

    assert_eq!(mode(root.path()), 0o700);
    assert_eq!(mode(config.attempt_dir()), 0o700);
    assert_eq!(mode(config.directory()), 0o700);
    assert_eq!(mode(config.config_file()), 0o600);
    assert_eq!(std::fs::read(config.config_file()).unwrap(), b"{}");
    assert_eq!(config.attempt_dir().parent(), Some(root.path()));
}

#[test]
fn concurrent_configs_have_distinct_generated_ids() {
    let (_temp, root) = prepared_root();
    let first_root = root.clone();
    let second_root = root.clone();

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(move || first_root.create_docker_config().unwrap());
        let second = scope.spawn(move || second_root.create_docker_config().unwrap());
        (first.join().unwrap(), second.join().unwrap())
    });

    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_ne!(first.directory(), second.directory());
}

#[test]
fn new_attempt_is_empty_after_previous_cleanup() {
    let (_temp, root) = prepared_root();
    let mut first = root.create_docker_config().unwrap();
    let first_path = first.directory().to_path_buf();
    std::fs::write(
        first.config_file(),
        r#"{"auths":{"registry.test":{"auth":"synthetic"}}}"#,
    )
    .unwrap();
    first.cleanup().unwrap();

    let second = root.create_docker_config().unwrap();

    assert_ne!(first_path, second.directory());
    assert_eq!(std::fs::read(second.config_file()).unwrap(), b"{}");
}

#[test]
fn inserts_and_validates_reserved_host_environment() {
    let (_temp, root) = prepared_root();
    let config = root.create_docker_config().unwrap();
    let mut env = HashMap::new();

    config
        .insert_into_host_env(&mut env, "job environment")
        .unwrap();
    config
        .validate_override(env.get(DOCKER_CONFIG_ENV).unwrap(), "step environment")
        .unwrap();

    let error = config
        .validate_override("/shared/.docker", "step environment")
        .unwrap_err();
    assert!(matches!(
        error,
        JobDockerConfigError::ReservedEnvironmentOverride {
            source: "step environment"
        }
    ));
    assert!(!error.to_string().contains("synthetic"));
}

#[test]
fn cleanup_is_idempotent_and_keeps_neighbor() {
    let (_temp, root) = prepared_root();
    let mut owned = root.create_docker_config().unwrap();
    let neighbor = root.create_docker_config().unwrap();
    let owned_dir = owned.attempt_dir().to_path_buf();
    let neighbor_dir = neighbor.attempt_dir().to_path_buf();

    owned.cleanup().unwrap();
    owned.cleanup().unwrap();

    assert!(!owned_dir.exists());
    assert!(neighbor_dir.exists());
}

#[test]
fn cleanup_refuses_config_symlink_without_touching_target() {
    let (_temp, root) = prepared_root();
    let mut config = root.create_docker_config().unwrap();
    let outside = root.path().parent().unwrap().join("outside-config.json");
    std::fs::write(&outside, "synthetic-outside").unwrap();
    std::fs::remove_file(config.config_file()).unwrap();
    std::os::unix::fs::symlink(&outside, config.config_file()).unwrap();

    let error = config.cleanup().unwrap_err();

    assert!(matches!(error, JobDockerConfigError::UnsafeEntry { .. }));
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "synthetic-outside"
    );
    assert!(config.attempt_dir().exists());
}

#[test]
fn generated_id_collision_is_rejected() {
    let (_temp, root) = prepared_root();
    let id = Uuid::nil();
    let first = root.create_with_id(id).unwrap();

    let error = root.create_with_id(id).unwrap_err();

    assert!(matches!(
        error,
        JobDockerConfigError::AttemptCollision { attempt_id } if attempt_id == id
    ));
    assert!(first.config_file().exists());
}

#[test]
fn daemon_docker_config_is_not_copied_or_modified() {
    let temp = TempDir::new().unwrap();
    let daemon_dir = temp.path().join("daemon-docker");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    let daemon_file = daemon_dir.join("config.json");
    let marker = r#"{"auths":{"registry.test":{"auth":"synthetic-host"}},"currentContext":"host"}"#;
    std::fs::write(&daemon_file, marker).unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "job::docker_config::docker_config_test::daemon_docker_config_child",
            "--nocapture",
        ])
        .env(DOCKER_CONFIG_ENV, &daemon_dir)
        .env("CHIMERA_DAEMON_CONFIG_CHILD", temp.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(std::fs::read_to_string(daemon_file).unwrap(), marker);
}

#[test]
fn daemon_docker_config_child() {
    let Some(parent) = std::env::var_os("CHIMERA_DAEMON_CONFIG_CHILD") else {
        return;
    };
    let parent = std::path::PathBuf::from(parent);
    let inherited = std::env::var_os(DOCKER_CONFIG_ENV).unwrap();
    assert_eq!(
        std::path::PathBuf::from(inherited),
        parent.join("daemon-docker")
    );

    let root = JobResourceRoot::prepare(&parent.join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();

    assert_eq!(std::fs::read(config.config_file()).unwrap(), b"{}");
    assert_ne!(config.directory(), parent.join("daemon-docker"));
}

#[test]
fn stale_root_with_live_child_is_not_removed() {
    let (temp, root) = prepared_root();
    let mut config = root.create_docker_config().unwrap();
    let stale_dir = config.attempt_dir().to_path_buf();
    let mut child = ChildGuard {
        child: std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 1; done"])
            .current_dir(config.directory())
            .spawn()
            .unwrap(),
    };

    let result = JobResourceRoot::prepare(root.path());

    assert!(matches!(
        result,
        Err(JobDockerConfigError::StaleJobResources { .. })
    ));
    assert!(stale_dir.exists());

    child.stop();
    config.cleanup().unwrap();
    assert!(!stale_dir.exists());
    JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
}

#[test]
fn umask_zero_still_creates_private_paths() {
    let temp = TempDir::new().unwrap();
    let child_test = "job::docker_config::docker_config_test::umask_zero_child";
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", child_test, "--nocapture"])
        .env("CHIMERA_UMASK_ZERO_CHILD", temp.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(mode(&temp.path().join("job-resources")), 0o700);
    let attempt = std::fs::read_dir(temp.path().join("job-resources"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(mode(&attempt), 0o700);
    assert_eq!(mode(&attempt.join("docker")), 0o700);
    assert_eq!(mode(&attempt.join("docker/config.json")), 0o600);
}

#[test]
fn umask_zero_child() {
    let Some(root_parent) = std::env::var_os("CHIMERA_UMASK_ZERO_CHILD") else {
        return;
    };
    unsafe {
        libc::umask(0);
    }
    let root =
        JobResourceRoot::prepare(&std::path::PathBuf::from(root_parent).join("job-resources"))
            .unwrap();
    root.create_docker_config().unwrap();
}

#[test]
fn read_only_root_fails_without_fallback() {
    let (_temp, root) = prepared_root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = root.create_docker_config();

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        result,
        Err(JobDockerConfigError::UnsafeRoot { .. })
    ));
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
}

#[test]
fn prepare_rejects_symlink_root() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("job-resources");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = JobResourceRoot::prepare(&link);

    assert!(matches!(
        result,
        Err(JobDockerConfigError::UnsafeRoot { .. })
    ));
}

#[test]
fn cleanup_refuses_special_file() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let mut config = root.create_docker_config().unwrap();
    let socket_path = config.attempt_dir().join("unexpected.sock");
    let socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let result = config.cleanup();

    assert!(matches!(
        result,
        Err(JobDockerConfigError::UnsafeEntry { .. })
    ));
    assert!(config.attempt_dir().exists());
    drop(socket);
    std::fs::remove_file(socket_path).unwrap();
    config.cleanup().unwrap();
}
