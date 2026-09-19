use std::collections::HashMap;
use std::os::unix::ffi::OsStringExt;
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
    let private_tmp = config.attempt_dir().join("tmp");

    assert_eq!(mode(root.path()), 0o700);
    assert_eq!(mode(config.attempt_dir()), 0o700);
    assert_eq!(mode(config.directory()), 0o700);
    assert_eq!(mode(&private_tmp), 0o700);
    assert_eq!(std::fs::read_dir(&private_tmp).unwrap().count(), 0);
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
fn cleanup_allows_symlinks_and_sockets_inside_private_tmp() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let mut config = root.create_docker_config().unwrap();
    let target = temp.path().join("outside-target");
    std::fs::write(&target, "preserve me").unwrap();
    std::os::unix::fs::symlink(&target, config.private_tmp().join("link")).unwrap();
    let socket =
        std::os::unix::net::UnixListener::bind(config.private_tmp().join("service.sock")).unwrap();
    let attempt = config.attempt_dir().to_path_buf();

    config.cleanup().unwrap();

    assert!(!attempt.exists());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve me");
    drop(socket);
}

#[test]
fn cleanup_handles_non_writable_directories_inside_private_tmp() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let mut config = root.create_docker_config().unwrap();
    let attempt = config.attempt_dir().to_path_buf();
    let private_tmp = config.private_tmp().to_path_buf();
    let locked = private_tmp.join("locked");
    let nested = locked.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("secret"), "synthetic").unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::set_permissions(&private_tmp, std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = config.cleanup();
    if result.is_err() {
        if nested.exists() {
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        if locked.exists() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        if private_tmp.exists() {
            std::fs::set_permissions(&private_tmp, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        if attempt.exists() {
            std::fs::remove_dir_all(&attempt).unwrap();
        }
    }

    result.unwrap();
    assert!(!attempt.exists());
}

#[test]
fn creation_refuses_replacement_root_before_mutation() {
    let (temp, root) = prepared_root();
    let original_root = root.path().to_path_buf();
    let moved_root = temp.path().join("moved-job-resources");
    std::fs::rename(&original_root, &moved_root).unwrap();
    std::fs::create_dir(&original_root).unwrap();
    std::fs::set_permissions(&original_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let attempt_id = Uuid::nil();
    let attempt_name = attempt_id.simple().to_string();

    let error = root.create_with_id(attempt_id).unwrap_err();

    assert!(matches!(error, JobDockerConfigError::UnsafeEntry { .. }));
    assert!(!original_root.join(&attempt_name).exists());
    assert!(!moved_root.join(&attempt_name).exists());
}

#[test]
fn creation_refuses_ancestor_symlink_before_mutation() {
    let temp = TempDir::new().unwrap();
    let original_parent = temp.path().join("resource-parent");
    std::fs::create_dir(&original_parent).unwrap();
    let root_path = original_parent.join("job-resources");
    let root = JobResourceRoot::prepare(&root_path).unwrap();
    let moved_parent = temp.path().join("moved-resource-parent");
    std::fs::rename(&original_parent, &moved_parent).unwrap();
    std::os::unix::fs::symlink(&moved_parent, &original_parent).unwrap();
    let attempt_id = Uuid::from_u128(1);
    let attempt_name = attempt_id.simple().to_string();
    let moved_root = moved_parent.join("job-resources");

    let error = root.create_with_id(attempt_id).unwrap_err();

    assert!(matches!(error, JobDockerConfigError::UnsafeEntry { .. }));
    assert!(!root_path.join(&attempt_name).exists());
    assert!(!moved_root.join(&attempt_name).exists());
}

#[test]
fn cleanup_refuses_moved_root_replaced_by_symlink() {
    let (temp, root) = prepared_root();
    let original_root = root.path().to_path_buf();
    let mut config = root.create_docker_config().unwrap();
    let attempt_name = config.attempt_dir().file_name().unwrap().to_owned();
    let moved_root = temp.path().join("moved-job-resources");
    std::fs::rename(&original_root, &moved_root).unwrap();
    std::os::unix::fs::symlink(&moved_root, &original_root).unwrap();

    let error = config.cleanup().unwrap_err();

    assert!(matches!(error, JobDockerConfigError::UnsafeEntry { .. }));
    assert!(
        std::fs::symlink_metadata(&original_root)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(moved_root.join(attempt_name).exists());
}

#[test]
fn cleanup_refuses_replacement_attempt_at_same_path() {
    let (temp, root) = prepared_root();
    let mut config = root.create_docker_config().unwrap();
    let attempt_path = config.attempt_dir().to_path_buf();
    let moved_attempt = temp.path().join("moved-attempt");
    std::fs::rename(&attempt_path, &moved_attempt).unwrap();
    std::fs::create_dir(&attempt_path).unwrap();
    std::fs::set_permissions(&attempt_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let replacement_marker = attempt_path.join("replacement-marker");
    std::fs::write(&replacement_marker, "replacement").unwrap();

    let error = config.cleanup().unwrap_err();

    assert!(matches!(error, JobDockerConfigError::UnsafeEntry { .. }));
    assert!(moved_attempt.join("docker/config.json").exists());
    assert_eq!(
        std::fs::read_to_string(replacement_marker).unwrap(),
        "replacement"
    );
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
fn utf8_path_rejects_non_utf8_bytes() {
    let invalid =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(b"job-resources-\xff".to_vec()));

    let error = utf8_path(&invalid).unwrap_err();

    assert!(matches!(
        error,
        JobDockerConfigError::UnsafeRoot {
            reason: "path is not valid UTF-8",
            ..
        }
    ));
}

#[test]
fn prepare_rejects_non_utf8_path_before_creating_it() {
    let temp = TempDir::new().unwrap();
    let invalid = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"job-resources-\xff".to_vec()));

    let error = JobResourceRoot::prepare(&invalid).unwrap_err();

    assert!(
        matches!(
            &error,
            JobDockerConfigError::UnsafeRoot {
                reason: "path is not valid UTF-8",
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
    assert!(!invalid.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_rejects_non_utf8_canonical_root() {
    let temp = TempDir::new().unwrap();
    let invalid_name = std::ffi::OsString::from_vec(b"job-resources-\xff".to_vec());
    let path = temp.path().join(invalid_name);

    let error = JobResourceRoot::prepare(&path).unwrap_err();

    assert!(
        matches!(
            &error,
            JobDockerConfigError::UnsafeRoot {
                reason: "path is not valid UTF-8",
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
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

#[test]
fn cleanup_failure_poisoned_root_blocks_sibling_creation() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let sibling_root = root.clone();
    let mut config = root.create_docker_config().unwrap();
    let socket_path = config.attempt_dir().join("unexpected.sock");
    let socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    config.cleanup().unwrap_err();
    let creation_error = sibling_root.create_docker_config().unwrap_err();

    assert!(
        creation_error
            .to_string()
            .contains("poisoned-job-resource-root")
    );
    drop(socket);
    std::fs::remove_file(socket_path).unwrap();
    config.cleanup().unwrap();
}
