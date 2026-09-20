use std::collections::HashMap;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;
use uuid::Uuid;

use super::*;

#[test]
fn execution_domain_owns_all_attempt_paths() {
    let (_temp, root) = prepared_root();
    let domain = admitted_domain(&root).unwrap();

    assert_eq!(
        domain.docker_config_dir().parent(),
        Some(domain.attempt_dir())
    );
    assert_eq!(domain.private_tmp().parent(), Some(domain.attempt_dir()));
    assert_eq!(domain.work_dir().parent(), Some(domain.attempt_dir()));
    assert_ne!(domain.attempt_id(), uuid::Uuid::nil());
}

fn admitted_domain(root: &ExecutionDomainRoot) -> Result<ExecutionDomain, ExecutionDomainError> {
    futures::executor::block_on(root.reserve())?.provision()
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn prepared_root() -> (TempDir, ExecutionDomainRoot) {
    prepared_root_with_capacity(1)
}

fn prepared_root_with_capacity(capacity: usize) -> (TempDir, ExecutionDomainRoot) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("job-resources");
    let root = ExecutionDomainRoot::prepare(&path, NonZeroUsize::new(capacity).unwrap()).unwrap();
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

    let config = admitted_domain(&root).unwrap();
    let private_tmp = config.attempt_dir().join("tmp");

    assert_eq!(mode(root.path()), 0o700);
    assert_eq!(mode(config.attempt_dir()), 0o700);
    assert_eq!(mode(config.docker_config_dir()), 0o700);
    assert_eq!(mode(&private_tmp), 0o700);
    assert_eq!(std::fs::read_dir(&private_tmp).unwrap().count(), 0);
    assert_eq!(mode(config.config_file()), 0o600);
    assert_eq!(std::fs::read(config.config_file()).unwrap(), b"{}");
    assert_eq!(config.attempt_dir().parent(), Some(root.path()));
}

#[test]
fn concurrent_configs_have_distinct_generated_ids() {
    let (_temp, root) = prepared_root_with_capacity(2);
    let first_root = root.clone();
    let second_root = root.clone();

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(move || admitted_domain(&first_root).unwrap());
        let second = scope.spawn(move || admitted_domain(&second_root).unwrap());
        (first.join().unwrap(), second.join().unwrap())
    });

    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_ne!(first.docker_config_dir(), second.docker_config_dir());
    assert_ne!(first.work_dir(), second.work_dir());
    assert_ne!(first.private_tmp(), second.private_tmp());
}

#[test]
fn new_attempt_is_empty_after_previous_cleanup() {
    let (_temp, root) = prepared_root();
    let first = admitted_domain(&root).unwrap();
    let first_path = first.docker_config_dir().to_path_buf();
    std::fs::write(
        first.config_file(),
        r#"{"auths":{"registry.test":{"auth":"synthetic"}}}"#,
    )
    .unwrap();
    std::fs::write(first.work_dir().join("workspace-canary"), "secret").unwrap();
    std::fs::write(first.private_tmp().join("credential-canary"), "credential").unwrap();
    first.destroy().unwrap();

    let second = admitted_domain(&root).unwrap();

    assert_ne!(first_path, second.docker_config_dir());
    assert_eq!(std::fs::read(second.config_file()).unwrap(), b"{}");
    assert_eq!(std::fs::read_dir(second.work_dir()).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(second.private_tmp()).unwrap().count(), 0);
}

#[test]
fn inserts_and_validates_reserved_host_environment() {
    let (_temp, root) = prepared_root();
    let config = admitted_domain(&root).unwrap();
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
        ExecutionDomainError::ReservedEnvironmentOverride {
            source: "step environment"
        }
    ));
    assert!(!error.to_string().contains("synthetic"));
}

#[test]
fn destroy_removes_owned_attempt_and_keeps_neighbor() {
    let (_temp, root) = prepared_root_with_capacity(2);
    let owned = admitted_domain(&root).unwrap();
    let neighbor = admitted_domain(&root).unwrap();
    let owned_dir = owned.attempt_dir().to_path_buf();
    let neighbor_dir = neighbor.attempt_dir().to_path_buf();

    owned.destroy().unwrap();

    assert!(!owned_dir.exists());
    assert!(neighbor_dir.exists());
}

#[test]
fn cleanup_allows_symlinks_and_sockets_inside_private_tmp() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = admitted_domain(&root).unwrap();
    let target = temp.path().join("outside-target");
    std::fs::write(&target, "preserve me").unwrap();
    std::os::unix::fs::symlink(&target, config.private_tmp().join("link")).unwrap();
    let socket =
        std::os::unix::net::UnixListener::bind(config.private_tmp().join("service.sock")).unwrap();
    let attempt = config.attempt_dir().to_path_buf();

    config.destroy().unwrap();

    assert!(!attempt.exists());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve me");
    drop(socket);
}

#[test]
fn cleanup_handles_non_writable_directories_inside_private_tmp() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = admitted_domain(&root).unwrap();
    let attempt = config.attempt_dir().to_path_buf();
    let private_tmp = config.private_tmp().to_path_buf();
    let locked = private_tmp.join("locked");
    let nested = locked.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("secret"), "synthetic").unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::set_permissions(&private_tmp, std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = config.destroy();
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
fn cleanup_removes_work_and_temp_when_workspace_leaf_is_missing() {
    use crate::job::workspace::Workspace;

    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = admitted_domain(&root).unwrap();
    let tool_cache = temp.path().join("tool-cache");
    let workspace = Workspace::create(
        config.work_dir(),
        config.private_tmp(),
        &tool_cache,
        "runner-0",
        "owner/repo",
    )
    .unwrap();
    let attempt = config.attempt_dir().to_path_buf();
    let command_canary = workspace.env_file().to_path_buf();
    let temp_canary = workspace.runner_temp().join("checkout-credential-canary");
    std::fs::write(&command_canary, "APP_ENV=secret").unwrap();
    std::fs::write(&temp_canary, "credential").unwrap();
    std::fs::remove_dir_all(workspace.workspace_dir()).unwrap();

    config.destroy().unwrap();

    assert!(!attempt.exists());
    assert!(!command_canary.exists());
    assert!(!temp_canary.exists());
}

#[test]
fn cleanup_allows_workspace_symlinks_without_touching_their_targets() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = admitted_domain(&root).unwrap();
    let target = temp.path().join("outside-workspace-target");
    std::fs::write(&target, "preserve me").unwrap();
    std::os::unix::fs::symlink(&target, config.work_dir().join("repository-link")).unwrap();
    let attempt = config.attempt_dir().to_path_buf();

    config.destroy().unwrap();

    assert!(!attempt.exists());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve me");
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

    let error = root.create_domain_with_id(attempt_id).unwrap_err();

    assert!(matches!(error, ExecutionDomainError::UnsafeEntry { .. }));
    assert!(!original_root.join(&attempt_name).exists());
    assert!(!moved_root.join(&attempt_name).exists());
}

#[test]
fn creation_refuses_ancestor_symlink_before_mutation() {
    let temp = TempDir::new().unwrap();
    let original_parent = temp.path().join("resource-parent");
    std::fs::create_dir(&original_parent).unwrap();
    let root_path = original_parent.join("job-resources");
    let root = ExecutionDomainRoot::prepare(&root_path, NonZeroUsize::new(1).unwrap()).unwrap();
    let moved_parent = temp.path().join("moved-resource-parent");
    std::fs::rename(&original_parent, &moved_parent).unwrap();
    std::os::unix::fs::symlink(&moved_parent, &original_parent).unwrap();
    let attempt_id = Uuid::from_u128(1);
    let attempt_name = attempt_id.simple().to_string();
    let moved_root = moved_parent.join("job-resources");

    let error = root.create_domain_with_id(attempt_id).unwrap_err();

    assert!(matches!(error, ExecutionDomainError::UnsafeEntry { .. }));
    assert!(!root_path.join(&attempt_name).exists());
    assert!(!moved_root.join(&attempt_name).exists());
}

#[test]
fn cleanup_refuses_moved_root_replaced_by_symlink() {
    let (temp, root) = prepared_root();
    let original_root = root.path().to_path_buf();
    let config = admitted_domain(&root).unwrap();
    let attempt_name = config.attempt_dir().file_name().unwrap().to_owned();
    let moved_root = temp.path().join("moved-job-resources");
    std::fs::rename(&original_root, &moved_root).unwrap();
    std::os::unix::fs::symlink(&moved_root, &original_root).unwrap();

    let error = config.destroy().unwrap_err();

    assert!(matches!(error, ExecutionDomainError::UnsafeEntry { .. }));
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
    let config = admitted_domain(&root).unwrap();
    let attempt_path = config.attempt_dir().to_path_buf();
    let moved_attempt = temp.path().join("moved-attempt");
    std::fs::rename(&attempt_path, &moved_attempt).unwrap();
    std::fs::create_dir(&attempt_path).unwrap();
    std::fs::set_permissions(&attempt_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let replacement_marker = attempt_path.join("replacement-marker");
    std::fs::write(&replacement_marker, "replacement").unwrap();

    let error = config.destroy().unwrap_err();

    assert!(matches!(error, ExecutionDomainError::UnsafeEntry { .. }));
    assert!(moved_attempt.join("docker/config.json").exists());
    assert_eq!(
        std::fs::read_to_string(replacement_marker).unwrap(),
        "replacement"
    );
}

#[test]
fn cleanup_refuses_config_symlink_without_touching_target() {
    let (_temp, root) = prepared_root();
    let config = admitted_domain(&root).unwrap();
    let attempt_dir = config.attempt_dir().to_path_buf();
    let outside = root.path().parent().unwrap().join("outside-config.json");
    std::fs::write(&outside, "synthetic-outside").unwrap();
    std::fs::remove_file(config.config_file()).unwrap();
    std::os::unix::fs::symlink(&outside, config.config_file()).unwrap();

    let error = config.destroy().unwrap_err();

    assert!(matches!(error, ExecutionDomainError::UnsafeEntry { .. }));
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "synthetic-outside"
    );
    assert!(attempt_dir.exists());
}

#[test]
fn generated_id_collision_is_rejected() {
    let (_temp, root) = prepared_root();
    let id = Uuid::nil();
    let first = root.create_domain_with_id(id).unwrap();

    let error = root.create_domain_with_id(id).unwrap_err();

    assert!(matches!(
        error,
        ExecutionDomainError::AttemptCollision { attempt_id } if attempt_id == id
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
            "job::execution_domain::execution_domain_test::daemon_docker_config_child",
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

    let root = ExecutionDomainRoot::prepare(
        &parent.join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = admitted_domain(&root).unwrap();

    assert_eq!(std::fs::read(config.config_file()).unwrap(), b"{}");
    assert_ne!(config.docker_config_dir(), parent.join("daemon-docker"));
}

#[test]
fn stale_root_with_live_child_is_not_removed() {
    let (temp, root) = prepared_root();
    let config = admitted_domain(&root).unwrap();
    let stale_dir = config.attempt_dir().to_path_buf();
    let work_canary = config.work_dir().join("workspace-canary");
    let temp_canary = config.private_tmp().join("checkout-credential-canary");
    std::fs::write(&work_canary, "APP_ENV=secret").unwrap();
    std::fs::write(&temp_canary, "credential").unwrap();
    let mut child = ChildGuard {
        child: std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 1; done"])
            .current_dir(config.docker_config_dir())
            .spawn()
            .unwrap(),
    };

    let result = ExecutionDomainRoot::prepare(root.path(), NonZeroUsize::new(1).unwrap());

    assert!(matches!(
        result,
        Err(ExecutionDomainError::StaleJobResources { .. })
    ));
    assert!(stale_dir.exists());
    assert_eq!(
        std::fs::read_to_string(&work_canary).unwrap(),
        "APP_ENV=secret"
    );
    assert_eq!(std::fs::read_to_string(&temp_canary).unwrap(), "credential");

    child.stop();
    config.destroy().unwrap();
    assert!(!stale_dir.exists());
    ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
}

#[test]
fn umask_zero_still_creates_private_paths() {
    let temp = TempDir::new().unwrap();
    let child_test = "job::execution_domain::execution_domain_test::umask_zero_child";
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
    assert_eq!(mode(&attempt.join("journal.json")), 0o600);
}

#[test]
fn umask_zero_child() {
    let Some(root_parent) = std::env::var_os("CHIMERA_UMASK_ZERO_CHILD") else {
        return;
    };
    unsafe {
        libc::umask(0);
    }
    let root = ExecutionDomainRoot::prepare(
        &std::path::PathBuf::from(root_parent).join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    admitted_domain(&root).unwrap();
}

#[test]
fn read_only_root_fails_without_fallback() {
    let (_temp, root) = prepared_root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = admitted_domain(&root);

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        result,
        Err(ExecutionDomainError::UnsafeRoot { .. })
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
        ExecutionDomainError::UnsafeRoot {
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

    let error = ExecutionDomainRoot::prepare(&invalid, NonZeroUsize::new(1).unwrap()).unwrap_err();

    assert!(
        matches!(
            &error,
            ExecutionDomainError::UnsafeRoot {
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

    let error = ExecutionDomainRoot::prepare(&path, NonZeroUsize::new(1).unwrap()).unwrap_err();

    assert!(
        matches!(
            &error,
            ExecutionDomainError::UnsafeRoot {
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

    let result = ExecutionDomainRoot::prepare(&link, NonZeroUsize::new(1).unwrap());

    assert!(matches!(
        result,
        Err(ExecutionDomainError::UnsafeRoot { .. })
    ));
}

#[test]
fn cleanup_refuses_special_file() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = admitted_domain(&root).unwrap();
    let attempt_dir = config.attempt_dir().to_path_buf();
    let socket_path = config.attempt_dir().join("unexpected.sock");
    let socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let result = config.destroy();

    assert!(matches!(
        result,
        Err(ExecutionDomainError::UnsafeEntry { .. })
    ));
    assert!(attempt_dir.exists());
    drop(socket);
    std::fs::remove_file(socket_path).unwrap();
    std::fs::remove_dir_all(attempt_dir).unwrap();
}

#[test]
fn cleanup_failure_poisoned_root_blocks_sibling_creation() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let sibling_root = root.clone();
    let config = admitted_domain(&root).unwrap();
    let attempt_dir = config.attempt_dir().to_path_buf();
    let work_canary = config.work_dir().join("workspace-canary");
    let temp_canary = config.private_tmp().join("checkout-credential-canary");
    std::fs::write(&work_canary, "APP_ENV=secret").unwrap();
    std::fs::write(&temp_canary, "credential").unwrap();
    let socket_path = config.attempt_dir().join("unexpected.sock");
    let socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    config.destroy().unwrap_err();
    let creation_error = admitted_domain(&sibling_root).unwrap_err();

    assert!(
        creation_error
            .to_string()
            .contains("poisoned-job-resource-root")
    );
    assert_eq!(
        std::fs::read_to_string(&work_canary).unwrap(),
        "APP_ENV=secret"
    );
    assert_eq!(std::fs::read_to_string(&temp_canary).unwrap(), "credential");
    drop(socket);
    std::fs::remove_file(socket_path).unwrap();
    std::fs::remove_dir_all(attempt_dir).unwrap();
}

#[test]
fn injected_permission_cleanup_failure_preserves_canaries_and_blocks_reuse() {
    let temp = TempDir::new_in("/tmp").unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let sibling_root = root.clone();
    let mut config = admitted_domain(&root).unwrap();
    let work_canary = config.work_dir().join("workspace-canary");
    let temp_canary = config.private_tmp().join("checkout-v6-credential-canary");
    std::fs::write(&work_canary, "workspace-secret").unwrap();
    std::fs::write(&temp_canary, "credential-secret").unwrap();

    let cleanup_error = config
        .destroy_with_remover(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic permission failure",
            ))
        })
        .unwrap_err();
    let creation_error = admitted_domain(&sibling_root).unwrap_err();

    assert!(matches!(
        cleanup_error,
        ExecutionDomainError::Cleanup { ref source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert!(
        creation_error
            .to_string()
            .contains("poisoned-job-resource-root")
    );
    assert_eq!(
        std::fs::read_to_string(&work_canary).unwrap(),
        "workspace-secret"
    );
    assert_eq!(
        std::fs::read_to_string(&temp_canary).unwrap(),
        "credential-secret"
    );

    assert_eq!(
        DomainLifecycle::load(config.attempt_dir()).unwrap().state(),
        DomainState::Quarantined
    );
    std::fs::remove_dir_all(config.attempt_dir()).unwrap();
}

#[test]
fn domain_lifecycle_persists_ready_running_cleaning_and_destroying() {
    let (_temp, root) = prepared_root();
    let mut domain = admitted_domain(&root).unwrap();
    assert_eq!(
        DomainLifecycle::load(domain.attempt_dir()).unwrap().state(),
        DomainState::Ready
    );
    domain.mark_running().unwrap();
    assert_eq!(
        DomainLifecycle::load(domain.attempt_dir()).unwrap().state(),
        DomainState::Running
    );
    domain.mark_cleaning().unwrap();
    assert_eq!(
        DomainLifecycle::load(domain.attempt_dir()).unwrap().state(),
        DomainState::Cleaning
    );
    domain
        .destroy_with_remover(|path| {
            assert_eq!(
                DomainLifecycle::load(path).unwrap().state(),
                DomainState::Destroying
            );
            std::fs::remove_dir_all(path)
        })
        .unwrap();
    assert_eq!(domain.lifecycle.state(), DomainState::Destroyed);
    assert!(!domain.attempt_dir().exists());
}

#[test]
fn failed_quarantine_retains_original_cleanup_error_and_poisons_root() {
    let (_temp, root) = prepared_root();
    let mut domain = admitted_domain(&root).unwrap();
    let error = domain
        .destroy_with_remover(|path| {
            std::fs::write(path.join("journal.json.next"), "incomplete").unwrap();
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cleanup failure",
            ))
        })
        .unwrap_err();
    assert!(
        matches!(error, ExecutionDomainError::QuarantineFailed { cleanup, .. }
        if matches!(&*cleanup, ExecutionDomainError::Cleanup { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied))
    );
    assert!(matches!(
        admitted_domain(&root),
        Err(ExecutionDomainError::PoisonedRoot { .. })
    ));
}

#[test]
fn creation_syncs_resource_root_after_ready_publication() {
    use std::os::unix::fs::MetadataExt;
    let (_temp, root) = prepared_root();
    let id = Uuid::from_u128(21);
    let attempt = root.path().join(id.simple().to_string());
    let called = std::cell::Cell::new(false);
    let domain = root
        .create_with_id_and_sync(id, |directory| {
            assert_eq!(
                directory.metadata()?.ino(),
                std::fs::metadata(root.path())?.ino()
            );
            assert_eq!(
                DomainLifecycle::load(&attempt).unwrap().state(),
                DomainState::Ready
            );
            assert!(attempt.join("docker/config.json").is_file());
            assert!(attempt.join("tmp").is_dir());
            assert!(attempt.join("work").is_dir());
            directory.sync_all()?;
            called.set(true);
            Ok(())
        })
        .unwrap();
    assert!(called.get());
    domain.destroy().unwrap();
}

#[test]
fn failed_creation_root_sync_preserves_attempt_and_poisons_root() {
    let (_temp, root) = prepared_root();
    let id = Uuid::from_u128(22);
    let attempt = root.path().join(id.simple().to_string());
    let error = root
        .create_with_id_and_sync(id, |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "sync failure",
            ))
        })
        .unwrap_err();
    assert!(matches!(error, ExecutionDomainError::Io { source, .. }
        if source.kind() == std::io::ErrorKind::PermissionDenied));
    assert_eq!(
        DomainLifecycle::load(&attempt).unwrap().state(),
        DomainState::Ready
    );
    assert!(matches!(
        admitted_domain(&root),
        Err(ExecutionDomainError::PoisonedRoot { .. })
    ));
}

#[test]
fn removal_syncs_resource_root_before_completing_destroyed() {
    use std::os::unix::fs::MetadataExt;
    let (_temp, root) = prepared_root();
    let mut domain = admitted_domain(&root).unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    let called = std::cell::Cell::new(false);
    domain
        .destroy_with_remover_and_sync(
            |path| {
                assert_eq!(
                    DomainLifecycle::load(path).unwrap().state(),
                    DomainState::Destroying
                );
                std::fs::remove_dir_all(path)
            },
            |directory| {
                assert!(!attempt.exists());
                assert_eq!(
                    directory.metadata()?.ino(),
                    std::fs::metadata(root.path())?.ino()
                );
                directory.sync_all()?;
                called.set(true);
                Ok(())
            },
        )
        .unwrap();
    assert!(called.get());
    assert_eq!(domain.lifecycle.state(), DomainState::Destroyed);
}

#[test]
fn failed_removal_root_sync_keeps_destroying_and_poisons_root() {
    let (_temp, root) = prepared_root();
    let mut domain = admitted_domain(&root).unwrap();
    let error = domain
        .destroy_with_remover_and_sync(
            |path| std::fs::remove_dir_all(path),
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sync failure",
                ))
            },
        )
        .unwrap_err();
    assert!(
        matches!(error, ExecutionDomainError::QuarantineFailed { cleanup, .. }
        if matches!(&*cleanup, ExecutionDomainError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied))
    );
    assert!(!domain.attempt_dir().exists());
    assert!(!domain.destroyed);
    assert_eq!(domain.lifecycle.state(), DomainState::Destroying);
    assert!(matches!(
        admitted_domain(&root),
        Err(ExecutionDomainError::PoisonedRoot { .. })
    ));
}

#[test]
fn root_sync_refuses_replacement_without_touching_canary() {
    let (temp, root) = prepared_root();
    let mut domain = admitted_domain(&root).unwrap();
    let moved = temp.path().join("moved-root");
    let canary = root.path().join("canary");
    let error = domain
        .destroy_with_remover_and_sync(
            |path| {
                std::fs::remove_dir_all(path)?;
                std::fs::rename(root.path(), &moved)?;
                std::fs::create_dir(root.path())?;
                std::fs::write(&canary, "preserve-root-canary")
            },
            |_| panic!("must not sync a replaced root"),
        )
        .unwrap_err();
    assert!(
        matches!(error, ExecutionDomainError::QuarantineFailed { cleanup, .. }
        if matches!(&*cleanup, ExecutionDomainError::UnsafeEntry { .. }))
    );
    assert_eq!(
        std::fs::read_to_string(canary).unwrap(),
        "preserve-root-canary"
    );
    assert_eq!(domain.lifecycle.state(), DomainState::Destroying);
    assert!(matches!(
        admitted_domain(&root),
        Err(ExecutionDomainError::PoisonedRoot { .. })
    ));
}

#[test]
fn creation_rechecks_root_identity_after_sync() {
    let (temp, root) = prepared_root();
    let moved = temp.path().join("moved-root");
    let canary = root.path().join("canary");
    let id = Uuid::from_u128(23);
    let error = root
        .create_with_id_and_sync(id, |directory| {
            directory.sync_all()?;
            std::fs::rename(root.path(), &moved)?;
            std::fs::create_dir(root.path())?;
            std::fs::write(&canary, "preserve-root-canary")
        })
        .unwrap_err();
    assert!(matches!(error, ExecutionDomainError::UnsafeEntry { .. }));
    assert_eq!(
        std::fs::read_to_string(canary).unwrap(),
        "preserve-root-canary"
    );
    assert_eq!(
        DomainLifecycle::load(&moved.join(id.simple().to_string()))
            .unwrap()
            .state(),
        DomainState::Ready
    );
    assert!(matches!(
        admitted_domain(&root),
        Err(ExecutionDomainError::PoisonedRoot { .. })
    ));
}
