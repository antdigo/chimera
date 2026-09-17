use std::path::Path;

use crate::config::{load_config, load_config_if_exists};
use crate::import::test_support::{copy_fixture, fixture_path};
use crate::storage::{RootLock, RootLockError};

use super::*;

#[cfg(unix)]
fn snapshot(path: &Path) -> (Vec<u8>, u64, std::time::SystemTime) {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).unwrap();
    (
        std::fs::read(path).unwrap(),
        metadata.ino(),
        metadata.modified().unwrap(),
    )
}

fn source_bytes(source: &Path) -> Vec<Vec<u8>> {
    [".runner", ".credentials", ".credentials_rsaparams"]
        .map(|name| std::fs::read(source.join(name)).unwrap())
        .into()
}

#[test]
fn dry_run_returns_eligible_without_creating_missing_root() {
    let root_parent = tempfile::tempdir().unwrap();
    let root = root_parent.path().join("missing-root");

    let outcome = import_official(&fixture_path(), "local-runner", &root, true).unwrap();

    assert_eq!(outcome.status, ImportStatus::Eligible);
    assert_eq!(outcome.local_name, "local-runner");
    assert_eq!(outcome.agent_id, 42);
    assert!(!root.exists());
    assert_eq!(
        outcome.to_string(),
        "eligible: local-name=local-runner, agent-id=42; offline validation only"
    );
}

#[cfg(unix)]
#[test]
fn dry_run_does_not_create_lock_or_rewrite_existing_config() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, "runners = []\nmarker = \"keep\"\n").unwrap();
    let config_before = snapshot(&config_path);

    let outcome = import_official(&fixture_path(), "local-runner", root.path(), true).unwrap();

    assert_eq!(outcome.status, ImportStatus::Eligible);
    assert_eq!(snapshot(&config_path), config_before);
    assert!(!root.path().join(".chimera.lock").exists());
    assert!(!root.path().join("runners/local-runner").exists());
}

#[cfg(unix)]
#[test]
fn import_then_repeat_is_noop_without_rewriting_credentials_or_config() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let first = import_official(&fixture_path(), "local-runner", &root, false).unwrap();
    assert_eq!(first.status, ImportStatus::Imported);
    assert_eq!(
        first.to_string(),
        "imported: local-name=local-runner, agent-id=42; offline validation only"
    );

    let paths = [
        root.join("config.toml"),
        root.join("runners/local-runner/runner.json"),
        root.join("runners/local-runner/credentials.json"),
        root.join("runners/local-runner/rsa_params.json"),
    ];
    let before: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();

    let second = import_official(&fixture_path(), "local-runner", &root, false).unwrap();
    let after: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();

    assert_eq!(second.status, ImportStatus::AlreadyImported);
    assert_eq!(before, after);
    let config = load_config(&root.join("config.toml")).unwrap();
    assert_eq!(config.runners, vec!["local-runner".to_string()]);
}

#[test]
fn busy_root_returns_target_busy_without_changes() {
    let source = copy_fixture();
    let source_before = source_bytes(source.path());
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, "runners = []\nmarker = \"keep\"\n").unwrap();
    let config_before = std::fs::read(&config_path).unwrap();
    let lock = RootLock::acquire(root.path()).unwrap();

    let error = import_official(source.path(), "local-runner", root.path(), false).unwrap_err();

    assert_eq!(error.category(), "target-busy");
    assert_eq!(
        error.to_string(),
        "target-busy: chimera root is locked by another writer"
    );
    assert_eq!(std::fs::read(config_path).unwrap(), config_before);
    assert_eq!(source_bytes(source.path()), source_before);
    assert!(!root.path().join("runners/local-runner").exists());
    drop(lock);
}

#[test]
fn invalid_source_apply_does_not_create_root_or_lock() {
    let source_parent = tempfile::tempdir().unwrap();
    let missing_source = source_parent.path().join("missing-source");
    let root_parent = tempfile::tempdir().unwrap();
    let root = root_parent.path().join("missing-root");

    let error = import_official(&missing_source, "local-runner", &root, false).unwrap_err();

    assert_eq!(error.category(), "invalid-source");
    assert!(!root.exists());
}

#[test]
fn root_lock_errors_are_mapped_to_safe_categories() {
    let busy = map_root_lock_error(RootLockError::Busy);
    assert_eq!(busy.category(), "target-busy");
    assert_eq!(
        busy.to_string(),
        "target-busy: chimera root is locked by another writer"
    );

    let unsafe_root = map_root_lock_error(RootLockError::UnsafeRoot(
        "SECRET_UNSAFE_ROOT_DETAIL".into(),
    ));
    let io = map_root_lock_error(RootLockError::Io(std::io::Error::other("SECRET_IO_DETAIL")));

    for error in [unsafe_root, io] {
        assert_eq!(error.category(), "write-failed");
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains("SECRET_UNSAFE_ROOT_DETAIL"));
        assert!(!diagnostic.contains("SECRET_IO_DETAIL"));
    }
}

#[test]
fn status_strings_are_stable() {
    assert_eq!(ImportStatus::Eligible.as_str(), "eligible");
    assert_eq!(ImportStatus::Imported.as_str(), "imported");
    assert_eq!(ImportStatus::AlreadyImported.as_str(), "already-imported");
}

#[test]
fn missing_config_remains_missing_during_read_only_gate() {
    let root = tempfile::tempdir().unwrap();

    let outcome = import_official(&fixture_path(), "local-runner", root.path(), true).unwrap();

    assert_eq!(outcome.status, ImportStatus::Eligible);
    assert!(
        load_config_if_exists(&root.path().join("config.toml"))
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn locked_apply_remains_anchored_when_root_path_is_replaced() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let initial = target::prepare_import(&fixture_path(), "local-runner", &root).unwrap();
    let canonical_root = initial.canonical_root().to_path_buf();
    let lock = RootLock::acquire(&canonical_root).unwrap();
    let locked_root = lock.try_clone_root().unwrap();
    let displaced = parent.path().join("locked-root");
    std::fs::rename(&root, &displaced).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("marker"), b"REPLACEMENT_ROOT").unwrap();
    let prepared = target::prepare_import_locked(
        &fixture_path(),
        "local-runner",
        &canonical_root,
        locked_root,
    )
    .unwrap();

    let outcome = commit::commit(prepared).unwrap();

    assert_eq!(outcome.status, ImportStatus::Imported);
    assert_eq!(
        load_config(&displaced.join("config.toml")).unwrap().runners,
        ["local-runner"]
    );
    assert!(displaced.join("runners/local-runner/runner.json").is_file());
    assert_eq!(
        std::fs::read(root.join("marker")).unwrap(),
        b"REPLACEMENT_ROOT"
    );
    assert!(!root.join("config.toml").exists());
    assert!(!root.join("runners").exists());
    drop(lock);
}

#[cfg(unix)]
#[test]
fn resume_rejects_unsafe_runners_without_mutating_state() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    crate::import::test_support::write_chimera_credentials(root.path(), "local-runner");
    let credential_paths = [
        root.path().join("runners/local-runner/runner.json"),
        root.path().join("runners/local-runner/credentials.json"),
        root.path().join("runners/local-runner/rsa_params.json"),
    ];
    let before: Vec<_> = credential_paths.iter().map(|path| snapshot(path)).collect();
    std::fs::set_permissions(
        root.path().join("runners"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    let error = import_official(&fixture_path(), "local-runner", root.path(), false).unwrap_err();

    assert_eq!(error.category(), "write-failed");
    assert!(!root.path().join("config.toml").exists());
    let after: Vec<_> = credential_paths.iter().map(|path| snapshot(path)).collect();
    assert_eq!(after, before);
}

#[cfg(unix)]
#[test]
fn already_imported_rejects_unsafe_runners_without_mutating_state() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    crate::import::test_support::write_chimera_credentials(root.path(), "local-runner");
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, "runners = [\"local-runner\"]\n").unwrap();
    let paths = [
        config_path,
        root.path().join("runners/local-runner/runner.json"),
        root.path().join("runners/local-runner/credentials.json"),
        root.path().join("runners/local-runner/rsa_params.json"),
    ];
    let before: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();
    std::fs::set_permissions(
        root.path().join("runners"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    let error = import_official(&fixture_path(), "local-runner", root.path(), false).unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let after: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();
    assert_eq!(after, before);
}
