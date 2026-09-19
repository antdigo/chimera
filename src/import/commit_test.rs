use std::cell::{Cell, RefCell};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::config::{load_config_if_exists, load_runner_credentials};
use crate::import::target::{PreparedImport, prepare_import, prepare_import_locked};
use crate::import::test_support::{
    copy_fixture, fixture_path, import_official_after_lock_release, write_chimera_credentials,
};
use crate::storage::RootLock;

use super::*;

fn prepare_locked_import(source: &Path, name: &str, root: &Path) -> (RootLock, PreparedImport) {
    let initial = prepare_import(source, name, root).unwrap();
    let canonical_root = initial.canonical_root().to_path_buf();
    let lock = RootLock::acquire(&canonical_root).unwrap();
    let prepared = prepare_import_locked(
        source,
        name,
        &canonical_root,
        lock.try_clone_root().unwrap(),
    )
    .unwrap();
    (lock, prepared)
}

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

#[cfg(unix)]
fn directory_inode(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path).unwrap().ino()
}

#[cfg(unix)]
fn displace_runners(root: &Path, displaced_name: &str) -> (PathBuf, u64) {
    use std::os::unix::fs::PermissionsExt;

    let runners = root.join("runners");
    let displaced = root.join(displaced_name);
    std::fs::rename(&runners, &displaced).unwrap();
    std::fs::create_dir(&runners).unwrap();
    std::fs::set_permissions(&runners, std::fs::Permissions::from_mode(0o700)).unwrap();
    let replacement_inode = directory_inode(&runners);
    (displaced, replacement_inode)
}

fn assert_directory_empty(path: &Path) {
    assert!(std::fs::read_dir(path).unwrap().next().is_none());
}

fn credential_paths(root: &Path, name: &str) -> [PathBuf; 3] {
    let directory = root.join("runners").join(name);
    [
        directory.join("runner.json"),
        directory.join("credentials.json"),
        directory.join("rsa_params.json"),
    ]
}

#[cfg(unix)]
fn credential_snapshot(root: &Path, name: &str) -> Vec<(Vec<u8>, u64, std::time::SystemTime)> {
    credential_paths(root, name)
        .iter()
        .map(|path| snapshot(path))
        .collect()
}

fn source_bytes(source: &Path) -> Vec<Vec<u8>> {
    [".runner", ".credentials", ".credentials_rsaparams"]
        .map(|name| std::fs::read(source.join(name)).unwrap())
        .into()
}

fn change_runner_scope(root: &Path, name: &str) {
    let path = root.join("runners").join(name).join("runner.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["gitHubUrl"] = serde_json::json!("https://github.com/example/other");
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum AdoptedReplacement {
    TargetDirectory,
    CredentialFile,
}

#[cfg(unix)]
struct AdoptedReplacementState {
    target_inode: u64,
    credentials: Vec<(Vec<u8>, u64, std::time::SystemTime)>,
}

#[cfg(unix)]
fn replace_adopted_set(
    root: &Path,
    name: &str,
    replacement: AdoptedReplacement,
) -> AdoptedReplacementState {
    use std::os::unix::fs::PermissionsExt;

    let target = root.join("runners").join(name);
    match replacement {
        AdoptedReplacement::TargetDirectory => {
            std::fs::rename(&target, root.join("displaced-target")).unwrap();
            write_chimera_credentials(root, name);
        }
        AdoptedReplacement::CredentialFile => {
            let credential = target.join("credentials.json");
            let displaced = root.join("displaced-credential.json");
            std::fs::rename(&credential, &displaced).unwrap();
            std::fs::copy(&displaced, &credential).unwrap();
            std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    AdoptedReplacementState {
        target_inode: directory_inode(&target),
        credentials: credential_snapshot(root, name),
    }
}

#[cfg(unix)]
fn assert_replacement_untouched(root: &Path, name: &str, state: &AdoptedReplacementState) {
    assert_eq!(
        directory_inode(&root.join("runners").join(name)),
        state.target_inode
    );
    assert!(
        credential_snapshot(root, name) == state.credentials,
        "replacement credential set changed"
    );
}

fn import_artifacts(root: &Path) -> Vec<PathBuf> {
    let mut paths = match std::fs::read_dir(root) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                let name = path.file_name().and_then(|name| name.to_str());
                name.is_some_and(|name| {
                    name.starts_with(".import-")
                        || (name.starts_with(".config.toml.") && name.ends_with(".tmp"))
                })
            })
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("unable to inspect import artifacts: {error}"),
    };
    paths.sort();
    paths
}

fn staging_path(root: &Path) -> PathBuf {
    let mut staging: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".import-"))
        })
        .collect();
    staging.sort();
    assert_eq!(staging.len(), 1, "unexpected staging paths: {staging:?}");
    staging.pop().unwrap()
}

fn assert_runner_once(root: &Path, name: &str) {
    let config = load_config_if_exists(&root.join("config.toml"))
        .unwrap()
        .unwrap();
    assert_eq!(
        config
            .runners
            .iter()
            .filter(|configured| configured.as_str() == name)
            .count(),
        1
    );
}

fn expect_write_failed<T>(result: Result<T, ImportError>, context: &str) -> ImportError {
    let error = match result {
        Ok(_) => panic!("{context} unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.category(), "write-failed", "{context}");
    error
}

#[test]
fn durability_sync_reopens_the_pinned_directory() {
    let root = tempfile::tempdir().unwrap();
    let lock = RootLock::acquire(root.path()).unwrap();
    let pinned = lock.try_clone_root().unwrap();

    let syncable = open_syncable_directory(&pinned).unwrap();

    assert_ne!(syncable.as_raw_fd(), pinned.as_raw_fd());
    assert_eq!(
        file_identity(&syncable).unwrap(),
        file_identity(&pinned).unwrap()
    );
    syncable.sync_all().unwrap();
}

#[cfg(unix)]
#[test]
fn published_credentials_without_config_are_completed_on_retry() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    let before = credential_snapshot(root.path(), "local-runner");
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let mut checkpoints = Vec::new();

    let outcome = commit_with_checkpoint(prepared, |point| {
        checkpoints.push(point);
        Ok(())
    })
    .unwrap();

    assert_eq!(outcome.status, ImportStatus::Imported);
    assert_runner_once(root.path(), "local-runner");
    assert_eq!(credential_snapshot(root.path(), "local-runner"), before);
    assert_eq!(
        checkpoints,
        vec![
            CommitPoint::AfterConfigTempWrite,
            CommitPoint::BeforeConfigPublish,
            CommitPoint::AfterConfigPublish,
        ]
    );
    assert!(import_artifacts(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn config_update_preserves_daemon_cache_unknown_settings_and_existing_runners() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "existing");
    change_runner_scope(root.path(), "existing");
    let config_path = root.path().join("config.toml");
    std::fs::write(
        &config_path,
        concat!(
            "runners = [\"existing\"]\n",
            "[daemon]\n",
            "log_format = \"json\"\n",
            "shutdown_timeout_secs = 17\n",
            "[cache]\n",
            "max_gb = 23\n",
            "cache_port = 12345\n",
            "[future]\n",
            "enabled = true\n",
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let outcome = commit_with_checkpoint(prepared, |_| Ok(())).unwrap();

    assert_eq!(outcome.status, ImportStatus::Imported);
    let config = load_config_if_exists(&config_path).unwrap().unwrap();
    assert_eq!(config.daemon.log_format, "json");
    assert_eq!(config.daemon.shutdown_timeout_secs, 17);
    assert_eq!(config.cache.max_gb, 23);
    assert_eq!(config.cache.cache_port, 12345);
    assert_eq!(config.runners, ["existing", "local-runner"]);
    let document: toml::Table =
        toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(document["future"]["enabled"].as_bool(), Some(true));
    assert_eq!(
        std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert!(import_artifacts(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn target_created_after_prepare_is_never_replaced() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let target = root.path().join("runners/local-runner");
    let marker = target.join("marker");
    let marker_inode = Cell::new(None);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterStagingValidation {
            std::fs::create_dir(&target)?;
            std::fs::write(&marker, b"NON_COOPERATING_WRITER")?;
            marker_inode.set(Some(directory_inode(&marker)));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "identity-conflict");
    assert_eq!(std::fs::read(&marker).unwrap(), b"NON_COOPERATING_WRITER");
    assert_eq!(Some(directory_inode(&marker)), marker_inode.get());
    assert!(
        load_config_if_exists(&root.path().join("config.toml"))
            .unwrap()
            .is_none()
    );
    assert!(import_artifacts(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn every_commit_checkpoint_is_recoverable_and_preserves_invariants() {
    let checkpoints = [
        CommitPoint::BeforeCreateStaging,
        CommitPoint::AfterCreateStaging,
        CommitPoint::AfterRunnerJson,
        CommitPoint::AfterCredentialsJson,
        CommitPoint::AfterRsaJson,
        CommitPoint::AfterStagingValidation,
        CommitPoint::AfterCredentialPublish,
        CommitPoint::AfterConfigTempWrite,
        CommitPoint::BeforeConfigPublish,
        CommitPoint::AfterConfigPublish,
    ];

    for failed_point in checkpoints {
        let source = copy_fixture();
        let source_before = source_bytes(source.path());
        let root = tempfile::tempdir().unwrap();
        write_chimera_credentials(root.path(), "previous");
        change_runner_scope(root.path(), "previous");
        std::fs::write(
            root.path().join("config.toml"),
            "runners = [\"previous\"]\nmarker = \"keep\"\n",
        )
        .unwrap();
        let previous_directory = root.path().join("runners/previous");
        let previous_directory_inode = directory_inode(&previous_directory);
        let previous_before = credential_snapshot(root.path(), "previous");
        let config_before = snapshot(&root.path().join("config.toml"));
        let (lock, prepared) = prepare_locked_import(source.path(), "local-runner", root.path());

        let error = commit_with_checkpoint(prepared, |point| {
            if point == failed_point {
                Err(std::io::Error::other("SECRET_CHECKPOINT_FAILURE"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert_eq!(error.category(), "write-failed", "at {failed_point:?}");
        assert!(
            !error.to_string().contains("SECRET_CHECKPOINT_FAILURE"),
            "at {failed_point:?}: {error}"
        );
        assert!(
            import_artifacts(root.path()).is_empty(),
            "at {failed_point:?}"
        );
        assert_eq!(
            source_bytes(source.path()),
            source_before,
            "at {failed_point:?}"
        );
        assert_eq!(
            directory_inode(&previous_directory),
            previous_directory_inode,
            "at {failed_point:?}"
        );
        assert_eq!(
            credential_snapshot(root.path(), "previous"),
            previous_before,
            "at {failed_point:?}"
        );

        let published = matches!(
            failed_point,
            CommitPoint::AfterCredentialPublish
                | CommitPoint::AfterConfigTempWrite
                | CommitPoint::BeforeConfigPublish
                | CommitPoint::AfterConfigPublish
        );
        let config_published = failed_point == CommitPoint::AfterConfigPublish;
        let target = root.path().join("runners/local-runner");
        let published_before_retry = if published {
            assert!(target.is_dir(), "at {failed_point:?}");
            assert_eq!(
                load_runner_credentials(&root.path().join("runners"), "local-runner").unwrap(),
                crate::import::test_support::fixture_credentials(),
                "at {failed_point:?}"
            );
            Some((
                directory_inode(&target),
                credential_snapshot(root.path(), "local-runner"),
            ))
        } else {
            assert!(!target.exists(), "at {failed_point:?}");
            None
        };

        let config_after_error = if config_published {
            assert_runner_once(root.path(), "local-runner");
            Some(snapshot(&root.path().join("config.toml")))
        } else {
            assert_eq!(
                snapshot(&root.path().join("config.toml")),
                config_before,
                "at {failed_point:?}"
            );
            let config = load_config_if_exists(&root.path().join("config.toml"))
                .unwrap()
                .unwrap();
            assert!(!config.runners.iter().any(|name| name == "local-runner"));
            None
        };

        drop(lock);
        let retry =
            import_official_after_lock_release(source.path(), "local-runner", root.path()).unwrap();

        assert_eq!(
            retry.status,
            if config_published {
                ImportStatus::AlreadyImported
            } else {
                ImportStatus::Imported
            },
            "at {failed_point:?}"
        );
        assert_runner_once(root.path(), "local-runner");
        assert!(
            import_artifacts(root.path()).is_empty(),
            "at {failed_point:?}"
        );
        assert_eq!(
            source_bytes(source.path()),
            source_before,
            "at {failed_point:?}"
        );
        assert_eq!(
            directory_inode(&previous_directory),
            previous_directory_inode,
            "at {failed_point:?}"
        );
        assert_eq!(
            credential_snapshot(root.path(), "previous"),
            previous_before,
            "at {failed_point:?}"
        );
        if let Some((target_inode, credentials)) = published_before_retry {
            assert_eq!(
                directory_inode(&target),
                target_inode,
                "at {failed_point:?}"
            );
            assert_eq!(
                credential_snapshot(root.path(), "local-runner"),
                credentials,
                "at {failed_point:?}"
            );
        }
        if let Some(config_after_error) = config_after_error {
            assert_eq!(
                snapshot(&root.path().join("config.toml")),
                config_after_error,
                "at {failed_point:?}"
            );
        }
    }
}

#[test]
fn config_cleanup_does_not_delete_a_new_file_after_publish() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let temp_path = RefCell::new(None::<PathBuf>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterConfigTempWrite {
            let path = import_artifacts(root.path())
                .into_iter()
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".config.toml."))
                })
                .ok_or_else(|| std::io::Error::other("config temp path is missing"))?;
            temp_path.replace(Some(path));
        } else if point == CommitPoint::AfterConfigPublish {
            let path = temp_path
                .borrow()
                .clone()
                .ok_or_else(|| std::io::Error::other("config temp path was not recorded"))?;
            assert!(!path.exists());
            std::fs::write(path, b"NON_COOPERATING_WRITER")?;
            return Err(std::io::Error::other(
                "injected failure after config publish",
            ));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let replacement = temp_path.borrow().clone().unwrap();
    assert_eq!(
        std::fs::read(replacement).unwrap(),
        b"NON_COOPERATING_WRITER"
    );
    assert_runner_once(root.path(), "local-runner");
}

#[cfg(unix)]
#[test]
fn new_import_uses_exact_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");

    let outcome =
        crate::import::import_official(&fixture_path(), "local-runner", &root, false).unwrap();

    assert_eq!(outcome.status, ImportStatus::Imported);
    for (path, mode) in [
        (root.clone(), 0o700),
        (root.join("runners"), 0o700),
        (root.join("runners/local-runner"), 0o700),
        (root.join(".chimera.lock"), 0o600),
        (root.join("config.toml"), 0o600),
        (root.join("runners/local-runner/runner.json"), 0o600),
        (root.join("runners/local-runner/credentials.json"), 0o600),
        (root.join("runners/local-runner/rsa_params.json"), 0o600),
    ] {
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            mode,
            "unexpected mode for {}",
            path.display()
        );
    }
}

#[test]
fn stock_loader_rejects_staging_tampering_before_publish() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterRsaJson {
            let staging = staging_path(root.path());
            let credentials_path = staging.join("credentials.json");
            let mut credentials: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&credentials_path).map_err(std::io::Error::other)?,
            )
            .map_err(std::io::Error::other)?;
            credentials["clientId"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
            std::fs::write(
                credentials_path,
                serde_json::to_vec_pretty(&credentials).map_err(std::io::Error::other)?,
            )?;
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    assert!(!root.path().join("runners/local-runner").exists());
    assert!(import_artifacts(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn group_or_world_writable_runners_directory_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let runners = root.path().join("runners");
    std::fs::create_dir(&runners).unwrap();
    std::fs::set_permissions(&runners, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let error = commit_with_checkpoint(prepared, |_| Ok(())).unwrap_err();

    assert_eq!(error.category(), "write-failed");
    assert!(!runners.join("local-runner").exists());
    assert!(
        load_config_if_exists(&root.path().join("config.toml"))
            .unwrap()
            .is_none()
    );
    assert!(import_artifacts(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn displaced_runners_after_staging_validation_prevents_credential_publish() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let displaced = RefCell::new(None::<(PathBuf, u64)>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterStagingValidation {
            displaced.replace(Some(displace_runners(
                root.path(),
                "displaced-runners-after-validation",
            )));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let (displaced_path, replacement_inode) = displaced.borrow().clone().unwrap();
    assert_directory_empty(&root.path().join("runners"));
    assert_directory_empty(&displaced_path);
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert!(!root.path().join("config.toml").exists());
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::Imported);
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert_runner_once(root.path(), "local-runner");
}

#[cfg(unix)]
#[test]
fn displaced_runners_after_credential_publish_prevents_config_publish() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let displaced = RefCell::new(None::<(PathBuf, u64)>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterCredentialPublish {
            displaced.replace(Some(displace_runners(
                root.path(),
                "displaced-runners-after-publish",
            )));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let (displaced_path, replacement_inode) = displaced.borrow().clone().unwrap();
    assert_directory_empty(&root.path().join("runners"));
    assert!(displaced_path.join("local-runner/runner.json").is_file());
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert!(!root.path().join("config.toml").exists());
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::Imported);
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert_runner_once(root.path(), "local-runner");
}

#[cfg(unix)]
#[test]
fn displaced_runners_before_resume_config_publish_prevents_config_publish() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let displaced = RefCell::new(None::<(PathBuf, u64)>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::BeforeConfigPublish {
            displaced.replace(Some(displace_runners(
                root.path(),
                "displaced-runners-before-config",
            )));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let (displaced_path, replacement_inode) = displaced.borrow().clone().unwrap();
    assert_directory_empty(&root.path().join("runners"));
    assert!(load_runner_credentials(&displaced_path, "local-runner").is_ok());
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert!(!root.path().join("config.toml").exists());
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::Imported);
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert_runner_once(root.path(), "local-runner");
}

#[cfg(unix)]
#[test]
fn displaced_runners_after_resume_config_publish_returns_write_failed() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let displaced = RefCell::new(None::<(PathBuf, u64)>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterConfigPublish {
            displaced.replace(Some(displace_runners(
                root.path(),
                "displaced-runners-after-config",
            )));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let (displaced_path, replacement_inode) = displaced.borrow().clone().unwrap();
    assert_directory_empty(&root.path().join("runners"));
    assert!(load_runner_credentials(&displaced_path, "local-runner").is_ok());
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert_runner_once(root.path(), "local-runner");
    assert!(import_artifacts(root.path()).is_empty());
}

#[test]
fn replaced_staging_is_neither_published_nor_deleted() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let replacement_path = RefCell::new(None::<PathBuf>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterStagingValidation {
            let staging = staging_path(root.path());
            std::fs::rename(&staging, root.path().join("displaced-staging"))?;
            std::fs::create_dir(&staging)?;
            std::fs::write(staging.join("marker"), b"REPLACEMENT_STAGING")?;
            replacement_path.replace(Some(staging));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let replacement = replacement_path.borrow().clone().unwrap();
    assert_eq!(
        std::fs::read(replacement.join("marker")).unwrap(),
        b"REPLACEMENT_STAGING"
    );
    assert!(!root.path().join("runners/local-runner").exists());
    assert!(
        load_config_if_exists(&root.path().join("config.toml"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn staging_cleanup_does_not_delete_a_replacement() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let replacement_path = RefCell::new(None::<PathBuf>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterRunnerJson {
            let staging = staging_path(root.path());
            std::fs::rename(&staging, root.path().join("displaced-staging"))?;
            std::fs::create_dir(&staging)?;
            std::fs::write(staging.join("marker"), b"REPLACEMENT_STAGING")?;
            replacement_path.replace(Some(staging));
            return Err(std::io::Error::other("injected staging failure"));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let replacement = replacement_path.borrow().clone().unwrap();
    assert_eq!(
        std::fs::read(replacement.join("marker")).unwrap(),
        b"REPLACEMENT_STAGING"
    );
}

#[cfg(unix)]
#[test]
fn staging_cleanup_preserves_every_entry_when_a_tracked_leaf_is_replaced() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let replacement = RefCell::new(None::<(PathBuf, u64)>);

    let result = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterRunnerJson {
            let staging = staging_path(root.path());
            let runner = staging.join("runner.json");
            std::fs::rename(&runner, root.path().join("displaced-runner.json"))?;
            std::fs::write(&runner, b"REPLACEMENT_RUNNER_JSON")?;
            replacement.replace(Some((staging, directory_inode(&runner))));
            return Err(std::io::Error::other("injected staging interruption"));
        }
        Ok(())
    });
    expect_write_failed(result, "staging leaf replacement");

    let state = replacement.borrow();
    let (staging, replacement_inode) = state.as_ref().unwrap();
    assert!(staging.is_dir());
    let runner = staging.join("runner.json");
    assert!(runner.is_file());
    assert_eq!(directory_inode(&runner), *replacement_inode);
    assert!(std::fs::read(&runner).unwrap() == b"REPLACEMENT_RUNNER_JSON");
    assert!(root.path().join("displaced-runner.json").is_file());
}

#[test]
fn post_create_staging_write_failure_cleans_partial_credentials() {
    struct FailingSerialize;

    impl serde::Serialize for FailingSerialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(2))?;
            serde::ser::SerializeMap::serialize_entry(&mut map, "partial", &true)?;
            Err(serde::ser::Error::custom(
                "injected staging serialization failure",
            ))
        }
    }

    let root = tempfile::tempdir().unwrap();
    let lock = RootLock::acquire(root.path()).unwrap();
    let root_file = lock.try_clone_root().unwrap();
    let staging_name = path_component(OsStr::new(".import-partial-write")).unwrap();
    let (staging, _, mut staging_cleanup) =
        create_staging_directory(&root_file, &staging_name).unwrap();

    let result = write_private_json_at(
        &staging,
        &mut staging_cleanup,
        CREDENTIAL_FILES[0],
        &FailingSerialize,
    );
    assert!(
        result.is_err(),
        "injected staging write unexpectedly succeeded"
    );
    drop(staging);
    drop(staging_cleanup);

    assert!(import_artifacts(root.path()).is_empty());
    assert!(!root.path().join("config.toml").exists());
    assert!(!root.path().join("runners/local-runner").exists());
}

#[test]
fn replaced_config_temp_is_neither_published_nor_deleted() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let replacement_path = RefCell::new(None::<PathBuf>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterConfigTempWrite {
            let temp = import_artifacts(root.path())
                .into_iter()
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".config.toml."))
                })
                .ok_or_else(|| std::io::Error::other("config temp is missing"))?;
            std::fs::rename(&temp, root.path().join("displaced-config-temp"))?;
            std::fs::write(&temp, b"REPLACEMENT_CONFIG_TEMP")?;
            replacement_path.replace(Some(temp));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let replacement = replacement_path.borrow().clone().unwrap();
    assert_eq!(
        std::fs::read(replacement).unwrap(),
        b"REPLACEMENT_CONFIG_TEMP"
    );
    assert!(!root.path().join("config.toml").exists());
}

#[test]
fn config_temp_cleanup_does_not_delete_a_replacement_before_publish() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let replacement_path = RefCell::new(None::<PathBuf>);

    let error = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::AfterConfigTempWrite {
            let temp = import_artifacts(root.path())
                .into_iter()
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".config.toml."))
                })
                .ok_or_else(|| std::io::Error::other("config temp is missing"))?;
            std::fs::rename(&temp, root.path().join("displaced-config-temp"))?;
            std::fs::write(&temp, b"REPLACEMENT_CONFIG_TEMP")?;
            replacement_path.replace(Some(temp));
            return Err(std::io::Error::other("injected config failure"));
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let replacement = replacement_path.borrow().clone().unwrap();
    assert_eq!(
        std::fs::read(replacement).unwrap(),
        b"REPLACEMENT_CONFIG_TEMP"
    );
}

#[cfg(unix)]
#[test]
fn mutated_config_temp_is_not_published_when_config_was_missing() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let result = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::BeforeConfigPublish {
            let temp = import_artifacts(root.path())
                .into_iter()
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".config.toml."))
                })
                .ok_or_else(|| std::io::Error::other("config temp is missing"))?;
            let inode = directory_inode(&temp);
            std::fs::write(&temp, b"SENSITIVE_CONFIG_TEMP_CONTENT")?;
            assert_eq!(directory_inode(&temp), inode);
        }
        Ok(())
    });
    let error = expect_write_failed(result, "same-inode config temp content mutation");

    assert!(!root.path().join("config.toml").exists());
    assert!(matches!(
        error,
        ImportError::WriteFailed(ref message)
            if message == "config temp file changed before publish"
                && !message.contains("SENSITIVE_CONFIG_TEMP_CONTENT")
    ));
}

#[cfg(unix)]
#[test]
fn mutated_config_temp_mode_does_not_replace_existing_config() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, "runners = []\nmarker = \"original\"\n").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let original = snapshot(&config_path);
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let result = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::BeforeConfigPublish {
            let temp = import_artifacts(root.path())
                .into_iter()
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".config.toml."))
                })
                .ok_or_else(|| std::io::Error::other("config temp is missing"))?;
            let inode = directory_inode(&temp);
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
            assert_eq!(directory_inode(&temp), inode);
        }
        Ok(())
    });
    let error = expect_write_failed(result, "same-inode config temp mode mutation");

    assert!(snapshot(&config_path) == original);
    assert!(matches!(
        error,
        ImportError::WriteFailed(ref message) if message == "config temp file changed before publish"
    ));
}

#[cfg(unix)]
#[test]
fn failed_runners_durability_barrier_recovers_without_rewriting_credentials() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::Runners {
                Err(std::io::Error::other("injected runners sync failure"))
            } else {
                directory.sync_all()
            }
        },
    )
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let before = credential_snapshot(root.path(), "local-runner");
    assert!(
        load_config_if_exists(&root.path().join("config.toml"))
            .unwrap()
            .is_none()
    );
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::Imported);
    assert_eq!(credential_snapshot(root.path(), "local-runner"), before);
}

#[cfg(unix)]
#[test]
fn failed_root_durability_barrier_recovers_without_rewriting_state() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let reached_root_final = Cell::new(false);

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::RootFinal {
                reached_root_final.set(true);
                Err(std::io::Error::other("injected root sync failure"))
            } else {
                open_syncable_directory(directory)?.sync_all()
            }
        },
    )
    .unwrap_err();

    assert!(reached_root_final.get(), "RootFinal was not reached");
    assert_eq!(error.category(), "write-failed");
    let credentials_before = credential_snapshot(root.path(), "local-runner");
    let config_before = snapshot(&root.path().join("config.toml"));
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::AlreadyImported);
    assert_eq!(
        credential_snapshot(root.path(), "local-runner"),
        credentials_before
    );
    assert_eq!(snapshot(&root.path().join("config.toml")), config_before);
}

#[cfg(unix)]
#[test]
fn displaced_runners_during_new_root_durability_returns_write_failed() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let displaced = RefCell::new(None::<(PathBuf, u64)>);

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            open_syncable_directory(directory)?.sync_all()?;
            if point == DurabilityPoint::RootFinal {
                displaced.replace(Some(displace_runners(
                    root.path(),
                    "displaced-runners-during-root-sync",
                )));
            }
            Ok(())
        },
    )
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let (displaced_path, replacement_inode) = displaced.borrow().clone().unwrap();
    assert_directory_empty(&root.path().join("runners"));
    assert!(load_runner_credentials(&displaced_path, "local-runner").is_ok());
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert_runner_once(root.path(), "local-runner");
    assert!(import_artifacts(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn resume_requires_runners_durability_before_config_publish() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    let before = credential_snapshot(root.path(), "local-runner");
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::Runners {
                Err(std::io::Error::other("injected runners sync failure"))
            } else {
                directory.sync_all()
            }
        },
    )
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    assert_eq!(credential_snapshot(root.path(), "local-runner"), before);
    assert!(!root.path().join("config.toml").exists());
}

#[cfg(unix)]
#[test]
fn already_imported_requires_root_durability_without_rewriting_state() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    std::fs::write(
        root.path().join("config.toml"),
        "runners = [\"local-runner\"]\n",
    )
    .unwrap();
    let credentials_before = credential_snapshot(root.path(), "local-runner");
    let config_before = snapshot(&root.path().join("config.toml"));
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::RootFinal {
                Err(std::io::Error::other("injected root sync failure"))
            } else {
                directory.sync_all()
            }
        },
    )
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    assert_eq!(
        credential_snapshot(root.path(), "local-runner"),
        credentials_before
    );
    assert_eq!(snapshot(&root.path().join("config.toml")), config_before);
}

#[cfg(unix)]
#[test]
fn already_imported_revalidates_runners_after_root_durability() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, "runners = [\"local-runner\"]\n").unwrap();
    let config_before = snapshot(&config_path);
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let displaced = RefCell::new(None::<(PathBuf, u64)>);

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            open_syncable_directory(directory)?.sync_all()?;
            if point == DurabilityPoint::RootFinal {
                displaced.replace(Some(displace_runners(
                    root.path(),
                    "displaced-runners-already-imported",
                )));
            }
            Ok(())
        },
    )
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let (displaced_path, replacement_inode) = displaced.borrow().clone().unwrap();
    assert_directory_empty(&root.path().join("runners"));
    assert!(load_runner_credentials(&displaced_path, "local-runner").is_ok());
    assert_eq!(
        directory_inode(&root.path().join("runners")),
        replacement_inode
    );
    assert_eq!(snapshot(&config_path), config_before);
}

#[cfg(unix)]
#[test]
fn new_import_rejects_replaced_target_directory_and_credential_child() {
    for replacement in [
        AdoptedReplacement::TargetDirectory,
        AdoptedReplacement::CredentialFile,
    ] {
        let root = tempfile::tempdir().unwrap();
        let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
        let replacement_state = RefCell::new(None::<AdoptedReplacementState>);

        let result = commit_with_checkpoint(prepared, |point| {
            if point == CommitPoint::AfterCredentialPublish {
                replacement_state.replace(Some(replace_adopted_set(
                    root.path(),
                    "local-runner",
                    replacement,
                )));
            }
            Ok(())
        });
        expect_write_failed(result, "new import with replaced credential set");

        let state = replacement_state.borrow();
        assert_replacement_untouched(root.path(), "local-runner", state.as_ref().unwrap());
        assert!(!root.path().join("config.toml").exists());
    }
}

#[cfg(unix)]
#[test]
fn resumed_import_rejects_replaced_target_directory_and_credential_child() {
    for replacement in [
        AdoptedReplacement::TargetDirectory,
        AdoptedReplacement::CredentialFile,
    ] {
        let root = tempfile::tempdir().unwrap();
        write_chimera_credentials(root.path(), "local-runner");
        let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
        let replacement_state = RefCell::new(None::<AdoptedReplacementState>);

        let result = commit_with_checkpoint(prepared, |point| {
            if point == CommitPoint::BeforeConfigPublish {
                replacement_state.replace(Some(replace_adopted_set(
                    root.path(),
                    "local-runner",
                    replacement,
                )));
            }
            Ok(())
        });
        expect_write_failed(result, "resumed import with replaced credential set");

        let state = replacement_state.borrow();
        assert_replacement_untouched(root.path(), "local-runner", state.as_ref().unwrap());
        assert!(!root.path().join("config.toml").exists());
    }
}

#[cfg(unix)]
#[test]
fn already_imported_rejects_replaced_target_directory_and_credential_child() {
    for replacement in [
        AdoptedReplacement::TargetDirectory,
        AdoptedReplacement::CredentialFile,
    ] {
        let root = tempfile::tempdir().unwrap();
        write_chimera_credentials(root.path(), "local-runner");
        let config_path = root.path().join("config.toml");
        std::fs::write(&config_path, "runners = [\"local-runner\"]\n").unwrap();
        let config_before = snapshot(&config_path);
        let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
        let replacement_state = RefCell::new(None::<AdoptedReplacementState>);

        let result = commit_with_checkpoint_and_sync(
            prepared,
            |_| Ok(()),
            |point, directory| {
                open_syncable_directory(directory)?.sync_all()?;
                if point == DurabilityPoint::RootFinal {
                    replacement_state.replace(Some(replace_adopted_set(
                        root.path(),
                        "local-runner",
                        replacement,
                    )));
                }
                Ok(())
            },
        );
        expect_write_failed(result, "already imported with replaced credential set");

        let state = replacement_state.borrow();
        assert_replacement_untouched(root.path(), "local-runner", state.as_ref().unwrap());
        assert!(snapshot(&config_path) == config_before);
    }
}

#[test]
fn expected_missing_config_that_appears_is_not_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let replacement = RefCell::new(None);

    let result = commit_with_checkpoint(prepared, |point| {
        if point == CommitPoint::BeforeConfigPublish {
            let config_path = root.path().join("config.toml");
            std::fs::write(&config_path, "runners = []\nmarker = \"replacement\"\n")?;
            replacement.replace(Some(snapshot(&config_path)));
        }
        Ok(())
    });
    expect_write_failed(result, "expected-missing config appeared");

    let current = snapshot(&root.path().join("config.toml"));
    assert!(Some(current) == *replacement.borrow());
}

#[derive(Debug, Clone, Copy)]
enum ExistingConfigChange {
    Replaced,
    MutatedInPlace,
    Removed,
}

#[test]
fn changed_existing_config_is_not_overwritten() {
    for change in [
        ExistingConfigChange::Replaced,
        ExistingConfigChange::MutatedInPlace,
        ExistingConfigChange::Removed,
    ] {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        std::fs::write(&config_path, "runners = []\nmarker = \"original\"\n").unwrap();
        let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
        let changed_snapshot = RefCell::new(None);

        let result = commit_with_checkpoint(prepared, |point| {
            if point == CommitPoint::BeforeConfigPublish {
                match change {
                    ExistingConfigChange::Replaced => {
                        std::fs::rename(&config_path, root.path().join("displaced-config"))?;
                        std::fs::write(&config_path, "runners = []\nmarker = \"replacement\"\n")?;
                        changed_snapshot.replace(Some(snapshot(&config_path)));
                    }
                    ExistingConfigChange::MutatedInPlace => {
                        std::fs::write(&config_path, "runners = []\nmarker = \"mutated\"\n")?;
                        changed_snapshot.replace(Some(snapshot(&config_path)));
                    }
                    ExistingConfigChange::Removed => {
                        std::fs::remove_file(&config_path)?;
                    }
                }
            }
            Ok(())
        });
        expect_write_failed(result, "changed existing config");

        match *changed_snapshot.borrow() {
            Some(ref expected) => assert!(snapshot(&config_path) == *expected),
            None => assert!(!config_path.exists()),
        }
    }
}

#[test]
fn already_imported_revalidates_config_before_success() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local-runner");
    let config_path = root.path().join("config.toml");
    std::fs::write(
        &config_path,
        "runners = [\"local-runner\"]\nmarker = \"original\"\n",
    )
    .unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let changed = RefCell::new(None);

    let result = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            open_syncable_directory(directory)?.sync_all()?;
            if point == DurabilityPoint::RootFinal {
                std::fs::write(
                    &config_path,
                    "runners = [\"local-runner\"]\nmarker = \"mutated\"\n",
                )?;
                changed.replace(Some(snapshot(&config_path)));
            }
            Ok(())
        },
    );
    expect_write_failed(result, "already imported with changed config");

    assert!(Some(snapshot(&config_path)) == *changed.borrow());
}

#[cfg(unix)]
#[test]
fn pre_config_root_durability_failure_prevents_config_and_retry_recovers() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let root_syncs = Cell::new(0usize);

    let result = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::RootBeforeConfig {
                root_syncs.set(root_syncs.get() + 1);
                return Err(std::io::Error::other(
                    "injected pre-config root sync failure",
                ));
            }
            open_syncable_directory(directory)?.sync_all()
        },
    );
    expect_write_failed(result, "pre-config root durability failure");

    assert_eq!(root_syncs.get(), 1);
    assert!(!root.path().join("config.toml").exists());
    let credentials_before = credential_snapshot(root.path(), "local-runner");
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::Imported);
    assert!(credential_snapshot(root.path(), "local-runner") == credentials_before);
}

#[cfg(unix)]
#[test]
fn final_root_durability_failure_happens_after_config_publication() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
    let root_syncs = Cell::new(0usize);

    let result = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::RootFinal {
                root_syncs.set(root_syncs.get() + 1);
                return Err(std::io::Error::other("injected final root sync failure"));
            }
            open_syncable_directory(directory)?.sync_all()
        },
    );
    expect_write_failed(result, "final root durability failure");

    assert_eq!(root_syncs.get(), 1);
    assert_runner_once(root.path(), "local-runner");
    let config_before = snapshot(&root.path().join("config.toml"));
    let credentials_before = credential_snapshot(root.path(), "local-runner");
    drop(lock);

    let retry =
        import_official_after_lock_release(&fixture_path(), "local-runner", root.path()).unwrap();

    assert_eq!(retry.status, ImportStatus::AlreadyImported);
    assert!(snapshot(&root.path().join("config.toml")) == config_before);
    assert!(credential_snapshot(root.path(), "local-runner") == credentials_before);
}

#[test]
fn new_and_resume_order_both_root_durability_barriers_around_config() {
    for resume in [false, true] {
        let root = tempfile::tempdir().unwrap();
        if resume {
            write_chimera_credentials(root.path(), "local-runner");
        }
        let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());
        let points = RefCell::new(Vec::new());

        commit_with_checkpoint_and_sync(
            prepared,
            |_| Ok(()),
            |point, directory| {
                points.borrow_mut().push(point);
                open_syncable_directory(directory)?.sync_all()
            },
        )
        .unwrap();

        assert_eq!(
            *points.borrow(),
            [
                DurabilityPoint::Runners,
                DurabilityPoint::RootBeforeConfig,
                DurabilityPoint::RootFinal,
            ]
        );
    }
}

#[cfg(unix)]
#[test]
fn visible_root_replaced_during_final_durability_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", &root);
    let displaced = parent.path().join("displaced-root");
    let replacement_marker = RefCell::new(None);

    let result = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            open_syncable_directory(directory)?.sync_all()?;
            if point == DurabilityPoint::RootFinal {
                std::fs::rename(&root, &displaced)?;
                std::fs::create_dir(&root)?;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
                let marker = root.join("marker");
                std::fs::write(&marker, b"replacement-root")?;
                replacement_marker.replace(Some(snapshot(&marker)));
            }
            Ok(())
        },
    );
    expect_write_failed(result, "visible root replaced during final durability");

    let marker = root.join("marker");
    assert!(Some(snapshot(&marker)) == *replacement_marker.borrow());
    assert!(!root.join("config.toml").exists());
    assert_runner_once(&displaced, "local-runner");
}
