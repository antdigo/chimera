use std::cell::{Cell, RefCell};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::config::{load_config_if_exists, load_runner_credentials};
use crate::import::target::{PreparedImport, prepare_import, prepare_import_locked};
use crate::import::test_support::{copy_fixture, fixture_path, write_chimera_credentials};
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
            crate::import::import_official(source.path(), "local-runner", root.path(), false)
                .unwrap();

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

    let retry = crate::import::import_official(&fixture_path(), "local-runner", root.path(), false)
        .unwrap();

    assert_eq!(retry.status, ImportStatus::Imported);
    assert_eq!(credential_snapshot(root.path(), "local-runner"), before);
}

#[cfg(unix)]
#[test]
fn failed_root_durability_barrier_recovers_without_rewriting_state() {
    let root = tempfile::tempdir().unwrap();
    let (lock, prepared) = prepare_locked_import(&fixture_path(), "local-runner", root.path());

    let error = commit_with_checkpoint_and_sync(
        prepared,
        |_| Ok(()),
        |point, directory| {
            if point == DurabilityPoint::Root {
                Err(std::io::Error::other("injected root sync failure"))
            } else {
                directory.sync_all()
            }
        },
    )
    .unwrap_err();

    assert_eq!(error.category(), "write-failed");
    let credentials_before = credential_snapshot(root.path(), "local-runner");
    let config_before = snapshot(&root.path().join("config.toml"));
    drop(lock);

    let retry = crate::import::import_official(&fixture_path(), "local-runner", root.path(), false)
        .unwrap();

    assert_eq!(retry.status, ImportStatus::AlreadyImported);
    assert_eq!(
        credential_snapshot(root.path(), "local-runner"),
        credentials_before
    );
    assert_eq!(snapshot(&root.path().join("config.toml")), config_before);
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
            if point == DurabilityPoint::Root {
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
