use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::import::test_support::{
    copy_fixture, fixture_credentials, fixture_path, mutate_json, write_chimera_credentials,
};

use super::*;

#[derive(Debug, PartialEq, Eq)]
struct TreeEntry {
    path: PathBuf,
    kind: &'static str,
    inode: u64,
    mode: u32,
    contents: Vec<u8>,
    link_target: Option<PathBuf>,
}

fn snapshot_tree(root: &Path) -> Vec<TreeEntry> {
    if std::fs::symlink_metadata(root).is_err() {
        return Vec::new();
    }

    fn visit(root: &Path, path: &Path, entries: &mut Vec<TreeEntry>) {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(path).unwrap();
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            "symlink"
        } else if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else {
            "other"
        };
        let relative = path.strip_prefix(root).unwrap();
        entries.push(TreeEntry {
            path: relative.to_path_buf(),
            kind,
            inode: metadata.ino(),
            mode: metadata.mode(),
            contents: if file_type.is_file() {
                std::fs::read(path).unwrap()
            } else {
                Vec::new()
            },
            link_target: if file_type.is_symlink() {
                Some(std::fs::read_link(path).unwrap())
            } else {
                None
            },
        });

        if file_type.is_dir() {
            let mut children: Vec<_> = std::fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            children.sort();
            for child in children {
                visit(root, &child, entries);
            }
        }
    }

    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries
}

fn copy_official_registration(destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for name in [".runner", ".credentials", ".credentials_rsaparams"] {
        std::fs::copy(fixture_path().join(name), destination.join(name)).unwrap();
    }
}

fn write_config(root: &Path, contents: &str) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("config.toml"), contents).unwrap();
}

fn assert_error_category(error: &ImportError, category: &str) {
    assert_eq!(error.category(), category, "got: {error:#}");
}

#[test]
fn accepts_ascii_local_name_boundaries() {
    for name in ["a".to_string(), "a".repeat(128)] {
        let root_parent = tempfile::tempdir().unwrap();
        let root = root_parent.path().join("missing-root");
        let prepared = prepare_import(&fixture_path(), &name, &root).unwrap();
        assert_eq!(prepared.disposition, TargetDisposition::New);
        assert!(!root.exists());
    }
}

#[test]
fn rejects_invalid_local_names() {
    let long_name = "a".repeat(129);
    for name in [
        "",
        ".",
        "..",
        "../runner",
        "runner/name",
        "/absolute",
        "раннер",
        long_name.as_str(),
    ] {
        let root_parent = tempfile::tempdir().unwrap();
        let root = root_parent.path().join("missing-root");
        let error = prepare_import(&fixture_path(), name, &root).unwrap_err();
        assert_eq!(error.category(), "invalid-source");
        assert!(!root.exists());
    }
}

#[test]
fn dry_plan_for_missing_root_does_not_create_root_or_config() {
    let root_parent = tempfile::tempdir().unwrap();
    let root = root_parent.path().join("missing-root");

    let prepared = prepare_import(&fixture_path(), "local", &root).unwrap();

    assert_eq!(prepared.disposition, TargetDisposition::New);
    assert!(!root.exists());
    assert!(!root.join("config.toml").exists());
}

#[test]
fn stores_canonical_root_in_planned_paths() {
    let root_parent = tempfile::tempdir().unwrap();
    std::fs::create_dir(root_parent.path().join("existing")).unwrap();
    let root = root_parent
        .path()
        .join("existing")
        .join("..")
        .join("missing-root");

    let prepared = prepare_import(&fixture_path(), "local", &root).unwrap();

    assert_eq!(
        prepared.paths.root,
        std::fs::canonicalize(root_parent.path())
            .unwrap()
            .join("missing-root")
    );
    assert!(!root_parent.path().join("missing-root").exists());
}

#[test]
fn rejects_source_equal_to_inside_or_containing_target() {
    let equal_root = tempfile::tempdir().unwrap();
    let equal_source = equal_root.path().join("runners/local");
    copy_official_registration(&equal_source);
    let equal_before = snapshot_tree(equal_root.path());

    let error = prepare_import(&equal_source, "local", equal_root.path()).unwrap_err();

    assert_error_category(&error, "invalid-source");
    assert_eq!(snapshot_tree(equal_root.path()), equal_before);

    let containing_source = copy_fixture();
    let nested_root = containing_source.path().join("nested-root");
    let containing_before = snapshot_tree(containing_source.path());

    let error = prepare_import(containing_source.path(), "local", &nested_root).unwrap_err();

    assert_error_category(&error, "invalid-source");
    assert_eq!(snapshot_tree(containing_source.path()), containing_before);
    assert!(!nested_root.exists());

    let inside_root = tempfile::tempdir().unwrap();
    let inside_source = inside_root.path().join("runners/local/official");
    copy_official_registration(&inside_source);
    let inside_before = snapshot_tree(inside_root.path());

    let error = prepare_import(&inside_source, "local", inside_root.path()).unwrap_err();

    assert_error_category(&error, "invalid-source");
    assert_eq!(snapshot_tree(inside_root.path()), inside_before);
}

#[test]
fn exact_target_plus_config_is_already_imported() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local");
    write_config(root.path(), "runners = [\"local\"]\n");
    let before = snapshot_tree(root.path());

    let prepared = prepare_import(&fixture_path(), "local", root.path()).unwrap();

    assert_eq!(prepared.disposition, TargetDisposition::AlreadyImported);
    assert_eq!(prepared.name, "local");
    assert_eq!(prepared.registration.credentials, fixture_credentials());
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn exact_target_without_config_entry_is_resume() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local");
    write_config(root.path(), "runners = []\n");
    let before = snapshot_tree(root.path());

    let prepared = prepare_import(&fixture_path(), "local", root.path()).unwrap();

    assert_eq!(prepared.disposition, TargetDisposition::Resume);
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn preserves_unknown_config_settings_and_original_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = tempfile::tempdir().unwrap();
    write_config(
        root.path(),
        "runners = []\nfuture_setting = \"keep-me\"\n[future]\nenabled = true\n",
    );
    let config_path = root.path().join("config.toml");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = snapshot_tree(root.path());

    let prepared = prepare_import(&fixture_path(), "local", root.path()).unwrap();

    assert_eq!(prepared.disposition, TargetDisposition::New);
    assert_eq!(
        prepared.config.document["future_setting"].as_str(),
        Some("keep-me")
    );
    assert_eq!(
        prepared.config.document["future"]["enabled"].as_bool(),
        Some(true)
    );
    assert_eq!(prepared.config.original_mode, Some(0o640));
    assert_eq!(
        std::fs::metadata(config_path).unwrap().mode() & 0o777,
        0o640
    );
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn same_name_with_different_credentials_is_conflict() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "local");
    mutate_json(
        &root.path().join("runners/local"),
        "rsa_params.json",
        |rsa| rsa["modulus"] = json!("AQ=="),
    );
    write_config(root.path(), "runners = [\"local\"]\n");
    let before = snapshot_tree(root.path());

    let error = prepare_import(&fixture_path(), "local", root.path()).unwrap_err();

    assert_error_category(&error, "identity-conflict");
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn same_identity_under_another_name_is_conflict() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "other");
    write_config(root.path(), "runners = []\n");
    let before = snapshot_tree(root.path());

    let error = prepare_import(&fixture_path(), "local", root.path()).unwrap_err();

    assert_error_category(&error, "identity-conflict");
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn same_agent_id_in_another_repo_is_not_conflict() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "other");
    mutate_json(
        &root.path().join("runners/other"),
        "runner.json",
        |runner| {
            runner["gitHubUrl"] = json!("https://github.com/example/other");
        },
    );
    write_config(root.path(), "runners = [\"other\"]\n");
    let before = snapshot_tree(root.path());

    let prepared = prepare_import(&fixture_path(), "local", root.path()).unwrap();

    assert_eq!(prepared.disposition, TargetDisposition::New);
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn config_name_without_credentials_is_conflict() {
    let root = tempfile::tempdir().unwrap();
    write_config(root.path(), "runners = [\"local\"]\n");
    let missing_target = root.path().join("runners/local");
    let before = snapshot_tree(root.path());

    let error = prepare_import(&fixture_path(), "local", root.path()).unwrap_err();

    assert_error_category(&error, "identity-conflict");
    assert!(!missing_target.exists());
    assert_eq!(snapshot_tree(root.path()), before);
}

#[cfg(unix)]
#[test]
fn rejects_symlink_in_runners_target_or_credential_file() {
    use std::os::unix::fs::symlink;

    let runners_root = tempfile::tempdir().unwrap();
    let runners_outside = tempfile::tempdir().unwrap();
    std::fs::write(runners_outside.path().join("marker"), "RUNNERS_MARKER").unwrap();
    symlink(runners_outside.path(), runners_root.path().join("runners")).unwrap();
    let runners_before = snapshot_tree(runners_root.path());
    let runners_outside_before = snapshot_tree(runners_outside.path());

    let error = prepare_import(&fixture_path(), "local", runners_root.path()).unwrap_err();

    assert_error_category(&error, "write-failed");
    assert_eq!(snapshot_tree(runners_root.path()), runners_before);
    assert_eq!(
        snapshot_tree(runners_outside.path()),
        runners_outside_before
    );

    let target_root = tempfile::tempdir().unwrap();
    let target_outside = tempfile::tempdir().unwrap();
    write_chimera_credentials(target_outside.path(), "local");
    std::fs::create_dir(target_root.path().join("runners")).unwrap();
    symlink(
        target_outside.path().join("runners/local"),
        target_root.path().join("runners/local"),
    )
    .unwrap();
    let target_before = snapshot_tree(target_root.path());
    let target_outside_before = snapshot_tree(target_outside.path());

    let error = prepare_import(&fixture_path(), "local", target_root.path()).unwrap_err();

    assert_error_category(&error, "write-failed");
    assert_eq!(snapshot_tree(target_root.path()), target_before);
    assert_eq!(snapshot_tree(target_outside.path()), target_outside_before);

    let credential_root = tempfile::tempdir().unwrap();
    let credential_outside = tempfile::tempdir().unwrap();
    write_chimera_credentials(credential_root.path(), "local");
    let runner_path = credential_root.path().join("runners/local/runner.json");
    let outside_runner = credential_outside.path().join("runner.json");
    std::fs::rename(&runner_path, &outside_runner).unwrap();
    symlink(&outside_runner, &runner_path).unwrap();
    let credential_before = snapshot_tree(credential_root.path());
    let credential_outside_before = snapshot_tree(credential_outside.path());

    let error = prepare_import(&fixture_path(), "local", credential_root.path()).unwrap_err();

    assert_error_category(&error, "write-failed");
    assert_eq!(snapshot_tree(credential_root.path()), credential_before);
    assert_eq!(
        snapshot_tree(credential_outside.path()),
        credential_outside_before
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_existing_config() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_config = outside.path().join("config.toml");
    std::fs::write(
        &outside_config,
        "runners = []\nsecret = \"SECRET_CONFIG\"\n",
    )
    .unwrap();
    symlink(&outside_config, root.path().join("config.toml")).unwrap();
    let root_before = snapshot_tree(root.path());
    let outside_before = snapshot_tree(outside.path());

    let error = prepare_import(&fixture_path(), "local", root.path()).unwrap_err();
    let diagnostic = format!("{error:#}");

    assert_error_category(&error, "write-failed");
    assert!(!diagnostic.contains("SECRET_CONFIG"));
    assert_eq!(snapshot_tree(root.path()), root_before);
    assert_eq!(snapshot_tree(outside.path()), outside_before);
}

#[test]
fn malformed_existing_config_or_runner_is_not_replaced() {
    let config_root = tempfile::tempdir().unwrap();
    std::fs::write(
        config_root.path().join("config.toml"),
        "runners = [\"SECRET_CONFIG\"",
    )
    .unwrap();
    let config_before = snapshot_tree(config_root.path());

    let config_error = prepare_import(&fixture_path(), "local", config_root.path()).unwrap_err();
    let config_diagnostic = format!("{config_error:#}");

    assert_error_category(&config_error, "write-failed");
    assert!(!config_diagnostic.contains("SECRET_CONFIG"));
    assert!(!config_diagnostic.contains("SECRET_EXISTING_CREDENTIAL"));
    assert_eq!(snapshot_tree(config_root.path()), config_before);

    let runner_root = tempfile::tempdir().unwrap();
    write_chimera_credentials(runner_root.path(), "local");
    std::fs::write(
        runner_root.path().join("runners/local/credentials.json"),
        "{\"SECRET_EXISTING_CREDENTIAL\"",
    )
    .unwrap();
    write_config(runner_root.path(), "runners = [\"local\"]\n");
    let runner_before = snapshot_tree(runner_root.path());

    let runner_error = prepare_import(&fixture_path(), "local", runner_root.path()).unwrap_err();
    let runner_diagnostic = format!("{runner_error:#}");

    assert_error_category(&runner_error, "write-failed");
    assert!(!runner_diagnostic.contains("SECRET_CONFIG"));
    assert!(!runner_diagnostic.contains("SECRET_EXISTING_CREDENTIAL"));
    assert_eq!(snapshot_tree(runner_root.path()), runner_before);
}

#[test]
fn rejects_duplicate_config_runner_names() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "other");
    write_config(root.path(), "runners = [\"other\", \"other\"]\n");
    let before = snapshot_tree(root.path());

    let error = prepare_import(&fixture_path(), "local", root.path()).unwrap_err();

    assert_error_category(&error, "write-failed");
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn rejects_malformed_existing_identity_without_exposing_url() {
    let root = tempfile::tempdir().unwrap();
    write_chimera_credentials(root.path(), "other");
    mutate_json(
        &root.path().join("runners/other"),
        "runner.json",
        |runner| {
            runner["gitHubUrl"] = json!("https://SECRET_EXISTING_URL.invalid/org/repo");
        },
    );
    write_config(root.path(), "runners = [\"other\"]\n");
    let before = snapshot_tree(root.path());

    let error = prepare_import(&fixture_path(), "local", root.path()).unwrap_err();
    let diagnostic = format!("{error:#}");

    assert_error_category(&error, "write-failed");
    assert!(!diagnostic.contains("SECRET_EXISTING_URL"));
    assert_eq!(snapshot_tree(root.path()), before);
}

#[test]
fn rejects_canonical_root_substitution_after_open() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let pinned = crate::storage::open_existing_root(&root).unwrap();
    let original = parent.path().join("original-root");
    std::fs::rename(&root, &original).unwrap();
    std::fs::create_dir(&root).unwrap();

    let canonical = canonicalize_allow_missing(&root).unwrap();
    let error = verify_opened_root_matches_path(&pinned, &canonical).unwrap_err();

    assert_error_category(&error, "write-failed");
    assert!(root.is_dir());
    assert!(original.is_dir());
}

#[cfg(unix)]
#[test]
fn pinned_directory_descriptors_ignore_path_substitution() {
    use std::os::unix::fs::symlink;

    let root_parent = tempfile::tempdir().unwrap();
    let root = root_parent.path().join("root");
    write_config(&root, "runners = []\nmarker = \"original\"\n");
    write_chimera_credentials(&root, "local");
    let replacement = root_parent.path().join("replacement");
    write_config(&replacement, "runners = []\nmarker = \"replacement\"\n");
    write_chimera_credentials(&replacement, "other");
    let pinned_root = crate::storage::open_existing_root(&root).unwrap();
    let displaced_root = root_parent.path().join("displaced-root");
    std::fs::rename(&root, &displaced_root).unwrap();
    symlink(&replacement, &root).unwrap();
    let displaced_before = snapshot_tree(&displaced_root);
    let replacement_before = snapshot_tree(&replacement);

    let config = load_preserved_config(&pinned_root).unwrap();
    let existing = inspect_existing_credentials(&pinned_root).unwrap();

    assert_eq!(config.document["marker"].as_str(), Some("original"));
    assert!(existing.contains_key("local"));
    assert!(!existing.contains_key("other"));
    assert_eq!(snapshot_tree(&displaced_root), displaced_before);
    assert_eq!(snapshot_tree(&replacement), replacement_before);

    let runners_parent = tempfile::tempdir().unwrap();
    let runners_root = runners_parent.path().join("root");
    write_chimera_credentials(&runners_root, "local");
    let runners_replacement = runners_parent.path().join("replacement");
    write_chimera_credentials(&runners_replacement, "other");
    let runners_root_fd = crate::storage::open_existing_root(&runners_root).unwrap();
    let pinned_runners = open_directory_at(&runners_root_fd, OsStr::new("runners")).unwrap();
    let displaced_runners = runners_root.join("original-runners");
    std::fs::rename(runners_root.join("runners"), &displaced_runners).unwrap();
    symlink(
        runners_replacement.join("runners"),
        runners_root.join("runners"),
    )
    .unwrap();

    let existing = inspect_runners_directory(&pinned_runners).unwrap();

    assert!(existing.contains_key("local"));
    assert!(!existing.contains_key("other"));

    let runner_parent = tempfile::tempdir().unwrap();
    let runner_root = runner_parent.path().join("root");
    write_chimera_credentials(&runner_root, "local");
    let runner_replacement = runner_parent.path().join("replacement");
    write_chimera_credentials(&runner_replacement, "other");
    let runner_root_fd = crate::storage::open_existing_root(&runner_root).unwrap();
    let runners_fd = open_directory_at(&runner_root_fd, OsStr::new("runners")).unwrap();
    let pinned_runner = open_directory_at(&runners_fd, OsStr::new("local")).unwrap();
    let displaced_runner = runner_root.join("runners/original-local");
    std::fs::rename(runner_root.join("runners/local"), &displaced_runner).unwrap();
    symlink(
        runner_replacement.join("runners/other"),
        runner_root.join("runners/local"),
    )
    .unwrap();

    let credentials = read_existing_credentials(&pinned_runner).unwrap();

    assert_eq!(credentials, fixture_credentials());
}

#[test]
fn config_bytes_and_mode_come_from_same_open_descriptor() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, "runners = []\nmarker = \"original\"\n").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let root_fd = crate::storage::open_existing_root(root.path()).unwrap();
    let original_fd = open_regular_at(&root_fd, OsStr::new("config.toml")).unwrap();
    std::fs::rename(&config_path, root.path().join("original-config.toml")).unwrap();
    std::fs::write(
        &config_path,
        "runners = [\"replacement\"]\nmarker = \"replacement\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let opened = read_opened_regular(original_fd).unwrap();
    let preserved = preserved_config_from_opened(opened).unwrap();

    assert!(preserved.model.runners.is_empty());
    assert_eq!(preserved.document["marker"].as_str(), Some("original"));
    assert_eq!(preserved.original_mode, Some(0o600));
}
