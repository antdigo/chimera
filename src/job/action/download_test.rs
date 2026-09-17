use std::io::Write;
use std::path::{Path, PathBuf};

use super::*;

fn make_test_tarball(files: &[(&str, &str, u32)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    for (path, content, mode) in files {
        // Add a prefix component to simulate GitHub's tarball format
        let full_path = format!("owner-repo-abc123/{path}");
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(*mode);
        header.set_cksum();
        builder
            .append_data(&mut header, &full_path, content.as_bytes())
            .unwrap();
    }

    let tar_data = builder.into_inner().unwrap();

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn cache_hit_skips_download() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().join("actions");
    let action_dir = remote_cache_path(&cache_dir, "actions", "checkout", "v4");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("action.yml"), "name: checkout").unwrap();

    let cache = ActionCache::new(cache_dir, reqwest::Client::new());
    let source = ActionSource::Remote {
        owner: "actions".into(),
        repo: "checkout".into(),
        git_ref: "v4".into(),
        path: None,
    };

    let result = cache
        .get_action(&source, tmp.path(), "fake-token")
        .await
        .unwrap();
    assert_eq!(result.path(), action_dir.canonicalize().unwrap());
    assert!(result.path().join("action.yml").exists());
}

#[tokio::test]
async fn tarball_extraction() {
    let mock_server = wiremock::MockServer::start().await;

    let tarball = make_test_tarball(&[
        (
            "action.yml",
            "name: test-action\nruns:\n  using: node20\n  main: index.js\n",
            0o644,
        ),
        ("index.js", "console.log('hello');\n", 0o644),
    ]);

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/repos/test-owner/test-action/tarball/v1",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_bytes(tarball)
                .insert_header("content-type", "application/gzip"),
        )
        .mount(&mock_server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().join("actions");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .unwrap();

    let cache = ActionCache {
        cache_dir: cache_dir.clone(),
        client,
    };

    // Override the download URL by manually calling download_tarball
    let dest = cache_dir.join("test-owner/test-action/v1");
    let url = format!(
        "{}/repos/test-owner/test-action/tarball/v1",
        mock_server.uri()
    );

    let response = cache
        .client
        .get(&url)
        .header("Authorization", "token fake-token")
        .header("User-Agent", "chimera")
        .send()
        .await
        .unwrap();

    let bytes = response.bytes().await.unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    extract_tarball(&bytes, &dest).unwrap();

    assert!(dest.join("action.yml").exists());
    assert!(dest.join("index.js").exists());

    let content = std::fs::read_to_string(dest.join("index.js")).unwrap();
    assert!(content.contains("console.log"));
}

/// Mode a freshly created regular file gets under the current umask, measured
/// in `directory` so assertions stay stable regardless of the host umask.
#[cfg(unix)]
fn baseline_file_mode(directory: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    let reference = directory.join("chimera-mode-baseline");
    std::fs::write(&reference, b"").unwrap();
    let mode = std::fs::metadata(&reference).unwrap().permissions().mode();
    std::fs::remove_file(&reference).unwrap();
    mode
}

#[cfg(unix)]
fn extracted_file_mode(directory: &Path, name: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(directory.join(name))
        .unwrap()
        .permissions()
        .mode()
}

#[cfg(unix)]
fn extract_to_temp_dir(tarball: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extracted");
    std::fs::create_dir_all(&dest).unwrap();
    extract_tarball(tarball, &dest).unwrap();
    tmp
}

#[cfg(unix)]
#[test]
fn tarball_extraction_preserves_executable_bits() {
    let tmp = extract_to_temp_dir(&make_test_tarball(&[
        ("run.sh", "#!/bin/sh\n", 0o755),
        ("owner-only.sh", "#!/bin/sh\n", 0o711),
    ]));
    let dest = tmp.path().join("extracted");

    let baseline = baseline_file_mode(&dest);
    for name in ["run.sh", "owner-only.sh"] {
        assert_eq!(
            extracted_file_mode(&dest, name),
            (baseline & !0o111) | 0o111,
            "{name}: exec bits must come from the header, read/write bits from the umask"
        );
    }
}

#[cfg(unix)]
#[test]
fn tarball_extraction_drops_special_and_extra_write_bits() {
    let tmp = extract_to_temp_dir(&make_test_tarball(&[
        ("setuid.sh", "#!/bin/sh\n", 0o4755),
        ("setgid.sh", "#!/bin/sh\n", 0o2755),
        ("sticky.sh", "#!/bin/sh\n", 0o1777),
        ("world-writable.sh", "#!/bin/sh\n", 0o777),
    ]));
    let dest = tmp.path().join("extracted");

    let baseline = baseline_file_mode(&dest);
    for name in ["setuid.sh", "setgid.sh", "sticky.sh", "world-writable.sh"] {
        let mode = extracted_file_mode(&dest, name);
        assert_eq!(
            mode & 0o7000,
            0,
            "{name}: setuid/setgid/sticky bits must not carry over"
        );
        assert_eq!(
            mode & 0o111,
            0o111,
            "{name}: executable bits must survive extraction"
        );
        assert_eq!(
            mode & !0o111,
            baseline & !0o111,
            "{name}: read/write bits must stay umask-derived"
        );
    }
}

#[cfg(unix)]
#[test]
fn tarball_extraction_keeps_non_executable_files_non_executable() {
    let tmp = extract_to_temp_dir(&make_test_tarball(&[
        ("plain.txt", "data\n", 0o644),
        ("shared.txt", "data\n", 0o666),
        ("no-permissions.txt", "data\n", 0o000),
    ]));
    let dest = tmp.path().join("extracted");

    let baseline = baseline_file_mode(&dest);
    for name in ["plain.txt", "shared.txt", "no-permissions.txt"] {
        assert_eq!(
            extracted_file_mode(&dest, name),
            baseline,
            "{name}: header read/write bits must not leak into the extracted file"
        );
    }
}

#[tokio::test]
async fn local_path_resolves_inside_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join(".github/actions/my-action");
    std::fs::create_dir_all(&action_dir).unwrap();

    let cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: PathBuf::from(".github/actions/my-action"),
    };

    let result = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();
    assert_eq!(result.path(), action_dir.canonicalize().unwrap());
}

#[tokio::test]
async fn local_action_parent_traversal_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: PathBuf::from("../outside"),
    };

    let error = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "action path must stay inside its source root"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn local_action_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, workspace.join("linked-action")).unwrap();
    let cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: PathBuf::from("linked-action"),
    };

    let error = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "action path must stay inside its source root"
    );
}

#[test]
fn remote_cache_path_hashes_path_like_refs() {
    let root = Path::new("/runner/actions");
    let escaped = remote_cache_path(root, "owner", "repo", "../../outside");
    let branch = remote_cache_path(root, "owner", "repo", "refs/heads/main");
    let expected_parent = root.join("remote-v1");

    assert_eq!(escaped.parent(), Some(expected_parent.as_path()));
    assert_eq!(branch.parent(), Some(expected_parent.as_path()));
    assert_ne!(escaped, branch);
    assert_eq!(escaped.file_name().unwrap().len(), 64);
}

/// Build a tarball with unsafe path entries (bypassing tar crate's safety checks).
fn make_unsafe_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    for (path, content) in files {
        let path_bytes = path.as_bytes();
        // Build a 512-byte tar header manually
        let mut header = [0u8; 512];
        header[..path_bytes.len()].copy_from_slice(path_bytes);
        // Mode field (offset 100, 8 bytes): "0000644\0"
        header[100..108].copy_from_slice(b"0000644\0");
        // Size field (offset 124, 12 bytes): octal size
        let size_str = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_str.as_bytes());
        // Type flag (offset 156): '0' = regular file
        header[156] = b'0';
        // Magic (offset 257): "ustar\0"
        header[257..263].copy_from_slice(b"ustar\0");
        // Version (offset 263): "00"
        header[263..265].copy_from_slice(b"00");
        // Compute checksum (offset 148, 8 bytes): treat checksum field as spaces
        header[148..156].copy_from_slice(b"        ");
        let cksum: u32 = header.iter().map(|&b| b as u32).sum();
        let cksum_str = format!("{:06o}\0 ", cksum);
        header[148..156].copy_from_slice(cksum_str.as_bytes());

        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(content);
        // Pad to 512-byte boundary
        let padding = (512 - (content.len() % 512)) % 512;
        tar_bytes.extend(std::iter::repeat_n(0u8, padding));
    }
    // End-of-archive: two 512-byte blocks of zeros
    tar_bytes.extend(std::iter::repeat_n(0u8, 1024));

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn path_traversal_entries_are_skipped() {
    let tarball = make_unsafe_tarball(&[
        ("owner-repo-abc123/action.yml", b"name: legit\n"),
        ("owner-repo-abc123/../escape.txt", b"malicious\n"),
        (
            "owner-repo-abc123/sub/../../etc/passwd",
            b"also malicious\n",
        ),
    ]);

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extracted");
    std::fs::create_dir_all(&dest).unwrap();
    extract_tarball(&tarball, &dest).unwrap();

    // Legit file should be extracted
    assert!(dest.join("action.yml").exists());

    // Malicious entries should not escape or be created
    assert!(!tmp.path().join("escape.txt").exists());
    assert!(!tmp.path().join("etc").exists());
}

#[test]
fn has_path_traversal_detection() {
    assert!(has_path_traversal(Path::new("../foo")));
    assert!(has_path_traversal(Path::new("foo/../../bar")));
    assert!(!has_path_traversal(Path::new("foo/bar")));
    assert!(!has_path_traversal(Path::new("foo")));
}

#[tokio::test]
async fn docker_action_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let source = ActionSource::Docker {
        image: "node:18".into(),
    };

    let result = cache.get_action(&source, tmp.path(), "fake-token").await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("should be handled before get_action")
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cloned_trusted_directory_reads_original_root_after_root_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "original").unwrap();
    let expected_path = action_dir.canonicalize().unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();
    assert_eq!(trusted.path(), expected_path);
    let cloned = trusted.clone();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "replacement-canary").unwrap();
    drop(trusted);

    let contents = cloned
        .read_optional_regular_file("sentinel")
        .unwrap()
        .unwrap();

    assert_eq!(String::from_utf8(contents).unwrap(), "original");
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn identity_validation_fails_closed_after_source_root_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "original").unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "replacement-canary").unwrap();

    let error = trusted.validate_path_identity().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cloned_trusted_directory_reads_original_root_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "original").unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();
    let cloned = trusted.clone();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    let replacement = tmp.path().join("replacement-workspace");
    let replacement_action = replacement.join("actions/test");
    std::fs::create_dir_all(&replacement_action).unwrap();
    std::fs::write(replacement_action.join("sentinel"), "replacement-canary").unwrap();
    symlink(&replacement, &workspace).unwrap();
    drop(trusted);

    let contents = cloned
        .read_optional_regular_file("sentinel")
        .unwrap()
        .unwrap();

    assert_eq!(String::from_utf8(contents).unwrap(), "original");
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn identity_validation_fails_closed_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "original").unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    let replacement = tmp.path().join("replacement-workspace");
    let replacement_action = replacement.join("actions/test");
    std::fs::create_dir_all(&replacement_action).unwrap();
    std::fs::write(replacement_action.join("sentinel"), "replacement-canary").unwrap();
    symlink(&replacement, &workspace).unwrap();

    let error = trusted.validate_path_identity().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}
