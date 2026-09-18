#[cfg(target_os = "linux")]
use std::io::Read;
use std::path::Path;

use super::*;
use crate::job::action::{ActionCache, ActionSource, TrustedActionDirectory};

fn trusted_action(path: &Path) -> TrustedActionDirectory {
    TrustedActionDirectory::resolve(path, Path::new(".")).unwrap()
}

fn archive_paths(archive: &[u8]) -> Vec<String> {
    let mut paths = tar::Archive::new(archive);
    let mut result: Vec<String> = paths
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    result.sort();
    result
}

fn archive_paths_in_order(archive: &[u8]) -> Vec<String> {
    let mut paths = tar::Archive::new(archive);
    paths
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn archive_file(archive: &[u8], wanted: &str) -> Vec<u8> {
    let mut archive = tar::Archive::new(archive);
    let mut entry = archive
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.path().unwrap() == Path::new(wanted))
        .unwrap();
    let mut content = Vec::new();
    entry.read_to_end(&mut content).unwrap();
    content
}

#[cfg(unix)]
fn set_mtime(path: &Path, seconds: libc::time_t) {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) },
        0
    );
}

#[test]
fn dockerfile_path_with_spaces_is_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("action");
    std::fs::create_dir_all(dir.join("docker files")).unwrap();
    std::fs::write(dir.join("docker files/Dockerfile"), "FROM scratch\n").unwrap();

    let resolved = resolve_build_paths(&trusted_action(&dir), "docker files/Dockerfile").unwrap();

    // Linux keeps only the relative path plus the pinned descriptor; the
    // canonical absolute pathnames are a non-Linux fallback detail.
    #[cfg(not(target_os = "linux"))]
    assert_eq!(resolved.action_root, dir.canonicalize().unwrap());
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        resolved.dockerfile_path,
        dir.join("docker files/Dockerfile").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.dockerfile_relative,
        Path::new("docker files/Dockerfile")
    );
}

#[test]
fn absolute_and_parent_dockerfile_paths_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("action");
    std::fs::create_dir_all(&dir).unwrap();

    assert_eq!(
        resolve_build_paths(&trusted_action(&dir), "/tmp/Dockerfile")
            .unwrap_err()
            .to_string(),
        "Dockerfile path must be relative to the action directory"
    );
    assert_eq!(
        resolve_build_paths(&trusted_action(&dir), "../Dockerfile")
            .unwrap_err()
            .to_string(),
        "Dockerfile path must be relative to the action directory"
    );
}

#[test]
fn dockerfile_directory_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let action = tmp.path().join("action");
    std::fs::create_dir_all(action.join("Dockerfile")).unwrap();

    let error = resolve_build_paths(&trusted_action(&action), "Dockerfile").unwrap_err();

    assert_eq!(error.to_string(), "Dockerfile must be a regular file");
}

#[cfg(unix)]
#[test]
fn dockerfile_symlink_outside_action_is_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("action");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(tmp.path().join("outside.Dockerfile"), "FROM scratch\n").unwrap();
    symlink(
        tmp.path().join("outside.Dockerfile"),
        dir.join("Dockerfile"),
    )
    .unwrap();

    let error = resolve_build_paths(&trusted_action(&dir), "Dockerfile").unwrap_err();

    assert_eq!(
        error.to_string(),
        "Dockerfile must resolve inside the action directory"
    );
}

#[test]
fn root_dockerignore_filters_files_but_keeps_dockerfile() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("keep.txt"), "keep").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), "synthetic-secret").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "secret.txt\nDockerfile\n").unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert_eq!(context.dockerfile, "Dockerfile");
    assert!(paths.contains(&"Dockerfile".to_string()));
    assert!(paths.contains(&"keep.txt".to_string()));
    assert!(!paths.contains(&"secret.txt".to_string()));
    let canary = b"synthetic-secret";
    assert!(
        context
            .archive
            .windows(canary.len())
            .all(|window| window != canary)
    );
}

/// The executor keeps one trusted directory capability across a job's
/// pre/main/post steps, so the same descriptor is traversed repeatedly.
/// Every clone shares one readdir offset: a traversal that does not rewind
/// observes an empty directory the second time (Linux-only code path).
#[cfg(target_os = "linux")]
#[test]
fn repeated_traversals_of_one_capability_see_the_full_directory() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("sentinel"), "original").unwrap();
    let trusted = trusted_action(tmp.path());

    for _ in 0..3 {
        let context = prepare_build_context(&trusted, "Dockerfile").unwrap();
        let paths = archive_paths(&context.archive);
        assert!(paths.contains(&"Dockerfile".to_string()));
        assert!(paths.contains(&"sentinel".to_string()));
    }
}

/// A budget interruption fires after `fdopendir` has taken ownership of the
/// duplicate descriptor; that exit must still close the stream, or repeated
/// cancelled preparations bleed descriptors in a long-running daemon.
#[cfg(target_os = "linux")]
#[test]
fn cancelled_enumeration_does_not_leak_directory_streams() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    let trusted = trusted_action(tmp.path());

    let cancel_token = tokio_util::sync::CancellationToken::new();
    cancel_token.cancel();
    let budget = PreparationBudget::new(
        std::time::Instant::now() + std::time::Duration::from_secs(600),
        cancel_token,
    );

    let root = trusted.clone_directory_descriptor().unwrap();

    let open_fds_before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    for _ in 0..64 {
        assert!(read_directory_names(&root, &budget).is_err());
    }
    let open_fds_after = std::fs::read_dir("/proc/self/fd").unwrap().count();

    // Parallel tests in this binary open and close their own descriptors, so
    // the drift is signed and may legitimately be negative; a real leak adds
    // one stream per iteration.
    let drift = open_fds_after as i64 - open_fds_before as i64;
    assert!(
        drift < 32,
        "cancelled enumerations must close their directory streams, fd drift {drift} over 64 runs"
    );
}

/// Preparation runs on a blocking worker that outlives an abandoned
/// `spawn_blocking` handle: it must stop itself once the step's budget has
/// fired, instead of packing an arbitrarily large context forever.
#[test]
fn cancelled_preparation_stops_before_packing_a_large_context() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    let large = tmp.path().join("large.bin");
    let mut buffer = vec![0u8; 32 * 1024 * 1024];
    buffer.fill(7);
    std::fs::write(&large, &buffer).unwrap();
    let trusted = trusted_action(tmp.path());

    let cancel_token = tokio_util::sync::CancellationToken::new();
    cancel_token.cancel();
    let budget = PreparationBudget::new(
        std::time::Instant::now() + std::time::Duration::from_secs(600),
        cancel_token,
    );

    let started = std::time::Instant::now();
    let error = prepare_build_context_with_budget(&trusted, "Dockerfile", budget).unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(error.to_string(), PREPARATION_CANCELLED);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "cancelled preparation must stop promptly, took {elapsed:?}"
    );
}

/// The copy loop inside `append_regular_file` wraps every error with
/// "adding file to Docker build context"; an interruption raised mid-copy
/// must stay recognizable behind that wrapper so the build classifies it as
/// a cancelled lifecycle instead of an ordinary failure.
#[test]
fn cancelled_during_file_copy_keeps_the_sentinel_through_context_wrapping() {
    let tmp = tempfile::tempdir().unwrap();
    let payload = tmp.path().join("payload.bin");
    std::fs::write(&payload, vec![7u8; 64 * 1024]).unwrap();
    let file = std::fs::File::open(&payload).unwrap();
    let metadata = file.metadata().unwrap();
    let identity = FileIdentity::from_metadata(&metadata);
    let entry = ContextEntry {
        relative: PathBuf::from("payload.bin"),
        mode: metadata.mode(),
        kind: ContextEntryKind::File(identity),
        archive_path: "payload.bin".to_string(),
    };

    let cancel_token = tokio_util::sync::CancellationToken::new();
    cancel_token.cancel();
    let budget = PreparationBudget::new(
        std::time::Instant::now() + std::time::Duration::from_secs(600),
        cancel_token,
    );

    let mut builder = tar::Builder::new(Vec::new());
    let error = append_regular_file(&mut builder, &entry, identity, file, &budget).unwrap_err();

    let causes = error
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>();
    assert!(
        causes.iter().any(|cause| cause == PREPARATION_CANCELLED),
        "sentinel lost behind context wrapping, chain: {causes:?}"
    );
}

#[test]
fn root_dockerignore_with_bom_and_escaped_hash_excludes_literal_hash_file() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("#secret.txt"), "synthetic-hash-secret").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), "synthetic-secret").unwrap();
    std::fs::write(
        tmp.path().join(".dockerignore"),
        "\u{feff}\\#secret.txt\nsecret.txt\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"Dockerfile".to_string()));
    assert!(!paths.contains(&"#secret.txt".to_string()));
    assert!(!paths.contains(&"secret.txt".to_string()));
    for canary in [b"synthetic-hash-secret".as_slice(), b"synthetic-secret"] {
        assert!(
            context
                .archive
                .windows(canary.len())
                .all(|window| window != canary)
        );
    }
}

#[test]
fn specific_dockerignore_with_bom_and_escaped_hash_replaces_root_ignore() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("docker")).unwrap();
    std::fs::write(tmp.path().join("docker/Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("root-only.txt"), "root").unwrap();
    std::fs::write(tmp.path().join("#secret.txt"), "synthetic-hash-secret").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), "synthetic-secret").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "root-only.txt\n").unwrap();
    std::fs::write(
        tmp.path().join("docker/Dockerfile.dockerignore"),
        "\u{feff}\\#secret.txt\nsecret.txt\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "docker/Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"root-only.txt".to_string()));
    assert!(!paths.contains(&"#secret.txt".to_string()));
    assert!(!paths.contains(&"secret.txt".to_string()));
    for canary in [b"synthetic-hash-secret".as_slice(), b"synthetic-secret"] {
        assert!(
            context
                .archive
                .windows(canary.len())
                .all(|window| window != canary)
        );
    }
}

#[test]
fn dockerfile_specific_ignore_replaces_root_ignore() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("docker")).unwrap();
    std::fs::write(tmp.path().join("docker/Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("root-only.txt"), "root").unwrap();
    std::fs::write(tmp.path().join("specific-only.txt"), "specific").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "root-only.txt\n").unwrap();
    std::fs::write(
        tmp.path().join("docker/Dockerfile.dockerignore"),
        "specific-only.txt\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "docker/Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"root-only.txt".to_string()));
    assert!(!paths.contains(&"specific-only.txt".to_string()));
}

#[test]
fn negation_and_double_star_follow_last_matching_rule() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("nested/keep")).unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("nested/drop.log"), "drop").unwrap();
    std::fs::write(tmp.path().join("nested/keep/keep.log"), "keep").unwrap();
    std::fs::write(
        tmp.path().join(".dockerignore"),
        "**/*.log\n!nested/keep/*.log\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(!paths.contains(&"nested/drop.log".to_string()));
    assert!(paths.contains(&"nested/keep/keep.log".to_string()));
}

/// Leading/trailing slashes in ignore rules are ignored, and separator-free
/// patterns match complete context-relative paths: they stay root-level
/// (`*.txt` does not reach `nested/drop.txt`; `**` is the only cross-level
/// wildcard). Verified against a real engine alongside the exclusion probes.
#[test]
fn leading_slash_negation_matches_root_paths_only() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("nested")).unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("nested/keep.txt"), "keep").unwrap();
    std::fs::write(tmp.path().join("nested/drop.txt"), "drop").unwrap();
    std::fs::write(tmp.path().join("drop.txt"), "drop").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "*.txt\n!/keep.txt\n").unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    // Nothing under nested/ is matched by the root-level rules at all.
    assert!(paths.contains(&"nested/keep.txt".to_string()));
    assert!(paths.contains(&"nested/drop.txt".to_string()));
    assert!(!paths.contains(&"drop.txt".to_string()));
}

/// Docker prunes excluded directories: an exception rule cannot re-include a
/// file whose ancestor directory is excluded — the walk never offers the
/// subtree for matching. A basename-shaped exception must not leak files out
/// of an excluded directory.
#[test]
fn exception_rule_cannot_reinclude_files_inside_excluded_directory() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("private")).unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(
        tmp.path().join("private/public.pem"),
        "CHIMERA_PRIVATE_CANARY",
    )
    .unwrap();
    std::fs::write(tmp.path().join("public.pem"), "shared").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "private/\n!public.pem\n").unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"public.pem".to_string()));
    assert!(!paths.contains(&"private/public.pem".to_string()));
    assert!(!paths.contains(&"private".to_string()));
    let canary = b"CHIMERA_PRIVATE_CANARY";
    assert!(
        context
            .archive
            .windows(canary.len())
            .all(|window| window != canary),
        "file from an excluded directory must not reach the daemon"
    );
}

#[cfg(unix)]
#[test]
fn symlink_outside_context_is_rejected_without_reading_target() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let action = tmp.path().join("action");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("canary"), "synthetic-secret").unwrap();
    symlink(tmp.path().join("canary"), action.join("leak")).unwrap();

    let error = prepare_build_context(&trusted_action(&action), "Dockerfile").unwrap_err();

    assert_eq!(
        error.to_string(),
        "build context symlink must stay inside the action directory"
    );
}

#[cfg(unix)]
#[test]
fn special_file_in_context_is_rejected() {
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    let _socket = UnixListener::bind(tmp.path().join("forbidden.sock")).unwrap();

    let error = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap_err();

    assert_eq!(
        error.to_string(),
        "build context contains an unsupported special file"
    );
}

#[cfg(unix)]
#[test]
fn digest_changes_for_content_mode_and_symlink_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("one"), "one").unwrap();
    std::fs::write(tmp.path().join("two"), "two").unwrap();
    std::fs::write(tmp.path().join("payload"), "alpha").unwrap();
    symlink("one", tmp.path().join("link")).unwrap();
    let first = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile")
        .unwrap()
        .digest;

    std::fs::write(tmp.path().join("payload"), "beta").unwrap();
    let content = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile")
        .unwrap()
        .digest;
    assert_ne!(first, content);

    let mut permissions = std::fs::metadata(tmp.path().join("payload"))
        .unwrap()
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(tmp.path().join("payload"), permissions).unwrap();
    let mode = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile")
        .unwrap()
        .digest;
    assert_ne!(content, mode);

    std::fs::remove_file(tmp.path().join("link")).unwrap();
    symlink("two", tmp.path().join("link")).unwrap();
    let target = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile")
        .unwrap()
        .digest;
    assert_ne!(mode, target);
}

#[cfg(unix)]
#[test]
fn digest_ignores_creation_order_and_mtime() {
    fn make(root: &Path, reverse: bool) {
        std::fs::write(root.join("Dockerfile"), "FROM scratch\n").unwrap();
        let files = if reverse { ["b", "a"] } else { ["a", "b"] };
        for file in files {
            std::fs::write(root.join(file), file).unwrap();
        }
    }

    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make(left.path(), false);
    make(right.path(), true);
    set_mtime(&left.path().join("a"), 1);
    set_mtime(&right.path().join("a"), 2);

    let left_digest = prepare_build_context(&trusted_action(left.path()), "Dockerfile")
        .unwrap()
        .digest;
    let right_digest = prepare_build_context(&trusted_action(right.path()), "Dockerfile")
        .unwrap()
        .digest;

    assert_eq!(left_digest, right_digest);
}

#[test]
fn dockerignore_cleans_dot_parent_and_repeated_separators() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("secret-one"), "synthetic-secret-one").unwrap();
    std::fs::write(tmp.path().join("secret-two"), "synthetic-secret-two").unwrap();
    std::fs::create_dir_all(tmp.path().join("nested")).unwrap();
    std::fs::write(
        tmp.path().join("nested/secret-three"),
        "synthetic-secret-three",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join(".dockerignore"),
        "./secret-one\nfolder/../secret-two\nnested//./secret-three\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    for (path, canary) in [
        ("secret-one", b"synthetic-secret-one".as_slice()),
        ("secret-two", b"synthetic-secret-two".as_slice()),
        ("nested/secret-three", b"synthetic-secret-three".as_slice()),
    ] {
        assert!(!paths.contains(&path.to_string()));
        assert!(
            context
                .archive
                .windows(canary.len())
                .all(|window| window != canary)
        );
    }
}

#[test]
fn ignored_parent_is_traversed_for_reincluded_descendant() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("nested/keep")).unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("nested/drop.txt"), "drop").unwrap();
    std::fs::write(tmp.path().join("nested/keep/keep.txt"), "keep").unwrap();
    std::fs::write(
        tmp.path().join(".dockerignore"),
        "nested/\n!nested/keep/keep.txt\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(!paths.contains(&"nested/drop.txt".to_string()));
    assert!(paths.contains(&"nested/keep/keep.txt".to_string()));
}

#[cfg(unix)]
#[test]
fn relative_parent_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let action = tmp.path().join("action");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("canary"), "synthetic-secret").unwrap();
    symlink("../canary", action.join("leak")).unwrap();

    let error = prepare_build_context(&trusted_action(&action), "Dockerfile").unwrap_err();

    assert_eq!(
        error.to_string(),
        "build context symlink must stay inside the action directory"
    );
}

#[cfg(unix)]
#[test]
fn selected_ignore_and_dockerfile_symlink_target_are_forced_into_context() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("real")).unwrap();
    std::fs::write(tmp.path().join("real/Dockerfile"), "FROM scratch\n").unwrap();
    symlink("real/Dockerfile", tmp.path().join("Dockerfile")).unwrap();
    std::fs::write(
        tmp.path().join(".dockerignore"),
        "Dockerfile\nreal/\n.dockerignore\n",
    )
    .unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&".dockerignore".to_string()));
    assert!(paths.contains(&"Dockerfile".to_string()));
    assert!(paths.contains(&"real/Dockerfile".to_string()));
}

#[cfg(unix)]
#[test]
fn dockerfile_symlink_chain_is_forced_through_ignored_intermediate_hops() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("actual")).unwrap();
    std::fs::write(tmp.path().join("actual/Dockerfile"), "FROM scratch\n").unwrap();
    symlink("link-two", tmp.path().join("link-one")).unwrap();
    symlink("actual", tmp.path().join("link-two")).unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "*\n").unwrap();

    let context =
        prepare_build_context(&trusted_action(tmp.path()), "link-one/Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&".dockerignore".to_string()));
    assert!(paths.contains(&"link-one".to_string()));
    assert!(paths.contains(&"link-two".to_string()));
    assert!(paths.contains(&"actual/Dockerfile".to_string()));
}

#[cfg(target_os = "linux")]
#[test]
fn opening_a_fifo_for_context_rejects_without_blocking() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt, sync::mpsc, time::Duration};

    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("forbidden.fifo");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

    // The Linux reader opens entries relative to the pinned root descriptor:
    // the O_PATH inspect must reject the FIFO without ever blocking on it.
    let trusted = trusted_action(tmp.path());
    let root = trusted.clone_directory_descriptor().unwrap();
    let name = std::ffi::OsStr::new("forbidden.fifo");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let inspected = open_at(
            &root,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .unwrap();
        let expected = FileIdentity::from_metadata(&inspected.metadata().unwrap());
        sender
            .send(open_regular_file_at(&root, name, expected).map(|_| ()))
            .unwrap();
    });

    let error = receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("opening a FIFO must not block")
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "build context contains an unsupported special file"
    );
}

#[test]
fn rooted_parent_dockerignore_pattern_is_cleaned_before_unanchoring() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), "synthetic-secret").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "/../secret.txt\n").unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(!paths.contains(&"secret.txt".to_string()));
    assert!(
        context
            .archive
            .windows(b"synthetic-secret".len())
            .all(|window| window != b"synthetic-secret")
    );
}

#[cfg(unix)]
#[test]
fn symlinked_dockerfile_parent_uses_and_forces_specific_ignore_file() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("actual")).unwrap();
    std::fs::write(tmp.path().join("actual/Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("actual/Dockerfile.dockerignore"), "*\n").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), "synthetic-secret").unwrap();
    symlink("actual", tmp.path().join("link")).unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "link/Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"link".to_string()));
    assert!(paths.contains(&"actual/Dockerfile".to_string()));
    assert!(paths.contains(&"actual/Dockerfile.dockerignore".to_string()));
    assert!(!paths.contains(&"secret.txt".to_string()));
}

#[test]
fn archive_entries_follow_sorted_relative_paths() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("z.txt"), "z").unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("a.txt"), "a").unwrap();

    let context = prepare_build_context(&trusted_action(tmp.path()), "Dockerfile").unwrap();

    assert_eq!(
        archive_paths_in_order(&context.archive),
        vec!["Dockerfile", "a.txt", "z.txt"]
    );
}

fn collect_context_with_replaced_artifact()
-> (tempfile::TempDir, ResolvedBuildPaths, CollectedContext) {
    let tmp = tempfile::tempdir().unwrap();
    let action_dir = tmp.path();
    let artifact = action_dir.join("artifact.txt");
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(&artifact, "original").unwrap();

    let paths = resolve_build_paths(&trusted_action(action_dir), "Dockerfile").unwrap();
    let budget = PreparationBudget::unbounded();
    let (ignore, ignore_file) = IgnoreRules::load(&paths, &budget).unwrap();
    let mut context =
        collect_context_entries(&paths, &ignore, ignore_file.as_ref(), &budget).unwrap();
    context
        .entries
        .sort_by(|left, right| left.archive_path.cmp(&right.archive_path));

    let replacement = action_dir.join("replacement.txt");
    std::fs::write(&replacement, "replacement").unwrap();
    std::fs::rename(&replacement, &artifact).unwrap();

    (tmp, paths, context)
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_file_after_traversal_rejects_context_emission() {
    let (_tmp, _paths, context) = collect_context_with_replaced_artifact();
    let artifact = context
        .entries
        .iter()
        .find(|entry| entry.relative == Path::new("artifact.txt"))
        .unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let budget = PreparationBudget::unbounded();

    let error = append_context_entry(&mut builder, &context.root, artifact, &budget).unwrap_err();

    assert_eq!(
        error.to_string(),
        "build context entry changed while it was being prepared"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn replacing_file_after_traversal_rejects_context_emission() {
    let (_tmp, paths, context) = collect_context_with_replaced_artifact();
    let artifact = context
        .entries
        .iter()
        .find(|entry| entry.relative == Path::new("artifact.txt"))
        .unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let budget = PreparationBudget::unbounded();

    let error = append_context_entry(&mut builder, &paths, artifact, &budget).unwrap_err();

    assert_eq!(
        error.to_string(),
        "build context entry changed while it was being prepared"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn trusted_context_keeps_archiving_original_action_after_source_root_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
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
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(action_dir.join("sentinel"), "replacement-canary").unwrap();

    let context = prepare_build_context(&trusted, "Dockerfile").unwrap();

    assert_eq!(archive_file(&context.archive, "sentinel"), b"original");
    assert!(
        context
            .archive
            .windows(b"replacement-canary".len())
            .all(|window| window != b"replacement-canary")
    );
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn trusted_context_fails_closed_after_source_root_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
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
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(action_dir.join("sentinel"), "replacement-canary").unwrap();

    let error = prepare_build_context(&trusted, "Dockerfile").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn trusted_context_keeps_archiving_original_action_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
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
    std::fs::write(replacement_action.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(replacement_action.join("sentinel"), "replacement-canary").unwrap();
    symlink(&replacement, &workspace).unwrap();

    let context = prepare_build_context(&trusted, "Dockerfile").unwrap();

    assert_eq!(archive_file(&context.archive, "sentinel"), b"original");
    assert!(
        context
            .archive
            .windows(b"replacement-canary".len())
            .all(|window| window != b"replacement-canary")
    );
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn trusted_context_fails_closed_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
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
    std::fs::write(replacement_action.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(replacement_action.join("sentinel"), "replacement-canary").unwrap();
    symlink(&replacement, &workspace).unwrap();

    let error = prepare_build_context(&trusted, "Dockerfile").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}

#[cfg(unix)]
fn make_remote_action_tarball(files: &[(&str, &str, u32)]) -> Vec<u8> {
    use std::io::Write;

    let mut builder = tar::Builder::new(Vec::new());
    for (path, content, mode) in files {
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

#[cfg(unix)]
fn archive_entry_mode(archive: &[u8], wanted: &str) -> u32 {
    let mut archive = tar::Archive::new(archive);
    archive
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.path().unwrap() == Path::new(wanted))
        .unwrap()
        .header()
        .mode()
        .unwrap()
}

#[cfg(unix)]
fn umask_baseline_mode(directory: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    let reference = directory.join("chimera-mode-baseline");
    std::fs::write(&reference, b"").unwrap();
    let mode = std::fs::metadata(&reference).unwrap().permissions().mode();
    std::fs::remove_file(&reference).unwrap();
    mode
}

#[cfg(unix)]
#[test]
fn extracted_executable_bits_flow_into_build_context() {
    use crate::job::action::download::extract_tarball;

    let tarball = make_remote_action_tarball(&[
        ("Dockerfile", "FROM scratch\n", 0o644),
        ("entrypoint.sh", "#!/bin/sh\n", 0o4755),
        ("helper.sh", "#!/bin/sh\n", 0o755),
    ]);

    let tmp = tempfile::tempdir().unwrap();
    let extracted = tmp.path().join("extracted");
    std::fs::create_dir_all(&extracted).unwrap();
    extract_tarball(&tarball, &extracted).unwrap();

    // The context tar header stores the permission bits only (no file-type
    // bits), so compare against the umask baseline masked the same way.
    let baseline = umask_baseline_mode(&extracted) & 0o7777;
    let context = prepare_build_context(&trusted_action(&extracted), "Dockerfile").unwrap();

    // The setuid header bit is dropped while the executable bits survive.
    assert_eq!(
        archive_entry_mode(&context.archive, "entrypoint.sh") & 0o7000,
        0
    );
    assert_eq!(
        archive_entry_mode(&context.archive, "entrypoint.sh"),
        (baseline & !0o111) | 0o111
    );
    assert_eq!(
        archive_entry_mode(&context.archive, "helper.sh"),
        (baseline & !0o111) | 0o111
    );
    // A non-executable file never becomes executable in the context tar.
    assert_eq!(
        archive_entry_mode(&context.archive, "Dockerfile") & 0o111,
        0
    );
    assert_eq!(archive_entry_mode(&context.archive, "Dockerfile"), baseline);
}
