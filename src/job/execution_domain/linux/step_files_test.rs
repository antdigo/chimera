use super::*;
use std::os::unix::fs::{MetadataExt, symlink};

#[test]
fn step_files_are_private_fresh_and_bind_command_environment() {
    let root = tempfile::tempdir().unwrap();
    let mut files = StepFiles::open(root.path()).unwrap();
    let id = StepFilesId::new();
    files.prepare(id.clone(), b"{\"event\":1}").unwrap();
    let dir = root.path().join(id.component());
    assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    for name in ["env", "path", "output", "state", "summary", "event.json"] {
        assert_eq!(
            std::fs::metadata(dir.join(name)).unwrap().mode() & 0o777,
            0o600
        );
    }
    let env = files.environment(&id, &HashMap::new()).unwrap();
    assert_eq!(
        env["GITHUB_ENV"],
        format!("/run/chimera/steps/{}/env", id.component())
    );
    assert_eq!(
        std::fs::read(dir.join("event.json")).unwrap(),
        b"{\"event\":1}"
    );
    let mut bad = env.clone();
    bad.insert("GITHUB_OUTPUT".into(), "/work/CANARY".into());
    assert!(files.environment(&id, &bad).is_err());
    std::fs::write(dir.join("env"), "TOKEN=one\n").unwrap();
    assert_eq!(
        files.read(&id).unwrap().parse().unwrap().env["TOKEN"],
        "one"
    );
    assert!(files.prepare(id.clone(), b"{}").is_err());
    let next = StepFilesId::new();
    files.prepare(next.clone(), b"{}").unwrap();
    assert_eq!(files.read(&next).unwrap().env, "");
    assert!(files.read(&StepFilesId::new()).is_err());
}

#[test]
fn unsafe_replacements_and_oversized_or_invalid_utf8_state_are_refused() {
    for kind in [
        "symlink", "hardlink", "fifo", "replace", "large", "utf8", "reserved",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut files = StepFiles::open(root.path()).unwrap();
        let id = StepFilesId::new();
        files.prepare(id.clone(), b"{}").unwrap();
        let path = root.path().join(id.component()).join("env");
        match kind {
            "large" => std::fs::write(&path, vec![b'a'; 1024 * 1024 + 1]).unwrap(),
            "utf8" => std::fs::write(&path, [0xff]).unwrap(),
            "reserved" => std::fs::write(&path, "DOCKER_HOST=unix:///CANARY\n").unwrap(),
            "hardlink" => std::fs::hard_link(&path, root.path().join("alias")).unwrap(),
            _ => {
                std::fs::remove_file(&path).unwrap();
                match kind {
                    "symlink" => symlink("/etc/passwd", &path).unwrap(),
                    "replace" => std::fs::write(&path, "CANARY=x").unwrap(),
                    _ => {
                        let c =
                            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                    }
                }
            }
        }
        assert!(files.read(&id).is_err(), "{kind}");
    }
}

#[test]
fn event_limit_is_four_mib_and_failure_creates_no_step() {
    let root = tempfile::tempdir().unwrap();
    let mut files = StepFiles::open(root.path()).unwrap();
    let id = StepFilesId::new();
    assert!(
        files
            .prepare(id.clone(), &vec![0; 4 * 1024 * 1024 + 1])
            .is_err()
    );
    assert!(!root.path().join(id.component()).exists());
    files.prepare(id, &vec![0; 4 * 1024 * 1024]).unwrap();
}

#[test]
fn regular_read_compares_the_opened_descriptor_to_the_original_inode() {
    let root = tempfile::tempdir().unwrap();
    let directory = BoundDir::open_root(root.path()).unwrap();
    let original = directory.write_new(c"env", b"original").unwrap();
    std::fs::rename(root.path().join("env"), root.path().join("old")).unwrap();
    std::fs::write(root.path().join("env"), "replacement").unwrap();
    assert!(
        directory
            .read_bound_regular(c"env", &original, 1024)
            .is_err()
    );
}

#[test]
fn step_transactions_release_descriptors_on_success_and_read_error() {
    const TEST: &str = "job::execution_domain::linux::step_files::step_files_test::step_transactions_release_descriptors_on_success_and_read_error";
    if std::env::var_os("CHIMERA_B8_FD_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env("CHIMERA_B8_FD_CHILD", "1")
            .status()
            .unwrap();
        assert!(result.success());
        return;
    }
    let limit = libc::rlimit {
        rlim_cur: 128,
        rlim_max: 128,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let root = tempfile::tempdir().unwrap();
    let mut files = StepFiles::open(root.path()).unwrap();
    let baseline = std::fs::read_dir("/proc/self/fd").unwrap().count();
    for index in 0..128 {
        let id = StepFilesId::new();
        files.prepare(id.clone(), b"{}").unwrap();
        if index % 2 == 0 {
            std::fs::write(root.path().join(id.component()).join("env"), [0xff]).unwrap();
            assert!(files.read(&id).is_err());
        } else {
            assert_eq!(files.read(&id).unwrap().env, "");
        }
        assert!(files.read(&id).is_err());
        assert_eq!(
            std::fs::read_dir("/proc/self/fd").unwrap().count(),
            baseline
        );
    }
    let partial_root = tempfile::tempdir().unwrap();
    let mut partial = StepFiles::open(partial_root.path()).unwrap();
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let tight = libc::rlimit {
        rlim_cur: (before + 4) as u64,
        rlim_max: 128,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) }, 0);
    let id = StepFilesId::new();
    assert!(partial.prepare(id.clone(), b"{}").is_err());
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
    assert!(!partial_root.path().join(id.component()).exists());
}

#[test]
fn partial_cleanup_preserves_all_entries_if_inventory_or_identity_changed() {
    for extra in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let parent = BoundDir::open_root(root.path()).unwrap();
        let child = parent.create_child(c"step", 0o700).unwrap();
        let original = child.write_new(c"env", b"").unwrap();
        let directory = root.path().join("step");
        if extra {
            std::fs::write(directory.join("unknown"), "keep").unwrap();
        } else {
            std::fs::remove_file(directory.join("env")).unwrap();
            std::fs::write(directory.join("env"), "keep").unwrap();
        }
        assert!(
            parent
                .remove_created_child(c"step", &child, &[(c"env", &original)])
                .is_err()
        );
        assert!(directory.join("env").exists());
        assert_eq!(
            std::fs::read_dir(directory).unwrap().count(),
            if extra { 2 } else { 1 }
        );
    }
}

#[test]
fn prepared_step_capacity_is_bounded_before_mutation_and_recovers_after_read() {
    let root = tempfile::tempdir().unwrap();
    let mut files = StepFiles::open(root.path()).unwrap();
    let ids: Vec<_> = (0..32).map(|_| StepFilesId::new()).collect();
    for id in &ids {
        files.prepare(id.clone(), b"{}").unwrap();
    }
    let extra = StepFilesId::new();
    assert!(files.prepare(extra.clone(), b"{}").is_err());
    assert!(!root.path().join(extra.component()).exists());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 32);
    files.read(&ids[0]).unwrap();
    files.prepare(extra, b"{}").unwrap();
}
