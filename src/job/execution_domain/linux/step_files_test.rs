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
