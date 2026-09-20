use std::os::unix::fs::symlink;

use sha2::{Digest, Sha256};

use super::DomainWorkspaceReader;

#[test]
fn hashes_sorted_deduplicated_regular_files() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("a.txt"), b"a").unwrap();
    std::fs::write(temp.path().join("b.txt"), b"b").unwrap();
    let reader = DomainWorkspaceReader::new(temp.path().to_path_buf()).unwrap();

    let digest = reader.hash_files(&["*.txt".into(), "a.*".into()]).unwrap();

    let mut expected = Sha256::new();
    expected.update(b"a");
    expected.update(b"b");
    assert_eq!(digest, format!("{:x}", expected.finalize()));
    assert_eq!(reader.hash_files(&["*.none".into()]).unwrap(), "");
}

#[test]
fn refuses_escape_symlink_and_revoked_reader() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("canary"), b"keep").unwrap();
    symlink(outside.path(), temp.path().join("outside")).unwrap();
    let reader = DomainWorkspaceReader::new(temp.path().to_path_buf()).unwrap();

    assert!(reader.hash_files(&["../canary".into()]).is_err());
    assert!(reader.hash_files(&["**/*".into()]).is_err());
    assert_eq!(
        std::fs::read(outside.path().join("canary")).unwrap(),
        b"keep"
    );
    reader.revoke_and_wait();
    assert!(reader.hash_files(&["*".into()]).is_err());
}

#[test]
fn stays_bound_to_original_directory_after_path_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("work");
    let moved = temp.path().join("moved");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("value.txt"), b"original").unwrap();
    let reader = DomainWorkspaceReader::new(root.clone()).unwrap();

    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("value.txt"), b"replacement").unwrap();

    let mut expected = Sha256::new();
    expected.update(b"original");
    assert_eq!(
        reader.hash_files(&["*.txt".into()]).unwrap(),
        format!("{:x}", expected.finalize())
    );
}
