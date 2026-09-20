use std::os::unix::fs::symlink;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{DomainWorkspaceReader, ReadLimits};
use crate::job::execution_domain::{ExecutionDomainError, FailureCategory};

fn assert_category(error: ExecutionDomainError, expected: FailureCategory) {
    let ExecutionDomainError::Backend { category, .. } = error else {
        panic!("expected backend failure, got {error:?}");
    };
    assert_eq!(category, expected);
}

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

#[test]
fn refuses_entry_budget_before_collecting_large_directory() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..256 {
        std::fs::create_dir(temp.path().join(format!("empty-{index:03}"))).unwrap();
    }
    let reader = DomainWorkspaceReader::new(temp.path().to_path_buf()).unwrap();
    let limits = ReadLimits {
        max_entries: 32,
        ..ReadLimits::default()
    };

    let error = reader
        .hash_files_with_limits(&["**/*".into()], limits)
        .unwrap_err();

    assert_category(error, FailureCategory::InvalidInput);
}

#[test]
fn refuses_depth_path_bytes_and_match_budgets() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("first/second")).unwrap();
    std::fs::write(temp.path().join("a.txt"), b"a").unwrap();
    std::fs::write(temp.path().join("b.txt"), b"b").unwrap();
    let reader = DomainWorkspaceReader::new(temp.path().to_path_buf()).unwrap();

    let depth = reader
        .hash_files_with_limits(
            &["**/*".into()],
            ReadLimits {
                max_depth: 1,
                ..ReadLimits::default()
            },
        )
        .unwrap_err();
    assert_category(depth, FailureCategory::InvalidInput);

    let path_bytes = reader
        .hash_files_with_limits(
            &["**/*".into()],
            ReadLimits {
                max_path_bytes: 1,
                ..ReadLimits::default()
            },
        )
        .unwrap_err();
    assert_category(path_bytes, FailureCategory::InvalidInput);

    let matches = reader
        .hash_files_with_limits(
            &["*.txt".into()],
            ReadLimits {
                max_matches: 1,
                ..ReadLimits::default()
            },
        )
        .unwrap_err();
    assert_category(matches, FailureCategory::InvalidInput);
}

#[test]
fn checks_deadline_while_traversing_entries() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("entry"), b"data").unwrap();
    let reader = DomainWorkspaceReader::new(temp.path().to_path_buf()).unwrap();

    let error = reader
        .hash_files_with_limits(
            &["*".into()],
            ReadLimits {
                max_time: Duration::ZERO,
                ..ReadLimits::default()
            },
        )
        .unwrap_err();

    assert_category(error, FailureCategory::Timeout);
}

#[test]
fn traverses_large_empty_tree_without_collecting_directory_entries() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..2_048 {
        std::fs::create_dir(temp.path().join(format!("empty-{index:04}"))).unwrap();
    }
    let reader = DomainWorkspaceReader::new(temp.path().to_path_buf()).unwrap();

    let digest = reader.hash_files(&["**/*.txt".into()]).unwrap();

    assert_eq!(digest, "");
}
