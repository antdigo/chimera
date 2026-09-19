use tempfile::TempDir;

use super::*;
use crate::cache::auth::CapabilityId;

fn owner(token: &str) -> CapabilityId {
    CapabilityId::from_token(token)
}

fn make_tracker(tmp: &TempDir) -> UploadTracker {
    let tmp_dir = tmp.path().join("uploads");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    UploadTracker::new(tmp_dir)
}

#[tokio::test]
async fn reserve_and_commit() {
    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let owner = owner("upload-test-owner");

    let id = tracker
        .reserve(
            owner.clone(),
            "upload-test-job".into(),
            "my-key".into(),
            "my-version".into(),
            "owner/repo".into(),
            "refs/heads/main".into(),
        )
        .await
        .unwrap();

    let data = b"hello world";
    tracker.write_chunk(&owner, id, 0, data).await.unwrap();

    let (key, version, scope_repo, scope_ref, path, size) =
        tracker.commit(&owner, id, data.len() as u64).await.unwrap();
    assert_eq!(key, "my-key");
    assert_eq!(version, "my-version");
    assert_eq!(scope_repo, "owner/repo");
    assert_eq!(scope_ref, "refs/heads/main");
    assert_eq!(size, data.len() as u64);

    let content = std::fs::read(path).unwrap();
    assert_eq!(content, data);
}

#[tokio::test]
async fn committed_upload_diagnostics_identify_job_without_capability() {
    use tracing::instrument::WithSubscriber;

    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let token = "SENTINEL_UPLOAD_RUNTIME_TOKEN";
    let owner = owner(token);
    let id = tracker
        .reserve(
            owner.clone(),
            "safe-job-id".into(),
            "key".into(),
            "v1".into(),
            "owner/repo".into(),
            "refs/heads/main".into(),
        )
        .await
        .unwrap();
    tracker.write_chunk(&owner, id, 0, b"data").await.unwrap();
    let logs = crate::testing::CapturedLogs::default();

    let (_, _, _, _, path, size) = tracker
        .commit(&owner, id, 4)
        .with_subscriber(logs.subscriber())
        .await
        .unwrap();

    assert_eq!(std::fs::read(path).unwrap(), b"data");
    assert_eq!(size, 4);
    let output = logs.text();
    assert!(
        output.contains("safe-job-id"),
        "committed session should identify its owner job"
    );
    assert!(!output.contains(token));
    assert!(!output.contains(&format!("{owner:?}")));
    assert!(!output.contains(&blake3::hash(token.as_bytes()).to_hex().to_string()));
}

#[tokio::test]
async fn chunked_upload() {
    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let owner = owner("upload-test-owner");

    let id = tracker
        .reserve(
            owner.clone(),
            "upload-test-job".into(),
            "k".into(),
            "v".into(),
            "owner/repo".into(),
            "refs/heads/main".into(),
        )
        .await
        .unwrap();

    tracker.write_chunk(&owner, id, 0, b"hello").await.unwrap();
    tracker.write_chunk(&owner, id, 5, b" world").await.unwrap();

    let (_, _, _, _, path, size) = tracker.commit(&owner, id, 11).await.unwrap();
    assert_eq!(size, 11);

    let content = std::fs::read(path).unwrap();
    assert_eq!(content, b"hello world");
}

#[tokio::test]
async fn size_mismatch() {
    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let owner = owner("upload-test-owner");

    let id = tracker
        .reserve(
            owner.clone(),
            "upload-test-job".into(),
            "k".into(),
            "v".into(),
            "owner/repo".into(),
            "refs/heads/main".into(),
        )
        .await
        .unwrap();
    tracker.write_chunk(&owner, id, 0, b"short").await.unwrap();

    let result = tracker.commit(&owner, id, 100).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("does not match"));
}

#[tokio::test]
async fn upload_not_found() {
    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let owner = owner("upload-test-owner");

    let result = tracker.write_chunk(&owner, 999, 0, b"data").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn foreign_owner_cannot_write_or_consume_upload_session() {
    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let owner_a = owner("runtime-a");
    let owner_b = owner("runtime-b");
    let id = tracker
        .reserve(
            owner_a.clone(),
            "job-a".into(),
            "k".into(),
            "v".into(),
            "org/repo".into(),
            "refs/heads/main".into(),
        )
        .await
        .unwrap();

    let write_error = tracker
        .write_chunk(&owner_b, id, 0, b"evil")
        .await
        .unwrap_err();
    assert!(
        write_error.downcast_ref::<CacheError>().is_some_and(
            |error| matches!(error, CacheError::UploadNotFound(value) if *value == id)
        )
    );
    let commit_error = tracker.commit(&owner_b, id, 4).await.unwrap_err();
    assert!(
        commit_error.downcast_ref::<CacheError>().is_some_and(
            |error| matches!(error, CacheError::UploadNotFound(value) if *value == id)
        )
    );

    tracker
        .write_chunk(&owner_a, id, 0, b"owner")
        .await
        .unwrap();
    let (_, _, _, _, path, size) = tracker.commit(&owner_a, id, 5).await.unwrap();
    assert_eq!(size, 5);
    assert_eq!(std::fs::read(path).unwrap(), b"owner");
}

#[test]
fn parse_content_range_valid() {
    let (start, end) = parse_content_range("bytes 0-99/*").unwrap();
    assert_eq!(start, 0);
    assert_eq!(end, 99);
}

#[test]
fn parse_content_range_with_total() {
    let (start, end) = parse_content_range("bytes 100-199/200").unwrap();
    assert_eq!(start, 100);
    assert_eq!(end, 199);
}

#[test]
fn parse_content_range_invalid() {
    assert!(parse_content_range("invalid").is_err());
    assert!(parse_content_range("bytes abc-def/*").is_err());
    assert!(parse_content_range("bytes 0/*").is_err());
}

#[tokio::test]
async fn cleanup_stale_files() {
    let tmp = TempDir::new().unwrap();
    let upload_dir = tmp.path().join("uploads");
    std::fs::create_dir_all(&upload_dir).unwrap();

    // Create stale upload files
    std::fs::write(upload_dir.join("upload-1.tmp"), "stale").unwrap();
    std::fs::write(upload_dir.join("upload-2.tmp"), "stale").unwrap();
    // Non-upload file should be left alone
    std::fs::write(upload_dir.join("other.txt"), "keep").unwrap();

    UploadTracker::cleanup_stale_files(&upload_dir);

    assert!(!upload_dir.join("upload-1.tmp").exists());
    assert!(!upload_dir.join("upload-2.tmp").exists());
    assert!(upload_dir.join("other.txt").exists());
}
