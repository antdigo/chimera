use std::sync::Arc;
use std::sync::atomic::Ordering;

use tempfile::TempDir;

use super::*;
use crate::cache::auth::{CacheAuthority, CacheScope, CapabilityEpoch, JobCapabilityClaims};

const REPO: &str = "owner/repo";
const MAIN_REF: &str = "refs/heads/main";
const FEATURE_REF: &str = "refs/heads/feature";

async fn make_manager(tmp: &TempDir, max_bytes: u64) -> CacheManager {
    let entries_dir = tmp.path().join("entries");
    let data_dir = tmp.path().join("data");
    let tmp_dir = tmp.path().join("tmp");

    CacheManager::new(entries_dir, data_dir, tmp_dir, max_bytes)
        .await
        .unwrap()
}

async fn upload_blob(manager: &CacheManager, key: &str, version: &str, data: &[u8]) {
    upload_scoped_blob(manager, key, version, REPO, MAIN_REF, data).await;
}

async fn upload_scoped_blob(
    manager: &CacheManager,
    key: &str,
    version: &str,
    repo: &str,
    git_ref: &str,
    data: &[u8],
) {
    let owner = CapabilityEpoch::for_test("manager-test-owner");
    let id = manager
        .reserve_upload(
            owner.clone(),
            "manager-test-job".into(),
            key.to_string(),
            version.to_string(),
            repo.to_string(),
            git_ref.to_string(),
        )
        .await
        .unwrap();
    manager.write_chunk(&owner, id, 0, data).await.unwrap();
    manager
        .commit_upload(&owner, id, data.len() as u64)
        .await
        .unwrap();
}

async fn over_quota_lru_manager(tmp: &TempDir) -> Arc<CacheManager> {
    let manager = Arc::new(make_manager(tmp, 10).await);
    upload_blob(&manager, "oldest", "v1", b"aaaaaaaaaa").await;
    upload_blob(&manager, "next", "v1", b"bbbbbbbbbb").await;

    let mut entries = manager.entries.write().await;
    for (key, age) in [("oldest", 10), ("next", 5)] {
        let mut entry = entries.remove(REPO, MAIN_REF, key, "v1").unwrap();
        entry.last_accessed_at = Utc::now() - chrono::Duration::minutes(age);
        entries.insert(entry);
    }
    drop(entries);
    manager
}

#[tokio::test]
async fn full_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let manager = make_manager(&tmp, 1024 * 1024).await;

    let data = b"cache roundtrip data";
    upload_blob(&manager, "my-key", "v1", data).await;

    let entry = manager
        .lookup(&["my-key".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    assert_eq!(entry.key, "my-key");
    assert_eq!(entry.size_bytes, data.len() as u64);

    let blob_path = manager.blob_path(&entry.blob_hash).unwrap();
    let content = std::fs::read(blob_path).unwrap();
    assert_eq!(content, data);
}

#[tokio::test]
async fn cache_miss() {
    let tmp = TempDir::new().unwrap();
    let manager = make_manager(&tmp, 1024 * 1024).await;

    let result = manager
        .lookup(&["nonexistent".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await;
    assert!(result.is_none());
    assert_eq!(manager.stats.misses.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn blob_dedup_across_entries() {
    let tmp = TempDir::new().unwrap();
    let manager = make_manager(&tmp, 1024 * 1024).await;

    let data = b"shared content";
    upload_blob(&manager, "key-a", "v1", data).await;
    upload_blob(&manager, "key-b", "v1", data).await;

    let entry_a = manager
        .lookup(&["key-a".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    let entry_b = manager
        .lookup(&["key-b".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();

    // Same content -> same blob hash
    assert_eq!(entry_a.blob_hash, entry_b.blob_hash);
}

#[tokio::test]
async fn lru_eviction() {
    let tmp = TempDir::new().unwrap();
    // Very small limit to trigger eviction
    let manager = make_manager(&tmp, 50).await;

    // Upload entries that together exceed 50 bytes
    upload_blob(&manager, "old", "v1", &[0u8; 30]).await;

    // Backdate the entry so it's eligible for eviction
    {
        let mut entries = manager.entries.write().await;
        let entry = entries.remove(REPO, MAIN_REF, "old", "v1").unwrap();
        let mut backdated = entry;
        backdated.last_accessed_at = Utc::now() - chrono::Duration::minutes(5);
        entries.insert(backdated);
    }

    upload_blob(&manager, "new", "v1", &[1u8; 30]).await;

    // "old" should have been evicted
    let old = manager
        .lookup(&["old".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await;
    assert!(old.is_none());

    // "new" should still exist
    let new = manager
        .lookup(&["new".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await;
    assert!(new.is_some());
}

#[tokio::test]
async fn eviction_rechecks_lru_after_a_waiting_candidate_is_refreshed() {
    let tmp = TempDir::new().unwrap();
    let manager = over_quota_lru_manager(&tmp).await;
    let eviction_wait = manager.arm_before_eviction_entry_wait();
    let eviction_manager = manager.clone();
    let eviction = tokio::spawn(async move { eviction_manager.evict().await });
    eviction_wait.reached.notified().await;

    let refreshed = manager
        .lookup(&["oldest".into()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    let blob_path = manager.blob_path(&refreshed.blob_hash).unwrap();
    let authority = CacheAuthority::new();
    authority
        .register_job(
            "eviction-grant-owner",
            JobCapabilityClaims {
                scope: CacheScope {
                    repo: REPO.into(),
                    git_ref: MAIN_REF.into(),
                    default_ref: MAIN_REF.into(),
                },
                job_id: "eviction-grant-job".into(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let authorized = authority
        .authenticate("eviction-grant-owner")
        .await
        .unwrap();
    let grant = authority
        .issue_download(&authorized, refreshed.blob_hash.clone())
        .await
        .unwrap();

    eviction_wait.resume.notify_one();
    eviction.await.unwrap();

    let entries = manager.entries.read().await;
    assert!(entries.get(REPO, MAIN_REF, "oldest", "v1").is_some());
    assert!(entries.get(REPO, MAIN_REF, "next", "v1").is_none());
    drop(entries);
    assert!(blob_path.exists(), "refreshed entry blob was removed");
    assert_eq!(
        authority.resolve_download(grant).await.unwrap(),
        refreshed.blob_hash,
    );
}

#[tokio::test]
async fn eviction_stops_when_another_worker_restores_the_quota() {
    let tmp = TempDir::new().unwrap();
    let manager = over_quota_lru_manager(&tmp).await;
    let eviction_wait = manager.arm_before_eviction_entry_wait();
    let first_manager = manager.clone();
    let first = tokio::spawn(async move { first_manager.evict().await });
    eviction_wait.reached.notified().await;

    let refreshed = manager
        .lookup(&["oldest".into()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    let refreshed_blob_path = manager.blob_path(&refreshed.blob_hash).unwrap();
    manager.evict().await;
    {
        let entries = manager.entries.read().await;
        assert_eq!(entries.total_size_bytes(), 10);
        assert!(entries.get(REPO, MAIN_REF, "next", "v1").is_none());
    }

    eviction_wait.resume.notify_one();
    first.await.unwrap();

    let entries = manager.entries.read().await;
    assert_eq!(entries.total_size_bytes(), 10);
    assert!(entries.get(REPO, MAIN_REF, "oldest", "v1").is_some());
    drop(entries);
    assert!(
        refreshed_blob_path.exists(),
        "first worker over-evicted after quota was restored",
    );
}

#[tokio::test]
async fn persist_and_reload() {
    let tmp = TempDir::new().unwrap();
    let entries_dir = tmp.path().join("entries");
    let data_dir = tmp.path().join("data");
    let tmp_dir = tmp.path().join("tmp");

    // Create manager and upload
    {
        let manager = CacheManager::new(
            entries_dir.clone(),
            data_dir.clone(),
            tmp_dir.clone(),
            1024 * 1024,
        )
        .await
        .unwrap();
        upload_blob(&manager, "persist-key", "v1", b"persist data").await;
    }

    // Create new manager from same dirs -- should recover
    let manager = CacheManager::new(entries_dir, data_dir, tmp_dir, 1024 * 1024)
        .await
        .unwrap();

    let entry = manager
        .lookup(&["persist-key".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    assert_eq!(entry.key, "persist-key");

    let blob_path = manager.blob_path(&entry.blob_hash).unwrap();
    let content = std::fs::read(blob_path).unwrap();
    assert_eq!(content, b"persist data");
}

#[tokio::test]
async fn overwrite_persists_replacement_and_releases_old_blob() {
    let tmp = TempDir::new().unwrap();
    let entries_dir = tmp.path().join("entries");
    let data_dir = tmp.path().join("data");
    let tmp_dir = tmp.path().join("tmp");
    let manager = CacheManager::new(
        entries_dir.clone(),
        data_dir.clone(),
        tmp_dir.clone(),
        1024 * 1024,
    )
    .await
    .unwrap();

    upload_blob(&manager, "replace", "v1", b"old").await;
    let old = manager
        .lookup(&["replace".into()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    let old_blob = manager.blob_path(&old.blob_hash).unwrap();
    upload_blob(&manager, "replace", "v1", b"replacement").await;
    let replacement = manager
        .entries
        .read()
        .await
        .get(REPO, MAIN_REF, "replace", "v1")
        .unwrap()
        .clone();
    assert_eq!(
        tokio::fs::read(manager.blob_path(&replacement.blob_hash).unwrap())
            .await
            .unwrap(),
        b"replacement",
    );
    assert!(!old_blob.exists(), "old unreferenced blob was retained");
    drop(manager);

    let reloaded = CacheManager::new(entries_dir, data_dir, tmp_dir, 1024 * 1024)
        .await
        .unwrap();
    let replacement = reloaded
        .lookup(&["replace".into()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await
        .expect("replacement metadata must survive reload");
    assert_eq!(
        tokio::fs::read(reloaded.blob_path(&replacement.blob_hash).unwrap())
            .await
            .unwrap(),
        b"replacement",
    );
}

#[tokio::test]
async fn concurrent_access() {
    let tmp = TempDir::new().unwrap();
    let manager = Arc::new(make_manager(&tmp, 1024 * 1024).await);

    let mut handles = Vec::new();
    for i in 0..10 {
        let mgr = manager.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("concurrent-{i}");
            let data = format!("data-{i}");
            upload_scoped_blob(&mgr, &key, "v1", REPO, MAIN_REF, data.as_bytes()).await;

            let entry = mgr.lookup(&[key], "v1", REPO, MAIN_REF, MAIN_REF).await;
            assert!(entry.is_some());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let entries = manager.entries.read().await;
    assert_eq!(entries.entry_count(), 10);
}

#[tokio::test]
async fn stats_tracking() {
    let tmp = TempDir::new().unwrap();
    let manager = make_manager(&tmp, 1024 * 1024).await;

    upload_blob(&manager, "key", "v1", b"data").await;

    manager
        .lookup(&["key".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await;
    manager
        .lookup(&["key".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await;
    manager
        .lookup(&["miss".to_string()], "v1", REPO, MAIN_REF, MAIN_REF)
        .await;

    assert_eq!(manager.stats.hits.load(Ordering::Relaxed), 2);
    assert_eq!(manager.stats.misses.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn cross_repo_isolation() {
    let tmp = TempDir::new().unwrap();
    let manager = make_manager(&tmp, 1024 * 1024).await;

    upload_scoped_blob(&manager, "key", "v1", "org/repo-a", MAIN_REF, b"data-a").await;
    upload_scoped_blob(&manager, "key", "v1", "org/repo-b", MAIN_REF, b"data-b").await;

    let entry_a = manager
        .lookup(&["key".to_string()], "v1", "org/repo-a", MAIN_REF, MAIN_REF)
        .await
        .unwrap();
    let entry_b = manager
        .lookup(&["key".to_string()], "v1", "org/repo-b", MAIN_REF, MAIN_REF)
        .await
        .unwrap();

    // Different repos, different content -> different blobs
    assert_ne!(entry_a.blob_hash, entry_b.blob_hash);
    assert_eq!(entry_a.scope_repo, "org/repo-a");
    assert_eq!(entry_b.scope_repo, "org/repo-b");

    // Unknown repo sees nothing
    let result = manager
        .lookup(&["key".to_string()], "v1", "org/repo-c", MAIN_REF, MAIN_REF)
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn ref_fallback() {
    let tmp = TempDir::new().unwrap();
    let manager = make_manager(&tmp, 1024 * 1024).await;

    // Upload to main
    upload_scoped_blob(&manager, "key", "v1", REPO, MAIN_REF, b"main-data").await;

    // Feature branch can read from main (fallback)
    let entry = manager
        .lookup(&["key".to_string()], "v1", REPO, FEATURE_REF, MAIN_REF)
        .await
        .unwrap();
    assert_eq!(entry.scope_ref, MAIN_REF);

    // Main cannot read from feature branch (no reverse fallback)
    upload_scoped_blob(&manager, "feature-only", "v1", REPO, FEATURE_REF, b"feat").await;
    let result = manager
        .lookup(
            &["feature-only".to_string()],
            "v1",
            REPO,
            MAIN_REF,
            MAIN_REF,
        )
        .await;
    assert!(result.is_none());
}
