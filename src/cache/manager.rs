use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing::{debug, info, warn};

use super::auth::{CacheAuthError, CacheAuthority, CacheOperationPermit, CapabilityEpoch};
use super::entry::{CacheEntry, EntryIndex, load_entries_from_disk};
use super::error::CacheError;
use super::store::BlobStore;
use super::upload::{LockedUpload, UploadTracker};

pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl CacheStats {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
}

/// Orchestrates blob store, entry index, upload tracker, and LRU eviction.
///
/// Nested acquisition order is capability gate (in the server), upload session,
/// per-entry I/O coordination, then the in-memory index. The index is always
/// released before filesystem or blob-refcount I/O; code that first probes the
/// index releases that probe guard before waiting for per-entry coordination.
pub struct CacheManager {
    store: BlobStore,
    entries: RwLock<EntryIndex>,
    entry_io: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
    uploads: UploadTracker,
    max_bytes: u64,
    pub stats: CacheStats,
    entries_dir: PathBuf,
    #[cfg(test)]
    before_entry_publish: super::test_support::PausePoint,
    #[cfg(test)]
    before_lookup_index: super::test_support::PausePoint,
    #[cfg(test)]
    before_lookup_persist: super::test_support::PausePoint,
}

impl CacheManager {
    /// Create a new CacheManager, recovering state from disk.
    pub async fn new(
        entries_dir: PathBuf,
        data_dir: PathBuf,
        tmp_dir: PathBuf,
        max_bytes: u64,
    ) -> Result<Self> {
        // Ensure directories exist
        std::fs::create_dir_all(&entries_dir)
            .with_context(|| format!("creating entries dir {}", entries_dir.display()))?;
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("creating data dir {}", data_dir.display()))?;
        std::fs::create_dir_all(&tmp_dir)
            .with_context(|| format!("creating tmp dir {}", tmp_dir.display()))?;

        let store = BlobStore::new(data_dir, tmp_dir.clone());
        let uploads = UploadTracker::new(tmp_dir);

        // Clean stale uploads from previous crash
        UploadTracker::cleanup_stale_files(store.tmp_dir());

        // Load entries from disk
        let disk_entries = load_entries_from_disk(&entries_dir)?;
        let mut index = EntryIndex::new();

        // Rebuild blob ref counts and verify blobs exist
        for entry in disk_entries {
            if store.exists(&entry.blob_hash) {
                store.incref(&entry.blob_hash).await;
                index.insert(entry);
            } else {
                warn!(key = %entry.key, hash = %entry.blob_hash, "removing orphaned entry (blob missing)");
                entry.remove_file(&entries_dir);
            }
        }

        // Delete orphaned blobs (blobs with no entry pointing to them)
        if let Ok(all_hashes) = store.all_hashes() {
            let referenced: std::collections::HashSet<String> = index
                .all_entries()
                .iter()
                .map(|e| e.blob_hash.clone())
                .collect();
            for hash in all_hashes {
                if !referenced.contains(&hash) {
                    debug!(hash, "removing orphaned blob");
                    // Set refcount to 1 then decref to 0, which triggers deletion
                    store.set_refcount(&hash, 1).await;
                    store.decref(&hash).await;
                }
            }
        }

        let manager = Self {
            store,
            entries: RwLock::new(index),
            entry_io: Mutex::new(HashMap::new()),
            uploads,
            max_bytes,
            stats: CacheStats::new(),
            entries_dir,
            #[cfg(test)]
            before_entry_publish: Default::default(),
            #[cfg(test)]
            before_lookup_index: Default::default(),
            #[cfg(test)]
            before_lookup_persist: Default::default(),
        };

        // Run initial eviction in case max_gb was lowered
        manager.evict().await;

        let entry_count = manager.entries.read().await.entry_count();
        let total = manager.store.total_bytes().unwrap_or(0);
        info!(
            entries = entry_count,
            total_bytes = total,
            max_bytes,
            "cache manager initialized"
        );

        Ok(manager)
    }

    /// Look up a cache entry with scope isolation.
    /// Falls back to default_ref if no match on scope_ref (feature branch reads from default branch).
    pub async fn lookup(
        &self,
        keys: &[String],
        version: &str,
        scope_repo: &str,
        scope_ref: &str,
        default_ref: &str,
    ) -> Option<CacheEntry> {
        self.lookup_inner(keys, version, scope_repo, scope_ref, default_ref, None)
            .await
            .expect("lookup without admission cannot fail authorization")
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "admitted lookup keeps GitHub's ordered scope inputs explicit"
    )]
    pub(crate) async fn lookup_admitted(
        &self,
        keys: &[String],
        version: &str,
        scope_repo: &str,
        scope_ref: &str,
        default_ref: &str,
        authority: &CacheAuthority,
        permit: &CacheOperationPermit,
    ) -> Result<Option<CacheEntry>, CacheAuthError> {
        self.lookup_inner(
            keys,
            version,
            scope_repo,
            scope_ref,
            default_ref,
            Some((authority, permit)),
        )
        .await
    }

    async fn lookup_inner(
        &self,
        keys: &[String],
        version: &str,
        scope_repo: &str,
        scope_ref: &str,
        default_ref: &str,
        admission: Option<(&CacheAuthority, &CacheOperationPermit)>,
    ) -> Result<Option<CacheEntry>, CacheAuthError> {
        loop {
            let expected_file = self
                .entries
                .read()
                .await
                .find(keys, version, scope_repo, scope_ref, default_ref)
                .map(CacheEntry::filename);
            let entry_io = expected_file
                .as_deref()
                .map(|filename| self.entry_io_lock(filename));
            let _entry_io_guard = match &entry_io {
                Some(lock) => Some(lock.lock().await),
                None => None,
            };

            let mut entries = self.entries.write().await;
            #[cfg(test)]
            self.before_lookup_index.wait().await;
            if let Some((authority, permit)) = admission {
                authority.revalidate(permit).await?;
            }
            let current_file = entries
                .find(keys, version, scope_repo, scope_ref, default_ref)
                .map(CacheEntry::filename);
            if current_file != expected_file {
                drop(entries);
                continue;
            }
            let entry = entries.lookup(keys, version, scope_repo, scope_ref, default_ref);
            match &entry {
                Some(_) => self.stats.hits.fetch_add(1, Ordering::Relaxed),
                None => self.stats.misses.fetch_add(1, Ordering::Relaxed),
            };
            drop(entries);

            if let Some(entry) = &entry {
                #[cfg(test)]
                self.before_lookup_persist.wait().await;
                if let Err(error) = self.persist_entry(entry.clone()).await {
                    warn!(error = %error, "failed to persist cache lookup metadata");
                }
            }
            return Ok(entry);
        }
    }

    fn entry_io_lock(&self, filename: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .entry_io
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(filename).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(filename.to_owned(), Arc::downgrade(&lock));
        lock
    }

    async fn persist_entry(&self, entry: CacheEntry) -> Result<()> {
        let entries_dir = self.entries_dir.clone();
        tokio::task::spawn_blocking(move || entry.persist(&entries_dir))
            .await
            .context("joining cache entry persistence task")?
    }

    /// Reserve a new upload session with scope.
    pub(crate) async fn reserve_upload(
        &self,
        owner: CapabilityEpoch,
        owner_job_id: String,
        key: String,
        version: String,
        scope_repo: String,
        scope_ref: String,
    ) -> Result<u64> {
        self.uploads
            .reserve(owner, owner_job_id, key, version, scope_repo, scope_ref)
            .await
    }

    /// Write a chunk to an upload session.
    #[cfg(test)]
    pub(crate) async fn write_chunk(
        &self,
        owner: &CapabilityEpoch,
        id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        self.uploads.write_chunk(owner, id, offset, data).await
    }

    pub(crate) async fn lock_upload(
        &self,
        owner: &CapabilityEpoch,
        id: u64,
    ) -> Result<LockedUpload> {
        self.uploads.lock(owner, id).await
    }

    pub(crate) async fn write_chunk_locked(
        &self,
        locked: LockedUpload,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        self.uploads.write_chunk_locked(locked, offset, data).await
    }

    /// Commit an upload: finalize the blob and create a cache entry.
    #[cfg(test)]
    pub(crate) async fn commit_upload(
        &self,
        owner: &CapabilityEpoch,
        id: u64,
        expected_size: u64,
    ) -> Result<()> {
        let locked = self.uploads.lock(owner, id).await?;
        self.commit_upload_locked(locked, expected_size).await
    }

    pub(crate) async fn commit_upload_locked(
        &self,
        locked: LockedUpload,
        expected_size: u64,
    ) -> Result<()> {
        let (key, version, scope_repo, scope_ref, tmp_path, size) =
            self.uploads.commit_locked(locked, expected_size).await?;

        let hash = self
            .store
            .store_from_file(&tmp_path)
            .await
            .context("storing blob")?;

        // Incref before persist: if we crash after persist but before incref, the
        // on-disk entry would reference a blob with refcount 0 (orphan cleanup
        // would delete it). By incrementing first, the blob is protected.
        self.store.incref(&hash).await;

        let entry = CacheEntry {
            key: key.clone(),
            version: version.clone(),
            scope_repo: scope_repo.clone(),
            scope_ref: scope_ref.clone(),
            blob_hash: hash,
            size_bytes: size,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
        };

        #[cfg(test)]
        self.before_entry_publish.wait().await;

        let entry_io = self.entry_io_lock(&entry.filename());
        let _entry_io_guard = entry_io.lock().await;
        if let Err(error) = self.persist_entry(entry.clone()).await {
            self.store.decref(&entry.blob_hash).await;
            return Err(error).context("persisting entry");
        }

        // If an entry with the same scope+key+version already exists (duplicate commit),
        // decref the old blob to avoid leaking refcounts.
        let old = {
            let mut entries = self.entries.write().await;
            let old = entries.remove(&scope_repo, &scope_ref, &key, &version);
            entries.insert(entry);
            old
        };
        if let Some(old) = old {
            self.store.decref(&old.blob_hash).await;
        }
        drop(_entry_io_guard);
        drop(entry_io);

        // Run eviction if we're over limit
        self.evict().await;

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn arm_before_upload_write(&self) -> std::sync::Arc<super::test_support::Pause> {
        self.uploads.before_write.arm()
    }

    #[cfg(test)]
    pub(crate) fn arm_before_upload_session_wait(
        &self,
    ) -> std::sync::Arc<super::test_support::Pause> {
        self.uploads.before_session_wait.arm()
    }

    #[cfg(test)]
    pub(crate) fn arm_before_entry_publish(&self) -> std::sync::Arc<super::test_support::Pause> {
        self.before_entry_publish.arm()
    }

    #[cfg(test)]
    pub(crate) fn arm_before_lookup_index(&self) -> std::sync::Arc<super::test_support::Pause> {
        self.before_lookup_index.arm()
    }

    #[cfg(test)]
    pub(crate) fn arm_before_lookup_persist(&self) -> std::sync::Arc<super::test_support::Pause> {
        self.before_lookup_persist.arm()
    }

    #[cfg(test)]
    pub(crate) fn arm_before_blob_store_io(
        &self,
    ) -> std::sync::Arc<super::test_support::BlockingPause> {
        self.store.before_store_io.arm()
    }

    /// Get the filesystem path for a blob.
    pub fn blob_path(&self, hash: &str) -> Result<PathBuf, CacheError> {
        self.store.blob_path(hash)
    }

    /// Evict oldest entries until total size is under max_bytes.
    /// Each victim is validated and removed under the index lock, then its I/O
    /// runs under only that entry's coordination lock.
    async fn evict(&self) {
        loop {
            let now = Utc::now();
            let protection_window = chrono::Duration::seconds(60);
            let victim = {
                let entries = self.entries.read().await;
                let total = entries.total_size_bytes();
                if total <= self.max_bytes {
                    return;
                }
                entries
                    .lru_candidates()
                    .into_iter()
                    .find(|entry| {
                        now.signed_duration_since(entry.last_accessed_at) > protection_window
                    })
                    .cloned()
            };
            let Some(victim) = victim else {
                debug!("no evictable entries (all within protection window)");
                return;
            };

            let entry_io = self.entry_io_lock(&victim.filename());
            let _entry_io_guard = entry_io.lock().await;
            let removed = {
                let mut entries = self.entries.write().await;
                let unchanged = entries
                    .get(
                        &victim.scope_repo,
                        &victim.scope_ref,
                        &victim.key,
                        &victim.version,
                    )
                    .is_some_and(|current| {
                        current.blob_hash == victim.blob_hash
                            && current.created_at == victim.created_at
                    });
                unchanged.then(|| {
                    entries
                        .remove(
                            &victim.scope_repo,
                            &victim.scope_ref,
                            &victim.key,
                            &victim.version,
                        )
                        .expect("validated eviction entry must still exist")
                })
            };
            let Some(removed) = removed else {
                continue;
            };
            info!(
                key = removed.key,
                version = removed.version,
                scope_repo = removed.scope_repo,
                scope_ref = removed.scope_ref,
                size_bytes = removed.size_bytes,
                "evicting cache entry"
            );
            let entries_dir = self.entries_dir.clone();
            let removed_file = removed.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || {
                removed_file.remove_file(&entries_dir);
            })
            .await
            {
                warn!(error = %error, "cache entry removal task failed");
            }
            self.store.decref(&removed.blob_hash).await;
        }
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod manager_test;
