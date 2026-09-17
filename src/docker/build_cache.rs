use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const CACHE_SCHEMA_VERSION: u8 = 1;
const BUILD_OPTIONS_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DockerBuildScope {
    runner_identity: String,
    github_scope: String,
}

impl DockerBuildScope {
    pub fn new(runner_identity: impl Into<String>, github_scope: impl Into<String>) -> Self {
        Self {
            runner_identity: runner_identity.into(),
            github_scope: github_scope.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BuildCacheKey {
    cache_schema: u8,
    options_schema: u8,
    daemon_id: String,
    runner_identity: String,
    github_scope: String,
    platform: String,
    dockerfile: String,
    context_digest: [u8; 32],
}

impl BuildCacheKey {
    pub(crate) fn new(
        daemon_id: &str,
        scope: &DockerBuildScope,
        platform: &str,
        dockerfile: &str,
        context_digest: [u8; 32],
    ) -> Self {
        Self {
            cache_schema: CACHE_SCHEMA_VERSION,
            options_schema: BUILD_OPTIONS_SCHEMA_VERSION,
            daemon_id: daemon_id.to_string(),
            runner_identity: scope.runner_identity.clone(),
            github_scope: scope.github_scope.clone(),
            platform: platform.to_string(),
            dockerfile: dockerfile.to_string(),
            context_digest,
        }
    }

    pub(crate) fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        for field in [
            vec![self.cache_schema],
            vec![self.options_schema],
            self.daemon_id.as_bytes().to_vec(),
            self.runner_identity.as_bytes().to_vec(),
            self.github_scope.as_bytes().to_vec(),
            self.platform.as_bytes().to_vec(),
            self.dockerfile.as_bytes().to_vec(),
            self.context_digest.to_vec(),
        ] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(&field);
        }
        hasher.finalize().to_hex().to_string()
    }

    pub(crate) fn internal_tag(&self, namespace: &str) -> String {
        format!(
            "chimera-internal/action-cache:{namespace}-{}",
            self.fingerprint()
        )
    }
}

pub(crate) enum BudgetOutcome<T> {
    Ready(T),
    Cancelled,
    TimedOut,
}

pub(crate) async fn within_budget<T>(
    deadline: Instant,
    cancel_token: &CancellationToken,
    future: impl Future<Output = T>,
) -> BudgetOutcome<T> {
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => BudgetOutcome::Cancelled,
        _ = tokio::time::sleep_until(deadline) => BudgetOutcome::TimedOut,
        value = &mut future => BudgetOutcome::Ready(value),
    }
}

pub(crate) struct BuildCache {
    entries: Mutex<HashMap<BuildCacheKey, String>>,
    locks: Mutex<HashMap<BuildCacheKey, Arc<Mutex<()>>>>,
}

pub(crate) enum CacheOutcome {
    Ready { image_id: String, cache_hit: bool },
    Cancelled,
    TimedOut,
}

impl BuildCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn get_or_build<I, IFut, B, BFut>(
        &self,
        key: BuildCacheKey,
        deadline: Instant,
        cancel_token: &CancellationToken,
        inspect: I,
        build: B,
    ) -> Result<CacheOutcome>
    where
        I: Fn(String) -> IFut,
        IFut: Future<Output = Result<bool>>,
        B: FnOnce() -> BFut,
        BFut: Future<Output = Result<String>>,
    {
        let key_lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = match within_budget(deadline, cancel_token, key_lock.lock_owned()).await {
            BudgetOutcome::Ready(guard) => guard,
            BudgetOutcome::Cancelled => return Ok(CacheOutcome::Cancelled),
            BudgetOutcome::TimedOut => return Ok(CacheOutcome::TimedOut),
        };

        let cached_image_id = {
            let entries = self.entries.lock().await;
            entries.get(&key).cloned()
        };
        if let Some(image_id) = cached_image_id {
            match within_budget(deadline, cancel_token, inspect(image_id.clone())).await {
                BudgetOutcome::Ready(Ok(true)) => {
                    return Ok(CacheOutcome::Ready {
                        image_id,
                        cache_hit: true,
                    });
                }
                BudgetOutcome::Ready(Ok(false)) => {
                    self.entries.lock().await.remove(&key);
                }
                BudgetOutcome::Ready(Err(error)) => return Err(error),
                BudgetOutcome::Cancelled => return Ok(CacheOutcome::Cancelled),
                BudgetOutcome::TimedOut => return Ok(CacheOutcome::TimedOut),
            }
        }

        match within_budget(deadline, cancel_token, build()).await {
            BudgetOutcome::Ready(Ok(image_id)) => {
                self.entries.lock().await.insert(key, image_id.clone());
                Ok(CacheOutcome::Ready {
                    image_id,
                    cache_hit: false,
                })
            }
            BudgetOutcome::Ready(Err(error)) => Err(error),
            BudgetOutcome::Cancelled => Ok(CacheOutcome::Cancelled),
            BudgetOutcome::TimedOut => Ok(CacheOutcome::TimedOut),
        }
    }

    #[cfg(test)]
    pub(super) async fn key_lock_for_test(&self, key: BuildCacheKey) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .await
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    #[cfg(test)]
    pub(super) async fn entry_count_for_test(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
#[path = "build_cache_test.rs"]
mod build_cache_test;
