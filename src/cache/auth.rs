use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use uuid::Uuid;

pub const JOB_CAPABILITY_LIFETIME: Duration = Duration::minutes(6 * 60 + 10);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityId([u8; 32]);

impl CapabilityId {
    pub(crate) fn from_token(token: &str) -> Self {
        Self(*blake3::hash(token.as_bytes()).as_bytes())
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct CapabilityEpoch {
    capability_id: CapabilityId,
    registration_id: Uuid,
}

impl CapabilityEpoch {
    #[cfg(test)]
    pub(crate) fn for_test(token: &str) -> Self {
        Self {
            capability_id: CapabilityId::from_token(token),
            registration_id: Uuid::new_v4(),
        }
    }
}

impl fmt::Debug for CapabilityEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityEpoch([redacted])")
    }
}

#[derive(Clone)]
pub struct CapabilityHandle {
    epoch: CapabilityEpoch,
    operation_gate: Arc<RwLock<()>>,
}

impl CapabilityHandle {
    pub fn capability_id(&self) -> &CapabilityId {
        &self.epoch.capability_id
    }
}

impl fmt::Debug for CapabilityHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityHandle([redacted])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheScope {
    pub repo: String,
    pub git_ref: String,
    pub default_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobCapabilityClaims {
    pub scope: CacheScope,
    pub job_id: String,
}

#[derive(Clone)]
pub struct AuthorizedJob {
    epoch: CapabilityEpoch,
    claims: JobCapabilityClaims,
    expires_at: DateTime<Utc>,
    operation_gate: Arc<RwLock<()>>,
}

impl AuthorizedJob {
    pub fn capability_id(&self) -> &CapabilityId {
        &self.epoch.capability_id
    }

    pub(crate) fn epoch(&self) -> &CapabilityEpoch {
        &self.epoch
    }

    #[cfg(test)]
    pub(crate) fn lifecycle_handle(&self) -> CapabilityHandle {
        CapabilityHandle {
            epoch: self.epoch.clone(),
            operation_gate: self.operation_gate.clone(),
        }
    }

    pub fn scope(&self) -> &CacheScope {
        &self.claims.scope
    }

    pub fn job_id(&self) -> &str {
        &self.claims.job_id
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at.to_owned()
    }
}

impl fmt::Debug for AuthorizedJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedJob")
            .field("claims", &self.claims)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CacheAuthError {
    #[error("runtime token is empty")]
    EmptyToken,
    #[error("runtime token already has an active capability")]
    DuplicateToken,
    #[error("cache capability is not active")]
    Unauthorized,
    #[error("cache URL scope does not match the capability")]
    ScopeMismatch,
    #[error("download grant not found")]
    DownloadNotFound,
}

struct JobCapability {
    epoch: CapabilityEpoch,
    claims: JobCapabilityClaims,
    expires_at: DateTime<Utc>,
    operation_gate: Arc<RwLock<()>>,
}

struct DownloadGrant {
    parent: CapabilityEpoch,
    blob_hash: String,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct AuthorityState {
    jobs: HashMap<CapabilityId, JobCapability>,
    downloads: HashMap<Uuid, DownloadGrant>,
}

impl AuthorityState {
    fn prune(&mut self, revoked: &mut HashSet<CapabilityEpoch>, now: DateTime<Utc>) {
        self.jobs.retain(|_, capability| {
            if revoked.contains(&capability.epoch) || capability.expires_at <= now {
                capability.operation_gate.try_write().is_err()
            } else {
                true
            }
        });
        revoked.retain(|epoch| {
            self.jobs
                .get(&epoch.capability_id)
                .is_some_and(|job| job.epoch == *epoch)
        });
        self.downloads.retain(|_, grant| {
            grant.expires_at > now
                && self
                    .jobs
                    .get(&grant.parent.capability_id)
                    .is_some_and(|job| job.epoch == grant.parent)
        });
    }
}

pub struct CacheAuthority {
    state: RwLock<AuthorityState>,
    revoked: Mutex<HashSet<CapabilityEpoch>>,
    now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    #[cfg(test)]
    pub(crate) before_download_start: super::test_support::PausePoint,
}

impl Default for CacheAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheAuthority {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(AuthorityState::default()),
            revoked: Mutex::new(HashSet::new()),
            now: Arc::new(Utc::now),
            #[cfg(test)]
            before_download_start: Default::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        Self {
            state: RwLock::new(AuthorityState::default()),
            revoked: Mutex::new(HashSet::new()),
            now,
            before_download_start: Default::default(),
        }
    }

    fn now(&self) -> DateTime<Utc> {
        (self.now)()
    }

    fn revoked(&self) -> MutexGuard<'_, HashSet<CapabilityEpoch>> {
        self.revoked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_revoked(&self, epoch: &CapabilityEpoch) -> bool {
        self.revoked().contains(epoch)
    }

    /// Invalidate a capability synchronously so a lifecycle guard can revoke
    /// access while an async task is being unwound or dropped. The async
    /// `revoke` path additionally removes the capability's download grants.
    pub(crate) fn revoke_immediately(&self, handle: &CapabilityHandle) {
        self.revoked().insert(handle.epoch.clone());
    }

    pub async fn register_job(
        &self,
        token: &str,
        claims: JobCapabilityClaims,
        issued_at: DateTime<Utc>,
    ) -> Result<CapabilityHandle, CacheAuthError> {
        if token.is_empty() {
            return Err(CacheAuthError::EmptyToken);
        }

        let id = CapabilityId::from_token(token);
        let mut state = self.state.write().await;
        let now = self.now();
        let mut revoked = self.revoked();
        state.prune(&mut revoked, now);

        if state.jobs.contains_key(&id) {
            return Err(CacheAuthError::DuplicateToken);
        }

        let operation_gate = Arc::new(RwLock::new(()));
        let epoch = CapabilityEpoch {
            capability_id: id.clone(),
            registration_id: Uuid::new_v4(),
        };
        state.jobs.insert(
            id.clone(),
            JobCapability {
                epoch: epoch.clone(),
                claims,
                expires_at: issued_at + JOB_CAPABILITY_LIFETIME,
                operation_gate: operation_gate.clone(),
            },
        );
        Ok(CapabilityHandle {
            epoch,
            operation_gate,
        })
    }

    pub async fn authorize(
        &self,
        token: &str,
        requested_scope: &CacheScope,
    ) -> Result<AuthorizedJob, CacheAuthError> {
        let job = self.authenticate(token).await?;
        if job.scope() != requested_scope {
            return Err(CacheAuthError::ScopeMismatch);
        }
        Ok(job)
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthorizedJob, CacheAuthError> {
        if token.is_empty() {
            return Err(CacheAuthError::Unauthorized);
        }

        let id = CapabilityId::from_token(token);
        let state = self.state.read().await;
        let now = self.now();
        let capability = state.jobs.get(&id).ok_or(CacheAuthError::Unauthorized)?;
        if self.is_revoked(&capability.epoch) || capability.expires_at <= now {
            return Err(CacheAuthError::Unauthorized);
        }
        Ok(AuthorizedJob {
            epoch: capability.epoch.clone(),
            claims: capability.claims.clone(),
            expires_at: capability.expires_at.to_owned(),
            operation_gate: capability.operation_gate.clone(),
        })
    }

    pub async fn revoke(&self, handle: &CapabilityHandle) {
        self.revoked().insert(handle.epoch.clone());
        let _exclusive = handle.operation_gate.clone().write_owned().await;

        let mut state = self.state.write().await;
        if state
            .jobs
            .get(handle.capability_id())
            .is_some_and(|capability| capability.epoch == handle.epoch)
        {
            state.jobs.remove(handle.capability_id());
        }
        state
            .downloads
            .retain(|_, grant| grant.parent != handle.epoch);
        self.revoked().remove(&handle.epoch);
    }

    pub(crate) async fn admit(
        &self,
        job: &AuthorizedJob,
    ) -> Result<CacheOperationPermit, CacheAuthError> {
        let guard = job.operation_gate.clone().read_owned().await;
        let state = self.state.read().await;
        let now = self.now();
        let capability = state
            .jobs
            .get(job.capability_id())
            .ok_or(CacheAuthError::Unauthorized)?;
        if self.is_revoked(job.epoch())
            || capability.expires_at <= now
            || capability.epoch != job.epoch
        {
            return Err(CacheAuthError::Unauthorized);
        }

        Ok(CacheOperationPermit {
            epoch: job.epoch.clone(),
            _guard: guard,
        })
    }

    pub(crate) async fn revalidate(
        &self,
        permit: &CacheOperationPermit,
    ) -> Result<(), CacheAuthError> {
        let state = self.state.read().await;
        let capability = state
            .jobs
            .get(&permit.epoch.capability_id)
            .ok_or(CacheAuthError::Unauthorized)?;
        if self.is_revoked(&permit.epoch)
            || capability.expires_at <= self.now()
            || capability.epoch != permit.epoch
        {
            return Err(CacheAuthError::Unauthorized);
        }
        Ok(())
    }

    pub async fn issue_download(
        &self,
        job: &AuthorizedJob,
        blob_hash: String,
    ) -> Result<Uuid, CacheAuthError> {
        let mut state = self.state.write().await;
        let now = self.now();
        let mut revoked = self.revoked();
        state.prune(&mut revoked, now);
        drop(revoked);
        let parent = state
            .jobs
            .get(job.capability_id())
            .ok_or(CacheAuthError::Unauthorized)?;
        if parent.epoch != job.epoch || parent.expires_at <= now || self.is_revoked(job.epoch()) {
            return Err(CacheAuthError::Unauthorized);
        }
        let expires_at = parent.expires_at.to_owned();
        let grant = Uuid::new_v4();
        state.downloads.insert(
            grant,
            DownloadGrant {
                parent: job.epoch.clone(),
                blob_hash,
                expires_at,
            },
        );
        Ok(grant)
    }

    pub async fn resolve_download(&self, grant: Uuid) -> Result<String, CacheAuthError> {
        let mut state = self.state.write().await;
        let now = self.now();
        let Some(download) = state.downloads.get(&grant) else {
            return Err(CacheAuthError::DownloadNotFound);
        };
        let parent = download.parent.clone();
        let blob_hash = download.blob_hash.clone();
        let grant_expired = download.expires_at <= now;
        let parent_active = state
            .jobs
            .get(&parent.capability_id)
            .is_some_and(|capability| {
                capability.epoch == parent
                    && !self.is_revoked(&parent)
                    && capability.expires_at > now
            });
        if grant_expired || !parent_active {
            state.downloads.remove(&grant);
            return Err(CacheAuthError::DownloadNotFound);
        }

        Ok(blob_hash)
    }

    #[cfg(test)]
    pub(crate) async fn download_count(&self) -> usize {
        self.state.read().await.downloads.len()
    }

    pub(crate) async fn authorize_download_start(
        &self,
        grant: Uuid,
    ) -> Result<AuthorizedDownload, CacheAuthError> {
        let operation_gate = {
            let state = self.state.read().await;
            let download = state
                .downloads
                .get(&grant)
                .ok_or(CacheAuthError::DownloadNotFound)?;
            state
                .jobs
                .get(&download.parent.capability_id)
                .filter(|capability| capability.epoch == download.parent)
                .map(|capability| capability.operation_gate.clone())
                .ok_or(CacheAuthError::DownloadNotFound)?
        };
        let guard = operation_gate.clone().read_owned().await;
        let state = self.state.read().await;
        let now = self.now();
        let download = state
            .downloads
            .get(&grant)
            .ok_or(CacheAuthError::DownloadNotFound)?;
        let parent = state
            .jobs
            .get(&download.parent.capability_id)
            .ok_or(CacheAuthError::DownloadNotFound)?;
        if download.expires_at <= now
            || self.is_revoked(&download.parent)
            || parent.expires_at <= now
            || parent.epoch != download.parent
        {
            return Err(CacheAuthError::DownloadNotFound);
        }

        Ok(AuthorizedDownload {
            blob_hash: download.blob_hash.clone(),
            _guard: guard,
        })
    }
}

pub(crate) struct CacheOperationPermit {
    epoch: CapabilityEpoch,
    _guard: OwnedRwLockReadGuard<()>,
}

pub(crate) struct AuthorizedDownload {
    blob_hash: String,
    _guard: OwnedRwLockReadGuard<()>,
}

impl AuthorizedDownload {
    pub(crate) fn blob_hash(&self) -> &str {
        &self.blob_hash
    }
}

#[cfg(test)]
#[path = "auth_test.rs"]
mod auth_test;
