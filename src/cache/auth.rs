use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

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

#[derive(Clone, Debug)]
pub struct AuthorizedJob {
    capability_id: CapabilityId,
    claims: JobCapabilityClaims,
    expires_at: DateTime<Utc>,
    operation_gate: Arc<RwLock<()>>,
}

impl AuthorizedJob {
    pub fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
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
    claims: JobCapabilityClaims,
    expires_at: DateTime<Utc>,
    revoked: bool,
    operation_gate: Arc<RwLock<()>>,
}

struct DownloadGrant {
    parent: CapabilityId,
    blob_hash: String,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct AuthorityState {
    jobs: HashMap<CapabilityId, JobCapability>,
    downloads: HashMap<Uuid, DownloadGrant>,
}

impl AuthorityState {
    fn prune(&mut self, revoked: &mut HashSet<CapabilityId>, now: DateTime<Utc>) {
        self.jobs.retain(|id, capability| {
            !capability.revoked && !revoked.contains(id) && capability.expires_at > now
        });
        revoked.retain(|id| self.jobs.contains_key(id));
        self.downloads
            .retain(|_, grant| grant.expires_at > now && self.jobs.contains_key(&grant.parent));
    }
}

pub struct CacheAuthority {
    state: RwLock<AuthorityState>,
    revoked: Mutex<HashSet<CapabilityId>>,
    operation_gates: Mutex<HashMap<CapabilityId, Weak<RwLock<()>>>>,
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
            operation_gates: Mutex::new(HashMap::new()),
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
            operation_gates: Mutex::new(HashMap::new()),
            now,
            before_download_start: Default::default(),
        }
    }

    fn now(&self) -> DateTime<Utc> {
        (self.now)()
    }

    fn revoked(&self) -> MutexGuard<'_, HashSet<CapabilityId>> {
        self.revoked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_revoked(&self, id: &CapabilityId) -> bool {
        self.revoked().contains(id)
    }

    fn operation_gates(&self) -> MutexGuard<'_, HashMap<CapabilityId, Weak<RwLock<()>>>> {
        self.operation_gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Invalidate a capability synchronously so a lifecycle guard can revoke
    /// access while an async task is being unwound or dropped. The async
    /// `revoke` path additionally removes the capability's download grants.
    pub(crate) fn revoke_immediately(&self, id: &CapabilityId) {
        self.revoked().insert(id.clone());
    }

    pub async fn register_job(
        &self,
        token: &str,
        claims: JobCapabilityClaims,
        issued_at: DateTime<Utc>,
    ) -> Result<CapabilityId, CacheAuthError> {
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
        revoked.remove(&id);
        let mut operation_gates = self.operation_gates();
        operation_gates.retain(|_, gate| gate.strong_count() > 0);
        operation_gates.insert(id.clone(), Arc::downgrade(&operation_gate));
        drop(operation_gates);
        state.jobs.insert(
            id.clone(),
            JobCapability {
                claims,
                expires_at: issued_at + JOB_CAPABILITY_LIFETIME,
                revoked: false,
                operation_gate,
            },
        );
        Ok(id)
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
        if capability.revoked || self.is_revoked(&id) || capability.expires_at <= now {
            return Err(CacheAuthError::Unauthorized);
        }
        Ok(AuthorizedJob {
            capability_id: id,
            claims: capability.claims.clone(),
            expires_at: capability.expires_at.to_owned(),
            operation_gate: capability.operation_gate.clone(),
        })
    }

    pub async fn revoke(&self, id: &CapabilityId) {
        let operation_gate = self.operation_gates().get(id).and_then(Weak::upgrade);
        self.revoke_immediately(id);

        let _exclusive = match operation_gate {
            Some(operation_gate) => Some(operation_gate.write_owned().await),
            None => None,
        };

        let mut state = self.state.write().await;
        if let Some(capability) = state.jobs.get_mut(id) {
            capability.revoked = true;
        }
        state.downloads.retain(|_, grant| &grant.parent != id);
        self.operation_gates().remove(id);
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
        if capability.revoked
            || self.is_revoked(job.capability_id())
            || capability.expires_at <= now
            || !Arc::ptr_eq(&capability.operation_gate, &job.operation_gate)
        {
            return Err(CacheAuthError::Unauthorized);
        }

        Ok(CacheOperationPermit { _guard: guard })
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
        let parent = state
            .jobs
            .get(job.capability_id())
            .ok_or(CacheAuthError::Unauthorized)?;
        if !Arc::ptr_eq(&parent.operation_gate, &job.operation_gate) {
            return Err(CacheAuthError::Unauthorized);
        }
        let expires_at = parent.expires_at.to_owned();
        let grant = Uuid::new_v4();
        state.downloads.insert(
            grant,
            DownloadGrant {
                parent: job.capability_id().clone(),
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
        let parent_active = state.jobs.get(&parent).is_some_and(|capability| {
            !capability.revoked && !self.is_revoked(&parent) && capability.expires_at > now
        });
        if grant_expired || !parent_active {
            state.downloads.remove(&grant);
            return Err(CacheAuthError::DownloadNotFound);
        }

        Ok(blob_hash)
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
                .get(&download.parent)
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
            .get(&download.parent)
            .ok_or(CacheAuthError::DownloadNotFound)?;
        if download.expires_at <= now
            || parent.revoked
            || self.is_revoked(&download.parent)
            || parent.expires_at <= now
            || !Arc::ptr_eq(&parent.operation_gate, &operation_gate)
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
