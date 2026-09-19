use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use tokio::sync::RwLock;
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

pub struct CacheAuthority {
    state: RwLock<AuthorityState>,
    now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl CacheAuthority {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(AuthorityState::default()),
            now: Arc::new(Utc::now),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        Self {
            state: RwLock::new(AuthorityState::default()),
            now,
        }
    }

    fn now(&self) -> DateTime<Utc> {
        (self.now)()
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
        state
            .jobs
            .retain(|_, capability| !capability.revoked && capability.expires_at > now);
        let active_parents: std::collections::HashSet<_> = state.jobs.keys().cloned().collect();
        state
            .downloads
            .retain(|_, grant| grant.expires_at > now && active_parents.contains(&grant.parent));

        if state.jobs.contains_key(&id) {
            return Err(CacheAuthError::DuplicateToken);
        }

        state.jobs.insert(
            id.clone(),
            JobCapability {
                claims,
                expires_at: issued_at + JOB_CAPABILITY_LIFETIME,
                revoked: false,
            },
        );
        Ok(id)
    }

    pub async fn authorize(
        &self,
        token: &str,
        requested_scope: &CacheScope,
    ) -> Result<AuthorizedJob, CacheAuthError> {
        if token.is_empty() {
            return Err(CacheAuthError::Unauthorized);
        }

        let id = CapabilityId::from_token(token);
        let state = self.state.read().await;
        let now = self.now();
        let capability = state.jobs.get(&id).ok_or(CacheAuthError::Unauthorized)?;
        if capability.revoked || capability.expires_at <= now {
            return Err(CacheAuthError::Unauthorized);
        }
        if &capability.claims.scope != requested_scope {
            return Err(CacheAuthError::ScopeMismatch);
        }

        Ok(AuthorizedJob {
            capability_id: id,
            claims: capability.claims.clone(),
            expires_at: capability.expires_at.to_owned(),
        })
    }

    pub async fn revoke(&self, id: &CapabilityId) {
        let mut state = self.state.write().await;
        if let Some(capability) = state.jobs.get_mut(id) {
            capability.revoked = true;
        }
        state.downloads.retain(|_, grant| &grant.parent != id);
    }

    pub async fn issue_download(
        &self,
        job: &AuthorizedJob,
        blob_hash: String,
    ) -> Result<Uuid, CacheAuthError> {
        let mut state = self.state.write().await;
        let now = self.now();
        let parent = state
            .jobs
            .get(job.capability_id())
            .ok_or(CacheAuthError::Unauthorized)?;
        if parent.revoked || parent.expires_at <= now {
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
        let parent_active = state
            .jobs
            .get(&parent)
            .is_some_and(|capability| !capability.revoked && capability.expires_at > now);
        if grant_expired || !parent_active {
            state.downloads.remove(&grant);
            return Err(CacheAuthError::DownloadNotFound);
        }

        Ok(blob_hash)
    }
}

#[cfg(test)]
#[path = "auth_test.rs"]
mod auth_test;
