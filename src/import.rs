use std::path::PathBuf;

use crate::config::RunnerCredentials;

mod source;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("invalid-source: {0}")]
    InvalidSource(String),
    #[error("unsupported-registration: {0}")]
    UnsupportedRegistration(String),
    #[error("identity-conflict: {0}")]
    IdentityConflict(String),
    #[error("target-busy: {0}")]
    TargetBusy(String),
    #[error("write-failed: {0}")]
    WriteFailed(String),
}

impl ImportError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidSource(_) => "invalid-source",
            Self::UnsupportedRegistration(_) => "unsupported-registration",
            Self::IdentityConflict(_) => "identity-conflict",
            Self::TargetBusy(_) => "target-busy",
            Self::WriteFailed(_) => "write-failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunnerIdentity {
    scope: String,
    pool_id: u64,
    agent_id: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedRegistration {
    credentials: RunnerCredentials,
    identity: RunnerIdentity,
    canonical_source: PathBuf,
}

#[cfg(test)]
pub(crate) mod test_support;
