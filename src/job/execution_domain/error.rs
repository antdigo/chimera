use std::io;
use std::path::PathBuf;

use uuid::Uuid;

use super::journal::DomainState;

#[derive(Debug)]
pub enum ExecutionDomainError {
    // Lifecycle states are an internal runner contract, even though callers can
    // inspect the public error category and its redacted Display output.
    #[allow(private_interfaces)]
    InvalidTransition {
        from: DomainState,
        to: DomainState,
    },
    InvalidJournal {
        path: PathBuf,
        source: serde_json::Error,
    },
    UnsupportedJournalVersion {
        path: PathBuf,
        version: u32,
    },
    QuarantineFailed {
        cleanup: Box<ExecutionDomainError>,
        quarantine: Box<ExecutionDomainError>,
    },
    StaleJobResources {
        path: PathBuf,
    },
    StaleLegacyJobData {
        path: PathBuf,
    },
    UnsafeRoot {
        path: PathBuf,
        reason: &'static str,
    },
    ChimeraRootUnderHostTmp {
        path: PathBuf,
    },
    PoisonedRoot {
        path: PathBuf,
    },
    AttemptCollision {
        attempt_id: Uuid,
    },
    UnsafeEntry {
        path: PathBuf,
    },
    ReservedEnvironmentOverride {
        source: &'static str,
    },
    ImplicitCredentialStore {
        helper: &'static str,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Cleanup {
        path: PathBuf,
        source: io::Error,
    },
    CreationRollback {
        path: PathBuf,
        create: Box<ExecutionDomainError>,
        cleanup: io::Error,
    },
}

impl std::fmt::Display for ExecutionDomainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid-domain-transition: {from:?} to {to:?}")
            }
            Self::InvalidJournal { path, .. } => {
                write!(formatter, "invalid-lifecycle-journal: {}", path.display())
            }
            Self::UnsupportedJournalVersion { path, version } => write!(
                formatter,
                "unsupported-lifecycle-journal-version: {version}: {}",
                path.display()
            ),
            Self::QuarantineFailed {
                cleanup,
                quarantine,
            } => write!(
                formatter,
                "{cleanup}; lifecycle quarantine failed: {quarantine}"
            ),
            Self::StaleJobResources { path } => write!(
                formatter,
                "stale-job-resources: resource root is not empty: {}",
                path.display()
            ),
            Self::StaleLegacyJobData { path } => write!(
                formatter,
                "stale-legacy-job-data: refusing jobs until the legacy path is recovered: {}",
                path.display()
            ),
            Self::UnsafeRoot { path, reason } => write!(
                formatter,
                "unsafe-job-resource-root: {reason}: {}",
                path.display()
            ),
            Self::ChimeraRootUnderHostTmp { path } => write!(
                formatter,
                "chimera-root-under-host-tmp: Linux host-job isolation hides /tmp; move the Chimera root outside /tmp: {}",
                path.display()
            ),
            Self::PoisonedRoot { path } => write!(
                formatter,
                "poisoned-job-resource-root: cleanup failed; refusing new jobs: {}",
                path.display()
            ),
            Self::AttemptCollision { attempt_id } => write!(
                formatter,
                "job-resource-collision: generated attempt id already exists: {attempt_id}"
            ),
            Self::UnsafeEntry { path } => write!(
                formatter,
                "unsafe-job-resource-path: refusing replaced, symlink, or special file: {}",
                path.display()
            ),
            Self::ReservedEnvironmentOverride { source } => write!(
                formatter,
                "reserved-environment-variable: DOCKER_CONFIG cannot be changed by {source}"
            ),
            Self::ImplicitCredentialStore { helper } => write!(
                formatter,
                "reserved-host-capability: implicit Docker credential helper {helper} is not supported in host step PATH"
            ),
            Self::Io {
                operation, path, ..
            } => write!(
                formatter,
                "job-docker-config-io: {operation} failed for {}",
                path.display()
            ),
            Self::Cleanup { path, .. } => write!(
                formatter,
                "job-resource-cleanup: cleanup failed for {}",
                path.display()
            ),
            Self::CreationRollback {
                path,
                create,
                cleanup,
            } => write!(
                formatter,
                "job-resource-rollback: creation failed for {}: {create}; rollback failed: {cleanup}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ExecutionDomainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Cleanup { source, .. } => Some(source),
            Self::CreationRollback { create, .. } => Some(create),
            Self::InvalidJournal { source, .. } => Some(source),
            Self::QuarantineFailed { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}

/// A job completed and its completion was published, but the per-job Docker
/// config cleanup failed. Terminal for the runner: the resource root is no
/// longer trustworthy, so the daemon must stop instead of taking new jobs.
#[derive(Debug)]
pub struct ExecutionDomainCleanupFatalError {
    pub source: ExecutionDomainError,
}

impl std::fmt::Display for ExecutionDomainCleanupFatalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "job-resource-cleanup-fatal: completion published after cleanup failed: {}",
            self.source
        )
    }
}

impl std::error::Error for ExecutionDomainCleanupFatalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
