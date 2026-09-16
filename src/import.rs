use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::RunnerCredentials;

mod source;
mod target;

pub(crate) fn read_regular_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let after = file.metadata()?;
    if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path changed while opening",
        ));
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

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
