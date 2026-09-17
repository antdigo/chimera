use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::RunnerCredentials;

mod source;
mod target;

pub(crate) struct OpenedRegularFile {
    pub(crate) bytes: Vec<u8>,
    pub(crate) metadata: Metadata,
}

pub(crate) fn read_opened_regular(mut file: File) -> std::io::Result<OpenedRegularFile> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        ));
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(OpenedRegularFile { bytes, metadata })
}

pub(crate) fn read_regular_no_follow_with_metadata(
    path: &Path,
) -> std::io::Result<OpenedRegularFile> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        ));
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let opened = read_opened_regular(file)?;
    if before.dev() != opened.metadata.dev() || before.ino() != opened.metadata.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path changed while opening",
        ));
    }
    Ok(opened)
}

pub(crate) fn read_regular_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    read_regular_no_follow_with_metadata(path).map(|opened| opened.bytes)
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
