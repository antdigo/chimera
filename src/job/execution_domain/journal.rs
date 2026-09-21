use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(all(target_os = "linux", test))]
use super::AttemptIdentity;
use super::ExecutionDomainError;
use super::filesystem::{
    DirectoryIdentity, directory_identity, io_error, validate_bound_directory,
};
#[cfg(target_os = "linux")]
use super::linux::dirfd::BoundDir;

const TRUSTED_JOURNAL_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const LINUX_JOURNAL_VERSION: u32 = 2;
#[cfg(target_os = "linux")]
const LINUX_LAYOUT_VERSION: u32 = 1;
const JOURNAL_FILE: &str = "journal.json";
const NEXT_JOURNAL_FILE: &str = "journal.json.next";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DomainState {
    Provisioning,
    Ready,
    Running,
    Cleaning,
    Destroying,
    Destroyed,
    Quarantined,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedJournalRecord {
    version: u32,
    attempt_id: Uuid,
    state: DomainState,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxJournalRecord {
    version: u32,
    backend: String,
    attempt_id: Uuid,
    state: DomainState,
    layout_version: u32,
}

#[cfg(all(target_os = "linux", test))]
#[derive(Debug, Deserialize)]
struct JournalVersion {
    version: u32,
}

#[cfg(all(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LinuxJournalEvidence {
    Missing,
    TrustedV1Diagnostic,
    Recoverable(DomainState),
}

#[derive(Debug)]
enum JournalDirectory {
    Trusted(DirectoryIdentity),
    #[cfg(target_os = "linux")]
    Strict(BoundDir),
}

#[derive(Debug)]
pub(super) struct DomainLifecycle {
    attempt_dir: PathBuf,
    directory: JournalDirectory,
    attempt_id: Uuid,
    state: DomainState,
}

impl DomainLifecycle {
    pub(super) fn create(
        attempt_dir: &Path,
        attempt_id: Uuid,
    ) -> Result<Self, ExecutionDomainError> {
        let lifecycle = Self::bind(attempt_dir, attempt_id, DomainState::Provisioning)?;
        lifecycle.refuse_next()?;
        let path = lifecycle.attempt_dir.join(JOURNAL_FILE);
        let mut file = new_journal(&path)?;
        lifecycle.write_record(&mut file, &path, DomainState::Provisioning)?;
        lifecycle.sync_directory()?;
        Ok(lifecycle)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn create_strict(
        attempt_dir: &Path,
        attempt_id: Uuid,
    ) -> Result<Self, ExecutionDomainError> {
        let directory = BoundDir::open_root(attempt_dir)?;
        let lifecycle = Self {
            attempt_dir: attempt_dir.to_owned(),
            directory: JournalDirectory::Strict(directory),
            attempt_id,
            state: DomainState::Provisioning,
        };
        lifecycle.refuse_next()?;
        if let JournalDirectory::Strict(directory) = &lifecycle.directory {
            directory.write_new(
                c"journal.json",
                &lifecycle.record_bytes(DomainState::Provisioning)?,
            )?;
        }
        Ok(lifecycle)
    }

    #[cfg(all(target_os = "linux", test))]
    pub(super) fn load_strict(attempt_dir: &Path) -> Result<Self, ExecutionDomainError> {
        let mut lifecycle = Self {
            attempt_dir: attempt_dir.to_owned(),
            directory: JournalDirectory::Strict(BoundDir::open_root(attempt_dir)?),
            attempt_id: Uuid::nil(),
            state: DomainState::Provisioning,
        };
        lifecycle.refuse_next()?;
        let record = lifecycle.read_record()?;
        lifecycle.attempt_id = record.attempt_id;
        lifecycle.state = record.state;
        Ok(lifecycle)
    }

    #[cfg(test)]
    pub(super) fn load(attempt_dir: &Path) -> Result<Self, ExecutionDomainError> {
        let mut lifecycle = Self::bind(attempt_dir, Uuid::nil(), DomainState::Provisioning)?;
        lifecycle.refuse_next()?;
        let record = lifecycle.read_record()?;
        lifecycle.attempt_id = record.attempt_id;
        lifecycle.state = record.state;
        Ok(lifecycle)
    }

    fn bind(
        attempt_dir: &Path,
        attempt_id: Uuid,
        state: DomainState,
    ) -> Result<Self, ExecutionDomainError> {
        let metadata = fs::symlink_metadata(attempt_dir)
            .map_err(|source| io_error("reading journal directory", attempt_dir, source))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ExecutionDomainError::UnsafeEntry {
                path: attempt_dir.to_owned(),
            });
        }
        let attempt_dir = fs::canonicalize(attempt_dir)
            .map_err(|source| io_error("canonicalizing journal directory", attempt_dir, source))?;
        let attempt_identity =
            directory_identity(&attempt_dir, "reading journal directory identity")?;
        Ok(Self {
            attempt_dir,
            directory: JournalDirectory::Trusted(attempt_identity),
            attempt_id,
            state,
        })
    }

    pub(super) fn state(&self) -> DomainState {
        self.state
    }

    pub(super) fn transition(&mut self, to: DomainState) -> Result<(), ExecutionDomainError> {
        if !transition_allowed(self.state, to) {
            return Err(ExecutionDomainError::InvalidTransition {
                from: self.state,
                to,
            });
        }
        self.validate_directory()?;
        self.refuse_next()?;
        let current = self.read_record()?;
        if current.attempt_id != self.attempt_id || current.state != self.state {
            return Err(ExecutionDomainError::UnsafeEntry {
                path: self.attempt_dir.join(JOURNAL_FILE),
            });
        }
        self.write_next(to)?;
        self.state = to;
        Ok(())
    }

    pub(super) fn complete_destroyed(&mut self) -> Result<(), ExecutionDomainError> {
        if !matches!(
            self.state,
            DomainState::Destroying | DomainState::Quarantined
        ) {
            return Err(ExecutionDomainError::InvalidTransition {
                from: self.state,
                to: DomainState::Destroyed,
            });
        }
        self.state = DomainState::Destroyed;
        Ok(())
    }

    fn validate_directory(&self) -> Result<(), ExecutionDomainError> {
        match &self.directory {
            JournalDirectory::Trusted(identity) => {
                let metadata = fs::symlink_metadata(&self.attempt_dir).map_err(|source| {
                    io_error("reading journal directory", &self.attempt_dir, source)
                })?;
                validate_bound_directory(&self.attempt_dir, *identity, &metadata)
            }
            #[cfg(target_os = "linux")]
            JournalDirectory::Strict(directory) => directory.verify_binding(),
        }
    }

    fn refuse_next(&self) -> Result<(), ExecutionDomainError> {
        #[cfg(target_os = "linux")]
        if let JournalDirectory::Strict(directory) = &self.directory {
            return directory.refuse_entry(c"journal.json.next");
        }
        let path = self.attempt_dir.join(NEXT_JOURNAL_FILE);
        match fs::symlink_metadata(&path) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error(
                "checking pending lifecycle journal",
                &path,
                source,
            )),
            Ok(_) => Err(ExecutionDomainError::UnsafeEntry { path }),
        }
    }

    fn read_record(&self) -> Result<TrustedJournalRecord, ExecutionDomainError> {
        let path = self.attempt_dir.join(JOURNAL_FILE);
        let bytes = self.read_bytes(&path)?;
        match &self.directory {
            JournalDirectory::Trusted(_) => parse_trusted_record(&path, &bytes),
            #[cfg(target_os = "linux")]
            JournalDirectory::Strict(_) => {
                let record = parse_linux_record(&path, &bytes)?;
                Ok(TrustedJournalRecord {
                    version: record.version,
                    attempt_id: record.attempt_id,
                    state: record.state,
                })
            }
        }
    }

    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, ExecutionDomainError> {
        #[cfg(target_os = "linux")]
        if let JournalDirectory::Strict(directory) = &self.directory {
            return directory.read_regular(c"journal.json", 4096);
        }
        // NONBLOCK also makes special-file replacement fail without hanging on a FIFO.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|source| io_error("opening lifecycle journal", path, source))?;
        if !file
            .metadata()
            .map_err(|source| io_error("reading lifecycle journal metadata", path, source))?
            .is_file()
        {
            return Err(ExecutionDomainError::UnsafeEntry {
                path: path.to_owned(),
            });
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| io_error("reading lifecycle journal", path, source))?;
        Ok(bytes)
    }

    fn write_next(&self, state: DomainState) -> Result<(), ExecutionDomainError> {
        #[cfg(target_os = "linux")]
        if let JournalDirectory::Strict(directory) = &self.directory {
            return directory.write_atomic(c"journal.json", &self.record_bytes(state)?);
        }
        let next = self.attempt_dir.join(NEXT_JOURNAL_FILE);
        let mut file = new_journal(&next)?;
        self.write_record(&mut file, &next, state)?;
        let journal = self.attempt_dir.join(JOURNAL_FILE);
        fs::rename(&next, &journal)
            .map_err(|source| io_error("replacing lifecycle journal", &journal, source))?;
        self.sync_directory()
    }

    #[cfg(target_os = "linux")]
    fn record_bytes(&self, state: DomainState) -> Result<Vec<u8>, ExecutionDomainError> {
        serde_json::to_vec(&LinuxJournalRecord {
            version: LINUX_JOURNAL_VERSION,
            backend: "linux".to_owned(),
            attempt_id: self.attempt_id,
            state,
            layout_version: LINUX_LAYOUT_VERSION,
        })
        .map_err(|source| invalid_journal(&self.attempt_dir.join(JOURNAL_FILE), source))
    }

    fn write_record(
        &self,
        file: &mut File,
        path: &Path,
        state: DomainState,
    ) -> Result<(), ExecutionDomainError> {
        let record = TrustedJournalRecord {
            version: TRUSTED_JOURNAL_VERSION,
            attempt_id: self.attempt_id,
            state,
        };
        let bytes = serde_json::to_vec(&record).map_err(|source| invalid_journal(path, source))?;
        file.write_all(&bytes)
            .map_err(|source| io_error("writing lifecycle journal", path, source))?;
        file.sync_all()
            .map_err(|source| io_error("syncing lifecycle journal", path, source))
    }

    fn sync_directory(&self) -> Result<(), ExecutionDomainError> {
        #[cfg(target_os = "linux")]
        if let JournalDirectory::Strict(directory) = &self.directory {
            return directory.sync_directory();
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.attempt_dir)
            .map_err(|source| io_error("opening journal directory", &self.attempt_dir, source))?;
        dir.sync_all()
            .map_err(|source| io_error("syncing journal directory", &self.attempt_dir, source))
    }
}

#[cfg(all(target_os = "linux", test))]
pub(super) fn inspect_linux_journal(
    directory: &BoundDir,
    attempt: AttemptIdentity,
) -> Result<LinuxJournalEvidence, ExecutionDomainError> {
    directory.refuse_entry(c"journal.json.next")?;
    let bytes = match directory.read_regular(c"journal.json", 4096) {
        Ok(bytes) => bytes,
        Err(ExecutionDomainError::Backend {
            errno: Some(libc::ENOENT),
            ..
        }) => return Ok(LinuxJournalEvidence::Missing),
        Err(error) => return Err(error),
    };
    let path = directory.root_path().join(JOURNAL_FILE);
    let version = parse_version(&path, &bytes)?;
    match version {
        TRUSTED_JOURNAL_VERSION => {
            let record = parse_trusted_record(&path, &bytes)?;
            if record.attempt_id != attempt.uuid() {
                return Err(ExecutionDomainError::UnsafeEntry { path });
            }
            Ok(LinuxJournalEvidence::TrustedV1Diagnostic)
        }
        LINUX_JOURNAL_VERSION => {
            let record = parse_linux_record(&path, &bytes)?;
            if record.attempt_id != attempt.uuid() || record.state == DomainState::Destroyed {
                return Err(ExecutionDomainError::UnsafeEntry { path });
            }
            Ok(LinuxJournalEvidence::Recoverable(record.state))
        }
        version => Err(ExecutionDomainError::UnsupportedJournalVersion { path, version }),
    }
}

#[cfg(all(target_os = "linux", test))]
fn parse_version(path: &Path, bytes: &[u8]) -> Result<u32, ExecutionDomainError> {
    serde_json::from_slice::<JournalVersion>(bytes)
        .map(|record| record.version)
        .map_err(|source| invalid_journal(path, source))
}

fn parse_trusted_record(
    path: &Path,
    bytes: &[u8],
) -> Result<TrustedJournalRecord, ExecutionDomainError> {
    let record: TrustedJournalRecord =
        serde_json::from_slice(bytes).map_err(|source| invalid_journal(path, source))?;
    if record.version != TRUSTED_JOURNAL_VERSION {
        return Err(ExecutionDomainError::UnsupportedJournalVersion {
            path: path.to_owned(),
            version: record.version,
        });
    }
    Ok(record)
}

#[cfg(target_os = "linux")]
fn parse_linux_record(
    path: &Path,
    bytes: &[u8],
) -> Result<LinuxJournalRecord, ExecutionDomainError> {
    let record: LinuxJournalRecord =
        serde_json::from_slice(bytes).map_err(|source| invalid_journal(path, source))?;
    if record.version != LINUX_JOURNAL_VERSION {
        return Err(ExecutionDomainError::UnsupportedJournalVersion {
            path: path.to_owned(),
            version: record.version,
        });
    }
    if record.backend != "linux" || record.layout_version != LINUX_LAYOUT_VERSION {
        return Err(ExecutionDomainError::UnsafeEntry {
            path: path.to_owned(),
        });
    }
    Ok(record)
}

fn new_journal(path: &Path) -> Result<File, ExecutionDomainError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error("creating lifecycle journal", path, source))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("setting lifecycle journal permissions", path, source))?;
    Ok(file)
}

fn invalid_journal(path: &Path, source: serde_json::Error) -> ExecutionDomainError {
    // Serde's unknown-value errors can include credentials from a corrupt record.
    // Keep location/category diagnostics, including in Debug and the source chain.
    let source = <serde_json::Error as serde::de::Error>::custom(format!(
        "invalid journal {:?} at line {} column {}",
        source.classify(),
        source.line(),
        source.column()
    ));
    ExecutionDomainError::InvalidJournal {
        path: path.to_owned(),
        source,
    }
}

fn transition_allowed(from: DomainState, to: DomainState) -> bool {
    matches!(
        (from, to),
        (
            DomainState::Provisioning,
            DomainState::Ready | DomainState::Destroying
        ) | (
            DomainState::Ready,
            DomainState::Running | DomainState::Destroying
        ) | (
            DomainState::Running,
            DomainState::Cleaning | DomainState::Destroying
        ) | (DomainState::Cleaning, DomainState::Destroying)
            | (DomainState::Destroying, DomainState::Quarantined)
            | (DomainState::Quarantined, DomainState::Destroying)
    )
}
