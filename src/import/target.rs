use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::config::{ChimeraConfig, ChimeraPaths, RunnerCredentials};
use crate::storage::{RootLockError, open_existing_root};

use super::source::{existing_runner_identity, read_official_registration};
use super::{
    ImportError, ImportOutcome, ImportStatus, OpenedRegularFile, RunnerIdentity,
    ValidatedRegistration, read_opened_regular,
};

const CREDENTIAL_FILES: [&str; 3] = ["runner.json", "credentials.json", "rsa_params.json"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CredentialSetSnapshot {
    directory: FileIdentity,
    files: [FileIdentity; 3],
}

#[derive(Debug)]
struct PinnedCredentialFile {
    name: CString,
    file: File,
    identity: FileIdentity,
}

#[derive(Debug)]
pub(super) struct PinnedCredentialSet {
    parent: File,
    name: CString,
    directory: File,
    snapshot: CredentialSetSnapshot,
    files: Vec<PinnedCredentialFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetDisposition {
    New,
    Resume,
    AlreadyImported,
}

#[derive(Debug)]
enum ConfigSnapshot {
    Missing,
    Existing {
        identity: FileIdentity,
        bytes: Vec<u8>,
        mode: u32,
    },
}

#[derive(Debug)]
pub(crate) struct PreservedConfig {
    model: ChimeraConfig,
    document: toml::Table,
    snapshot: ConfigSnapshot,
}

impl PreservedConfig {
    const fn mode(&self) -> Option<u32> {
        match &self.snapshot {
            ConfigSnapshot::Missing => None,
            ConfigSnapshot::Existing { mode, .. } => Some(*mode),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreparedImport {
    name: String,
    registration: ValidatedRegistration,
    paths: ChimeraPaths,
    config: PreservedConfig,
    disposition: TargetDisposition,
    credential_snapshot: Option<CredentialSetSnapshot>,
    locked_root: Option<File>,
}

impl PreparedImport {
    pub(super) fn outcome(&self, status: ImportStatus) -> ImportOutcome {
        ImportOutcome {
            status,
            local_name: self.name.clone(),
            agent_id: self.registration.credentials.info.agent_id,
        }
    }

    pub(super) fn canonical_root(&self) -> &Path {
        &self.paths.root
    }

    pub(super) const fn disposition(&self) -> TargetDisposition {
        self.disposition
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn credentials(&self) -> &RunnerCredentials {
        &self.registration.credentials
    }

    pub(super) fn configured_runners(&self) -> &[String] {
        &self.config.model.runners
    }

    pub(super) const fn config_document(&self) -> &toml::Table {
        &self.config.document
    }

    pub(super) const fn config_mode(&self) -> Option<u32> {
        self.config.mode()
    }

    pub(super) const fn config_was_missing(&self) -> bool {
        matches!(&self.config.snapshot, ConfigSnapshot::Missing)
    }

    pub(super) const fn credential_snapshot(&self) -> Option<&CredentialSetSnapshot> {
        self.credential_snapshot.as_ref()
    }

    pub(super) fn locked_root(&self) -> Result<&File, ImportError> {
        self.locked_root.as_ref().ok_or_else(|| {
            ImportError::WriteFailed("import commit is missing the locked root descriptor".into())
        })
    }

    pub(super) fn validate_visible_root(&self) -> Result<(), ImportError> {
        verify_opened_root_matches_path(self.locked_root()?, &self.paths.root)
    }

    pub(super) fn validate_original_config(&self) -> Result<(), ImportError> {
        self.config.snapshot.validate(self.locked_root()?)
    }
}

pub(crate) fn prepare_import(
    source: &Path,
    name: &str,
    root: &Path,
) -> Result<PreparedImport, ImportError> {
    validate_local_name(name)?;
    let registration = read_official_registration(source)?;
    let opened_root = open_root_if_present(root)?;

    let canonical_root = canonicalize_allow_missing(root)?;
    if let Some(root) = opened_root.as_ref() {
        verify_opened_root_matches_path(root, &canonical_root)?;
    }
    prepare_with_root(
        name,
        registration,
        ChimeraPaths::new(canonical_root),
        opened_root,
        false,
    )
}

pub(crate) fn prepare_import_locked(
    source: &Path,
    name: &str,
    canonical_root: &Path,
    locked_root: File,
) -> Result<PreparedImport, ImportError> {
    validate_local_name(name)?;
    let registration = read_official_registration(source)?;
    prepare_with_root(
        name,
        registration,
        ChimeraPaths::new(canonical_root.to_path_buf()),
        Some(locked_root),
        true,
    )
}

fn prepare_with_root(
    name: &str,
    registration: ValidatedRegistration,
    paths: ChimeraPaths,
    opened_root: Option<File>,
    retain_locked_root: bool,
) -> Result<PreparedImport, ImportError> {
    if retain_locked_root {
        let root = opened_root.as_ref().ok_or_else(|| {
            ImportError::WriteFailed("import commit is missing the locked root descriptor".into())
        })?;
        verify_opened_root_matches_path(root, &paths.root)?;
    }

    let target = paths.runner_dir(name);
    if registration.canonical_source.starts_with(&target)
        || target.starts_with(&registration.canonical_source)
    {
        return Err(ImportError::InvalidSource(
            "source and target paths must not overlap".into(),
        ));
    }

    let (config, existing) = match opened_root.as_ref() {
        Some(root) => (
            load_preserved_config(root)?,
            inspect_existing_credentials(root)?,
        ),
        None => (default_preserved_config()?, BTreeMap::new()),
    };
    validate_config_entries(name, &config, &existing)?;
    let disposition = classify_disposition(name, &registration, &config, &existing)?;
    let credential_snapshot = match disposition {
        TargetDisposition::New => None,
        TargetDisposition::Resume | TargetDisposition::AlreadyImported => {
            let root = opened_root.as_ref().ok_or_else(|| {
                ImportError::WriteFailed("unable to pin adopted runner credentials".into())
            })?;
            let runners = open_directory_at(root, OsStr::new("runners")).map_err(|_| {
                ImportError::WriteFailed("unable to pin adopted runner credentials".into())
            })?;
            let pinned = pin_credential_set(&runners, name, None, &registration.credentials)?;
            Some(pinned.snapshot.clone())
        }
    };

    Ok(PreparedImport {
        name: name.to_owned(),
        registration,
        paths,
        config,
        disposition,
        credential_snapshot,
        locked_root: if retain_locked_root {
            opened_root
        } else {
            None
        },
    })
}

fn validate_local_name(name: &str) -> Result<(), ImportError> {
    let valid_length = (1..=128).contains(&name.len());
    let valid_chars = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_length || !valid_chars || matches!(name, "." | "..") {
        return Err(ImportError::InvalidSource(
            "local name must be 1-128 ASCII characters from [A-Za-z0-9._-] and not '.' or '..'"
                .into(),
        ));
    }
    Ok(())
}

fn open_root_if_present(root: &Path) -> Result<Option<File>, ImportError> {
    match open_existing_root(root) {
        Ok(root) => Ok(Some(root)),
        Err(RootLockError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ImportError::WriteFailed(
            "unable to validate existing target root".into(),
        )),
    }
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf, ImportError> {
    let mut ancestor = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ImportError::WriteFailed("unable to resolve target root".into()))?
            .join(path)
    };
    let mut missing = Vec::<OsString>::new();

    loop {
        match std::fs::symlink_metadata(&ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = ancestor.components().next_back().ok_or_else(|| {
                    ImportError::WriteFailed("unable to resolve target root".into())
                })?;
                match component {
                    Component::Normal(value) => missing.push(value.to_owned()),
                    Component::CurDir => {}
                    Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                        return Err(ImportError::WriteFailed(
                            "target root has an unsupported missing path component".into(),
                        ));
                    }
                }
                if !ancestor.pop() {
                    return Err(ImportError::WriteFailed(
                        "unable to resolve target root".into(),
                    ));
                }
            }
            Err(_) => {
                return Err(ImportError::WriteFailed(
                    "unable to inspect target root".into(),
                ));
            }
        }
    }

    let mut canonical = std::fs::canonicalize(&ancestor)
        .map_err(|_| ImportError::WriteFailed("unable to resolve target root".into()))?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn verify_opened_root_matches_path(root: &File, path: &Path) -> Result<(), ImportError> {
    let opened = root
        .metadata()
        .map_err(|_| ImportError::WriteFailed("unable to inspect opened target root".into()))?;
    let resolved = open_existing_root(path).map_err(|_| {
        ImportError::WriteFailed("visible target root changed during import".into())
    })?;
    let resolved = resolved.metadata().map_err(|_| {
        ImportError::WriteFailed("visible target root changed during import".into())
    })?;
    if FileIdentity::from_metadata(&opened) != FileIdentity::from_metadata(&resolved) {
        return Err(ImportError::WriteFailed(
            "visible target root changed during import".into(),
        ));
    }
    Ok(())
}

fn load_preserved_config(root: &File) -> Result<PreservedConfig, ImportError> {
    let file = match open_regular_at(root, OsStr::new("config.toml")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return default_preserved_config();
        }
        Err(_) => {
            return Err(ImportError::WriteFailed(
                "unable to read existing config.toml".into(),
            ));
        }
    };
    let opened = read_opened_regular(file)
        .map_err(|_| ImportError::WriteFailed("unable to read existing config.toml".into()))?;
    preserved_config_from_opened(opened)
}

fn preserved_config_from_opened(opened: OpenedRegularFile) -> Result<PreservedConfig, ImportError> {
    let text = std::str::from_utf8(&opened.bytes)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let model = toml::from_str(text)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let document = toml::from_str(text)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let identity = FileIdentity::from_metadata(&opened.metadata);
    let mode = opened.metadata.mode() & 0o777;

    Ok(PreservedConfig {
        model,
        document,
        snapshot: ConfigSnapshot::Existing {
            identity,
            bytes: opened.bytes,
            mode,
        },
    })
}

fn default_preserved_config() -> Result<PreservedConfig, ImportError> {
    let model = ChimeraConfig::default();
    let text = toml::to_string_pretty(&model)
        .map_err(|_| ImportError::WriteFailed("unable to prepare default config.toml".into()))?;
    let document = toml::from_str(&text)
        .map_err(|_| ImportError::WriteFailed("unable to prepare default config.toml".into()))?;
    Ok(PreservedConfig {
        model,
        document,
        snapshot: ConfigSnapshot::Missing,
    })
}

impl ConfigSnapshot {
    fn validate(&self, root: &File) -> Result<(), ImportError> {
        match self {
            Self::Missing => match open_regular_at(root, OsStr::new("config.toml")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Ok(_) | Err(_) => Err(ImportError::WriteFailed(
                    "config.toml changed during import".into(),
                )),
            },
            Self::Existing {
                identity,
                bytes,
                mode,
            } => {
                let file = open_regular_at(root, OsStr::new("config.toml")).map_err(|_| {
                    ImportError::WriteFailed("config.toml changed during import".into())
                })?;
                let opened = read_opened_regular(file).map_err(|_| {
                    ImportError::WriteFailed("config.toml changed during import".into())
                })?;
                if FileIdentity::from_metadata(&opened.metadata) != *identity
                    || opened.bytes != *bytes
                    || opened.metadata.mode() & 0o777 != *mode
                {
                    return Err(ImportError::WriteFailed(
                        "config.toml changed during import".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

pub(super) fn pin_credential_set(
    runners: &File,
    name: &str,
    expected_snapshot: Option<&CredentialSetSnapshot>,
    expected_credentials: &RunnerCredentials,
) -> Result<PinnedCredentialSet, ImportError> {
    let name = path_component(OsStr::new(name))
        .map_err(|_| ImportError::WriteFailed("unable to pin adopted runner credentials".into()))?;
    let directory = open_directory_at(runners, OsStr::from_bytes(name.as_bytes()))
        .map_err(|_| ImportError::WriteFailed("unable to pin adopted runner credentials".into()))?;
    validate_private_owned_directory(&directory).map_err(|_| {
        ImportError::WriteFailed("adopted runner credentials are not private owned storage".into())
    })?;
    let directory_identity = file_identity(&directory)
        .map_err(|_| ImportError::WriteFailed("unable to pin adopted runner credentials".into()))?;
    ensure_entry_identity(runners, &name, directory_identity).map_err(|_| {
        ImportError::WriteFailed("adopted runner credentials changed during import".into())
    })?;
    validate_exact_credential_entries(&directory).map_err(|_| {
        ImportError::WriteFailed("adopted runner credential set is incomplete or unsafe".into())
    })?;

    let mut files = Vec::with_capacity(CREDENTIAL_FILES.len());
    let mut identities = Vec::with_capacity(CREDENTIAL_FILES.len());
    for file_name in CREDENTIAL_FILES {
        let component = path_component(OsStr::new(file_name)).map_err(|_| {
            ImportError::WriteFailed("unable to pin adopted runner credentials".into())
        })?;
        let file =
            open_regular_at(&directory, OsStr::from_bytes(component.as_bytes())).map_err(|_| {
                ImportError::WriteFailed("unable to pin adopted runner credentials".into())
            })?;
        validate_private_owned_regular_file(&file).map_err(|_| {
            ImportError::WriteFailed(
                "adopted runner credentials are not private owned storage".into(),
            )
        })?;
        let identity = file_identity(&file).map_err(|_| {
            ImportError::WriteFailed("unable to pin adopted runner credentials".into())
        })?;
        ensure_entry_identity(&directory, &component, identity).map_err(|_| {
            ImportError::WriteFailed("adopted runner credentials changed during import".into())
        })?;
        identities.push(identity);
        files.push(PinnedCredentialFile {
            name: component,
            file,
            identity,
        });
    }
    let files_identity: [FileIdentity; 3] = identities
        .try_into()
        .map_err(|_| ImportError::WriteFailed("unable to pin adopted runner credentials".into()))?;
    let snapshot = CredentialSetSnapshot {
        directory: directory_identity,
        files: files_identity,
    };
    if expected_snapshot.is_some_and(|expected| expected != &snapshot) {
        return Err(ImportError::WriteFailed(
            "adopted runner credentials changed during import".into(),
        ));
    }

    let pinned = PinnedCredentialSet {
        parent: runners.try_clone().map_err(|_| {
            ImportError::WriteFailed("unable to pin adopted runner credentials".into())
        })?,
        name,
        directory,
        snapshot,
        files,
    };
    pinned.validate(expected_credentials)?;
    Ok(pinned)
}

impl PinnedCredentialSet {
    pub(super) const fn snapshot(&self) -> &CredentialSetSnapshot {
        &self.snapshot
    }

    pub(super) fn validate(
        &self,
        expected_credentials: &RunnerCredentials,
    ) -> Result<(), ImportError> {
        self.validate_namespace()?;
        let loaded = crate::config::load_runner_credentials_from_directory(&self.directory)
            .map_err(|_| {
                ImportError::WriteFailed("adopted runner credential validation failed".into())
            })?;
        if loaded != *expected_credentials {
            return Err(ImportError::WriteFailed(
                "adopted runner credentials changed during import".into(),
            ));
        }
        self.validate_namespace()
    }

    fn validate_namespace(&self) -> Result<(), ImportError> {
        ensure_entry_identity(&self.parent, &self.name, self.snapshot.directory)
            .and_then(|()| ensure_file_identity(&self.directory, self.snapshot.directory))
            .and_then(|()| validate_private_owned_directory(&self.directory))
            .and_then(|()| validate_exact_credential_entries(&self.directory))
            .map_err(|_| {
                ImportError::WriteFailed("adopted runner credentials changed during import".into())
            })?;

        for (index, file) in self.files.iter().enumerate() {
            let expected = self.snapshot.files.get(index).copied().ok_or_else(|| {
                ImportError::WriteFailed("adopted runner credential set is incomplete".into())
            })?;
            if expected != file.identity {
                return Err(ImportError::WriteFailed(
                    "adopted runner credentials changed during import".into(),
                ));
            }
            ensure_entry_identity(&self.directory, &file.name, expected)
                .and_then(|()| ensure_file_identity(&file.file, expected))
                .and_then(|()| validate_private_owned_regular_file(&file.file))
                .map_err(|_| {
                    ImportError::WriteFailed(
                        "adopted runner credentials changed during import".into(),
                    )
                })?;
        }
        Ok(())
    }
}

fn inspect_existing_credentials(
    root: &File,
) -> Result<BTreeMap<String, RunnerCredentials>, ImportError> {
    let runners = match open_directory_at(root, OsStr::new("runners")) {
        Ok(runners) => runners,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => {
            return Err(ImportError::WriteFailed(
                "unable to inspect existing runners directory".into(),
            ));
        }
    };
    inspect_runners_directory(&runners)
}

fn inspect_runners_directory(
    runners: &File,
) -> Result<BTreeMap<String, RunnerCredentials>, ImportError> {
    let names = read_directory_names(runners).map_err(|_| {
        ImportError::WriteFailed("unable to read existing runners directory".into())
    })?;
    let mut directories = Vec::with_capacity(names.len());
    for name in names {
        let display_name = name
            .to_str()
            .ok_or_else(|| {
                ImportError::WriteFailed("existing runner name is not valid UTF-8".into())
            })?
            .to_owned();
        let directory = open_directory_at(runners, &name).map_err(|_| {
            ImportError::WriteFailed("unable to inspect existing runner directory".into())
        })?;
        directories.push((display_name, directory));
    }

    let mut existing = BTreeMap::new();
    for (name, directory) in directories {
        existing.insert(name, read_existing_credentials(&directory)?);
    }
    Ok(existing)
}

fn read_existing_credentials(directory: &File) -> Result<RunnerCredentials, ImportError> {
    let info = parse_existing_json(directory, CREDENTIAL_FILES[0])?;
    let oauth = parse_existing_json(directory, CREDENTIAL_FILES[1])?;
    let rsa_params = parse_existing_json(directory, CREDENTIAL_FILES[2])?;
    Ok(RunnerCredentials {
        info,
        oauth,
        rsa_params,
    })
}

fn parse_existing_json<T: DeserializeOwned>(
    directory: &File,
    name: &str,
) -> Result<T, ImportError> {
    let file = open_regular_at(directory, OsStr::new(name)).map_err(|_| {
        ImportError::WriteFailed(format!(
            "unable to read existing runner credential file {name}"
        ))
    })?;
    let opened = read_opened_regular(file).map_err(|_| {
        ImportError::WriteFailed(format!(
            "unable to read existing runner credential file {name}"
        ))
    })?;
    serde_json::from_slice(&opened.bytes).map_err(|error| {
        ImportError::WriteFailed(format!(
            "unable to parse existing {name} at line {} column {}",
            error.line(),
            error.column()
        ))
    })
}

fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
}

fn open_regular_at(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
}

fn open_at(parent: &File, name: &OsStr, flags: i32) -> io::Result<File> {
    let name = path_component(name)?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn file_identity(file: &File) -> io::Result<FileIdentity> {
    file.metadata()
        .map(|metadata| FileIdentity::from_metadata(&metadata))
}

fn entry_identity(parent: &File, name: &CStr) -> io::Result<FileIdentity> {
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let entry = open_at(parent, OsStr::from_bytes(name.to_bytes()), flags)?;
    file_identity(&entry)
}

fn ensure_file_identity(file: &File, expected: FileIdentity) -> io::Result<()> {
    if file_identity(file)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened entry identity changed",
        ))
    }
}

fn ensure_entry_identity(parent: &File, name: &CStr, expected: FileIdentity) -> io::Result<()> {
    if entry_identity(parent, name)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory entry identity changed",
        ))
    }
}

fn validate_private_owned_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if metadata.is_dir() && metadata.uid() == effective_uid() && metadata.mode() & 0o777 == 0o700 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory is not private owned storage",
        ))
    }
}

fn validate_private_owned_regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.is_file() && metadata.uid() == effective_uid() && metadata.mode() & 0o777 == 0o600 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file is not private owned storage",
        ))
    }
}

fn validate_exact_credential_entries(directory: &File) -> io::Result<()> {
    let actual: BTreeSet<_> = read_directory_names(directory)?.into_iter().collect();
    let expected: BTreeSet<_> = CREDENTIAL_FILES.into_iter().map(OsString::from).collect();
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential directory contains an unexpected entry set",
        ))
    }
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn path_component(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a single component",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn read_directory_names(directory: &File) -> io::Result<Vec<OsString>> {
    let current = CString::new(".")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid current directory"))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            current.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        let _ = unsafe { libc::close(fd) };
        return Err(error);
    }
    let _stream = DirectoryStream(stream);
    let mut names = Vec::new();

    loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(error);
        }

        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }

    names.sort();
    Ok(names)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        let _ = unsafe { libc::closedir(self.0) };
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_errno(value: i32) {
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_vendor = "apple")]
fn set_errno(value: i32) {
    unsafe { *libc::__error() = value };
}

fn validate_config_entries(
    name: &str,
    config: &PreservedConfig,
    existing: &BTreeMap<String, RunnerCredentials>,
) -> Result<(), ImportError> {
    let mut configured = BTreeSet::new();
    for configured_name in &config.model.runners {
        if !configured.insert(configured_name) {
            return Err(ImportError::WriteFailed(
                "existing config.toml contains duplicate runner names".into(),
            ));
        }
        if configured_name != name && !existing.contains_key(configured_name) {
            return Err(ImportError::WriteFailed(
                "existing config.toml references incomplete runner credentials".into(),
            ));
        }
    }
    Ok(())
}

fn classify_disposition(
    name: &str,
    registration: &ValidatedRegistration,
    config: &PreservedConfig,
    existing: &BTreeMap<String, RunnerCredentials>,
) -> Result<TargetDisposition, ImportError> {
    for (existing_name, credentials) in existing {
        if existing_name == name {
            continue;
        }
        let identity = identity_from_credentials(credentials).map_err(|()| {
            ImportError::WriteFailed(
                "unable to derive identity from existing runner credentials".into(),
            )
        })?;
        if identity == registration.identity {
            return Err(ImportError::IdentityConflict(
                "registration identity already exists under another local name".into(),
            ));
        }
    }

    let name_in_config = config.model.runners.iter().any(|runner| runner == name);
    match (existing.get(name), name_in_config) {
        (Some(credentials), true) if credentials == &registration.credentials => {
            Ok(TargetDisposition::AlreadyImported)
        }
        (Some(credentials), false) if credentials == &registration.credentials => {
            Ok(TargetDisposition::Resume)
        }
        (Some(_), _) => Err(ImportError::IdentityConflict(
            "local name already stores different credentials".into(),
        )),
        (None, true) => Err(ImportError::IdentityConflict(
            "local name is configured without a complete credential set".into(),
        )),
        (None, false) => Ok(TargetDisposition::New),
    }
}

fn identity_from_credentials(credentials: &RunnerCredentials) -> Result<RunnerIdentity, ()> {
    if credentials.info.pool_id == 0 || credentials.info.agent_id == 0 {
        return Err(());
    }
    existing_runner_identity(
        &credentials.info.git_hub_url,
        credentials.info.pool_id,
        credentials.info.agent_id,
    )
    .map_err(|_| ())
}

#[cfg(test)]
#[path = "target_test.rs"]
mod target_test;
