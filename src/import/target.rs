use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::config::{ChimeraConfig, ChimeraPaths, RunnerCredentials};
use crate::storage::{RootLockError, open_existing_root};

use super::source::{read_official_registration, runner_identity};
use super::{
    ImportError, ImportOutcome, ImportStatus, OpenedRegularFile, RunnerIdentity,
    ValidatedRegistration, read_opened_regular,
};

const CREDENTIAL_FILES: [&str; 3] = ["runner.json", "credentials.json", "rsa_params.json"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetDisposition {
    New,
    Resume,
    AlreadyImported,
}

#[derive(Debug)]
pub(crate) struct PreservedConfig {
    model: ChimeraConfig,
    document: toml::Table,
    original_mode: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct PreparedImport {
    name: String,
    registration: ValidatedRegistration,
    paths: ChimeraPaths,
    config: PreservedConfig,
    disposition: TargetDisposition,
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
        self.config.original_mode
    }

    pub(super) fn locked_root(&self) -> Result<&File, ImportError> {
        self.locked_root.as_ref().ok_or_else(|| {
            ImportError::WriteFailed("import commit is missing the locked root descriptor".into())
        })
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

    Ok(PreparedImport {
        name: name.to_owned(),
        registration,
        paths,
        config,
        disposition,
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
    use std::os::unix::fs::MetadataExt;

    let opened = root
        .metadata()
        .map_err(|_| ImportError::WriteFailed("unable to inspect opened target root".into()))?;
    let resolved = std::fs::metadata(path)
        .map_err(|_| ImportError::WriteFailed("target root changed while planning".into()))?;
    if !resolved.is_dir() || opened.dev() != resolved.dev() || opened.ino() != resolved.ino() {
        return Err(ImportError::WriteFailed(
            "target root changed while planning".into(),
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
    use std::os::unix::fs::PermissionsExt;

    let text = std::str::from_utf8(&opened.bytes)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let model = toml::from_str(text)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let document = toml::from_str(text)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;

    Ok(PreservedConfig {
        model,
        document,
        original_mode: Some(opened.metadata.permissions().mode() & 0o777),
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
        original_mode: None,
    })
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
    let duplicate = directory.try_clone()?;
    let fd = duplicate.into_raw_fd();
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
    runner_identity(
        &credentials.info.git_hub_url,
        credentials.info.pool_id,
        credentials.info.agent_id,
    )
    .map_err(|_| ())
}

#[cfg(test)]
#[path = "target_test.rs"]
mod target_test;
