use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use serde::Serialize;
use uuid::Uuid;

use crate::config::load_runner_credentials_from_directory;

use super::target::{PreparedImport, TargetDisposition};
use super::{ImportError, ImportOutcome, ImportStatus};

const CREDENTIAL_FILES: [&str; 3] = ["runner.json", "credentials.json", "rsa_params.json"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitPoint {
    BeforeCreateStaging,
    AfterCreateStaging,
    AfterRunnerJson,
    AfterCredentialsJson,
    AfterRsaJson,
    AfterStagingValidation,
    AfterCredentialPublish,
    AfterConfigTempWrite,
    BeforeConfigPublish,
    AfterConfigPublish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurabilityPoint {
    Runners,
    Root,
}

pub(super) fn commit(prepared: PreparedImport) -> Result<ImportOutcome, ImportError> {
    commit_with_checkpoint(prepared, |_| Ok(()))
}

fn commit_with_checkpoint<F>(
    prepared: PreparedImport,
    checkpoint: F,
) -> Result<ImportOutcome, ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
{
    commit_with_checkpoint_and_sync(prepared, checkpoint, |_, directory| {
        open_syncable_directory(directory)?.sync_all()
    })
}

fn commit_with_checkpoint_and_sync<F, S>(
    prepared: PreparedImport,
    mut checkpoint: F,
    mut sync_directory: S,
) -> Result<ImportOutcome, ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
    S: FnMut(DurabilityPoint, &File) -> io::Result<()>,
{
    let root = prepared.locked_root()?;
    let runners = match prepared.disposition() {
        TargetDisposition::AlreadyImported => {
            let runners = open_runners_directory(root, false).map_err(|_| {
                ImportError::WriteFailed("runners directory is not safe for import".into())
            })?;
            validate_runners(&runners)?;
            sync_directory(DurabilityPoint::Root, root)
                .map_err(|_| ImportError::WriteFailed("unable to sync chimera root".into()))?;
            validate_runners(&runners)?;
            return Ok(prepared.outcome(ImportStatus::AlreadyImported));
        }
        TargetDisposition::New => {
            publish_credentials(&prepared, &mut checkpoint, &mut sync_directory)?
        }
        TargetDisposition::Resume => {
            let runners = open_runners_directory(root, false).map_err(|_| {
                ImportError::WriteFailed("runners directory is not safe for import".into())
            })?;
            sync_directory(DurabilityPoint::Runners, runners.directory())
                .map_err(|_| ImportError::WriteFailed("unable to sync runners directory".into()))?;
            validate_runners(&runners)?;
            runners
        }
    };

    write_config(&prepared, &runners, &mut checkpoint, &mut sync_directory)?;
    Ok(prepared.outcome(ImportStatus::Imported))
}

fn publish_credentials<F, S>(
    prepared: &PreparedImport,
    checkpoint: &mut F,
    sync_directory: &mut S,
) -> Result<RunnersHandle, ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
    S: FnMut(DurabilityPoint, &File) -> io::Result<()>,
{
    let root = prepared.locked_root()?;
    call_checkpoint(checkpoint, CommitPoint::BeforeCreateStaging)?;

    let staging_name = path_component(OsStr::new(&format!(".import-{}", Uuid::new_v4())))
        .map_err(|_| ImportError::WriteFailed("staging directory name is invalid".into()))?;
    let (staging, staging_identity, mut staging_cleanup) =
        create_staging_directory(root, &staging_name)
            .map_err(|_| ImportError::WriteFailed("unable to create staging directory".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterCreateStaging)?;

    write_private_json_at(&staging, CREDENTIAL_FILES[0], &prepared.credentials().info)
        .map_err(|_| ImportError::WriteFailed("unable to stage runner credentials".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterRunnerJson)?;

    write_private_json_at(&staging, CREDENTIAL_FILES[1], &prepared.credentials().oauth)
        .map_err(|_| ImportError::WriteFailed("unable to stage runner credentials".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterCredentialsJson)?;

    write_private_json_at(
        &staging,
        CREDENTIAL_FILES[2],
        &prepared.credentials().rsa_params,
    )
    .map_err(|_| ImportError::WriteFailed("unable to stage runner credentials".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterRsaJson)?;

    validate_staging(&staging, prepared)?;
    let runners = open_runners_directory(root, true)
        .map_err(|_| ImportError::WriteFailed("runners directory is not safe for import".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterStagingValidation)?;
    validate_runners(&runners)?;

    ensure_entry_identity(root, &staging_name, staging_identity)
        .map_err(|_| ImportError::WriteFailed("staging directory changed before publish".into()))?;
    ensure_file_identity(&staging, staging_identity)
        .map_err(|_| ImportError::WriteFailed("staging directory changed before publish".into()))?;

    let target_name = path_component(OsStr::new(prepared.name()))
        .map_err(|_| ImportError::WriteFailed("local runner name is invalid".into()))?;
    match entry_identity(runners.directory(), &target_name) {
        Ok(_) => {
            return Err(ImportError::IdentityConflict(
                "local name appeared during credential publication".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(ImportError::WriteFailed(
                "unable to inspect import target".into(),
            ));
        }
    }

    validate_runners(&runners)?;
    match rename_noreplace_at(root, &staging_name, runners.directory(), &target_name) {
        Ok(()) => staging_cleanup.disarm(),
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists
                || error.raw_os_error() == Some(libc::EEXIST) =>
        {
            return Err(ImportError::IdentityConflict(
                "local name appeared during credential publication".into(),
            ));
        }
        Err(_) => {
            return Err(ImportError::WriteFailed(
                "unable to publish runner credentials".into(),
            ));
        }
    }

    call_checkpoint(checkpoint, CommitPoint::AfterCredentialPublish)?;
    validate_runners(&runners)?;
    sync_directory(DurabilityPoint::Runners, runners.directory())
        .map_err(|_| ImportError::WriteFailed("unable to sync runners directory".into()))?;
    validate_runners(&runners)?;
    Ok(runners)
}

fn create_staging_directory(
    root: &File,
    name: &CString,
) -> io::Result<(File, EntryIdentity, CleanupGuard)> {
    let cleanup_parent = root.try_clone()?;
    create_directory_at(root, name, 0o700)?;
    let identity = entry_identity(root, name)?;
    let cleanup = CleanupGuard::new(cleanup_parent, name, identity, CleanupKind::Directory);
    chmod_directory_entry_for_open(root, name, 0o700)?;
    let directory = open_directory_at(root, name)?;
    ensure_file_identity(&directory, identity)?;
    set_file_mode(&directory, 0o700)?;
    validate_private_directory(&directory, true)?;
    Ok((directory, identity, cleanup))
}

fn write_private_json_at<T: Serialize>(directory: &File, name: &str, value: &T) -> io::Result<()> {
    let name = path_component(OsStr::new(name))?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut file = open_file_at(directory, &name, flags, 0o600)?;
    set_file_mode(&file, 0o600)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn validate_staging(staging: &File, prepared: &PreparedImport) -> Result<(), ImportError> {
    let loaded = load_runner_credentials_from_directory(staging)
        .map_err(|_| ImportError::WriteFailed("staging credential validation failed".into()))?;
    if loaded != *prepared.credentials() {
        return Err(ImportError::WriteFailed(
            "staging credentials changed during serialization".into(),
        ));
    }
    staging
        .sync_all()
        .map_err(|_| ImportError::WriteFailed("unable to sync staging directory".into()))
}

fn open_runners_directory(root: &File, create_missing: bool) -> io::Result<RunnersHandle> {
    let parent = root.try_clone()?;
    let name = path_component(OsStr::new("runners"))?;
    let created = match entry_identity(root, &name) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound && create_missing => {
            match create_directory_at(root, &name, 0o700) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };

    let expected = entry_identity(root, &name)?;
    if created {
        chmod_directory_entry_for_open(root, &name, 0o700)?;
    }
    let directory = open_directory_at(root, &name)?;
    ensure_file_identity(&directory, expected)?;
    if created {
        set_file_mode(&directory, 0o700)?;
    }
    validate_private_directory(&directory, created)?;
    Ok(RunnersHandle {
        directory,
        parent,
        name,
        expected,
    })
}

fn write_config<F, S>(
    prepared: &PreparedImport,
    runners_handle: &RunnersHandle,
    checkpoint: &mut F,
    sync_directory: &mut S,
) -> Result<(), ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
    S: FnMut(DurabilityPoint, &File) -> io::Result<()>,
{
    let root = prepared.locked_root()?;
    validate_runners(runners_handle)?;
    let mut runners = prepared.configured_runners().to_vec();
    if !runners.iter().any(|name| name == prepared.name()) {
        runners.push(prepared.name().to_owned());
    }

    let mut document = prepared.config_document().clone();
    document.insert(
        "runners".into(),
        toml::Value::Array(runners.into_iter().map(toml::Value::String).collect()),
    );
    let serialized = toml::to_string_pretty(&document)
        .map_err(|_| ImportError::WriteFailed("unable to serialize config.toml".into()))?;

    let temp_name = path_component(OsStr::new(&format!(".config.toml.{}.tmp", Uuid::new_v4())))
        .map_err(|_| ImportError::WriteFailed("config temp file name is invalid".into()))?;
    let mode = prepared.config_mode().unwrap_or(0o600) as libc::mode_t;
    let cleanup_parent = root
        .try_clone()
        .map_err(|_| ImportError::WriteFailed("unable to retain config temp parent".into()))?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut file = open_file_at(root, &temp_name, flags, mode)
        .map_err(|_| ImportError::WriteFailed("unable to create config temp file".into()))?;
    let identity = file_identity(&file)
        .map_err(|_| ImportError::WriteFailed("unable to inspect config temp file".into()))?;
    let mut temp_cleanup =
        CleanupGuard::new(cleanup_parent, &temp_name, identity, CleanupKind::File);
    set_file_mode(&file, mode)
        .map_err(|_| ImportError::WriteFailed("unable to secure config temp file".into()))?;
    file.write_all(serialized.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ImportError::WriteFailed("unable to write config temp file".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterConfigTempWrite)?;
    validate_runners(runners_handle)?;

    call_checkpoint(checkpoint, CommitPoint::BeforeConfigPublish)?;
    ensure_entry_identity(root, &temp_name, identity)
        .and_then(|()| ensure_file_identity(&file, identity))
        .map_err(|_| ImportError::WriteFailed("config temp file changed before publish".into()))?;
    let config_name = path_component(OsStr::new("config.toml"))
        .map_err(|_| ImportError::WriteFailed("config file name is invalid".into()))?;
    validate_runners(runners_handle)?;
    rename_at(root, &temp_name, root, &config_name)
        .map_err(|_| ImportError::WriteFailed("unable to publish config.toml".into()))?;
    temp_cleanup.disarm();
    call_checkpoint(checkpoint, CommitPoint::AfterConfigPublish)?;

    sync_directory(DurabilityPoint::Root, root)
        .map_err(|_| ImportError::WriteFailed("unable to sync chimera root".into()))
}

fn call_checkpoint<F>(checkpoint: &mut F, point: CommitPoint) -> Result<(), ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
{
    checkpoint(point)
        .map_err(|_| ImportError::WriteFailed("import interrupted at commit checkpoint".into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

#[derive(Debug)]
struct RunnersHandle {
    directory: File,
    parent: File,
    name: CString,
    expected: EntryIdentity,
}

impl RunnersHandle {
    const fn directory(&self) -> &File {
        &self.directory
    }

    fn validate(&self) -> io::Result<()> {
        ensure_entry_identity(&self.parent, &self.name, self.expected)?;
        ensure_file_identity(&self.directory, self.expected)?;
        validate_private_directory(&self.directory, false)
    }
}

fn validate_runners(runners: &RunnersHandle) -> Result<(), ImportError> {
    runners
        .validate()
        .map_err(|_| ImportError::WriteFailed("runners directory changed during import".into()))
}

fn file_identity(file: &File) -> io::Result<EntryIdentity> {
    let stat = stat_fd(file)?;
    Ok(EntryIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn entry_identity(parent: &File, name: &CStr) -> io::Result<EntryIdentity> {
    let stat = stat_at(parent, name)?;
    Ok(EntryIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn ensure_file_identity(file: &File, expected: EntryIdentity) -> io::Result<()> {
    if file_identity(file)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened entry identity changed",
        ))
    }
}

fn ensure_entry_identity(parent: &File, name: &CStr, expected: EntryIdentity) -> io::Result<()> {
    if entry_identity(parent, name)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory entry identity changed",
        ))
    }
}

fn create_directory_at(parent: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn chmod_directory_entry_for_open(
    parent: &File,
    name: &CStr,
    mode: libc::mode_t,
) -> io::Result<()> {
    let result = unsafe {
        libc::fchmodat(
            parent.as_raw_fd(),
            name.as_ptr(),
            mode,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_file_mode(file: &File, mode: libc::mode_t) -> io::Result<()> {
    let result = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn validate_private_directory(directory: &File, require_exact_mode: bool) -> io::Result<()> {
    let stat = stat_fd(directory)?;
    let mode = stat.st_mode as u32;
    let mode_is_safe = if require_exact_mode {
        mode & 0o777 == 0o700
    } else {
        mode & 0o022 == 0
    };
    if !is_directory(&stat) || stat.st_uid != effective_uid() || !mode_is_safe {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory is not private owned storage",
        ));
    }
    Ok(())
}

fn open_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    open_file_at(parent, name, flags, 0)
}

fn open_syncable_directory(directory: &File) -> io::Result<File> {
    let current = CString::new(".")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid current directory"))?;
    open_directory_at(directory, &current)
}

fn open_file_at(parent: &File, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    owned_file(fd)
}

fn rename_at(
    source_parent: &File,
    source_name: &CStr,
    target_parent: &File,
    target_name: &CStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameat(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            target_parent.as_raw_fd(),
            target_name.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_noreplace_at(
    source_parent: &File,
    source_name: &CStr,
    target_parent: &File,
    target_name: &CStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameat2(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            target_parent.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace_at(
    source_parent: &File,
    source_name: &CStr,
    target_parent: &File,
    target_name: &CStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            target_parent.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace_at(
    _source_parent: &File,
    _source_name: &CStr,
    _target_parent: &File,
    _target_name: &CStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory publish is unsupported on this platform",
    ))
}

fn stat_fd(file: &File) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

fn stat_at(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
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

fn owned_file(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

fn is_directory(stat: &libc::stat) -> bool {
    stat.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFDIR as u32
}

fn unlink_at(parent: &File, name: &CStr, flags: i32) -> io::Result<()> {
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug, Clone, Copy)]
enum CleanupKind {
    Directory,
    File,
}

#[derive(Debug)]
struct CleanupGuard {
    parent: File,
    name: CString,
    expected: EntryIdentity,
    kind: CleanupKind,
    armed: bool,
}

impl CleanupGuard {
    fn new(parent: File, name: &CStr, expected: EntryIdentity, kind: CleanupKind) -> Self {
        Self {
            parent,
            name: name.to_owned(),
            expected,
            kind,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn remove_directory(&self) -> io::Result<()> {
        let directory = open_directory_at(&self.parent, &self.name)?;
        ensure_file_identity(&directory, self.expected)?;
        for file_name in CREDENTIAL_FILES {
            let name = path_component(OsStr::new(file_name))?;
            if let Err(error) = unlink_at(&directory, &name, 0)
                && error.kind() != io::ErrorKind::NotFound
            {
                return Err(error);
            }
        }
        ensure_entry_identity(&self.parent, &self.name, self.expected)?;
        unlink_at(&self.parent, &self.name, libc::AT_REMOVEDIR)
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let result = ensure_entry_identity(&self.parent, &self.name, self.expected).and_then(
            |()| match self.kind {
                CleanupKind::Directory => self.remove_directory(),
                CleanupKind::File => unlink_at(&self.parent, &self.name, 0),
            },
        );
        if let Err(error) = result
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %error, "unable to clean temporary import storage safely");
        }
    }
}

#[cfg(test)]
#[path = "commit_test.rs"]
mod commit_test;
