use std::ffi::CString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use uuid::Uuid;

use crate::config::load_runner_credentials;

use super::target::{PreparedImport, TargetDisposition};
use super::{ImportError, ImportOutcome, ImportStatus};

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

pub(super) fn commit(prepared: PreparedImport) -> Result<ImportOutcome, ImportError> {
    commit_with_checkpoint(prepared, |_| Ok(()))
}

fn commit_with_checkpoint<F>(
    prepared: PreparedImport,
    mut checkpoint: F,
) -> Result<ImportOutcome, ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
{
    match prepared.disposition() {
        TargetDisposition::AlreadyImported => {
            return Ok(prepared.outcome(ImportStatus::AlreadyImported));
        }
        TargetDisposition::New => publish_credentials(&prepared, &mut checkpoint)?,
        TargetDisposition::Resume => {}
    }

    write_config(&prepared, &mut checkpoint)?;
    Ok(prepared.outcome(ImportStatus::Imported))
}

fn publish_credentials<F>(prepared: &PreparedImport, checkpoint: &mut F) -> Result<(), ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
{
    call_checkpoint(checkpoint, CommitPoint::BeforeCreateStaging)?;

    let staging_path = prepared
        .paths()
        .root
        .join(format!(".import-{}", Uuid::new_v4()));
    let mut staging_cleanup = create_staging_directory(&staging_path)
        .map_err(|_| ImportError::WriteFailed("unable to create staging directory".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterCreateStaging)?;

    write_private_json(
        &staging_path.join("runner.json"),
        &prepared.credentials().info,
    )
    .map_err(|_| ImportError::WriteFailed("unable to stage runner credentials".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterRunnerJson)?;

    write_private_json(
        &staging_path.join("credentials.json"),
        &prepared.credentials().oauth,
    )
    .map_err(|_| ImportError::WriteFailed("unable to stage runner credentials".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterCredentialsJson)?;

    write_private_json(
        &staging_path.join("rsa_params.json"),
        &prepared.credentials().rsa_params,
    )
    .map_err(|_| ImportError::WriteFailed("unable to stage runner credentials".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterRsaJson)?;

    validate_staging(&staging_path, prepared)?;
    let runners = ensure_runners_directory(&prepared.paths().runners_dir())
        .map_err(|_| ImportError::WriteFailed("runners directory is not safe for import".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterStagingValidation)?;

    let target = prepared.paths().runner_dir(prepared.name());
    if target
        .try_exists()
        .map_err(|_| ImportError::WriteFailed("unable to inspect import target".into()))?
    {
        return Err(ImportError::IdentityConflict(
            "local name appeared during credential publication".into(),
        ));
    }

    match rename_noreplace(&staging_path, &target) {
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

    runners
        .sync_all()
        .map_err(|_| ImportError::WriteFailed("unable to sync runners directory".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterCredentialPublish)
}

fn create_staging_directory(path: &Path) -> io::Result<CleanupGuard> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = DirBuilder::new();
    builder.mode(0o700).create(path)?;
    let cleanup = CleanupGuard::directory(path.to_path_buf());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(cleanup)
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut file, value).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn validate_staging(staging_path: &Path, prepared: &PreparedImport) -> Result<(), ImportError> {
    let staging_parent = staging_path
        .parent()
        .ok_or_else(|| ImportError::WriteFailed("staging directory has no parent".into()))?;
    let staging_name = staging_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| ImportError::WriteFailed("staging directory name is invalid".into()))?;
    let loaded = load_runner_credentials(staging_parent, staging_name)
        .map_err(|_| ImportError::WriteFailed("staging credential validation failed".into()))?;
    if loaded != *prepared.credentials() {
        return Err(ImportError::WriteFailed(
            "staging credentials changed during serialization".into(),
        ));
    }
    File::open(staging_path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ImportError::WriteFailed("unable to sync staging directory".into()))
}

fn ensure_runners_directory(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let created = match std::fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            match builder.mode(0o700).create(path) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };

    if created {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runners directory is not private owned storage",
        ));
    }
    Ok(directory)
}

fn write_config<F>(prepared: &PreparedImport, checkpoint: &mut F) -> Result<(), ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
{
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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

    let temp_path = prepared
        .paths()
        .root
        .join(format!(".config.toml.{}.tmp", Uuid::new_v4()));
    let mode = prepared.config_mode().unwrap_or(0o600);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp_path)
        .map_err(|_| ImportError::WriteFailed("unable to create config temp file".into()))?;
    let mut temp_cleanup = CleanupGuard::file(temp_path.clone());
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|_| ImportError::WriteFailed("unable to secure config temp file".into()))?;
    file.write_all(serialized.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ImportError::WriteFailed("unable to write config temp file".into()))?;
    call_checkpoint(checkpoint, CommitPoint::AfterConfigTempWrite)?;

    call_checkpoint(checkpoint, CommitPoint::BeforeConfigPublish)?;
    std::fs::rename(&temp_path, prepared.paths().config_file())
        .map_err(|_| ImportError::WriteFailed("unable to publish config.toml".into()))?;
    temp_cleanup.disarm();
    call_checkpoint(checkpoint, CommitPoint::AfterConfigPublish)?;

    File::open(&prepared.paths().root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ImportError::WriteFailed("unable to sync chimera root".into()))
}

fn call_checkpoint<F>(checkpoint: &mut F, point: CommitPoint) -> Result<(), ImportError>
where
    F: FnMut(CommitPoint) -> io::Result<()>,
{
    checkpoint(point)
        .map_err(|_| ImportError::WriteFailed("import interrupted at commit checkpoint".into()))
}

fn c_path(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    let source = c_path(source)?;
    let target = c_path(target)?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
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
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    let source = c_path(source)?;
    let target = c_path(target)?;
    let result = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(_source: &Path, _target: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory publish is unsupported on this platform",
    ))
}

#[derive(Debug, Clone, Copy)]
enum CleanupKind {
    Directory,
    File,
}

#[derive(Debug)]
struct CleanupGuard {
    path: PathBuf,
    kind: CleanupKind,
    armed: bool,
}

impl CleanupGuard {
    fn directory(path: PathBuf) -> Self {
        Self {
            path,
            kind: CleanupKind::Directory,
            armed: true,
        }
    }

    fn file(path: PathBuf) -> Self {
        Self {
            path,
            kind: CleanupKind::File,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let result = match self.kind {
            CleanupKind::Directory => std::fs::remove_dir_all(&self.path),
            CleanupKind::File => std::fs::remove_file(&self.path),
        };
        if let Err(error) = result
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %error, "unable to clean temporary import storage");
        }
    }
}

#[cfg(test)]
#[path = "commit_test.rs"]
mod commit_test;
