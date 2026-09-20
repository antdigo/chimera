use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

use super::ExecutionDomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn directory_identity(
    path: &Path,
    operation: &'static str,
) -> Result<DirectoryIdentity, ExecutionDomainError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error(operation, path, source))?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(super) fn validate_bound_directory(
    path: &Path,
    expected_identity: DirectoryIdentity,
    metadata: &fs::Metadata,
) -> Result<(), ExecutionDomainError> {
    let actual_identity = DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || actual_identity != expected_identity
    {
        return Err(ExecutionDomainError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }

    let canonical = fs::canonicalize(path).map_err(|source| ExecutionDomainError::Cleanup {
        path: path.to_path_buf(),
        source,
    })?;
    if canonical != path {
        return Err(ExecutionDomainError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(super) fn create_private_dir(
    path: &Path,
    operation: &'static str,
) -> Result<(), ExecutionDomainError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error(operation, path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("setting private directory permissions", path, source))
}

pub(super) fn validate_bound_private_directory(
    path: &Path,
    expected_identity: DirectoryIdentity,
) -> Result<(), ExecutionDomainError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading directory metadata", path, source))?;
    validate_private_directory_metadata(path, &metadata)?;
    validate_bound_directory(path, expected_identity, &metadata)
}

pub(super) fn validate_private_directory(path: &Path) -> Result<(), ExecutionDomainError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading directory metadata", path, source))?;
    validate_private_directory_metadata(path, &metadata)
}

fn validate_private_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ExecutionDomainError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ExecutionDomainError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ExecutionDomainError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "directory is owned by another uid",
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(ExecutionDomainError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "directory mode is not 0700",
        });
    }
    Ok(())
}

fn validate_removal_tree(path: &Path) -> Result<(), ExecutionDomainError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading cleanup metadata", path, source))?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(ExecutionDomainError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|source| io_error("reading cleanup directory", path, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| io_error("reading cleanup entry", path, source))?;
            validate_removal_tree(&entry.path())?;
        }
    }
    Ok(())
}

pub(super) fn validate_attempt_removal_tree(
    attempt_dir: &Path,
    private_tmp: &Path,
    private_tmp_identity: DirectoryIdentity,
    work_dir: &Path,
    work_dir_identity: DirectoryIdentity,
) -> Result<(), ExecutionDomainError> {
    let entries = fs::read_dir(attempt_dir)
        .map_err(|source| io_error("reading cleanup directory", attempt_dir, source))?;
    for entry in entries {
        let entry =
            entry.map_err(|source| io_error("reading cleanup entry", attempt_dir, source))?;
        let path = entry.path();
        if path == private_tmp {
            prepare_owned_directory_for_removal(&path, private_tmp_identity)?;
        } else if path == work_dir {
            prepare_owned_directory_for_removal(&path, work_dir_identity)?;
        } else if entry.file_name() == "journal.json" {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("reading journal cleanup metadata", &path, source))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(ExecutionDomainError::UnsafeEntry { path });
            }
        } else {
            validate_removal_tree(&path)?;
        }
    }
    Ok(())
}

fn prepare_owned_directory_for_removal(
    path: &Path,
    expected_identity: DirectoryIdentity,
) -> Result<(), ExecutionDomainError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading private cleanup metadata", path, source))?;
    validate_bound_directory(path, expected_identity, &metadata)?;
    prepare_owned_directory_tree_for_removal(path, &metadata)
}

fn prepare_owned_directory_tree_for_removal(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ExecutionDomainError> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ExecutionDomainError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("restoring cleanup directory permissions", path, source))?;

    let entries = fs::read_dir(path)
        .map_err(|source| io_error("reading private temp cleanup directory", path, source))?;
    for entry in entries {
        let entry =
            entry.map_err(|source| io_error("reading private temp cleanup entry", path, source))?;
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child)
            .map_err(|source| io_error("reading private temp cleanup entry", &child, source))?;
        if child_metadata.is_dir() && !child_metadata.file_type().is_symlink() {
            prepare_owned_directory_tree_for_removal(&child, &child_metadata)?;
        }
    }
    Ok(())
}

pub(super) fn utf8_path(path: &Path) -> Result<&str, ExecutionDomainError> {
    path.to_str()
        .ok_or_else(|| ExecutionDomainError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8",
        })
}

pub(super) fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> ExecutionDomainError {
    ExecutionDomainError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
