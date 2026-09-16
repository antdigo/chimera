use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Debug)]
pub(crate) struct RootLock {
    _file: File,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RootLockError {
    #[error("root storage is busy")]
    Busy,
    #[error("unsafe root: {0}")]
    UnsafeRoot(String),
    #[error("root storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl RootLock {
    pub(crate) fn acquire(root: &Path) -> Result<RootLock, RootLockError> {
        ensure_root(root)?;

        let file = open_lock_file(&root.join(".chimera.lock"))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(RootLockError::UnsafeRoot(
                "lock file is not private regular storage owned by the current user".into(),
            ));
        }

        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            let code = error.raw_os_error();
            if code == Some(libc::EWOULDBLOCK) || code == Some(libc::EAGAIN) {
                return Err(RootLockError::Busy);
            }
            return Err(RootLockError::Io(error));
        }

        Ok(Self { _file: file })
    }
}

pub(crate) fn validate_existing_root(root: &Path) -> Result<(), RootLockError> {
    let metadata = std::fs::symlink_metadata(root)?;

    if metadata.file_type().is_symlink() {
        return Err(RootLockError::UnsafeRoot(
            "root must not be a symbolic link".into(),
        ));
    }
    if !metadata.is_dir() {
        return Err(RootLockError::UnsafeRoot("root is not a directory".into()));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(RootLockError::UnsafeRoot(
            "root is not owned by the current user".into(),
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(RootLockError::UnsafeRoot(
            "root is group- or world-writable".into(),
        ));
    }

    Ok(())
}

fn ensure_root(root: &Path) -> Result<(), RootLockError> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => return validate_existing_root(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(RootLockError::Io(error)),
    }

    let mut missing = Vec::new();
    let mut current = root;
    loop {
        match std::fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(|| {
                    RootLockError::UnsafeRoot("root has no existing ancestor".into())
                })?;
            }
            Err(error) => return Err(RootLockError::Io(error)),
        }
    }

    for component in missing.iter().rev() {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(component) {
            Ok(()) => {
                std::fs::set_permissions(component, Permissions::from_mode(0o700))?;
                validate_existing_root(component)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_existing_root(component)?;
            }
            Err(error) => return Err(RootLockError::Io(error)),
        }
    }

    std::fs::symlink_metadata(root)?;
    validate_existing_root(root)
}

fn open_lock_file(path: &Path) -> Result<File, RootLockError> {
    let open_new = || {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        Ok::<_, std::io::Error>(file)
    };

    match open_new() {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(RootLockError::Io),
        Err(error) => Err(RootLockError::Io(error)),
    }
}

#[cfg(test)]
#[path = "storage_test.rs"]
mod storage_test;
