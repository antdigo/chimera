use std::collections::VecDeque;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

const MAX_SYMLINKS: usize = 40;
const MAX_SYMLINK_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct RootLock {
    root: File,
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

#[derive(Debug)]
struct DirectoryHandle {
    file: File,
    shared: bool,
}

#[derive(Debug)]
enum PathPart {
    Parent,
    Normal(OsString),
}

impl RootLock {
    pub(crate) fn acquire(root: &Path) -> Result<RootLock, RootLockError> {
        match validate_existing_root(root) {
            Ok(()) => {}
            Err(RootLockError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let root = open_root(root, true)?;
        let file = open_lock_file(&root)?;
        validate_lock_file(&file)?;

        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            let code = error.raw_os_error();
            if code == Some(libc::EWOULDBLOCK) || code == Some(libc::EAGAIN) {
                return Err(RootLockError::Busy);
            }
            return Err(RootLockError::Io(error));
        }

        Ok(Self { root, _file: file })
    }

    pub(crate) fn try_clone_root(&self) -> std::io::Result<File> {
        self.root.try_clone()
    }
}

pub(crate) fn open_existing_root(root: &Path) -> Result<File, RootLockError> {
    open_root(root, false)
}

pub(crate) fn validate_existing_root(root: &Path) -> Result<(), RootLockError> {
    open_existing_root(root).map(drop)
}

fn open_root(root: &Path, create_missing: bool) -> Result<File, RootLockError> {
    // Pathname rechecks cannot bind the lock open to the validated root inode, so every
    // component is resolved relative to a pinned directory descriptor.
    let absolute_root = absolute_root(root)?;
    let (_, parts) = path_parts(&absolute_root)?;
    let mut pending = VecDeque::from(parts);
    let mut directories = vec![open_root_directory()?];
    let mut followed_symlinks = 0usize;

    while let Some(part) = pending.pop_front() {
        match part {
            PathPart::Parent => {
                if directories.len() > 1 {
                    directories.pop();
                }
            }
            PathPart::Normal(name) => {
                let is_final = pending.is_empty();
                let parent = directories.last().ok_or_else(|| {
                    RootLockError::UnsafeRoot("root path lost its directory anchor".into())
                })?;
                let name = path_component(&name)?;

                match stat_at(parent.file.as_raw_fd(), &name) {
                    Ok(stat) => {
                        validate_entry_in_parent(parent, &stat)?;
                        if is_symlink(&stat) {
                            if is_final {
                                return Err(RootLockError::UnsafeRoot(
                                    "root must not be a symbolic link".into(),
                                ));
                            }

                            followed_symlinks += 1;
                            if followed_symlinks > MAX_SYMLINKS {
                                return Err(RootLockError::UnsafeRoot(
                                    "root path contains too many symbolic links".into(),
                                ));
                            }
                            let target = read_link_at(parent.file.as_raw_fd(), &name)?;
                            prepend_link_target(&mut directories, &mut pending, &target)?;
                            continue;
                        }
                        if !is_directory(&stat) {
                            return Err(RootLockError::UnsafeRoot(
                                "root path component is not a directory".into(),
                            ));
                        }

                        let directory = open_directory_at(parent.file.as_raw_fd(), &name)?;
                        let stat = stat_fd(&directory)?;
                        let shared = validate_ancestor(&stat)?;
                        directories.push(DirectoryHandle {
                            file: directory,
                            shared,
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        if !create_missing {
                            return Err(RootLockError::Io(error));
                        }

                        let created = create_directory_at(&parent.file, &name)?;
                        let directory = if created {
                            open_new_directory_at(parent.file.as_raw_fd(), &name)?
                        } else {
                            let stat = stat_at(parent.file.as_raw_fd(), &name)?;
                            validate_entry_in_parent(parent, &stat)?;
                            if !is_directory(&stat) {
                                return Err(RootLockError::UnsafeRoot(
                                    "concurrent root component is not a safe directory".into(),
                                ));
                            }
                            open_directory_at(parent.file.as_raw_fd(), &name)?
                        };
                        let stat = stat_fd(&directory)?;
                        let shared = validate_ancestor(&stat)?;
                        directories.push(DirectoryHandle {
                            file: directory,
                            shared,
                        });
                    }
                    Err(error) => return Err(RootLockError::Io(error)),
                }
            }
        }
    }

    let root = directories
        .pop()
        .ok_or_else(|| RootLockError::UnsafeRoot("root path lost its directory anchor".into()))?;
    let stat = stat_fd(&root.file)?;
    validate_root(&stat)?;
    Ok(root.file)
}

fn absolute_root(root: &Path) -> Result<PathBuf, RootLockError> {
    if root.is_absolute() {
        return Ok(root.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(root))
}

fn path_parts(path: &Path) -> Result<(bool, Vec<PathPart>), RootLockError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(RootLockError::UnsafeRoot(
                    "unsupported root path prefix".into(),
                ));
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => parts.push(PathPart::Parent),
            Component::Normal(name) => parts.push(PathPart::Normal(name.to_owned())),
        }
    }
    Ok((path.is_absolute(), parts))
}

fn prepend_link_target(
    directories: &mut Vec<DirectoryHandle>,
    pending: &mut VecDeque<PathPart>,
    target: &Path,
) -> Result<(), RootLockError> {
    let (absolute, target_parts) = path_parts(target)?;
    if absolute {
        directories.truncate(1);
    }
    for part in target_parts.into_iter().rev() {
        pending.push_front(part);
    }
    Ok(())
}

fn open_root_directory() -> Result<DirectoryHandle, RootLockError> {
    let root = CString::new("/").map_err(|_| invalid_path_component())?;
    let fd = unsafe { libc::open(root.as_ptr(), directory_open_flags()) };
    let file = owned_file(fd)?;
    let stat = stat_fd(&file)?;
    let shared = validate_ancestor(&stat)?;
    Ok(DirectoryHandle { file, shared })
}

fn open_directory_at(parent: RawFd, name: &CString) -> Result<File, RootLockError> {
    let fd = unsafe { libc::openat(parent, name.as_ptr(), directory_open_flags()) };
    owned_file(fd).map_err(RootLockError::Io)
}

fn open_new_directory_at(parent: RawFd, name: &CString) -> Result<File, RootLockError> {
    let created = stat_at(parent, name)?;
    if !is_directory(&created) || created.st_uid != effective_uid() {
        return Err(RootLockError::UnsafeRoot(
            "new root component changed before it could be opened".into(),
        ));
    }

    let file = match open_chmod_directory_at(parent, name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            // A restrictive umask can remove owner-search permission. No untrusted user can
            // replace entries in the validated parent, and no-follow prevents chmod of a
            // substituted symlink target before the opened inode is identity-checked below.
            let result =
                unsafe { libc::fchmodat(parent, name.as_ptr(), 0o700, libc::AT_SYMLINK_NOFOLLOW) };
            if result != 0 {
                return Err(RootLockError::Io(io::Error::last_os_error()));
            }
            open_chmod_directory_at(parent, name)?
        }
        Err(error) => return Err(RootLockError::Io(error)),
    };

    let opened = stat_fd(&file)?;
    if opened.st_dev != created.st_dev || opened.st_ino != created.st_ino {
        return Err(RootLockError::UnsafeRoot(
            "new root component changed before it could be opened".into(),
        ));
    }

    let chmod_result = unsafe { libc::fchmod(file.as_raw_fd(), 0o700) };
    if chmod_result != 0 {
        return Err(RootLockError::Io(io::Error::last_os_error()));
    }
    Ok(file)
}

fn open_chmod_directory_at(parent: RawFd, name: &CString) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    owned_file(fd)
}

fn create_directory_at(parent: &File, name: &CString) -> Result<bool, RootLockError> {
    create_directory_at_with_sync(parent, name, sync_directory)
}

fn create_directory_at_with_sync<F>(
    parent: &File,
    name: &CString,
    sync_parent: F,
) -> Result<bool, RootLockError>
where
    F: FnOnce(&File) -> io::Result<()>,
{
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        let directory = open_new_directory_at(parent.as_raw_fd(), name)?;
        sync_directory(&directory)?;
        sync_parent(parent)?;
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        return Ok(false);
    }
    Err(RootLockError::Io(error))
}

fn sync_directory(directory: &File) -> io::Result<()> {
    let current = CString::new(".").map_err(|_| invalid_path_component())?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), current.as_ptr(), flags) };
    owned_file(fd)?.sync_all()
}

fn open_lock_file(root: &File) -> Result<File, RootLockError> {
    let name = CString::new(".chimera.lock").map_err(|_| invalid_path_component())?;
    let flags = libc::O_RDWR
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK;

    match open_file_at(root.as_raw_fd(), &name, flags, 0o600) {
        Ok(file) => {
            let chmod_result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
            if chmod_result != 0 {
                return Err(RootLockError::Io(io::Error::last_os_error()));
            }
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
            open_file_at(root.as_raw_fd(), &name, flags, 0).map_err(RootLockError::Io)
        }
        Err(error) => Err(RootLockError::Io(error)),
    }
}

fn open_file_at(parent: RawFd, name: &CString, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, mode as libc::c_uint) };
    owned_file(fd)
}

fn validate_entry_in_parent(
    parent: &DirectoryHandle,
    stat: &libc::stat,
) -> Result<(), RootLockError> {
    // Sticky shared ancestors such as /tmp prevent replacement only for entries owned by
    // the current user or root.
    if parent.shared && stat.st_uid != effective_uid() && stat.st_uid != 0 {
        return Err(RootLockError::UnsafeRoot(
            "root path entry in shared storage is owned by another user".into(),
        ));
    }
    Ok(())
}

fn validate_ancestor(stat: &libc::stat) -> Result<bool, RootLockError> {
    if !is_directory(stat) {
        return Err(RootLockError::UnsafeRoot(
            "root ancestry contains a non-directory".into(),
        ));
    }
    if stat.st_uid != effective_uid() && stat.st_uid != 0 {
        return Err(RootLockError::UnsafeRoot(
            "root ancestry is owned by another user".into(),
        ));
    }

    let mode = stat.st_mode as u32;
    let shared = mode & 0o022 != 0;
    if shared && mode & libc::S_ISVTX as u32 == 0 {
        return Err(RootLockError::UnsafeRoot(
            "root ancestry is writable by untrusted users".into(),
        ));
    }
    Ok(shared)
}

fn validate_root(stat: &libc::stat) -> Result<(), RootLockError> {
    if !is_directory(stat) {
        return Err(RootLockError::UnsafeRoot("root is not a directory".into()));
    }
    if stat.st_uid != effective_uid() {
        return Err(RootLockError::UnsafeRoot(
            "root is not owned by the current user".into(),
        ));
    }
    if stat.st_mode as u32 & 0o022 != 0 {
        return Err(RootLockError::UnsafeRoot(
            "root is group- or world-writable".into(),
        ));
    }
    Ok(())
}

fn validate_lock_file(file: &File) -> Result<(), RootLockError> {
    let stat = stat_fd(file)?;
    if !is_regular_file(&stat) || stat.st_uid != effective_uid() || stat.st_mode as u32 & 0o077 != 0
    {
        return Err(RootLockError::UnsafeRoot(
            "lock file is not private regular storage owned by the current user".into(),
        ));
    }
    Ok(())
}

fn stat_fd(file: &File) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

fn stat_at(parent: RawFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent,
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

fn read_link_at(parent: RawFd, name: &CString) -> Result<PathBuf, RootLockError> {
    let mut capacity = 256usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        let length = unsafe {
            libc::readlinkat(
                parent,
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Err(RootLockError::Io(io::Error::last_os_error()));
        }
        let length = length as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(PathBuf::from(OsString::from_vec(buffer)));
        }
        if capacity >= MAX_SYMLINK_BYTES {
            return Err(RootLockError::UnsafeRoot(
                "root path symbolic link target is too long".into(),
            ));
        }
        capacity *= 2;
    }
}

fn path_component(component: &OsStr) -> Result<CString, RootLockError> {
    CString::new(component.as_bytes()).map_err(|_| RootLockError::Io(invalid_path_component()))
}

fn invalid_path_component() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "root path contains a NUL byte")
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

fn is_regular_file(stat: &libc::stat) -> bool {
    stat.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFREG as u32
}

fn is_symlink(stat: &libc::stat) -> bool {
    stat.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFLNK as u32
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn directory_open_flags() -> i32 {
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

#[cfg(target_vendor = "apple")]
fn directory_open_flags() -> i32 {
    libc::O_SEARCH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn directory_open_flags() -> i32 {
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

#[cfg(test)]
#[path = "storage_test.rs"]
mod storage_test;
