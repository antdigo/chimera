use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::{ExecutionDomainError, FailureCategory, Stage};

pub(super) const RESOLVE_POLICY: u64 = libc::RESOLVE_BENEATH
    | libc::RESOLVE_NO_SYMLINKS
    | libc::RESOLVE_NO_MAGICLINKS
    | libc::RESOLVE_NO_XDEV;
const DIRECTORY_FLAGS: i32 =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
const READ_FLAGS: i32 = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: (u32, u32),
    inode: u64,
    mount_id: u64,
}

struct Binding {
    fd: OwnedFd,
    identity: Identity,
    parent: Option<(Arc<Binding>, CString)>,
}

/// The caller holds the exclusive resource-root lock throughout this capability's
/// lifetime. Descendant bindings share poison state; failure never rolls back by path.
pub(in super::super) struct BoundDir {
    binding: Arc<Binding>,
    poisoned: Arc<AtomicBool>,
    root_path: Arc<PathBuf>,
}

impl std::fmt::Debug for BoundDir {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BoundDir")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SyncKind {
    File,
    Directory,
}

impl BoundDir {
    pub(super) fn clone_bound(&self) -> Self {
        Self {
            binding: Arc::clone(&self.binding),
            poisoned: Arc::clone(&self.poisoned),
            root_path: Arc::clone(&self.root_path),
        }
    }

    pub(in super::super) fn open_root(path: &Path) -> Result<Self, ExecutionDomainError> {
        if !path.is_absolute() {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let fd = owned_fd(unsafe { libc::open(c"/".as_ptr(), DIRECTORY_FLAGS) })?;
        let mut binding = Arc::new(Binding {
            identity: identity(&metadata(fd.as_raw_fd())?),
            fd,
            parent: None,
        });
        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => CString::new(name.as_encoded_bytes())
                    .map_err(|_| failure(FailureCategory::InvalidInput))?,
                _ => return Err(failure(FailureCategory::InvalidInput)),
            };
            // Initial trusted root selection may traverse mount boundaries. Every
            // boundary is pinned; subsequent child operations forbid crossing one.
            let fd = open_at(
                binding.fd.as_raw_fd(),
                &name,
                DIRECTORY_FLAGS,
                0,
                RESOLVE_POLICY & !libc::RESOLVE_NO_XDEV,
            )?;
            binding = Arc::new(Binding {
                identity: identity(&metadata(fd.as_raw_fd())?),
                fd,
                parent: Some((binding, name)),
            });
        }
        let directory = Self {
            binding,
            poisoned: Arc::new(AtomicBool::new(false)),
            root_path: Arc::new(path.to_owned()),
        };
        directory.verify_binding()?;
        Ok(directory)
    }

    pub(in crate::job::execution_domain) fn from_pinned_root(
        file: File,
        path: PathBuf,
    ) -> Result<Self, ExecutionDomainError> {
        let fd: OwnedFd = file.into();
        let binding = Arc::new(Binding {
            identity: identity(&metadata(fd.as_raw_fd())?),
            fd,
            parent: None,
        });
        let directory = Self {
            binding,
            poisoned: Arc::new(AtomicBool::new(false)),
            root_path: Arc::new(path),
        };
        directory.verify_binding()?;
        Ok(directory)
    }

    pub(in super::super) fn verify_binding(&self) -> Result<(), ExecutionDomainError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(ExecutionDomainError::PoisonedRoot {
                path: self.root_path.as_ref().clone(),
            });
        }
        verify_chain(&self.binding).inspect_err(|_| self.poison())
    }

    pub(in crate::job::execution_domain) fn verify_private_directory(
        &self,
    ) -> Result<(), ExecutionDomainError> {
        self.verify_binding()?;
        let metadata = metadata(self.fd())?;
        if u32::from(metadata.stx_mode) & libc::S_IFMT != libc::S_IFDIR
            || u32::from(metadata.stx_mode) & 0o777 != 0o700
            || metadata.stx_uid != unsafe { libc::geteuid() }
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }

    pub(super) fn verify_attempt_removal_tree(&self) -> Result<(), ExecutionDomainError> {
        self.inventory(RemovalPolicy::Attempt).map(drop)
    }

    pub(super) fn verify_empty_partial_attempt(&self) -> Result<(), ExecutionDomainError> {
        self.verify_binding()?;
        if directory_entries_stream(self.fd())?.next().is_some() {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.verify_binding()
    }

    // Creation is also used inside init for private workflow command files.
    // Destructive removal remains gated on the manager's cgroup-empty proof.
    pub(super) fn child(&self, name: &CStr) -> Result<Self, ExecutionDomainError> {
        component(name)?;
        self.verify_binding()?;
        let fd = open_at(self.fd(), name, DIRECTORY_FLAGS, 0, RESOLVE_POLICY)?;
        let child = Self {
            binding: Arc::new(Binding {
                identity: identity(&metadata(fd.as_raw_fd())?),
                fd,
                parent: Some((Arc::clone(&self.binding), name.to_owned())),
            }),
            poisoned: Arc::clone(&self.poisoned),
            root_path: Arc::clone(&self.root_path),
        };
        child.verify_binding()?;
        Ok(child)
    }

    pub(super) fn create_child(
        &self,
        name: &CStr,
        mode: u32,
    ) -> Result<Self, ExecutionDomainError> {
        component(name)?;
        if mode != 0o700 {
            return Err(failure(FailureCategory::InvalidInput));
        }
        self.verify_binding()?;
        let staging = CString::new(format!(".new-{}", uuid::Uuid::new_v4().simple()))
            .map_err(|_| failure(FailureCategory::InvalidInput))?;
        checked(unsafe { libc::mkdirat(self.fd(), staging.as_ptr(), mode) })?;
        let result = (|| {
            let created = self.child(&staging)?;
            checked(unsafe { libc::fchmod(created.fd(), mode) })?;
            created.verify_binding()?;
            self.verify_binding()?;
            rename(self.fd(), &staging, name, libc::RENAME_NOREPLACE)?;
            sync(self.fd(), SyncKind::Directory).map_err(io_failure)?;
            let child = self.child(name)?;
            if child.binding.identity != created.binding.identity {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            Ok(child)
        })();
        result.inspect_err(|_| self.poison())
    }

    pub(in super::super) fn refuse_entry(&self, name: &CStr) -> Result<(), ExecutionDomainError> {
        component(name)?;
        self.verify_binding()?;
        if self.optional_metadata(name)?.is_some() {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }

    pub(in super::super) fn read_regular(
        &self,
        name: &CStr,
        limit: usize,
    ) -> Result<Vec<u8>, ExecutionDomainError> {
        self.read_regular_with(name, limit, |reader, bytes| reader.read_to_end(bytes))
    }

    pub(super) fn read_bound_regular(
        &self,
        name: &CStr,
        original: &OwnedFd,
        limit: usize,
    ) -> Result<Vec<u8>, ExecutionDomainError> {
        let original = metadata(original.as_raw_fd())?;
        self.read_regular_bound_with(name, limit, Some(&original), |reader, bytes| {
            reader.read_to_end(bytes)
        })
    }

    pub(super) fn read_regular_with<F>(
        &self,
        name: &CStr,
        limit: usize,
        read: F,
    ) -> Result<Vec<u8>, ExecutionDomainError>
    where
        F: FnOnce(&mut dyn Read, &mut Vec<u8>) -> io::Result<usize>,
    {
        self.read_regular_bound_with(name, limit, None, read)
    }

    fn read_regular_bound_with<F>(
        &self,
        name: &CStr,
        limit: usize,
        original: Option<&libc::statx>,
        read: F,
    ) -> Result<Vec<u8>, ExecutionDomainError>
    where
        F: FnOnce(&mut dyn Read, &mut Vec<u8>) -> io::Result<usize>,
    {
        component(name)?;
        self.verify_binding()?;
        let fd = open_at(self.fd(), name, READ_FLAGS, 0, RESOLVE_POLICY)?;
        let before = metadata(fd.as_raw_fd())?;
        if original.is_some_and(|original| identity(&before) != identity(original)) {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.validate_regular(&before, limit)?;
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        let bound = limit
            .checked_add(1)
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
        read(&mut (&mut file).take(bound as u64), &mut bytes).map_err(io_failure)?;
        let after = metadata(file.as_raw_fd()).inspect_err(|_| self.poison())?;
        self.validate_regular(&after, limit)
            .inspect_err(|_| self.poison())?;
        if bytes.len() > limit
            || bytes.len() as u64 != after.stx_size
            || before.stx_size != after.stx_size
            || before.stx_mtime.tv_sec != after.stx_mtime.tv_sec
            || before.stx_mtime.tv_nsec != after.stx_mtime.tv_nsec
            || before.stx_ctime.tv_sec != after.stx_ctime.tv_sec
            || before.stx_ctime.tv_nsec != after.stx_ctime.tv_nsec
        {
            self.poison();
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.verify_entry(name, &before)?;
        self.verify_binding()?;
        Ok(bytes)
    }

    pub(in super::super) fn write_atomic(
        &self,
        name: &CStr,
        bytes: &[u8],
    ) -> Result<(), ExecutionDomainError> {
        self.write_atomic_with_sync(name, bytes, sync)
    }

    pub(in super::super) fn write_new(
        &self,
        name: &CStr,
        bytes: &[u8],
    ) -> Result<OwnedFd, ExecutionDomainError> {
        self.write_with_sync(name, bytes, true, sync)
    }

    pub(super) fn write_atomic_with_sync<F>(
        &self,
        name: &CStr,
        bytes: &[u8],
        sync_file: F,
    ) -> Result<(), ExecutionDomainError>
    where
        F: FnMut(RawFd, SyncKind) -> io::Result<()>,
    {
        self.write_with_sync(name, bytes, false, sync_file)
            .map(drop)
    }

    fn write_with_sync<F>(
        &self,
        name: &CStr,
        bytes: &[u8],
        new: bool,
        mut sync_file: F,
    ) -> Result<OwnedFd, ExecutionDomainError>
    where
        F: FnMut(RawFd, SyncKind) -> io::Result<()>,
    {
        component(name)?;
        let result = (|| {
            self.verify_binding()?;
            let previous = self.optional_metadata(name)?;
            if new && previous.is_some() {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            if let Some(previous) = &previous {
                self.validate_regular(previous, usize::MAX)?;
            }
            let mut next_bytes = name.to_bytes().to_vec();
            next_bytes.extend_from_slice(b".next");
            let next =
                CString::new(next_bytes).map_err(|_| failure(FailureCategory::InvalidInput))?;
            self.refuse_entry(&next)?;
            let fd = open_at(
                self.fd(),
                &next,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
                RESOLVE_POLICY,
            )?;
            checked(unsafe { libc::fchmod(fd.as_raw_fd(), 0o600) })?;
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(io_failure)?;
            sync_file(file.as_raw_fd(), SyncKind::File).map_err(io_failure)?;
            let written = metadata(file.as_raw_fd())?;
            self.validate_regular(&written, bytes.len())?;
            self.verify_binding()?;
            self.verify_entry(&next, &written)?;
            if let Some(previous) = &previous {
                self.verify_entry(name, previous)?;
            } else {
                self.refuse_entry(name)?;
            }
            rename(
                self.fd(),
                &next,
                name,
                if previous.is_none() {
                    libc::RENAME_NOREPLACE
                } else {
                    0
                },
            )?;
            sync_file(self.fd(), SyncKind::Directory).map_err(io_failure)?;
            self.verify_entry(name, &written)?;
            self.verify_binding()?;
            Ok(file.into())
        })();
        result.inspect_err(|_| self.poison())
    }

    pub(super) fn fd(&self) -> RawFd {
        self.binding.fd.as_raw_fd()
    }

    pub(in crate::job::execution_domain) fn root_path(&self) -> &Path {
        self.root_path.as_path()
    }

    pub(in crate::job::execution_domain) fn sync_directory(
        &self,
    ) -> Result<(), ExecutionDomainError> {
        self.verify_binding()?;
        sync(self.fd(), SyncKind::Directory).map_err(io_failure)
    }

    /// Roll back only a just-created transaction with a complete descriptor inventory.
    /// Failure poison does not preclude proving these identities afresh for rollback.
    pub(super) fn remove_created_child(
        &self,
        name: &CStr,
        child: &Self,
        files: &[(&CStr, &OwnedFd)],
    ) -> Result<(), ExecutionDomainError> {
        let result = (|| {
            component(name)?;
            verify_chain(&self.binding)?;
            verify_chain(&child.binding)?;
            let child_named = stat_at(self.fd(), name).map_err(io_failure)?;
            if identity(&child_named) != child.binding.identity {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            let mut count = 0;
            for entry in directory_entries_stream(child.fd())? {
                let entry = entry?;
                count += 1;
                if count > files.len() || !files.iter().any(|(name, _)| *name == entry.as_c_str()) {
                    return Err(failure(FailureCategory::IdentityMismatch));
                }
            }
            if count != files.len() {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            let verify = |name: &CStr, fd: &OwnedFd| -> Result<(), ExecutionDomainError> {
                let original = metadata(fd.as_raw_fd())?;
                let current = stat_at(child.fd(), name).map_err(io_failure)?;
                if identity(&current) != identity(&original)
                    || current.stx_mode != original.stx_mode
                    || current.stx_nlink != 1
                {
                    return Err(failure(FailureCategory::IdentityMismatch));
                }
                Ok(())
            };
            for (name, fd) in files {
                verify(name, fd)?;
            }
            for (name, fd) in files {
                verify_chain(&child.binding)?;
                verify(name, fd)?;
                checked(unsafe { libc::unlinkat(child.fd(), name.as_ptr(), 0) })?;
            }
            verify_chain(&child.binding)?;
            checked(unsafe { libc::unlinkat(self.fd(), name.as_ptr(), libc::AT_REMOVEDIR) })?;
            sync(self.fd(), SyncKind::Directory).map_err(io_failure)
        })();
        result.inspect_err(|_| self.poison())
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn optional_metadata(&self, name: &CStr) -> Result<Option<libc::statx>, ExecutionDomainError> {
        match stat_at(self.fd(), name) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(io_failure(error)),
        }
    }

    pub(super) fn verify_entry(
        &self,
        name: &CStr,
        expected: &libc::statx,
    ) -> Result<(), ExecutionDomainError> {
        self.verify_named_entry(name, expected, true)
    }

    fn verify_named_entry(
        &self,
        name: &CStr,
        expected: &libc::statx,
        check_links: bool,
    ) -> Result<(), ExecutionDomainError> {
        self.verify_binding()?;
        let current = stat_at(self.fd(), name)
            .map_err(io_failure)
            .inspect_err(|_| self.poison())?;
        if identity(&current) != identity(expected)
            || current.stx_mode != expected.stx_mode
            || (check_links && current.stx_nlink != expected.stx_nlink)
        {
            self.poison();
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }

    fn validate_regular(
        &self,
        metadata: &libc::statx,
        limit: usize,
    ) -> Result<(), ExecutionDomainError> {
        if u32::from(metadata.stx_mode) & libc::S_IFMT != libc::S_IFREG
            || metadata.stx_nlink != 1
            || metadata.stx_size > limit as u64
            || metadata.stx_mnt_id != self.binding.identity.mount_id
            || (metadata.stx_dev_major, metadata.stx_dev_minor) != self.binding.identity.device
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }

    /// Only the cgroup-empty teardown driver may enable this in production (Task 10).
    pub(super) fn remove_tree(&self, name: &CStr) -> Result<(), ExecutionDomainError> {
        component(name)?;
        let result = (|| {
            let attempt = self.child(name)?;
            // Inventory the whole tree before the first unlink so unknown control
            // entries and mounts preserve all available recovery evidence.
            let tree = attempt.inventory(RemovalPolicy::Attempt)?;
            attempt.remove_inventory(tree)?;
            attempt.verify_binding()?;
            checked(unsafe { libc::unlinkat(self.fd(), name.as_ptr(), libc::AT_REMOVEDIR) })?;
            sync(self.fd(), SyncKind::Directory).map_err(io_failure)
        })();
        result.inspect_err(|_| self.poison())
    }

    fn inventory(&self, policy: RemovalPolicy) -> Result<Vec<RemovalEntry>, ExecutionDomainError> {
        self.verify_binding()?;
        let mut entries = Vec::new();
        for name in directory_entries(self.fd())? {
            let metadata = stat_at(self.fd(), &name).map_err(io_failure)?;
            if identity(&metadata).mount_id != self.binding.identity.mount_id
                || identity(&metadata).device != self.binding.identity.device
                || metadata.stx_uid != unsafe { libc::geteuid() }
            {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            let mode = u32::from(metadata.stx_mode) & libc::S_IFMT;
            if policy == RemovalPolicy::Attempt {
                let expected_directory = matches!(
                    name.to_bytes(),
                    b"rootlesskit"
                        | b"rootfs"
                        | b"work"
                        | b"tmp"
                        | b"home"
                        | b"run"
                        | b"docker"
                        | b"docker-data"
                        | b"docker-exec"
                );
                if !(expected_directory && mode == libc::S_IFDIR
                    || name.to_bytes() == b"journal.json"
                        && mode == libc::S_IFREG
                        && metadata.stx_nlink == 1)
                {
                    return Err(failure(FailureCategory::IdentityMismatch));
                }
            }
            match mode {
                libc::S_IFDIR => {
                    let child = self.child(&name)?;
                    let child_policy = match policy {
                        RemovalPolicy::Attempt
                            if matches!(name.to_bytes(), b"rootlesskit" | b"rootfs") =>
                        {
                            RemovalPolicy::Supervisor
                        }
                        RemovalPolicy::Attempt => RemovalPolicy::Writable,
                        policy => policy,
                    };
                    let children = child.inventory(child_policy)?;
                    entries.push(RemovalEntry::Directory(name, child, children));
                }
                libc::S_IFREG | libc::S_IFLNK | libc::S_IFIFO => {
                    if mode != libc::S_IFREG && policy != RemovalPolicy::Writable {
                        return Err(failure(FailureCategory::IdentityMismatch));
                    }
                    if mode == libc::S_IFREG
                        && policy != RemovalPolicy::Writable
                        && metadata.stx_nlink != 1
                    {
                        return Err(failure(FailureCategory::IdentityMismatch));
                    }
                    entries.push(RemovalEntry::Leaf {
                        name,
                        expected: Box::new(metadata),
                        writable: policy == RemovalPolicy::Writable,
                    });
                }
                // A socket name alone does not prove ownership. No managed runtime
                // creates owned sockets yet; admission is added with its owner.
                _ => return Err(failure(FailureCategory::IdentityMismatch)),
            }
        }
        Ok(entries)
    }

    fn remove_inventory(&self, entries: Vec<RemovalEntry>) -> Result<(), ExecutionDomainError> {
        for entry in entries {
            match entry {
                RemovalEntry::Directory(name, directory, entries) => {
                    directory.remove_inventory(entries)?;
                    directory.verify_binding()?;
                    checked(unsafe {
                        libc::unlinkat(self.fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                    })?;
                }
                RemovalEntry::Leaf {
                    name,
                    expected,
                    writable,
                } => {
                    // Earlier unlinks of the same inode change nlink. The name,
                    // inode, mode and mount binding still prove which leaf is removed.
                    self.verify_named_entry(&name, &expected, !writable)?;
                    checked(unsafe { libc::unlinkat(self.fd(), name.as_ptr(), 0) })?;
                }
            }
            self.verify_binding()?;
        }
        sync(self.fd(), SyncKind::Directory).map_err(io_failure)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemovalPolicy {
    Attempt,
    Supervisor,
    Writable,
}

enum RemovalEntry {
    Directory(CString, BoundDir, Vec<RemovalEntry>),
    Leaf {
        name: CString,
        expected: Box<libc::statx>,
        writable: bool,
    },
}

pub(super) fn directory_entries(fd: RawFd) -> Result<Vec<CString>, ExecutionDomainError> {
    directory_entries_stream(fd)?.collect()
}

pub(super) struct DirectoryEntries(*mut libc::DIR);

impl Drop for DirectoryEntries {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

pub(super) fn directory_entries_stream(
    fd: RawFd,
) -> Result<DirectoryEntries, ExecutionDomainError> {
    use std::os::fd::IntoRawFd;
    let duplicate = open_at(fd, c".", DIRECTORY_FLAGS, 0, RESOLVE_POLICY)?;
    let raw = duplicate.into_raw_fd();
    let directory = unsafe { libc::fdopendir(raw) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(raw) };
        return Err(io_failure(error));
    }
    Ok(DirectoryEntries(directory))
}

impl Iterator for DirectoryEntries {
    type Item = Result<CString, ExecutionDomainError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    None
                } else {
                    Some(Err(io_failure(error)))
                };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name != c"." && name != c".." {
                return Some(component(name).map(|()| name.to_owned()));
            }
        }
    }
}

fn verify_chain(binding: &Binding) -> Result<(), ExecutionDomainError> {
    let current = metadata(binding.fd.as_raw_fd())?;
    if identity(&current) != binding.identity
        || u32::from(current.stx_mode) & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    if let Some((parent, name)) = &binding.parent {
        verify_chain(parent)?;
        let named = stat_at(parent.fd.as_raw_fd(), name).map_err(io_failure)?;
        if identity(&named) != binding.identity
            || u32::from(named.stx_mode) & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
    }
    Ok(())
}

fn component(name: &CStr) -> Result<(), ExecutionDomainError> {
    if name.is_empty() || name == c"." || name == c".." || name.to_bytes().contains(&b'/') {
        return Err(failure(FailureCategory::InvalidInput));
    }
    Ok(())
}

pub(super) fn metadata(fd: RawFd) -> Result<libc::statx, ExecutionDomainError> {
    stat_at(fd, c"").map_err(io_failure)
}

pub(super) fn stat_at(fd: RawFd, name: &CStr) -> io::Result<libc::statx> {
    let mut value = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let requested = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
    let result = unsafe {
        libc::statx(
            fd,
            name.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            requested,
            value.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = unsafe { value.assume_init() };
    if value.stx_mask & requested != requested {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    Ok(value)
}

fn identity(metadata: &libc::statx) -> Identity {
    Identity {
        device: (metadata.stx_dev_major, metadata.stx_dev_minor),
        inode: metadata.stx_ino,
        mount_id: metadata.stx_mnt_id,
    }
}

pub(super) fn open_at(
    fd: RawFd,
    name: &CStr,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> Result<OwnedFd, ExecutionDomainError> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.mode = mode as u64;
    how.resolve = resolve;
    owned_fd(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            fd,
            name.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    } as i32)
}

fn owned_fd(fd: i32) -> Result<OwnedFd, ExecutionDomainError> {
    if fd < 0 {
        Err(io_failure(io::Error::last_os_error()))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn rename(fd: RawFd, old: &CStr, new: &CStr, flags: u32) -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::renameat2(fd, old.as_ptr(), fd, new.as_ptr(), flags) })
}

fn sync(fd: RawFd, _kind: SyncKind) -> io::Result<()> {
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn checked(result: i32) -> Result<(), ExecutionDomainError> {
    if result == 0 {
        Ok(())
    } else {
        Err(io_failure(io::Error::last_os_error()))
    }
}

fn io_failure(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Filesystem,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Filesystem,
        category,
        errno: None,
    }
}
