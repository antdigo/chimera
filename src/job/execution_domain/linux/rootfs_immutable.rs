use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::{
    ExecutionDomainError, FailureCategory, MountInput, SYSTEM_INPUTS, checked_metadata, failure,
    invalid, io_failure, open_path, parse_mountinfo,
};

// These are refusal ceilings, not sizing defaults. Wide caches are streamed;
// descriptors and path storage grow only with the bounded directory depth.
const MAX_ENTRIES: usize = 10_000_000;
const MAX_DEPTH: usize = 128;
const MAX_DURATION: Duration = Duration::from_secs(30);

pub(super) fn fingerprint(
    input: &MountInput,
    namespace: bool,
) -> Result<[u8; 32], ExecutionDomainError> {
    checked_metadata(input)?;
    let fd = open_path(&input.source)?;
    fingerprint_fd(input, &fd, namespace)
}

pub(super) fn fingerprint_fd(
    input: &MountInput,
    fd: &OwnedFd,
    namespace: bool,
) -> Result<[u8; 32], ExecutionDomainError> {
    inspect(input, fd, namespace, MAX_ENTRIES, MAX_DEPTH)
}

pub(super) fn verify_snapshot(
    input: &MountInput,
    fd: &OwnedFd,
    namespace: bool,
) -> Result<(), ExecutionDomainError> {
    if input.immutable_fingerprint != Some(fingerprint_fd(input, fd, namespace)?) {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn fingerprint_with_budget(
    input: &MountInput,
    namespace: bool,
    entries: usize,
    depth: usize,
) -> Result<[u8; 32], ExecutionDomainError> {
    let fd = open_path(&input.source)?;
    inspect(input, &fd, namespace, entries, depth)
}

fn inspect(
    input: &MountInput,
    fd: &OwnedFd,
    namespace: bool,
    entries: usize,
    depth: usize,
) -> Result<[u8; 32], ExecutionDomainError> {
    let before = metadata(fd.as_raw_fd())?;
    if libc::makedev(before.stx_dev_major, before.stx_dev_minor) != input.expected_device
        || before.stx_ino != input.expected_inode
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    let readonly = readonly_superblock(before.stx_mnt_id)?;
    let owner = if namespace {
        fs::read_to_string("/proc/sys/kernel/overflowuid")
            .map_err(io_failure)?
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid())?
    } else {
        // Root-owned operator inputs are outside the service's user mapping.
        // Do not accept arbitrary non-service UIDs: they may be subordinate IDs.
        if unsafe { libc::geteuid() } == 0 && !readonly {
            return Err(invalid());
        }
        0
    };
    let mut walk = Walk {
        remaining: entries,
        max_depth: depth,
        deadline: Instant::now() + MAX_DURATION,
        mount_id: before.stx_mnt_id,
        device: (before.stx_dev_major, before.stx_dev_minor),
        readonly,
        owner,
        system: SYSTEM_INPUTS.contains(&input.target.as_str()),
        input,
        digest: Sha256::new(),
    };
    walk.visit(fd, Path::new(""), 0)?;
    if !same_metadata(&before, &metadata(fd.as_raw_fd())?)
        || readonly_superblock(before.stx_mnt_id)? != readonly
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    // The named source must still designate the object whose tree was checked.
    checked_metadata(input)?;
    Ok(walk.digest.finalize().into())
}

struct Walk<'a> {
    remaining: usize,
    max_depth: usize,
    deadline: Instant,
    mount_id: u64,
    device: (u32, u32),
    readonly: bool,
    owner: u32,
    system: bool,
    input: &'a MountInput,
    digest: Sha256,
}

impl Walk<'_> {
    fn visit(
        &mut self,
        fd: &OwnedFd,
        relative: &Path,
        depth: usize,
    ) -> Result<(), ExecutionDomainError> {
        if self.remaining == 0 || depth >= self.max_depth || Instant::now() >= self.deadline {
            return Err(failure(FailureCategory::Unavailable));
        }
        self.remaining -= 1;
        let before = metadata(fd.as_raw_fd())?;
        let kind = u32::from(before.stx_mode) & libc::S_IFMT;
        if !matches!(kind, libc::S_IFDIR | libc::S_IFREG | libc::S_IFLNK)
            || before.stx_mnt_id != self.mount_id
            || (before.stx_dev_major, before.stx_dev_minor) != self.device
            || !self.readonly
                && (before.stx_uid != self.owner
                    || kind != libc::S_IFLNK && before.stx_mode & 0o022 != 0)
        {
            return Err(invalid());
        }
        let name = relative.as_os_str().as_encoded_bytes();
        self.digest.update((name.len() as u64).to_le_bytes());
        self.digest.update(name);
        hash_metadata(&mut self.digest, &before);
        if kind == libc::S_IFLNK {
            let mut target = [0u8; 4096];
            let size = unsafe {
                libc::readlinkat(
                    fd.as_raw_fd(),
                    c"".as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if size < 0 {
                return Err(io_failure(io::Error::last_os_error()));
            }
            if size as usize == target.len() {
                return Err(invalid());
            }
            let target = &target[..size as usize];
            if !self.system {
                use std::os::unix::ffi::OsStrExt;
                confined_symlink(
                    &self.input.source,
                    relative,
                    Path::new(std::ffi::OsStr::from_bytes(target)),
                )?;
            }
            self.digest.update((target.len() as u64).to_le_bytes());
            self.digest.update(target);
        } else if kind == libc::S_IFDIR {
            let mut entries = Directory::open(fd.as_raw_fd())?;
            while let Some(name) = entries.next()? {
                let child = open_child(fd.as_raw_fd(), &name)?;
                self.visit(
                    &child,
                    &relative.join(std::ffi::OsStr::from_bytes(name.to_bytes())),
                    depth + 1,
                )?;
                // Detect rename/replacement even when the replacement has the same
                // file type and lives on the same filesystem.
                let named = open_child(fd.as_raw_fd(), &name)?;
                if !same_metadata(&metadata(child.as_raw_fd())?, &metadata(named.as_raw_fd())?) {
                    return Err(failure(FailureCategory::IdentityMismatch));
                }
            }
        }
        if !same_metadata(&before, &metadata(fd.as_raw_fd())?) {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }
}

use std::os::unix::ffi::OsStrExt;

fn confined_symlink(
    root: &Path,
    relative: &Path,
    target: &Path,
) -> Result<(), ExecutionDomainError> {
    let path = if target.is_absolute() {
        target.strip_prefix(root).map_err(|_| invalid())?.to_owned()
    } else {
        relative.parent().unwrap_or(Path::new("")).join(target)
    };
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

fn readonly_superblock(mount_id: u64) -> Result<bool, ExecutionDomainError> {
    // The left-side ro flag (also reported by statvfs) may be merely a readonly
    // bind, which namespace root can undo. Only the superblock-side flag counts.
    let mounts = parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").map_err(io_failure)?)?;
    mounts
        .iter()
        .find(|mount| mount.id == mount_id)
        .map(|mount| mount.super_readonly)
        .ok_or_else(invalid)
}

fn metadata(fd: RawFd) -> Result<libc::statx, ExecutionDomainError> {
    let mut value = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let mask = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
    if unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            mask,
            value.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let value = unsafe { value.assume_init() };
    if value.stx_mask & mask != mask {
        return Err(failure(FailureCategory::Unsupported));
    }
    Ok(value)
}

fn same_metadata(a: &libc::statx, b: &libc::statx) -> bool {
    a.stx_ino == b.stx_ino
        && a.stx_dev_major == b.stx_dev_major
        && a.stx_dev_minor == b.stx_dev_minor
        && a.stx_mnt_id == b.stx_mnt_id
        && a.stx_mode == b.stx_mode
        && a.stx_uid == b.stx_uid
        && a.stx_gid == b.stx_gid
        && a.stx_size == b.stx_size
        && a.stx_nlink == b.stx_nlink
        && a.stx_ctime.tv_sec == b.stx_ctime.tv_sec
        && a.stx_ctime.tv_nsec == b.stx_ctime.tv_nsec
        && a.stx_mtime.tv_sec == b.stx_mtime.tv_sec
        && a.stx_mtime.tv_nsec == b.stx_mtime.tv_nsec
}

fn hash_metadata(hash: &mut Sha256, stat: &libc::statx) {
    // UID/GID and mount IDs are translated by namespace entry. Ownership policy
    // is checked on each pass; chown also changes ctime, included in this digest.
    for value in [
        stat.stx_ino,
        stat.stx_dev_major as u64,
        stat.stx_dev_minor as u64,
        stat.stx_mode as u64,
        stat.stx_size,
        stat.stx_nlink as u64,
        stat.stx_ctime.tv_sec as u64,
        stat.stx_ctime.tv_nsec as u64,
        stat.stx_mtime.tv_sec as u64,
        stat.stx_mtime.tv_nsec as u64,
    ] {
        hash.update(value.to_le_bytes());
    }
}

fn open_child(parent: RawFd, name: &CStr) -> Result<OwnedFd, ExecutionDomainError> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_XDEV;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if raw < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

struct Directory(*mut libc::DIR);
impl Directory {
    fn open(fd: RawFd) -> Result<Self, ExecutionDomainError> {
        let raw = unsafe {
            libc::openat(
                fd,
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(io_failure(io::Error::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let directory = unsafe { libc::fdopendir(fd.as_raw_fd()) };
        if directory.is_null() {
            return Err(io_failure(io::Error::last_os_error()));
        }
        let _ = fd.into_raw_fd();
        Ok(Self(directory))
    }
    fn next(&mut self) -> Result<Option<CString>, ExecutionDomainError> {
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(io_failure(error))
                };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name != c"." && name != c".." {
                return Ok(Some(name.to_owned()));
            }
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}
