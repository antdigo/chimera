use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::{ExecutionDomainError, FailureCategory, Stage};

const MAX_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_HASH_TIME: Duration = Duration::from_secs(30);
const MAX_TRAVERSAL_DEPTH: usize = 128;
const MAX_TRAVERSAL_ENTRIES: usize = 1_000_000;
const MAX_RELATIVE_PATH_BYTES: usize = 256 * 1024 * 1024;
const MAX_MATCHES: usize = 100_000;
const DIRECTORY_FLAGS: i32 =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
const READ_FLAGS: i32 = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

#[derive(Clone, Copy, Debug)]
struct ReadLimits {
    max_hash_bytes: u64,
    max_time: Duration,
    max_depth: usize,
    max_entries: usize,
    max_path_bytes: usize,
    max_matches: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_hash_bytes: MAX_HASH_BYTES,
            max_time: MAX_HASH_TIME,
            max_depth: MAX_TRAVERSAL_DEPTH,
            max_entries: MAX_TRAVERSAL_ENTRIES,
            max_path_bytes: MAX_RELATIVE_PATH_BYTES,
            max_matches: MAX_MATCHES,
        }
    }
}

#[derive(Debug, Default)]
struct TraversalBudget {
    entries: usize,
    path_bytes: usize,
    matches: usize,
}

struct Traversal<'a> {
    root_device: u64,
    patterns: &'a [glob::Pattern],
    matched: &'a mut BTreeSet<PathBuf>,
    budget: &'a mut TraversalBudget,
    started: Instant,
    limits: ReadLimits,
}

#[derive(Debug)]
struct RootBinding {
    fd: OwnedFd,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct ReaderState {
    root: Option<Arc<RootBinding>>,
    bound_path: PathBuf,
    revoked: bool,
    active: usize,
}

#[derive(Debug)]
struct SharedReader {
    state: Mutex<ReaderState>,
    idle: Condvar,
}

/// Opaque, revocable descriptor-bound capability used by the synchronous
/// expression evaluator. A path is consumed exactly once while binding; all
/// workflow-controlled traversal thereafter is relative to the pinned dirfd.
#[derive(Clone, Debug)]
pub struct DomainWorkspaceReader {
    shared: Arc<SharedReader>,
}

struct ReadLease {
    shared: Arc<SharedReader>,
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.active = state.active.saturating_sub(1);
            self.shared.idle.notify_all();
        }
    }
}

impl DomainWorkspaceReader {
    #[cfg(test)]
    pub(crate) fn new(root: PathBuf) -> Result<Self, ExecutionDomainError> {
        let reader = Self::unbound();
        reader.bind(root)?;
        Ok(reader)
    }

    pub(super) fn unbound() -> Self {
        Self {
            shared: Arc::new(SharedReader {
                state: Mutex::new(ReaderState {
                    root: None,
                    bound_path: PathBuf::new(),
                    revoked: false,
                    active: 0,
                }),
                idle: Condvar::new(),
            }),
        }
    }

    pub fn hash_files(&self, patterns: &[String]) -> Result<String, ExecutionDomainError> {
        self.hash_files_with_limits(patterns, ReadLimits::default())
    }

    fn hash_files_with_limits(
        &self,
        patterns: &[String],
        limits: ReadLimits,
    ) -> Result<String, ExecutionDomainError> {
        let (_lease, root) = self.acquire()?;
        verify_directory(&root.fd, root.device, root.inode)?;
        let started = Instant::now();
        let compiled = patterns
            .iter()
            .map(|pattern| {
                validate_pattern(pattern)?;
                glob::Pattern::new(pattern).map_err(|_| failure(FailureCategory::InvalidInput))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut matched = BTreeSet::new();
        let mut budget = TraversalBudget::default();
        let mut traversal = Traversal {
            root_device: root.device,
            patterns: &compiled,
            matched: &mut matched,
            budget: &mut budget,
            started,
            limits,
        };
        traversal.enumerate(root.fd.as_raw_fd(), Path::new(""), 0)?;
        if matched.is_empty() {
            return Ok(String::new());
        }

        let mut total = 0u64;
        let mut hasher = Sha256::new();
        for relative in matched {
            check_deadline(started, limits.max_time)?;
            let mut file = File::from(open_relative_regular(
                &root,
                &relative,
                started,
                limits.max_time,
            )?);
            let before = file.metadata().map_err(io_failure)?;
            validate_regular_metadata(&before, root.device)?;
            if before.len() > limits.max_hash_bytes.saturating_sub(total) {
                return Err(failure(FailureCategory::InvalidInput));
            }
            let mut buffer = [0u8; 64 * 1024];
            loop {
                check_deadline(started, limits.max_time)?;
                let count = file.read(&mut buffer).map_err(io_failure)?;
                check_deadline(started, limits.max_time)?;
                if count == 0 {
                    break;
                }
                total = total
                    .checked_add(count as u64)
                    .filter(|total| *total <= limits.max_hash_bytes)
                    .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
                hasher.update(&buffer[..count]);
            }
            let after = file.metadata().map_err(io_failure)?;
            validate_regular_metadata(&after, root.device)?;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.mode() != after.mode()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn acquire(&self) -> Result<(ReadLease, Arc<RootBinding>), ExecutionDomainError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| failure(FailureCategory::Io))?;
        if state.revoked {
            return Err(failure(FailureCategory::Unavailable));
        }
        let root = state
            .root
            .clone()
            .ok_or_else(|| failure(FailureCategory::Unavailable))?;
        state.active += 1;
        drop(state);
        Ok((
            ReadLease {
                shared: Arc::clone(&self.shared),
            },
            root,
        ))
    }

    pub(super) fn bind(&self, root: PathBuf) -> Result<(), ExecutionDomainError> {
        let binding = Arc::new(open_root(&root)?);
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| failure(FailureCategory::Io))?;
        if state.root.is_some() && state.bound_path == root {
            return Ok(());
        }
        if state.revoked || state.active != 0 || state.root.is_some() {
            return Err(failure(FailureCategory::Unavailable));
        }
        state.bound_path = root;
        state.root = Some(binding);
        Ok(())
    }

    pub(super) fn revoke_and_wait(&self) {
        let Ok(mut state) = self.shared.state.lock() else {
            return;
        };
        state.revoked = true;
        while state.active != 0 {
            let Ok(next) = self.shared.idle.wait(state) else {
                return;
            };
            state = next;
        }
        state.root.take();
    }
}

fn open_root(path: &Path) -> Result<RootBinding, ExecutionDomainError> {
    if !path.is_absolute() {
        return Err(failure(FailureCategory::InvalidInput));
    }
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| failure(FailureCategory::InvalidInput))?;
    let fd = owned_fd(unsafe { libc::open(path.as_ptr(), DIRECTORY_FLAGS) })?;
    let metadata = metadata(fd.as_raw_fd())?;
    if file_type(&metadata) != libc::S_IFDIR {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(RootBinding {
        fd,
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

fn verify_directory(fd: &OwnedFd, device: u64, inode: u64) -> Result<(), ExecutionDomainError> {
    let current = metadata(fd.as_raw_fd())?;
    if file_type(&current) != libc::S_IFDIR
        || current.st_dev as u64 != device
        || current.st_ino != inode
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

fn validate_pattern(pattern: &str) -> Result<(), ExecutionDomainError> {
    let path = Path::new(pattern);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(failure(FailureCategory::InvalidInput));
    }
    Ok(())
}

impl Traversal<'_> {
    fn enumerate(
        &mut self,
        directory: RawFd,
        relative_dir: &Path,
        depth: usize,
    ) -> Result<(), ExecutionDomainError> {
        check_deadline(self.started, self.limits.max_time)?;
        for_each_directory_entry(directory, self.started, self.limits.max_time, |name| {
            consume_budget(self.budget, self.limits, relative_dir, name)?;
            check_deadline(self.started, self.limits.max_time)?;
            let before = metadata_at(directory, name)?;
            check_deadline(self.started, self.limits.max_time)?;
            if before.st_dev as u64 != self.root_device {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            let relative = relative_dir.join(OsString::from_vec(name.to_bytes().to_vec()));
            match file_type(&before) {
                libc::S_IFDIR => {
                    let child_depth = depth
                        .checked_add(1)
                        .filter(|depth| *depth <= self.limits.max_depth)
                        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
                    let child = open_component_bounded(
                        directory,
                        name,
                        DIRECTORY_FLAGS,
                        self.started,
                        self.limits.max_time,
                    )?;
                    let after = metadata(child.as_raw_fd())?;
                    if !same_identity(&before, &after) || after.st_dev as u64 != self.root_device {
                        return Err(failure(FailureCategory::IdentityMismatch));
                    }
                    self.enumerate(child.as_raw_fd(), &relative, child_depth)?;
                }
                libc::S_IFREG => {
                    if self
                        .patterns
                        .iter()
                        .any(|pattern| pattern.matches_path(&relative))
                        && !self.matched.contains(&relative)
                    {
                        self.budget.matches = self
                            .budget
                            .matches
                            .checked_add(1)
                            .filter(|matches| *matches <= self.limits.max_matches)
                            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
                        self.matched.insert(relative);
                    }
                }
                _ => return Err(failure(FailureCategory::IdentityMismatch)),
            }
            Ok(())
        })
    }
}

fn consume_budget(
    budget: &mut TraversalBudget,
    limits: ReadLimits,
    relative_dir: &Path,
    name: &CStr,
) -> Result<(), ExecutionDomainError> {
    budget.entries = budget
        .entries
        .checked_add(1)
        .filter(|entries| *entries <= limits.max_entries)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;

    let separator = usize::from(!relative_dir.as_os_str().is_empty());
    let relative_bytes = relative_dir
        .as_os_str()
        .as_bytes()
        .len()
        .checked_add(separator)
        .and_then(|bytes| bytes.checked_add(name.to_bytes().len()))
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    budget.path_bytes = budget
        .path_bytes
        .checked_add(relative_bytes)
        .filter(|bytes| *bytes <= limits.max_path_bytes)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    Ok(())
}

fn open_relative_regular(
    root: &RootBinding,
    relative: &Path,
    started: Instant,
    max_time: Duration,
) -> Result<OwnedFd, ExecutionDomainError> {
    check_deadline(started, max_time)?;
    let mut directory = duplicate(root.fd.as_raw_fd())?;
    check_deadline(started, max_time)?;
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(failure(FailureCategory::InvalidInput));
        };
        let name =
            CString::new(name.as_bytes()).map_err(|_| failure(FailureCategory::InvalidInput))?;
        let last = components.peek().is_none();
        let next = open_component_bounded(
            directory.as_raw_fd(),
            &name,
            if last { READ_FLAGS } else { DIRECTORY_FLAGS },
            started,
            max_time,
        )?;
        let metadata = metadata(next.as_raw_fd())?;
        if metadata.st_dev as u64 != root.device
            || if last {
                file_type(&metadata) != libc::S_IFREG
            } else {
                file_type(&metadata) != libc::S_IFDIR
            }
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        directory = next;
    }
    Ok(directory)
}

fn validate_regular_metadata(
    metadata: &std::fs::Metadata,
    root_device: u64,
) -> Result<(), ExecutionDomainError> {
    if !metadata.is_file() || metadata.dev() != root_device || metadata.nlink() != 1 {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

fn check_deadline(started: Instant, max_time: Duration) -> Result<(), ExecutionDomainError> {
    if started.elapsed() > max_time {
        Err(failure(FailureCategory::Timeout))
    } else {
        Ok(())
    }
}

fn for_each_directory_entry(
    fd: RawFd,
    started: Instant,
    max_time: Duration,
    mut visit: impl FnMut(&CStr) -> Result<(), ExecutionDomainError>,
) -> Result<(), ExecutionDomainError> {
    // `dup(2)` shares the directory-stream offset with the pinned descriptor.
    // Reopen `.` instead so repeated and concurrent hashFiles() evaluations
    // always enumerate from an independent open file description.
    let reopened = open_component_bounded(fd, c".", DIRECTORY_FLAGS, started, max_time)?;
    let raw = reopened.into_raw_fd();
    let directory = unsafe { libc::fdopendir(raw) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(raw) };
        return Err(io_failure(error));
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let directory = Directory(directory);
    loop {
        check_deadline(started, max_time)?;
        clear_errno();
        let entry = unsafe { libc::readdir(directory.0) };
        check_deadline(started, max_time)?;
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(io_failure(error));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name == c"." || name == c".." {
            continue;
        }
        if name.is_empty() || name.to_bytes().contains(&b'/') {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        visit(name)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

fn metadata(fd: RawFd) -> Result<libc::stat, ExecutionDomainError> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(unsafe { value.assume_init() })
}

fn metadata_at(fd: RawFd, name: &CStr) -> Result<libc::stat, ExecutionDomainError> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(unsafe { value.assume_init() })
}

fn file_type(metadata: &libc::stat) -> libc::mode_t {
    metadata.st_mode & libc::S_IFMT
}

fn same_identity(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino && left.st_mode == right.st_mode
}

#[cfg(target_os = "linux")]
fn open_component(fd: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd, ExecutionDomainError> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_XDEV;
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

#[cfg(not(target_os = "linux"))]
fn open_component(fd: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd, ExecutionDomainError> {
    owned_fd(unsafe { libc::openat(fd, name.as_ptr(), flags) })
}

fn open_component_bounded(
    fd: RawFd,
    name: &CStr,
    flags: i32,
    started: Instant,
    max_time: Duration,
) -> Result<OwnedFd, ExecutionDomainError> {
    check_deadline(started, max_time)?;
    let opened = open_component(fd, name, flags)?;
    check_deadline(started, max_time)?;
    Ok(opened)
}

fn duplicate(fd: RawFd) -> Result<OwnedFd, ExecutionDomainError> {
    owned_fd(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })
}

fn owned_fd(fd: i32) -> Result<OwnedFd, ExecutionDomainError> {
    if fd < 0 {
        Err(io_failure(std::io::Error::last_os_error()))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn io_failure(error: std::io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::State,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::State,
        category,
        errno: None,
    }
}

#[cfg(test)]
#[path = "workspace_reader_test.rs"]
mod workspace_reader_test;
