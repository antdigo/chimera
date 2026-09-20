use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory, Stage};
use super::dirfd::{self, BoundDir};
use crate::config::resources::ValidatedLimits;

const CONTROLLERS: [&str; 4] = ["cpu", "memory", "pids", "io"];
const ENABLE: &str = "+cpu +memory +pids +io";
const READ_LIMIT: u64 = 1024 * 1024;
const MAX_GROUPS: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_ENTRIES: usize = MAX_GROUPS * 128;

struct TraversalBudget {
    groups: usize,
    entries: usize,
}

impl TraversalBudget {
    fn new() -> Self {
        Self {
            groups: MAX_GROUPS - 1,
            entries: MAX_ENTRIES,
        }
    }

    fn entry(&mut self) -> Result<(), ExecutionDomainError> {
        self.entries = self
            .entries
            .checked_sub(1)
            .ok_or_else(|| failure(FailureCategory::Unavailable))?;
        Ok(())
    }

    fn child(&mut self, depth: usize) -> Result<(), ExecutionDomainError> {
        if depth >= MAX_DEPTH {
            return Err(failure(FailureCategory::Unavailable));
        }
        self.groups = self
            .groups
            .checked_sub(1)
            .ok_or_else(|| failure(FailureCategory::Unavailable))?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CgroupOperation {
    CreateAttempt,
    WriteLimit(String, String),
    VerifyLimits,
    EnableControllers,
    CreateDomain,
    OpenMembership,
}

pub(super) fn creation_operations(writes: &[(&str, String)]) -> Vec<CgroupOperation> {
    let mut operations = vec![CgroupOperation::CreateAttempt];
    operations.extend(
        writes
            .iter()
            .map(|(name, value)| CgroupOperation::WriteLimit((*name).into(), value.clone())),
    );
    operations.extend([
        CgroupOperation::VerifyLimits,
        CgroupOperation::EnableControllers,
        CgroupOperation::CreateDomain,
        CgroupOperation::OpenMembership,
    ]);
    operations
}

pub(super) fn validate_controllers(value: &str) -> Result<(), ExecutionDomainError> {
    let available: BTreeSet<_> = value.split_whitespace().collect();
    if CONTROLLERS.iter().all(|name| available.contains(name)) {
        Ok(())
    } else {
        Err(failure(FailureCategory::Unsupported))
    }
}

// This boundary represents the external cgroup filesystem, not a second driver.
// Tests supply real temporary files to inject kernel read/write failures safely.
pub(super) trait CgroupFilesystem: Send + Sync + 'static {
    fn verify_filesystem(&self, fd: RawFd) -> io::Result<()> {
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        check(unsafe { libc::fstatfs(fd, stat.as_mut_ptr()) })?;
        if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(io::Error::from_raw_os_error(libc::ENODEV));
        }
        Ok(())
    }

    fn create(&self, parent: RawFd, name: &CStr) -> io::Result<()> {
        check(unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) })
    }

    fn read(&self, file: &mut File, _name: &CStr) -> io::Result<String> {
        read_bounded(file)
    }

    fn write(&self, file: &mut File, _name: &CStr, value: &str) -> io::Result<()> {
        // cgroup command writes must be one complete write; retrying a suffix
        // would send a different command to the kernel.
        let bytes = format!("{value}\n");
        match file.write(bytes.as_bytes()) {
            Ok(count) if count == bytes.len() => Ok(()),
            Ok(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            Err(error) => Err(error),
        }
    }

    fn remove(&self, parent: RawFd, name: &CStr, _child: RawFd) -> io::Result<()> {
        check(unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) })
    }
}

pub(super) struct KernelCgroupFs;
impl CgroupFilesystem for KernelCgroupFs {}

pub(super) struct CgroupRoot<F = KernelCgroupFs> {
    directory: Arc<CgroupDir<F>>,
    global: Option<ValidatedLimits>,
}

pub(super) struct AttemptCgroup<F = KernelCgroupFs> {
    directory: Arc<CgroupDir<F>>,
    domain: Arc<CgroupDir<F>>,
    membership: OwnedFd,
    limits: ValidatedLimits,
}

struct CgroupDir<F> {
    bound: BoundDir,
    fs: Arc<F>,
    parent: Option<(Arc<CgroupDir<F>>, CString)>,
}

impl CgroupRoot {
    pub(super) fn open_delegated(path: &Path) -> Result<Self, ExecutionDomainError> {
        Self::open_with_filesystem(path, Arc::new(KernelCgroupFs))
    }
}

impl<F: CgroupFilesystem> CgroupRoot<F> {
    pub(super) fn open_with_filesystem(
        path: &Path,
        fs: Arc<F>,
    ) -> Result<Self, ExecutionDomainError> {
        let directory = Arc::new(CgroupDir {
            bound: BoundDir::open_root(path)?,
            fs,
            parent: None,
        });
        directory.verify()?;
        validate_controllers(&directory.read(c"cgroup.controllers")?)?;
        if directory.read(c"cgroup.type")?.trim() != "domain" {
            return Err(failure(FailureCategory::Unsupported));
        }
        // systemd retains ownership of service-root resource controls. Delegate=
        // grants membership/subtree management, not writes to these ancestors.
        for name in [c"cgroup.kill", c"memory.swap.max"] {
            directory.open_control(name, libc::O_PATH)?;
        }
        for name in [c"cgroup.procs", c"cgroup.subtree_control"] {
            directory.open_control(name, libc::O_WRONLY)?;
        }
        directory.read(c"memory.swap.max")?;
        Ok(Self {
            directory,
            global: None,
        })
    }

    /// Called synchronously before spawning children, while the manager holds
    /// the exclusive service-root lock. A failed startup is not retried in place.
    pub(super) fn prepare_supervisor(
        &mut self,
        limits: &ValidatedLimits,
    ) -> Result<(), ExecutionDomainError> {
        if self.global.is_some() {
            return Err(failure(FailureCategory::NotReady));
        }
        verify_limits(&self.directory, limits)?;
        let self_pid = unsafe { libc::getpid() };
        if self.directory.members()?.iter().any(|pid| *pid != self_pid) {
            return Err(failure(FailureCategory::Unavailable));
        }
        let supervisor = match dirfd::stat_at(self.directory.bound.fd(), c"supervisor") {
            Ok(_) => self.directory.child(c"supervisor")?,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                self.directory.create(c"supervisor")?
            }
            Err(error) => return Err(io_failure(error)),
        };
        if supervisor.members()?.iter().any(|pid| *pid != self_pid) || supervisor.has_children()? {
            return Err(failure(FailureCategory::Unavailable));
        }
        supervisor.write(c"cgroup.procs", "0")?;
        if !self.directory.members()?.is_empty() || supervisor.members()? != vec![self_pid] {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.directory.enable_controllers()?;
        verify_limits(&self.directory, limits)?;
        self.global = Some(limits.clone());
        Ok(())
    }

    pub(super) fn create_attempt(
        &self,
        attempt: AttemptIdentity,
        limits: &ValidatedLimits,
    ) -> Result<AttemptCgroup<F>, ExecutionDomainError> {
        let global = self
            .global
            .as_ref()
            .ok_or_else(|| failure(FailureCategory::NotReady))?;
        verify_limits(&self.directory, global)?;
        validate_controllers(&self.directory.read(c"cgroup.subtree_control")?)?;
        if !self.directory.members()?.is_empty() {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        let name = CString::new(format!("attempt-{}", attempt.component()))
            .map_err(|_| failure(FailureCategory::InvalidInput))?;
        let mut directory = None;
        let mut domain = None;
        let mut membership = None;
        for operation in creation_operations(&limits.writes()) {
            match operation {
                CgroupOperation::CreateAttempt => directory = Some(self.directory.create(&name)?),
                CgroupOperation::WriteLimit(name, value) => {
                    let name =
                        CString::new(name).map_err(|_| failure(FailureCategory::InvalidInput))?;
                    required(&directory)?.write(&name, &value)?;
                }
                CgroupOperation::VerifyLimits => verify_limits(required(&directory)?, limits)?,
                CgroupOperation::EnableControllers => required(&directory)?.enable_controllers()?,
                CgroupOperation::CreateDomain => {
                    let created = required(&directory)?.create(c"domain")?;
                    for (name, _) in limits.writes() {
                        let name = CString::new(name)
                            .map_err(|_| failure(FailureCategory::InvalidInput))?;
                        created.open_control(&name, libc::O_WRONLY)?;
                    }
                    domain = Some(created);
                }
                CgroupOperation::OpenMembership => {
                    // No launcher descriptor exists until every limit has been
                    // read back and the complete delegation layout is bound.
                    membership =
                        Some(required(&domain)?.open_control(c"cgroup.procs", libc::O_WRONLY)?);
                }
            }
        }
        Ok(AttemptCgroup {
            directory: directory.ok_or_else(|| failure(FailureCategory::NotReady))?,
            domain: domain.ok_or_else(|| failure(FailureCategory::NotReady))?,
            membership: membership.ok_or_else(|| failure(FailureCategory::NotReady))?,
            limits: limits.clone(),
        })
    }
}

impl<F: CgroupFilesystem> AttemptCgroup<F> {
    pub(super) fn launch_membership_fd(&self) -> BorrowedFd<'_> {
        self.membership.as_fd()
    }

    pub(super) fn limits_match(&self) -> Result<(), ExecutionDomainError> {
        verify_limits(&self.directory, &self.limits)
    }

    /// RootlessKit creates and evacuates into `init` before this barrier.
    pub(super) fn finish_evacuation(&self) -> Result<(), ExecutionDomainError> {
        let init = self.domain.child(c"init")?;
        if !self.domain.members()?.is_empty() || init.members()?.is_empty() {
            return Err(failure(FailureCategory::NotReady));
        }
        self.domain.enable_controllers()
    }

    pub(super) fn kill(&self) -> Result<(), ExecutionDomainError> {
        match self.directory.write(c"cgroup.kill", "1") {
            Ok(()) => Ok(()),
            Err(error) => {
                // A pidfd targets only the process observed in bound membership.
                // Failure still reaches the caller; only wait_empty can prove
                // destruction, regardless of best-effort fallback progress.
                self.kill_members_best_effort();
                Err(error)
            }
        }
    }

    fn kill_members_best_effort(&self) {
        let groups = match self.directory.tree() {
            Ok(groups) => groups,
            Err(error) => {
                tracing::warn!(%error, "cannot inventory cgroup for pidfd fallback");
                return;
            }
        };
        for group in groups {
            if let Err(error) = group.kill_members() {
                tracing::warn!(%error, "cgroup pidfd fallback incomplete");
            }
        }
    }

    pub(super) async fn wait_empty(&self, timeout: Duration) -> Result<(), ExecutionDomainError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let directory = Arc::clone(&self.directory);
            let scan = tokio::task::spawn_blocking(move || directory.recursively_empty());
            let empty = tokio::time::timeout_at(deadline, scan)
                .await
                .map_err(|_| failure(FailureCategory::Timeout))?
                .map_err(|_| failure(FailureCategory::Unavailable))??;
            if empty {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failure(FailureCategory::Timeout));
            }
            tokio::time::sleep_until(
                (tokio::time::Instant::now() + Duration::from_millis(10)).min(deadline),
            )
            .await;
        }
    }

    pub(super) fn remove(&self) -> Result<(), ExecutionDomainError> {
        if !self.directory.recursively_empty()? {
            return Err(failure(FailureCategory::Unavailable));
        }
        let groups = self.directory.tree()?;
        for group in groups.into_iter().rev() {
            group.verify()?;
            if !group.members()?.is_empty() || group.populated()? {
                return Err(failure(FailureCategory::Unavailable));
            }
            let (parent, name) = group
                .parent
                .as_ref()
                .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
            parent.verify()?;
            group
                .fs
                .remove(parent.bound.fd(), name, group.bound.fd())
                .map_err(io_failure)?;
            parent.verify()?;
        }
        Ok(())
    }
}

impl<F: CgroupFilesystem> CgroupDir<F> {
    fn verify(&self) -> Result<(), ExecutionDomainError> {
        self.bound.verify_binding()?;
        self.fs
            .verify_filesystem(self.bound.fd())
            .map_err(io_failure)
    }

    fn child(self: &Arc<Self>, name: &CStr) -> Result<Arc<Self>, ExecutionDomainError> {
        self.verify()?;
        let child = Arc::new(Self {
            bound: self.bound.child(name)?,
            fs: Arc::clone(&self.fs),
            parent: Some((Arc::clone(self), name.to_owned())),
        });
        child.verify()?;
        Ok(child)
    }

    fn create(self: &Arc<Self>, name: &CStr) -> Result<Arc<Self>, ExecutionDomainError> {
        self.verify()?;
        self.bound.refuse_entry(name)?;
        self.fs.create(self.bound.fd(), name).map_err(io_failure)?;
        let child = self.child(name)?;
        child.open_control(c"cgroup.kill", libc::O_WRONLY)?;
        Ok(child)
    }

    fn open_control(&self, name: &CStr, flags: i32) -> Result<OwnedFd, ExecutionDomainError> {
        self.verify()?;
        let flags = if flags & libc::O_PATH != 0 {
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
        } else {
            flags | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW
        };
        let fd = dirfd::open_at(self.bound.fd(), name, flags, 0, dirfd::RESOLVE_POLICY)?;
        let metadata = dirfd::metadata(fd.as_raw_fd())?;
        let parent = dirfd::metadata(self.bound.fd())?;
        if u32::from(metadata.stx_mode) & libc::S_IFMT != libc::S_IFREG
            || metadata.stx_nlink != 1
            || metadata.stx_mnt_id != parent.stx_mnt_id
            || metadata.stx_dev_major != parent.stx_dev_major
            || metadata.stx_dev_minor != parent.stx_dev_minor
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.fs
            .verify_filesystem(fd.as_raw_fd())
            .map_err(io_failure)?;
        self.bound.verify_entry(name, &metadata)?;
        Ok(fd)
    }

    fn read(&self, name: &CStr) -> Result<String, ExecutionDomainError> {
        let mut file = File::from(self.open_control(name, libc::O_RDONLY)?);
        let before = dirfd::metadata(file.as_raw_fd())?;
        let value = self.fs.read(&mut file, name).map_err(io_failure)?;
        self.bound.verify_entry(name, &before)?;
        self.verify()?;
        Ok(value)
    }

    fn write(&self, name: &CStr, value: &str) -> Result<(), ExecutionDomainError> {
        let mut file = File::from(self.open_control(name, libc::O_WRONLY)?);
        let before = dirfd::metadata(file.as_raw_fd())?;
        self.fs.write(&mut file, name, value).map_err(io_failure)?;
        self.bound.verify_entry(name, &before)?;
        self.verify()
    }

    fn enable_controllers(&self) -> Result<(), ExecutionDomainError> {
        validate_controllers(&self.read(c"cgroup.controllers")?)?;
        if !self.members()?.is_empty() {
            return Err(failure(FailureCategory::Unavailable));
        }
        self.write(c"cgroup.subtree_control", ENABLE)?;
        validate_controllers(&self.read(c"cgroup.subtree_control")?)
    }

    fn members(&self) -> Result<Vec<i32>, ExecutionDomainError> {
        self.read(c"cgroup.procs")?
            .split_whitespace()
            .map(|value| {
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|pid| *pid > 0)
                    .ok_or_else(|| failure(FailureCategory::IdentityMismatch))
            })
            .collect()
    }

    fn populated(&self) -> Result<bool, ExecutionDomainError> {
        let text = self.read(c"cgroup.events")?;
        let mut value = None;
        for line in text.lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            if words.first() == Some(&"populated") {
                if value.is_some() || words.len() != 2 {
                    return Err(failure(FailureCategory::IdentityMismatch));
                }
                value = match words[1] {
                    "0" => Some(false),
                    "1" => Some(true),
                    _ => return Err(failure(FailureCategory::IdentityMismatch)),
                };
            }
        }
        value.ok_or_else(|| failure(FailureCategory::IdentityMismatch))
    }

    fn has_children(&self) -> Result<bool, ExecutionDomainError> {
        self.verify()?;
        let mut budget = TraversalBudget::new();
        let mut entries = dirfd::directory_entries_stream(self.bound.fd())?;
        loop {
            budget.entry()?;
            let Some(name) = entries.next() else {
                break;
            };
            if self.entry_is_directory(&name?)? {
                return Ok(true);
            }
        }
        self.verify()?;
        Ok(false)
    }

    fn entry_is_directory(&self, name: &CStr) -> Result<bool, ExecutionDomainError> {
        let metadata = dirfd::stat_at(self.bound.fd(), name).map_err(io_failure)?;
        let parent = dirfd::metadata(self.bound.fd())?;
        if metadata.stx_mnt_id != parent.stx_mnt_id
            || metadata.stx_dev_major != parent.stx_dev_major
            || metadata.stx_dev_minor != parent.stx_dev_minor
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        match u32::from(metadata.stx_mode) & libc::S_IFMT {
            libc::S_IFDIR => Ok(true),
            libc::S_IFREG if metadata.stx_nlink == 1 => Ok(false),
            _ => Err(failure(FailureCategory::IdentityMismatch)),
        }
    }

    fn tree(self: &Arc<Self>) -> Result<Vec<Arc<Self>>, ExecutionDomainError> {
        let mut groups = Vec::new();
        self.collect_tree(0, &mut TraversalBudget::new(), &mut groups)?;
        Ok(groups)
    }

    fn collect_tree(
        self: &Arc<Self>,
        depth: usize,
        budget: &mut TraversalBudget,
        groups: &mut Vec<Arc<Self>>,
    ) -> Result<(), ExecutionDomainError> {
        self.verify()?;
        groups.push(Arc::clone(self));
        let mut entries = dirfd::directory_entries_stream(self.bound.fd())?;
        loop {
            // Reserve work before readdir allocates the next name, and reserve
            // each node/depth before opening its bound descriptor. Both budgets
            // are shared across the entire tree, including detached timed-out scans.
            budget.entry()?;
            let Some(name) = entries.next() else {
                break;
            };
            let name = name?;
            if self.entry_is_directory(&name)? {
                budget.child(depth + 1)?;
                let child = self.child(&name)?;
                child.collect_tree(depth + 1, budget, groups)?;
            }
        }
        self.verify()
    }

    fn recursively_empty(self: &Arc<Self>) -> Result<bool, ExecutionDomainError> {
        for group in self.tree()? {
            if group.populated()? || !group.members()?.is_empty() {
                return Ok(false);
            }
        }
        // cgroup.events is hierarchical. Re-read after inventory to cover a
        // child created/populated while scanning earlier descendants.
        Ok(!self.populated()? && self.members()?.is_empty())
    }

    fn kill_members(&self) -> Result<(), ExecutionDomainError> {
        for pid in self.members()? {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(io_failure(error));
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // A recycled PID outside the exact cgroup must not be signalled.
            if !self.members()?.contains(&pid) {
                continue;
            }
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(io_failure(error));
                }
            }
        }
        Ok(())
    }
}

fn required<T>(value: &Option<T>) -> Result<&T, ExecutionDomainError> {
    value
        .as_ref()
        .ok_or_else(|| failure(FailureCategory::NotReady))
}

fn verify_limits<F: CgroupFilesystem>(
    directory: &CgroupDir<F>,
    limits: &ValidatedLimits,
) -> Result<(), ExecutionDomainError> {
    for (name, expected) in limits.writes() {
        let key = CString::new(name).map_err(|_| failure(FailureCategory::InvalidInput))?;
        let actual = directory.read(&key)?;
        let matches = if name == "io.max" {
            io_limit_matches(&actual, &expected)?
        } else {
            actual.split_whitespace().eq(expected.split_whitespace())
        };
        if !matches {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
    }
    Ok(())
}

fn io_limit_matches(actual: &str, expected: &str) -> Result<bool, ExecutionDomainError> {
    fn fields(line: &str) -> Result<(&str, BTreeMap<&str, &str>), ExecutionDomainError> {
        let mut parts = line.split_whitespace();
        let device = parts
            .next()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
        let mut fields = BTreeMap::new();
        for part in parts {
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
            if fields.insert(key, value).is_some() {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
        }
        Ok((device, fields))
    }
    let (device, expected) = fields(expected)?;
    let mut matched = None;
    for line in actual.lines().filter(|line| !line.trim().is_empty()) {
        let (current, values) = fields(line)?;
        if current == device {
            if matched.is_some() {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            matched = Some(values == expected);
        }
    }
    Ok(matched == Some(true))
}

fn read_bounded(file: &mut File) -> io::Result<String> {
    let mut value = String::new();
    file.take(READ_LIMIT + 1).read_to_string(&mut value)?;
    if value.len() as u64 > READ_LIMIT {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }
    Ok(value)
}

fn check(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn io_failure(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Cgroup,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Cgroup,
        category,
        errno: None,
    }
}
