use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
#[cfg(test)]
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

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CgroupOperation {
    CreateAttempt,
    WriteLimit(String, String),
    VerifyLimits,
    EnableControllers,
    CreateDomain,
    OpenMembership,
}

#[cfg(test)]
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
pub(in crate::job::execution_domain) trait CgroupFilesystem:
    Send + Sync + 'static
{
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

pub(in crate::job::execution_domain) struct KernelCgroupFs;
impl CgroupFilesystem for KernelCgroupFs {}

#[cfg(test)]
pub(in crate::job::execution_domain) struct CgroupRoot<F = KernelCgroupFs> {
    directory: Arc<CgroupDir<F>>,
    #[cfg(test)]
    global: Option<ValidatedLimits>,
}

pub(in crate::job::execution_domain) struct AttemptCgroup<F = KernelCgroupFs> {
    directory: Arc<CgroupDir<F>>,
    domain: Arc<CgroupDir<F>>,
    membership: OwnedFd,
    limits: ValidatedLimits,
}

pub(super) struct CleanupCgroup<F = KernelCgroupFs> {
    directory: Arc<CgroupDir<F>>,
}

#[cfg(test)]
pub(super) struct RecoveredCgroup<F = KernelCgroupFs> {
    pub attempt: AttemptIdentity,
    pub kind: super::reconcile::OwnedKind,
    directory: Arc<CgroupDir<F>>,
    empty_proven: bool,
}

#[cfg(test)]
pub(super) struct RecoveryCgroupInventory<F = KernelCgroupFs> {
    pub entries: Vec<RecoveredCgroup<F>>,
    pub first_error: Option<ExecutionDomainError>,
}

struct BoundPidfd {
    pid: i32,
    fd: OwnedFd,
}

struct CgroupDir<F> {
    bound: BoundDir,
    fs: Arc<F>,
    parent: Option<(Arc<CgroupDir<F>>, CString)>,
}

#[cfg(test)]
impl CgroupRoot {
    #[cfg(test)]
    pub(super) fn open_delegated(path: &Path) -> Result<Self, ExecutionDomainError> {
        Self::open_with_filesystem(path, Arc::new(KernelCgroupFs))
    }
}

#[cfg(test)]
impl<F: CgroupFilesystem> CgroupRoot<F> {
    #[cfg(test)]
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
            #[cfg(test)]
            global: None,
        })
    }

    pub(super) fn recovery_inventory(
        &self,
    ) -> Result<RecoveryCgroupInventory<F>, ExecutionDomainError> {
        self.directory.verify()?;
        let mut inventory = RecoveryCgroupInventory {
            entries: Vec::new(),
            first_error: None,
        };
        for name in dirfd::directory_entries(self.directory.bound.fd())? {
            let is_directory = match self.directory.entry_is_directory(&name) {
                Ok(is_directory) => is_directory,
                Err(error) => {
                    retain_first(&mut inventory.first_error, error);
                    continue;
                }
            };
            if !is_directory {
                continue;
            }
            let value = match name.to_str() {
                Ok(value) => value,
                Err(_) => {
                    retain_first(
                        &mut inventory.first_error,
                        failure(FailureCategory::IdentityMismatch),
                    );
                    continue;
                }
            };
            if value == "supervisor" {
                continue;
            }
            let (kind, attempt) = match super::reconcile::parse_owned_name(value, false) {
                Ok(owned) => owned,
                Err(error) => {
                    retain_first(&mut inventory.first_error, error);
                    continue;
                }
            };
            match self.directory.child(&name) {
                Ok(directory) => inventory.entries.push(RecoveredCgroup {
                    attempt,
                    kind,
                    directory,
                    empty_proven: false,
                }),
                Err(error) => retain_first(&mut inventory.first_error, error),
            }
        }
        self.directory.verify()?;
        Ok(inventory)
    }

    /// Called synchronously before spawning children, while the manager holds
    /// the exclusive service-root lock. A failed startup is not retried in place.
    #[cfg(test)]
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

    #[cfg(test)]
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
        let creation = (|| {
            for operation in creation_operations(&limits.writes()) {
                match operation {
                    CgroupOperation::CreateAttempt => {
                        directory = Some(self.directory.create(&name)?)
                    }
                    CgroupOperation::WriteLimit(name, value) => {
                        let name = CString::new(name)
                            .map_err(|_| failure(FailureCategory::InvalidInput))?;
                        required(&directory)?.write(&name, &value)?;
                    }
                    CgroupOperation::VerifyLimits => verify_limits(required(&directory)?, limits)?,
                    CgroupOperation::EnableControllers => {
                        required(&directory)?.enable_controllers()?
                    }
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
            Ok::<(), ExecutionDomainError>(())
        })();
        if let Err(error) = creation {
            if let Some(directory) = &directory
                && let Err(cleanup) = remove_unlaunched(directory)
            {
                return Err(ExecutionDomainError::LifecycleAndDestroyFailed {
                    lifecycle: Box::new(error),
                    destroy: Box::new(cleanup),
                });
            }
            return Err(error);
        }
        Ok(AttemptCgroup {
            directory: directory.ok_or_else(|| failure(FailureCategory::NotReady))?,
            domain: domain.ok_or_else(|| failure(FailureCategory::NotReady))?,
            membership: membership.ok_or_else(|| failure(FailureCategory::NotReady))?,
            limits: limits.clone(),
        })
    }
}

#[cfg(test)]
impl<F: CgroupFilesystem> RecoveredCgroup<F> {
    pub(super) fn neutralize_until(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<(), ExecutionDomainError> {
        deadline_check(deadline)?;
        let mut first_error = None;
        let graceful_empty = match self.directory.recursively_empty_until(deadline) {
            Ok(empty) => empty,
            Err(error) => {
                retain_first(&mut first_error, error);
                false
            }
        };
        let mut empty_proven = graceful_empty;
        if !graceful_empty || first_error.is_some() {
            if let Err(error) = self.directory.write(c"cgroup.kill", "1") {
                retain_first(&mut first_error, error);
            }
            loop {
                match self.directory.recursively_empty_until(deadline) {
                    Ok(true) => {
                        empty_proven = true;
                        break;
                    }
                    Ok(false) => {
                        if let Err(error) = deadline_check(deadline) {
                            retain_first(&mut first_error, error);
                            break;
                        }
                        std::thread::sleep(
                            Duration::from_millis(10)
                                .min(deadline.saturating_duration_since(std::time::Instant::now())),
                        );
                    }
                    Err(error) => {
                        retain_first(&mut first_error, error);
                        break;
                    }
                }
            }
        }
        if !empty_proven && first_error.is_none() {
            first_error = Some(failure(FailureCategory::Timeout));
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.empty_proven = true;
        Ok(())
    }

    pub(super) fn remove(&mut self) -> Result<(), ExecutionDomainError> {
        if !self.empty_proven {
            return Err(failure(FailureCategory::Unavailable));
        }
        self.directory.remove_recursive_empty()
    }
}

fn remove_unlaunched<F: CgroupFilesystem>(
    directory: &Arc<CgroupDir<F>>,
) -> Result<(), ExecutionDomainError> {
    let groups = directory.tree()?;
    for group in &groups {
        if group.populated()? || !group.members()?.is_empty() {
            return Err(failure(FailureCategory::Unavailable));
        }
    }
    for group in groups.into_iter().rev() {
        let (parent, name) = group
            .parent
            .as_ref()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
        group.verify()?;
        parent.verify()?;
        group
            .fs
            .remove(parent.bound.fd(), name, group.bound.fd())
            .map_err(io_failure)?;
        parent.verify()?;
    }
    Ok(())
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

    pub(super) fn kill_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), ExecutionDomainError> {
        deadline_check(deadline)?;
        match self.directory.write(c"cgroup.kill", "1") {
            Ok(()) => deadline_check(deadline),
            Err(error) => {
                // A pidfd targets only the process observed in bound membership.
                // Failure still reaches the caller; only wait_empty can prove
                // destruction, regardless of best-effort fallback progress.
                let _ = self.kill_members_best_effort(deadline);
                Err(error)
            }
        }
    }

    pub(super) fn term(&self, deadline: std::time::Instant) -> Result<(), ExecutionDomainError> {
        let mut members = Vec::new();
        for group in self.directory.tree_until(deadline)? {
            deadline_check(deadline)?;
            members.extend(group.capture_members_until(deadline)?);
        }
        members.sort_by_key(|member| member.pid);
        members.dedup_by_key(|member| member.pid);
        for member in members {
            deadline_check(deadline)?;
            member.signal(libc::SIGTERM)?;
        }
        Ok(())
    }

    pub(super) fn attach_cleanup_worker(
        &self,
        attempt: AttemptIdentity,
        pid: u32,
    ) -> Result<CleanupCgroup<F>, ExecutionDomainError> {
        let (root, _) = self
            .directory
            .parent
            .as_ref()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
        let name = CString::new(format!("cleanup-{}", attempt.component()))
            .map_err(|_| failure(FailureCategory::InvalidInput))?;
        let directory = root.create(&name)?;
        if let Err(error) = directory.write(c"cgroup.procs", &pid.to_string()) {
            return match remove_unlaunched(&directory) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(ExecutionDomainError::LifecycleAndDestroyFailed {
                    lifecycle: Box::new(error),
                    destroy: Box::new(cleanup),
                }),
            };
        }
        let members = directory.members();
        if !matches!(&members, Ok(members) if members == &vec![pid as i32]) {
            let error = members
                .map(|_| failure(FailureCategory::IdentityMismatch))
                .unwrap_or_else(|error| error);
            let cleanup = CleanupCgroup {
                directory: Arc::clone(&directory),
            }
            .kill_wait_remove(std::time::Instant::now() + Duration::from_secs(2));
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(ExecutionDomainError::LifecycleAndDestroyFailed {
                    lifecycle: Box::new(error),
                    destroy: Box::new(cleanup),
                }),
            };
        }
        Ok(CleanupCgroup { directory })
    }

    pub(super) fn recursively_empty_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<bool, ExecutionDomainError> {
        loop {
            deadline_check(deadline)?;
            if self.directory.recursively_empty_until(deadline)? {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(
                Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(std::time::Instant::now())),
            );
        }
    }

    fn kill_members_best_effort(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), ExecutionDomainError> {
        let groups = match self.directory.tree_until(deadline) {
            Ok(groups) => groups,
            Err(error) => {
                tracing::warn!(%error, "cannot inventory cgroup for pidfd fallback");
                return Err(error);
            }
        };
        for group in groups {
            deadline_check(deadline)?;
            if let Err(error) = group.signal_members_until(libc::SIGKILL, deadline) {
                tracing::warn!(%error, "cgroup pidfd fallback incomplete");
                return Err(error);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn wait_empty(&self, timeout: Duration) -> Result<(), ExecutionDomainError> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
        loop {
            // Always join the bounded scan before observing its deadline. This
            // keeps blocking cgroupfs I/O off the async executor without the
            // timeout(detached-spawn_blocking) ownership hole.
            let directory = Arc::clone(&self.directory);
            let scan =
                tokio::task::spawn_blocking(move || directory.recursively_empty_until(deadline))
                    .await
                    .map_err(|_| failure(FailureCategory::Unavailable))?;
            if std::time::Instant::now() >= deadline {
                return Err(failure(FailureCategory::Timeout));
            }
            let empty = scan?;
            if empty {
                return Ok(());
            }
            tokio::time::sleep(
                Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(std::time::Instant::now())),
            )
            .await;
        }
    }

    pub(super) fn remove(&self) -> Result<(), ExecutionDomainError> {
        self.directory.remove_recursive_empty()
    }
}

impl<F: CgroupFilesystem> CgroupDir<F> {
    fn remove_recursive_empty(self: &Arc<Self>) -> Result<(), ExecutionDomainError> {
        if !self.recursively_empty()? {
            return Err(failure(FailureCategory::Unavailable));
        }
        let groups = self.tree()?;
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

impl<F: CgroupFilesystem> CleanupCgroup<F> {
    pub(super) fn kill_wait_remove(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), ExecutionDomainError> {
        if !self.directory.recursively_empty_until(deadline)? {
            self.directory.write(c"cgroup.kill", "1")?;
        }
        while !self.directory.recursively_empty_until(deadline)? {
            if std::time::Instant::now() >= deadline {
                return Err(failure(FailureCategory::Timeout));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let (parent, name) = self
            .directory
            .parent
            .as_ref()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
        self.directory.verify()?;
        parent.verify()?;
        self.directory
            .fs
            .remove(parent.bound.fd(), name, self.directory.bound.fd())
            .map_err(io_failure)?;
        parent.verify()
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
        let child = match self.child(name) {
            Ok(child) => child,
            Err(error) => {
                // mkdir succeeded but no exact child capability could be
                // retained. Preserve the deterministic entry and surface a
                // cleanup failure so callers quarantine rather than claiming
                // rollback success by pathname.
                return Err(ExecutionDomainError::LifecycleAndDestroyFailed {
                    lifecycle: Box::new(error),
                    destroy: Box::new(failure(FailureCategory::Unavailable)),
                });
            }
        };
        if let Err(error) = child.open_control(c"cgroup.kill", libc::O_WRONLY) {
            return match remove_unlaunched(&child) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(ExecutionDomainError::LifecycleAndDestroyFailed {
                    lifecycle: Box::new(error),
                    destroy: Box::new(cleanup),
                }),
            };
        }
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

    #[cfg(test)]
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

    fn tree_until(
        self: &Arc<Self>,
        deadline: std::time::Instant,
    ) -> Result<Vec<Arc<Self>>, ExecutionDomainError> {
        let mut groups = Vec::new();
        self.collect_tree_until(0, &mut TraversalBudget::new(), &mut groups, deadline)?;
        Ok(groups)
    }

    fn collect_tree_until(
        self: &Arc<Self>,
        depth: usize,
        budget: &mut TraversalBudget,
        groups: &mut Vec<Arc<Self>>,
        deadline: std::time::Instant,
    ) -> Result<(), ExecutionDomainError> {
        deadline_check(deadline)?;
        self.verify()?;
        deadline_check(deadline)?;
        groups.push(Arc::clone(self));
        let mut entries = dirfd::directory_entries_stream(self.bound.fd())?;
        loop {
            deadline_check(deadline)?;
            budget.entry()?;
            let Some(name) = entries.next() else {
                break;
            };
            let name = name?;
            if self.entry_is_directory(&name)? {
                budget.child(depth + 1)?;
                let child = self.child(&name)?;
                child.collect_tree_until(depth + 1, budget, groups, deadline)?;
            }
        }
        deadline_check(deadline)?;
        self.verify()
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

    fn recursively_empty_until(
        self: &Arc<Self>,
        deadline: std::time::Instant,
    ) -> Result<bool, ExecutionDomainError> {
        for group in self.tree_until(deadline)? {
            deadline_check(deadline)?;
            if group.populated()? || !group.members()?.is_empty() {
                deadline_check(deadline)?;
                return Ok(false);
            }
        }
        deadline_check(deadline)?;
        let empty = !self.populated()? && self.members()?.is_empty();
        deadline_check(deadline)?;
        Ok(empty)
    }

    fn signal_members_until(
        &self,
        signal: i32,
        deadline: std::time::Instant,
    ) -> Result<(), ExecutionDomainError> {
        for member in self.capture_members_until(deadline)? {
            deadline_check(deadline)?;
            member.signal(signal)?;
        }
        Ok(())
    }

    fn capture_members_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<Vec<BoundPidfd>, ExecutionDomainError> {
        deadline_check(deadline)?;
        let pids = self.members()?;
        deadline_check(deadline)?;
        let mut captured = Vec::new();
        for pid in pids {
            deadline_check(deadline)?;
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(io_failure(error));
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if !self.members()?.contains(&pid) {
                continue;
            }
            deadline_check(deadline)?;
            captured.push(BoundPidfd { pid, fd });
        }
        Ok(captured)
    }
}

fn deadline_check(deadline: std::time::Instant) -> Result<(), ExecutionDomainError> {
    if std::time::Instant::now() >= deadline {
        Err(failure(FailureCategory::Timeout))
    } else {
        Ok(())
    }
}

impl BoundPidfd {
    fn signal(&self, signal: i32) -> Result<(), ExecutionDomainError> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal,
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
        Ok(())
    }
}

#[cfg(test)]
fn required<T>(value: &Option<T>) -> Result<&T, ExecutionDomainError> {
    value
        .as_ref()
        .ok_or_else(|| failure(FailureCategory::NotReady))
}

#[cfg(test)]
fn retain_first(first: &mut Option<ExecutionDomainError>, error: ExecutionDomainError) {
    if first.is_none() {
        *first = Some(error);
    }
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
