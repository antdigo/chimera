use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::super::{ExecutionDomainError, FailureCategory, Stage};
use super::dirfd::{self, RESOLVE_POLICY};

const MAX_ENTRIES: usize = 524_288;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 1 << 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const REAP_GRACE: Duration = Duration::from_millis(250);
const CLEANUP_CGROUP_GRACE: Duration = Duration::from_secs(2);
#[cfg(test)]
const MIN_SUBORDINATE_IDS: u32 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::job::execution_domain) enum CleanupRootKind {
    Work,
    Tmp,
    Home,
    Run,
    DockerConfig,
    DockerData,
    DockerExec,
}

#[derive(Clone, Copy)]
pub(in crate::job::execution_domain) struct MappedIdRange {
    service_uid: u32,
    service_gid: u32,
    subuid_start: u32,
    subuid_count: u32,
    subgid_start: u32,
    subgid_count: u32,
}

impl MappedIdRange {
    pub(in crate::job::execution_domain) fn new(
        service_uid: u32,
        service_gid: u32,
        subuid_start: u32,
        subuid_count: u32,
        subgid_start: u32,
        subgid_count: u32,
    ) -> Result<Self, ExecutionDomainError> {
        if subuid_count == 0
            || subgid_count == 0
            || subuid_start.checked_add(subuid_count).is_none()
            || subgid_start.checked_add(subgid_count).is_none()
            || contains(subuid_start, subuid_count, service_uid)
            || contains(subgid_start, subgid_count, service_gid)
        {
            return Err(failure(FailureCategory::InvalidInput));
        }
        Ok(Self {
            service_uid,
            service_gid,
            subuid_start,
            subuid_count,
            subgid_start,
            subgid_count,
        })
    }

    fn owns(&self, uid: u32, gid: u32) -> bool {
        (uid == self.service_uid || contains(self.subuid_start, self.subuid_count, uid))
            && (gid == self.service_gid || contains(self.subgid_start, self.subgid_count, gid))
    }

    #[cfg(test)]
    pub(super) fn owns_for_test(&self, uid: u32, gid: u32) -> bool {
        self.owns(uid, gid)
    }
}

#[cfg(test)]
pub(in crate::job::execution_domain) struct IdMapSpec {
    service_user: String,
    range: MappedIdRange,
}

#[derive(Clone)]
pub(in crate::job::execution_domain) struct CleanupWorkerConfig {
    executable: Arc<VerifiedExecutable>,
    newuidmap: Arc<VerifiedExecutable>,
    newgidmap: Arc<VerifiedExecutable>,
    pending: Arc<Mutex<PendingCleanup>>,
}

#[derive(Default)]
struct PendingCleanup {
    children: Vec<std::process::Child>,
    cgroups: Vec<super::cgroup::CleanupCgroup>,
    bootstraps: Vec<(CString, dirfd::BoundDir)>,
}

struct VerifiedExecutable {
    fd: OwnedFd,
    identity: Identity,
}

impl VerifiedExecutable {
    fn command(&self) -> Result<Command, ExecutionDomainError> {
        if identity(&dirfd::metadata(self.fd.as_raw_fd())?) != self.identity {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(Command::new(format!(
            "/proc/self/fd/{}",
            self.fd.as_raw_fd()
        )))
    }
}

impl std::fmt::Debug for CleanupWorkerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CleanupWorkerConfig")
    }
}

fn retain_pending_cleanup(
    worker: &CleanupWorkerConfig,
    child: Option<std::process::Child>,
    cgroup: Option<super::cgroup::CleanupCgroup>,
    bootstrap: Option<(CString, dirfd::BoundDir)>,
) {
    let mut pending = worker
        .pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(child) = child {
        pending.children.push(child);
    }
    if let Some(cgroup) = cgroup {
        pending.cgroups.push(cgroup);
    }
    if let Some(bootstrap) = bootstrap {
        pending.bootstraps.push(bootstrap);
    }
}

fn retry_pending_cleanup(
    worker: &CleanupWorkerConfig,
    bootstrap_root: &dirfd::BoundDir,
) -> Result<(), ExecutionDomainError> {
    let cleanup_deadline = Instant::now()
        .checked_add(CLEANUP_CGROUP_GRACE)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let mut pending = {
        let mut slot = worker
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *slot)
    };
    if pending.children.is_empty() && pending.cgroups.is_empty() && pending.bootstraps.is_empty() {
        return Ok(());
    }

    let mut first_error = None;
    let mut retained_cgroups = Vec::new();
    for cgroup in pending.cgroups.drain(..) {
        if let Err(error) = cgroup.kill_wait_remove(cleanup_deadline) {
            if first_error.is_none() {
                first_error = Some(error);
            }
            retained_cgroups.push(cgroup);
        }
    }
    pending.cgroups = retained_cgroups;

    if let Err(error) = retry_pending_children(&mut pending.children, cleanup_deadline)
        && first_error.is_none()
    {
        first_error = Some(error);
    }

    if pending.children.is_empty() && pending.cgroups.is_empty() {
        let mut retained_bootstraps = Vec::new();
        for (name, bootstrap) in pending.bootstraps.drain(..) {
            if let Err(error) = bootstrap_root.remove_created_child(&name, &bootstrap, &[]) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                retained_bootstraps.push((name, bootstrap));
            }
        }
        pending.bootstraps = retained_bootstraps;
    }

    if !pending.children.is_empty() || !pending.cgroups.is_empty() || !pending.bootstraps.is_empty()
    {
        let mut slot = worker
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.children.append(&mut pending.children);
        slot.cgroups.append(&mut pending.cgroups);
        slot.bootstraps.append(&mut pending.bootstraps);
        return Err(first_error.unwrap_or_else(|| failure(FailureCategory::Unavailable)));
    }
    Ok(())
}

fn retry_pending_children<C: ReapableChild>(
    children: &mut Vec<C>,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    let mut retained = Vec::new();
    let mut first_error = None;
    for mut child in children.drain(..) {
        let wait = wait_child_status(&mut child, deadline);
        match observe_child(child) {
            Ok((false, _child)) => {}
            Ok((true, child)) => {
                if first_error.is_none() {
                    first_error = Some(
                        wait.err()
                            .unwrap_or_else(|| failure(FailureCategory::Timeout)),
                    );
                }
                retained.push(child);
            }
            Err((error, child)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                retained.push(child);
            }
        }
    }
    *children = retained;
    if children.is_empty() {
        Ok(())
    } else {
        Err(first_error.unwrap_or_else(|| failure(FailureCategory::Unavailable)))
    }
}

#[cfg(test)]
impl IdMapSpec {
    #[cfg(test)]
    pub(in crate::job::execution_domain) fn parse(
        service_user: &str,
        service_uid: u32,
        service_gid: u32,
        subuid: &str,
        subgid: &str,
    ) -> Result<Self, ExecutionDomainError> {
        if service_user.is_empty()
            || service_user.contains(':')
            || service_user
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_whitespace())
        {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let (subuid_start, subuid_count) = parse_single_range(service_user, subuid)?;
        let (subgid_start, subgid_count) = parse_single_range(service_user, subgid)?;
        if subuid_count < MIN_SUBORDINATE_IDS || subgid_count < MIN_SUBORDINATE_IDS {
            return Err(failure(FailureCategory::Unsupported));
        }
        Ok(Self {
            service_user: service_user.to_owned(),
            range: MappedIdRange::new(
                service_uid,
                service_gid,
                subuid_start,
                subuid_count,
                subgid_start,
                subgid_count,
            )?,
        })
    }

    #[cfg(test)]
    pub(super) fn subuid_start(&self) -> u32 {
        self.range.subuid_start
    }
}

#[cfg(test)]
impl std::fmt::Debug for IdMapSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdMapSpec")
            .field("service_user", &self.service_user)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
fn parse_single_range(user: &str, contents: &str) -> Result<(u32, u32), ExecutionDomainError> {
    let mut found = None;
    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(owner) = fields.next() else {
            continue;
        };
        let Some(start) = fields.next() else {
            return Err(failure(FailureCategory::InvalidInput));
        };
        let Some(count) = fields.next() else {
            return Err(failure(FailureCategory::InvalidInput));
        };
        if fields.next().is_some() {
            return Err(failure(FailureCategory::InvalidInput));
        }
        if owner != user {
            continue;
        }
        if found.is_some() {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let start = start
            .parse::<u32>()
            .map_err(|_| failure(FailureCategory::InvalidInput))?;
        let count = count
            .parse::<u32>()
            .map_err(|_| failure(FailureCategory::InvalidInput))?;
        found = Some((start, count));
    }
    found.ok_or_else(|| failure(FailureCategory::Unsupported))
}

fn contains(start: u32, count: u32, value: u32) -> bool {
    value >= start && value < start.saturating_add(count)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: (u32, u32),
    inode: u64,
    mount_id: u64,
    mode: u16,
    uid: u32,
    gid: u32,
}

pub(in crate::job::execution_domain) struct PinnedCleanupRoot {
    kind: CleanupRootKind,
    fd: OwnedFd,
    identity: Identity,
}

impl std::fmt::Debug for PinnedCleanupRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedCleanupRoot")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl PinnedCleanupRoot {
    pub(in crate::job::execution_domain) fn from_bound(
        kind: CleanupRootKind,
        directory: &dirfd::BoundDir,
    ) -> Result<Self, ExecutionDomainError> {
        directory.verify_binding()?;
        let fd = duplicate(directory.fd())?;
        let identity = identity(&dirfd::metadata(fd.as_raw_fd())?);
        if identity.mode as u32 & libc::S_IFMT != libc::S_IFDIR {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(Self { kind, fd, identity })
    }

    #[cfg(test)]
    pub(super) fn open_for_test(
        kind: CleanupRootKind,
        path: &std::path::Path,
    ) -> Result<Self, ExecutionDomainError> {
        Self::from_bound(kind, &dirfd::BoundDir::open_root(path)?)
    }

    fn verify(&self) -> Result<(), ExecutionDomainError> {
        let current = identity(&dirfd::metadata(self.fd.as_raw_fd())?);
        if current != self.identity {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(in crate::job::execution_domain) struct SocketIdentity(Identity);

pub(in crate::job::execution_domain) struct RuntimeSocketCapability {
    parent: PinnedCleanupRoot,
    name: CString,
    expected: SocketIdentity,
    scope: RuntimeSocketRootKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::job::execution_domain) enum RuntimeSocketRootKind {
    RootlessKitState,
}

impl RuntimeSocketCapability {
    pub(in crate::job::execution_domain) fn capture(
        scope: RuntimeSocketRootKind,
        parent: &dirfd::BoundDir,
        name: &CStr,
    ) -> Result<Self, ExecutionDomainError> {
        let expected_name = match scope {
            RuntimeSocketRootKind::RootlessKitState => c"api.sock",
        };
        if name != expected_name {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let parent = PinnedCleanupRoot::from_bound(CleanupRootKind::Run, parent)?;
        let metadata = dirfd::stat_at(parent.fd.as_raw_fd(), name).map_err(io_failure)?;
        let expected = identity(&metadata);
        if u32::from(expected.mode) & libc::S_IFMT != libc::S_IFSOCK
            || expected.device != parent.identity.device
            || expected.mount_id != parent.identity.mount_id
            || expected.uid != unsafe { libc::geteuid() }
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(Self {
            parent,
            name: name.to_owned(),
            expected: SocketIdentity(expected),
            scope,
        })
    }

    pub(in crate::job::execution_domain) fn remove(&self) -> Result<(), ExecutionDomainError> {
        let expected_name = match self.scope {
            RuntimeSocketRootKind::RootlessKitState => c"api.sock",
        };
        if self.name != expected_name {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.parent.verify()?;
        match dirfd::stat_at(self.parent.fd.as_raw_fd(), &self.name) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                // The captured daemon may have removed its own socket, or a
                // previous exact unlink may have reached an fsync failure.
                // Sync again so absence itself is durably proven.
                sync_directory(self.parent.fd.as_raw_fd())?;
                return self.parent.verify();
            }
            Err(error) => return Err(io_failure(error)),
            Ok(_) => {}
        }
        verify_named(
            self.parent.fd.as_raw_fd(),
            &self.name,
            self.expected.0,
            self.parent.identity,
        )?;
        checked(unsafe { libc::unlinkat(self.parent.fd.as_raw_fd(), self.name.as_ptr(), 0) })?;
        sync_directory(self.parent.fd.as_raw_fd())?;
        self.parent.verify()
    }
}

pub(in crate::job::execution_domain) struct MappedCleanupAuthority {
    map: MappedIdRange,
    roots: Vec<PinnedCleanupRoot>,
    timeout: Duration,
    worker: Option<CleanupWorkerConfig>,
    limits: InventoryLimits,
}

#[derive(Clone, Copy)]
struct InventoryLimits {
    entries: usize,
    depth: usize,
    path_bytes: usize,
}

impl Default for InventoryLimits {
    fn default() -> Self {
        Self {
            entries: MAX_ENTRIES,
            depth: MAX_DEPTH,
            path_bytes: MAX_PATH_BYTES,
        }
    }
}

impl std::fmt::Debug for MappedCleanupAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MappedCleanupAuthority")
    }
}

impl MappedCleanupAuthority {
    pub(in crate::job::execution_domain) fn new(
        map: MappedIdRange,
        roots: Vec<PinnedCleanupRoot>,
    ) -> Result<Self, ExecutionDomainError> {
        if roots.is_empty() || roots.len() > 7 {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let mut seen = Vec::new();
        for root in &roots {
            root.verify()?;
            if seen.contains(&root.kind) {
                return Err(failure(FailureCategory::InvalidInput));
            }
            seen.push(root.kind);
        }
        Ok(Self {
            map,
            roots,
            timeout: DEFAULT_TIMEOUT,
            worker: None,
            limits: InventoryLimits::default(),
        })
    }

    pub(in crate::job::execution_domain) fn with_worker(
        mut self,
        worker: CleanupWorkerConfig,
    ) -> Self {
        self.worker = Some(worker);
        self
    }

    pub(in crate::job::execution_domain) fn cleanup(
        &self,
        attempt: super::super::AttemptIdentity,
        cgroup: &super::cgroup::AttemptCgroup,
        bootstrap_root: &dirfd::BoundDir,
    ) -> Result<(), ExecutionDomainError> {
        let worker = self
            .worker
            .as_ref()
            .ok_or_else(|| failure(FailureCategory::NotReady))?;
        run_worker(self, worker, attempt, cgroup, bootstrap_root)
    }

    /// The caller executes this only in the fresh exact-map worker. Inventory
    /// of every root completes before the first unlink in any root.
    #[cfg(test)]
    fn inventory_and_unlink_in_verified_worker(&self) -> Result<(), ExecutionDomainError> {
        self.inventory_and_unlink_with_hook(|| {})
    }

    #[cfg(test)]
    fn inventory_and_unlink_with_hook(
        &self,
        after_inventory: impl FnOnce(),
    ) -> Result<(), ExecutionDomainError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
        let mut budget = Budget::default();
        let mut inventories = Vec::with_capacity(self.roots.len());
        let mut ignore = |_: u8, _: RawFd| Ok(());
        for (root_index, root) in self.roots.iter().enumerate() {
            root.verify()?;
            let mut context = InventoryContext {
                root: root.identity,
                map: &self.map,
                budget: &mut budget,
                limits: self.limits,
                deadline,
                root_index: root_index as u8,
                notify: &mut ignore,
            };
            inventories.push(inventory(root.fd.as_raw_fd(), 0, &mut context)?);
        }
        after_inventory();
        for (root, entries) in self.roots.iter().zip(inventories) {
            remove_inventory(root.fd.as_raw_fd(), root.identity, entries, deadline)?;
            root.verify()?;
            sync_directory(root.fd.as_raw_fd())?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn cleanup_for_test_current_map(&self) -> Result<(), ExecutionDomainError> {
        self.inventory_and_unlink_in_verified_worker()
    }

    #[cfg(test)]
    pub(super) fn with_entry_limit_for_test(mut self, entries: usize) -> Self {
        self.limits.entries = entries;
        self
    }

    #[cfg(test)]
    pub(super) fn cleanup_with_hook_for_test(
        &self,
        after_inventory: impl FnOnce(),
    ) -> Result<(), ExecutionDomainError> {
        self.inventory_and_unlink_with_hook(after_inventory)
    }
}

pub(super) fn internal_entry() -> Option<i32> {
    let mode = std::env::args_os().nth(1)?;
    if mode != "--internal-mapped-cleanup" {
        return None;
    }
    Some(worker_entry().map_or(78, |()| 0))
}

fn run_worker(
    authority: &MappedCleanupAuthority,
    worker: &CleanupWorkerConfig,
    attempt: super::super::AttemptIdentity,
    attempt_cgroup: &super::cgroup::AttemptCgroup,
    bootstrap_root: &dirfd::BoundDir,
) -> Result<(), ExecutionDomainError> {
    retry_pending_cleanup(worker, bootstrap_root)?;
    let bootstrap_name = CString::new(format!("cleanup-{}", attempt.component()))
        .map_err(|_| failure(FailureCategory::InvalidInput))?;
    let bootstrap = bootstrap_root.create_child(&bootstrap_name, 0o700)?;
    let (parent, child) = match seqpacket_pair() {
        Ok(pair) => pair,
        Err(error) => {
            return Err(combine_cleanup(
                error,
                bootstrap_root.remove_created_child(&bootstrap_name, &bootstrap, &[]),
            ));
        }
    };
    let parent = parent;
    let child_fd = child;
    let mut command = worker.executable.command()?;
    command
        .arg("--internal-mapped-cleanup")
        .env_clear()
        .stdin(Stdio::from(child_fd))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match command.spawn().map_err(io_failure) {
        Ok(child) => child,
        Err(error) => {
            return Err(combine_cleanup(
                error,
                bootstrap_root.remove_created_child(&bootstrap_name, &bootstrap, &[]),
            ));
        }
    };
    let deadline = Instant::now()
        .checked_add(authority.timeout)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let cleanup_cgroup = match attempt_cgroup.attach_cleanup_worker(attempt, child.id()) {
        Ok(cgroup) => cgroup,
        Err(error) => {
            let _ = child.kill();
            let reap_deadline = Instant::now()
                .checked_add(REAP_GRACE)
                .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
            let reap = wait_child_status(&mut child, reap_deadline);
            match observe_child(child) {
                Ok((true, child)) => {
                    retain_pending_cleanup(
                        worker,
                        Some(child),
                        None,
                        Some((bootstrap_name, bootstrap)),
                    );
                    return Err(combine_cleanup(
                        error,
                        Err(reap
                            .err()
                            .unwrap_or_else(|| failure(FailureCategory::Timeout))),
                    ));
                }
                Err((observation, child)) => {
                    retain_pending_cleanup(
                        worker,
                        Some(child),
                        None,
                        Some((bootstrap_name, bootstrap)),
                    );
                    return Err(combine_cleanup(error, Err(observation)));
                }
                Ok((false, _child)) => {}
            }
            let bootstrap_cleanup =
                bootstrap_root.remove_created_child(&bootstrap_name, &bootstrap, &[]);
            if bootstrap_cleanup.is_err() {
                retain_pending_cleanup(worker, None, None, Some((bootstrap_name, bootstrap)));
            }
            return Err(combine_cleanup(error, bootstrap_cleanup));
        }
    };
    let result = (|| {
        expect_packet(parent.as_raw_fd(), b"U", deadline, Some(child.id() as i32))?;
        install_map(worker, child.id(), true, authority.map, deadline)?;
        deny_setgroups(child.id())?;
        install_map(worker, child.id(), false, authority.map, deadline)?;
        verify_proc_map(child.id(), true, authority.map)?;
        verify_proc_map(child.id(), false, authority.map)?;
        send_packet(parent.as_raw_fd(), b"M", deadline)?;
        let mut root_fds = vec![bootstrap.fd()];
        root_fds.extend(authority.roots.iter().map(|root| root.fd.as_raw_fd()));
        let mut kinds = vec![b'R'];
        kinds.extend(authority.roots.iter().map(|root| root_kind_byte(root.kind)));
        send_fds(parent.as_raw_fd(), &kinds, &root_fds, deadline)?;

        let mut entries = 0usize;
        loop {
            let (message, fds, credentials) = receive_fds(parent.as_raw_fd(), 1, deadline)?;
            if credentials.is_none_or(|credentials| credentials.pid != child.id() as i32) {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            if message == b"D" {
                if !fds.is_empty() {
                    return Err(failure(FailureCategory::Protocol));
                }
                break;
            }
            if message.len() != 2 || message[0] != b'E' || fds.len() != 1 {
                return Err(failure(FailureCategory::Protocol));
            }
            entries = entries
                .checked_add(1)
                .filter(|count| *count <= MAX_ENTRIES)
                .ok_or_else(|| failure(FailureCategory::Unavailable))?;
            let root = authority
                .roots
                .get(message[1] as usize)
                .ok_or_else(|| failure(FailureCategory::Protocol))?;
            validate_host_entry(fds[0].as_raw_fd(), root.identity, authority.map)?;
        }
        send_packet(parent.as_raw_fd(), b"C", deadline)?;
        expect_packet(parent.as_raw_fd(), b"O", deadline, Some(child.id() as i32))
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let wait = wait_child(&mut child, deadline);
    let cleanup_deadline = Instant::now()
        .checked_add(CLEANUP_CGROUP_GRACE)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let cgroup_result = cleanup_cgroup.kill_wait_remove(cleanup_deadline);
    let (pending_child, observation_result) = match observe_child(child) {
        Ok((false, _child)) => (None, Ok(())),
        Ok((true, child)) => (Some(child), Ok(())),
        Err((error, child)) => (Some(child), Err(error)),
    };
    let bootstrap_result = if cgroup_result.is_ok() {
        bootstrap_root.remove_created_child(&bootstrap_name, &bootstrap, &[])
    } else {
        // Preserve bootstrap evidence until the sibling cleanup cgroup has an
        // exact recursive-empty/removal proof.
        Ok(())
    };
    if pending_child.is_some() || cgroup_result.is_err() || bootstrap_result.is_err() {
        retain_pending_cleanup(
            worker,
            pending_child,
            cgroup_result.is_err().then_some(cleanup_cgroup),
            (cgroup_result.is_err() || bootstrap_result.is_err())
                .then_some((bootstrap_name, bootstrap)),
        );
    }
    result
        .and(wait)
        .and(observation_result)
        .and(cgroup_result)
        .and(bootstrap_result)?;
    for root in &authority.roots {
        root.verify()?;
        if dirfd::directory_entries_stream(root.fd.as_raw_fd())?
            .next()
            .is_some()
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
    }
    Ok(())
}

fn deny_setgroups(pid: u32) -> Result<(), ExecutionDomainError> {
    let path = format!("/proc/{pid}/setgroups");
    std::fs::write(path, b"deny\n").map_err(io_failure)
}

fn combine_cleanup(
    first: ExecutionDomainError,
    cleanup: Result<(), ExecutionDomainError>,
) -> ExecutionDomainError {
    match cleanup {
        Ok(()) => first,
        Err(cleanup) => ExecutionDomainError::LifecycleAndDestroyFailed {
            lifecycle: Box::new(first),
            destroy: Box::new(cleanup),
        },
    }
}

fn worker_entry() -> Result<(), ExecutionDomainError> {
    let socket = 0;
    close_unrelated_worker_fds()?;
    require_empty_groups()?;
    checked(unsafe { libc::unshare(libc::CLONE_NEWUSER) })?;
    send_packet(socket, b"U", Instant::now() + DEFAULT_TIMEOUT)?;
    expect_packet(
        socket,
        b"M",
        Instant::now() + DEFAULT_TIMEOUT,
        Some(unsafe { libc::getppid() }),
    )?;
    let uid_count = verify_worker_map(true)?;
    let gid_count = verify_worker_map(false)?;
    let namespace_map = MappedIdRange::new(0, 0, 1, uid_count, 1, gid_count)?;
    let (kinds, fds, credentials) = receive_fds(socket, 8, Instant::now() + DEFAULT_TIMEOUT)?;
    if credentials.is_none_or(|credentials| credentials.pid != unsafe { libc::getppid() })
        || kinds.len() != fds.len()
        || kinds.len() < 2
        || kinds[0] != b'R'
    {
        return Err(failure(FailureCategory::Protocol));
    }
    let mut fds = fds.into_iter();
    let bootstrap = fds
        .next()
        .ok_or_else(|| failure(FailureCategory::Protocol))?;
    let mut roots = Vec::with_capacity(fds.len() - 1);
    for (kind, fd) in kinds.into_iter().skip(1).zip(fds) {
        let identity = identity(&dirfd::metadata(fd.as_raw_fd())?);
        if u32::from(identity.mode) & libc::S_IFMT != libc::S_IFDIR {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        roots.push(PinnedCleanupRoot {
            kind: parse_root_kind(kind)?,
            fd,
            identity,
        });
    }
    enter_minimal_mount_namespace(bootstrap.as_raw_fd())?;
    drop(bootstrap);
    let authority = MappedCleanupAuthority::new(namespace_map, roots)?;
    let deadline = Instant::now() + DEFAULT_TIMEOUT;
    let mut budget = Budget::default();
    let mut inventories = Vec::with_capacity(authority.roots.len());
    let mut notify =
        |root_index: u8, fd: RawFd| send_fds(socket, &[b'E', root_index], &[fd], deadline);
    for (root_index, root) in authority.roots.iter().enumerate() {
        let mut context = InventoryContext {
            root: root.identity,
            map: &authority.map,
            budget: &mut budget,
            limits: authority.limits,
            deadline,
            root_index: root_index as u8,
            notify: &mut notify,
        };
        inventories.push(inventory(root.fd.as_raw_fd(), 0, &mut context)?);
    }
    send_packet(socket, b"D", deadline)?;
    expect_packet(socket, b"C", deadline, Some(unsafe { libc::getppid() }))?;
    for (root, entries) in authority.roots.iter().zip(inventories) {
        remove_inventory(root.fd.as_raw_fd(), root.identity, entries, deadline)?;
        root.verify()?;
        sync_directory(root.fd.as_raw_fd())?;
    }
    send_packet(socket, b"O", deadline)
}

fn require_empty_groups() -> Result<(), ExecutionDomainError> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count == 0 {
        Ok(())
    } else if count < 0 {
        Err(io_failure(io::Error::last_os_error()))
    } else {
        Err(failure(FailureCategory::IdentityMismatch))
    }
}

pub(super) fn verify_empty_supplementary_groups() -> Result<(), ExecutionDomainError> {
    require_empty_groups()
}

pub(super) fn verify_rootlesskit_map(
    state: &dirfd::BoundDir,
    map: MappedIdRange,
) -> Result<(), ExecutionDomainError> {
    let bytes = state.read_regular(c"child_pid", 32)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| failure(FailureCategory::IdentityMismatch))?
        .trim();
    let pid = text
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
    verify_proc_map(pid, true, map)?;
    verify_proc_map(pid, false, map)?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(io_failure)?;
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?;
    if !groups.trim().is_empty() {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

fn install_map(
    worker: &CleanupWorkerConfig,
    pid: u32,
    uid: bool,
    map: MappedIdRange,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    let executable = if uid {
        &worker.newuidmap
    } else {
        &worker.newgidmap
    };
    let (service, start, count) = if uid {
        (map.service_uid, map.subuid_start, map.subuid_count)
    } else {
        (map.service_gid, map.subgid_start, map.subgid_count)
    };
    let mut command = executable.command()?;
    command
        .args([
            pid.to_string(),
            "0".into(),
            service.to_string(),
            "1".into(),
            "1".into(),
            start.to_string(),
            count.to_string(),
        ])
        .env_clear();
    let mut helper = command.spawn().map_err(io_failure)?;
    let status = match wait_child_status(&mut helper, deadline) {
        Ok(status) => status,
        Err(error) => match observe_child(helper) {
            Ok((false, _helper)) => return Err(error),
            Ok((true, helper)) => {
                retain_pending_cleanup(worker, Some(helper), None, None);
                return Err(error);
            }
            Err((observation, helper)) => {
                retain_pending_cleanup(worker, Some(helper), None, None);
                return Err(combine_cleanup(error, Err(observation)));
            }
        },
    };
    if status.success() {
        Ok(())
    } else {
        Err(failure(FailureCategory::Unavailable))
    }
}

fn close_unrelated_worker_fds() -> Result<(), ExecutionDomainError> {
    // FD 0 is the only bootstrap authority inherited across exec. All other
    // capabilities arrive later through authenticated SCM_RIGHTS packets.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 1u32, u32::MAX, 0u32) };
    if result < 0 {
        Err(io_failure(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn verify_proc_map(pid: u32, uid: bool, map: MappedIdRange) -> Result<(), ExecutionDomainError> {
    let path = format!("/proc/{pid}/{}_map", if uid { "uid" } else { "gid" });
    let contents = std::fs::read_to_string(path).map_err(io_failure)?;
    let (service, start, count) = if uid {
        (map.service_uid, map.subuid_start, map.subuid_count)
    } else {
        (map.service_gid, map.subgid_start, map.subgid_count)
    };
    verify_map_text(&contents, service, start, count)
}

fn verify_worker_map(uid: bool) -> Result<u32, ExecutionDomainError> {
    let contents = std::fs::read_to_string(if uid {
        "/proc/self/uid_map"
    } else {
        "/proc/self/gid_map"
    })
    .map_err(io_failure)?;
    let mut lines = contents.lines();
    let first = parse_map_line(
        lines
            .next()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?,
    )?;
    let second = parse_map_line(
        lines
            .next()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?,
    )?;
    if lines.next().is_some() || first.0 != 0 || first.2 != 1 || second.0 != 1 {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(second.2)
}

fn verify_map_text(
    contents: &str,
    service: u32,
    start: u32,
    count: u32,
) -> Result<(), ExecutionDomainError> {
    let mut lines = contents.lines();
    if parse_map_line(
        lines
            .next()
            .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?,
    )? != (0, service, 1)
        || parse_map_line(
            lines
                .next()
                .ok_or_else(|| failure(FailureCategory::IdentityMismatch))?,
        )? != (1, start, count)
        || lines.next().is_some()
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_map_text_for_test(
    contents: &str,
    service: u32,
    start: u32,
    count: u32,
) -> Result<(), ExecutionDomainError> {
    verify_map_text(contents, service, start, count)
}

fn parse_map_line(line: &str) -> Result<(u32, u32, u32), ExecutionDomainError> {
    let values = line
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| failure(FailureCategory::IdentityMismatch))
        })
        .collect::<Result<Vec<_>, _>>()?;
    match values.as_slice() {
        [inside, outside, count] => Ok((*inside, *outside, *count)),
        _ => Err(failure(FailureCategory::IdentityMismatch)),
    }
}

fn enter_minimal_mount_namespace(root_fd: RawFd) -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    checked(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    })?;
    let root = format!("/proc/self/fd/{root_fd}");
    let root = CString::new(root).map_err(|_| failure(FailureCategory::InvalidInput))?;
    checked(unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            root.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"mode=0700,size=1m".as_ptr().cast(),
        )
    })?;
    // The descriptor supplied by the supervisor still names the directory
    // underneath the new mount. Reopen the procfd path after mount(2), so
    // pivot_root operates on the tmpfs mount root rather than the host path.
    let mounted_root = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if mounted_root < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let mounted_root = unsafe { OwnedFd::from_raw_fd(mounted_root) };
    checked(unsafe { libc::fchdir(mounted_root.as_raw_fd()) })?;
    checked(unsafe { libc::mkdir(c"oldroot".as_ptr(), 0o700) })?;
    let pivot = unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"oldroot".as_ptr()) };
    if pivot < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    checked(unsafe { libc::chdir(c"/".as_ptr()) })?;
    checked(unsafe { libc::umount2(c"/oldroot".as_ptr(), libc::MNT_DETACH) })?;
    checked(unsafe { libc::rmdir(c"/oldroot".as_ptr()) })
}

#[derive(Default)]
struct Budget {
    entries: usize,
    path_bytes: usize,
}

enum Entry {
    Directory {
        name: CString,
        fd: OwnedFd,
        identity: Identity,
        children: Vec<Entry>,
    },
    Leaf {
        name: CString,
        identity: Identity,
    },
}

struct InventoryContext<'a> {
    root: Identity,
    map: &'a MappedIdRange,
    budget: &'a mut Budget,
    limits: InventoryLimits,
    deadline: Instant,
    root_index: u8,
    notify: &'a mut dyn FnMut(u8, RawFd) -> Result<(), ExecutionDomainError>,
}

fn inventory(
    fd: RawFd,
    depth: usize,
    context: &mut InventoryContext<'_>,
) -> Result<Vec<Entry>, ExecutionDomainError> {
    if depth > context.limits.depth || Instant::now() >= context.deadline {
        return Err(failure(FailureCategory::Timeout));
    }
    let mut entries = Vec::new();
    for name in dirfd::directory_entries_stream(fd)? {
        let name = name?;
        context.budget.entries = context
            .budget
            .entries
            .checked_add(1)
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
        context.budget.path_bytes = context
            .budget
            .path_bytes
            .checked_add(name.to_bytes().len())
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
        if context.budget.entries > context.limits.entries
            || context.budget.path_bytes > context.limits.path_bytes
        {
            return Err(failure(FailureCategory::Unavailable));
        }
        if Instant::now() >= context.deadline {
            return Err(failure(FailureCategory::Timeout));
        }
        let metadata = dirfd::stat_at(fd, &name).map_err(io_failure)?;
        let current = identity(&metadata);
        if current.device != context.root.device
            || current.mount_id != context.root.mount_id
            || !context.map.owns(current.uid, current.gid)
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        let pinned = dirfd::open_at(
            fd,
            &name,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
            RESOLVE_POLICY,
        )?;
        if identity(&dirfd::metadata(pinned.as_raw_fd())?) != current {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        (context.notify)(context.root_index, pinned.as_raw_fd())?;
        match u32::from(current.mode) & libc::S_IFMT {
            libc::S_IFDIR => {
                let child = dirfd::open_at(
                    fd,
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0,
                    RESOLVE_POLICY,
                )?;
                let opened = identity(&dirfd::metadata(child.as_raw_fd())?);
                if opened != current {
                    return Err(failure(FailureCategory::IdentityMismatch));
                }
                let children = inventory(child.as_raw_fd(), depth + 1, context)?;
                entries.push(Entry::Directory {
                    name,
                    fd: child,
                    identity: current,
                    children,
                });
            }
            libc::S_IFREG | libc::S_IFLNK | libc::S_IFIFO => {
                entries.push(Entry::Leaf {
                    name,
                    identity: current,
                });
            }
            _ => return Err(failure(FailureCategory::IdentityMismatch)),
        }
    }
    Ok(entries)
}

fn remove_inventory(
    parent: RawFd,
    root: Identity,
    entries: Vec<Entry>,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    for entry in entries {
        if Instant::now() >= deadline {
            return Err(failure(FailureCategory::Timeout));
        }
        match entry {
            Entry::Directory {
                name,
                fd,
                identity: expected,
                children,
            } => {
                verify_open_directory(parent, &name, fd.as_raw_fd(), expected, root)?;
                remove_inventory(fd.as_raw_fd(), root, children, deadline)?;
                verify_open_directory(parent, &name, fd.as_raw_fd(), expected, root)?;
                checked(unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) })?;
            }
            Entry::Leaf { name, identity } => {
                // Hardlinks are unlinked by name and identity; they are never
                // chmod'ed, chown'ed, truncated, or followed.
                verify_named(parent, &name, identity, root)?;
                checked(unsafe { libc::unlinkat(parent, name.as_ptr(), 0) })?;
            }
        }
    }
    sync_directory(parent)
}

fn verify_open_directory(
    parent: RawFd,
    name: &CStr,
    fd: RawFd,
    expected: Identity,
    root: Identity,
) -> Result<(), ExecutionDomainError> {
    verify_named(parent, name, expected, root)?;
    let opened = identity(&dirfd::metadata(fd)?);
    if opened != expected || u32::from(opened.mode) & libc::S_IFMT != libc::S_IFDIR {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

fn verify_named(
    parent: RawFd,
    name: &CStr,
    expected: Identity,
    root: Identity,
) -> Result<(), ExecutionDomainError> {
    let actual = identity(&dirfd::stat_at(parent, name).map_err(io_failure)?);
    if actual != expected || actual.device != root.device || actual.mount_id != root.mount_id {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(())
}

fn identity(metadata: &libc::statx) -> Identity {
    Identity {
        device: (metadata.stx_dev_major, metadata.stx_dev_minor),
        inode: metadata.stx_ino,
        mount_id: metadata.stx_mnt_id,
        mode: metadata.stx_mode,
        uid: metadata.stx_uid,
        gid: metadata.stx_gid,
    }
}

fn duplicate(fd: RawFd) -> Result<OwnedFd, ExecutionDomainError> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd), ExecutionDomainError> {
    let mut pair = [-1; 2];
    checked(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    })?;
    let pair = pair.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    let enabled: libc::c_int = 1;
    for fd in &pair {
        checked(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&raw const enabled).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        })?;
    }
    let [parent, child] = pair;
    Ok((parent, child))
}

fn send_packet(fd: RawFd, bytes: &[u8], deadline: Instant) -> Result<(), ExecutionDomainError> {
    send_fds(fd, bytes, &[], deadline)
}

fn expect_packet(
    fd: RawFd,
    expected: &[u8],
    deadline: Instant,
    expected_pid: Option<i32>,
) -> Result<(), ExecutionDomainError> {
    let (actual, fds, credentials) = receive_fds(fd, 0, deadline)?;
    if actual != expected
        || !fds.is_empty()
        || expected_pid.is_some_and(|pid| credentials.is_none_or(|value| value.pid != pid))
    {
        return Err(failure(FailureCategory::Protocol));
    }
    Ok(())
}

fn send_fds(
    socket: RawFd,
    bytes: &[u8],
    fds: &[RawFd],
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    if bytes.is_empty() || bytes.len() > 64 || fds.len() > 8 {
        return Err(failure(FailureCategory::InvalidInput));
    }
    wait_socket(socket, libc::POLLOUT, deadline)?;
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let control_len = if fds.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE((std::mem::size_of_val(fds)) as libc::c_uint) as usize }
    };
    let mut control = vec![0u8; control_len];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    if !fds.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(failure(FailureCategory::Protocol));
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of_val(fds) as libc::c_uint) as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                std::mem::size_of_val(fds),
            );
        }
    }
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent == bytes.len() as isize {
        Ok(())
    } else if sent < 0 {
        Err(io_failure(io::Error::last_os_error()))
    } else {
        Err(failure(FailureCategory::Protocol))
    }
}

type ReceivedFds = (Vec<u8>, Vec<OwnedFd>, Option<libc::ucred>);

fn receive_fds(
    socket: RawFd,
    max_fds: usize,
    deadline: Instant,
) -> Result<ReceivedFds, ExecutionDomainError> {
    wait_socket(socket, libc::POLLIN, deadline)?;
    let mut bytes = [0u8; 64];
    let mut iovec = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let rights = unsafe {
        libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as libc::c_uint) as usize
    };
    let credentials =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as libc::c_uint) as usize };
    let mut control = vec![0u8; rights + credentials];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let count = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count <= 0 {
        return if count == 0 {
            Err(failure(FailureCategory::Protocol))
        } else {
            Err(io_failure(io::Error::last_os_error()))
        };
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(failure(FailureCategory::Protocol));
    }
    let mut received = Vec::new();
    let mut peer = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let value = unsafe { &*header };
        if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_RIGHTS {
            let bytes = value
                .cmsg_len
                .checked_sub(unsafe { libc::CMSG_LEN(0) as usize })
                .ok_or_else(|| failure(FailureCategory::Protocol))?;
            let count = bytes / std::mem::size_of::<RawFd>();
            let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
            for index in 0..count {
                received.push(unsafe { OwnedFd::from_raw_fd(*data.add(index)) });
            }
            if bytes % std::mem::size_of::<RawFd>() != 0 || received.len() > max_fds {
                return Err(failure(FailureCategory::Protocol));
            }
        } else if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_CREDENTIALS {
            if value.cmsg_len
                != unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as libc::c_uint) }
                    as usize
                || peer.is_some()
            {
                return Err(failure(FailureCategory::Protocol));
            }
            peer = Some(unsafe { *libc::CMSG_DATA(header).cast::<libc::ucred>() });
        } else {
            return Err(failure(FailureCategory::Protocol));
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    Ok((bytes[..count as usize].to_vec(), received, peer))
}

#[cfg(test)]
pub(super) fn protocol_roundtrip_for_test(fd: RawFd) -> Result<(), ExecutionDomainError> {
    let (supervisor, worker) = seqpacket_pair()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    send_fds(worker.as_raw_fd(), b"E\0", &[fd], deadline)?;
    let (packet, received, credentials) = receive_fds(supervisor.as_raw_fd(), 1, deadline)?;
    if packet != b"E\0"
        || received.len() != 1
        || credentials.is_none_or(|value| value.pid != unsafe { libc::getpid() })
        || identity(&dirfd::metadata(received[0].as_raw_fd())?) != identity(&dirfd::metadata(fd)?)
    {
        return Err(failure(FailureCategory::Protocol));
    }

    // A packet carrying authority where the receiver expects no descriptors
    // must be rejected; MSG_CTRUNC also asks the kernel to close excess FDs.
    send_fds(worker.as_raw_fd(), b"X", &[fd], deadline)?;
    if receive_fds(supervisor.as_raw_fd(), 0, deadline).is_ok() {
        return Err(failure(FailureCategory::Protocol));
    }
    Ok(())
}

fn wait_socket(fd: RawFd, events: i16, deadline: Instant) -> Result<(), ExecutionDomainError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure(FailureCategory::Timeout));
        }
        let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 && descriptor.revents & events != 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(failure(FailureCategory::Timeout));
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io_failure(io::Error::last_os_error()));
        }
    }
}

fn validate_host_entry(
    fd: RawFd,
    root: Identity,
    map: MappedIdRange,
) -> Result<(), ExecutionDomainError> {
    let actual = identity(&dirfd::metadata(fd)?);
    if actual.device != root.device
        || actual.mount_id != root.mount_id
        || !map.owns(actual.uid, actual.gid)
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    match u32::from(actual.mode) & libc::S_IFMT {
        libc::S_IFDIR | libc::S_IFREG | libc::S_IFLNK | libc::S_IFIFO => Ok(()),
        _ => Err(failure(FailureCategory::IdentityMismatch)),
    }
}

fn wait_child(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    let status = wait_child_status(child, deadline)?;
    if status.success() {
        Ok(())
    } else {
        Err(failure(FailureCategory::Unavailable))
    }
}

fn wait_child_status(
    child: &mut impl ReapableChild,
    deadline: Instant,
) -> Result<std::process::ExitStatus, ExecutionDomainError> {
    const REAP_RESERVE: Duration = Duration::from_millis(25);
    let kill_at = deadline.checked_sub(REAP_RESERVE).unwrap_or(deadline);
    let reap_deadline = deadline
        .checked_add(REAP_GRACE)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let mut killed = false;
    loop {
        if let Some(status) = child.try_wait_status().map_err(io_failure)? {
            return if killed {
                Err(failure(FailureCategory::Timeout))
            } else {
                Ok(status)
            };
        }
        let now = Instant::now();
        if !killed && now >= kill_at {
            match child.kill_process() {
                Ok(()) => killed = true,
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => killed = true,
                Err(error) => return Err(io_failure(error)),
            }
        }
        let active_deadline = if killed { reap_deadline } else { deadline };
        if now >= active_deadline {
            return Err(failure(FailureCategory::Timeout));
        }
        std::thread::sleep(
            Duration::from_millis(5).min(active_deadline.saturating_duration_since(now)),
        );
    }
}

pub(super) trait ReapableChild {
    fn try_wait_status(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
    fn kill_process(&mut self) -> io::Result<()>;
}

impl ReapableChild for std::process::Child {
    fn try_wait_status(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.try_wait()
    }

    fn kill_process(&mut self) -> io::Result<()> {
        self.kill()
    }
}

fn observe_child<C: ReapableChild>(mut child: C) -> Result<(bool, C), (ExecutionDomainError, C)> {
    match child.try_wait_status() {
        Ok(status) => Ok((status.is_none(), child)),
        Err(error) => Err((io_failure(error), child)),
    }
}

#[cfg(test)]
pub(super) fn wait_child_for_test(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    wait_child(child, deadline)
}

#[cfg(test)]
pub(super) fn wait_reapable_child_for_test(
    child: &mut impl ReapableChild,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    wait_child_status(child, deadline).map(|_| ())
}

#[cfg(test)]
pub(super) fn retry_pending_children_for_test<C: ReapableChild>(
    children: &mut Vec<C>,
    deadline: Instant,
) -> Result<(), ExecutionDomainError> {
    retry_pending_children(children, deadline)
}

fn root_kind_byte(kind: CleanupRootKind) -> u8 {
    match kind {
        CleanupRootKind::Work => 0,
        CleanupRootKind::Tmp => 1,
        CleanupRootKind::Home => 2,
        CleanupRootKind::Run => 3,
        CleanupRootKind::DockerConfig => 4,
        CleanupRootKind::DockerData => 5,
        CleanupRootKind::DockerExec => 6,
    }
}

fn parse_root_kind(value: u8) -> Result<CleanupRootKind, ExecutionDomainError> {
    match value {
        0 => Ok(CleanupRootKind::Work),
        1 => Ok(CleanupRootKind::Tmp),
        2 => Ok(CleanupRootKind::Home),
        3 => Ok(CleanupRootKind::Run),
        4 => Ok(CleanupRootKind::DockerConfig),
        5 => Ok(CleanupRootKind::DockerData),
        6 => Ok(CleanupRootKind::DockerExec),
        _ => Err(failure(FailureCategory::Protocol)),
    }
}

fn checked(result: i32) -> Result<(), ExecutionDomainError> {
    if result == 0 {
        Ok(())
    } else {
        Err(io_failure(io::Error::last_os_error()))
    }
}

fn sync_directory(fd: RawFd) -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::fsync(fd) })
}

fn io_failure(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Destroy,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Destroy,
        category,
        errno: None,
    }
}
