use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::super::protocol::{Message, Request, Response};
use super::super::{
    AttemptIdentity, CommandOutcome, CommandSpec, CommandTarget, DestroyReport, DomainPath,
    ExecutionDomainError, FailureCategory, Stage,
};
use super::cleanup::{CleanupWorkerConfig, IdMapSpec};
use super::dirfd::{self, BoundDir};
use super::launcher::{KernelDomain, LaunchSpec, NetworkLaunch};
use super::{StrictBackendBuilder, StrictCleanupRecord, StrictPartialCleanup};

pub(super) struct NativePrerequisites {
    root: PathBuf,
    cgroup: PathBuf,
    binary: PathBuf,
    map: IdMapSpec,
}

impl NativePrerequisites {
    pub(super) fn from_paths(
        root: Option<PathBuf>,
        cgroup: Option<PathBuf>,
        binary: Option<PathBuf>,
    ) -> Result<Self, ExecutionDomainError> {
        let root = canonical_required(root)?;
        let cgroup = canonical_required(cgroup)?;
        let binary = canonical_required(binary)?;
        if unsafe { libc::geteuid() } == 0 {
            return Err(unavailable());
        }
        if Path::new("/.dockerenv").exists()
            || Path::new("/run/.containerenv").exists()
            || std::env::var_os("container").is_some()
        {
            return Err(unavailable());
        }
        let os_release = fs::read_to_string("/etc/os-release").map_err(io_error)?;
        if !os_release.lines().any(|line| line == "ID=debian")
            || fs::read_to_string("/proc/1/comm").map_err(io_error)?.trim() != "systemd"
        {
            return Err(unavailable());
        }
        verify_private_root(&root)?;
        verify_binary(&binary)?;
        verify_delegation(&cgroup)?;
        verify_helpers()?;
        verify_kernel_primitives()?;
        let user = service_user(unsafe { libc::geteuid() })?;
        let subuid = fs::read_to_string("/etc/subuid").map_err(io_error)?;
        let subgid = fs::read_to_string("/etc/subgid").map_err(io_error)?;
        let map = IdMapSpec::parse(
            &user,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            &subuid,
            &subgid,
        )?;
        let rootlesskit = Path::new("/usr/bin/rootlesskit");
        verify_binary(rootlesskit)?;
        let packages = fs::read_to_string("/var/lib/dpkg/status").map_err(io_error)?;
        if !installed_rootlesskit_235(&packages) {
            return Err(unavailable());
        }
        Ok(Self {
            root,
            cgroup,
            binary,
            map,
        })
    }

    fn from_environment() -> Result<Self, ExecutionDomainError> {
        Self::from_paths(
            std::env::var_os("CHIMERA_NATIVE_TEST_ROOT").map(PathBuf::from),
            std::env::var_os("CHIMERA_NATIVE_TEST_CGROUP").map(PathBuf::from),
            std::env::var_os("CHIMERA_NATIVE_TEST_BINARY").map(PathBuf::from),
        )
    }
}

// Failed teardown retains the production cleanup capability AND its root lock.
// A later selected test cannot reuse a poisoned root or overwrite its inventory.
static QUARANTINE: Mutex<Vec<QuarantinedFixture>> = Mutex::new(Vec::new());

struct QuarantinedFixture {
    _lock: crate::storage::RootLock,
    _cleanup: Option<StrictPartialCleanup>,
}

pub(super) struct NativeDomainFixture {
    cleanup: Option<StrictCleanupRecord>,
    lock: Option<crate::storage::RootLock>,
    active: BoundDir,
    cgroup_root: BoundDir,
    attempt_cgroup: BoundDir,
    attempt_path: PathBuf,
    attempt_name: CString,
    cgroup_name: CString,
    cleanup_cgroup_name: CString,
    launcher_pidfd: OwnedFd,
    report: Option<DestroyReport>,
    command_id: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct NativeSnapshot {
    pub live_processes: usize,
    pub cgroups: usize,
    pub mounts: usize,
    pub entries: usize,
}

impl NativeDomainFixture {
    pub(super) async fn prepare() -> Result<Self, ExecutionDomainError> {
        let prerequisites = NativePrerequisites::from_environment()?;
        super::cleanup::verify_empty_supplementary_groups()?;
        let worker = CleanupWorkerConfig::verified(
            &prerequisites.binary,
            Path::new("/usr/bin/newuidmap"),
            Path::new("/usr/bin/newgidmap"),
        )?;
        // Both cache mount targets need immutable inputs even for this shell-only
        // case. Use fixed operator-owned data, never a service-writable fixture.
        let mut rootfs =
            super::rootfs::RootfsPlan::debian(&super::rootfs::linux::ImmutableInputs {
                tool_cache: "/usr/share/zoneinfo/Etc".into(),
                actions_cache: "/usr/share/zoneinfo/Etc".into(),
                extra_tools: Vec::new(),
            })?;
        let limits = crate::config::resources::ResourceLimits {
            memory_high: "256 MiB".into(),
            memory_max: "512 MiB".into(),
            memory_swap_max: "0".into(),
            cpu_quota: "150%".into(),
            cpu_weight: 100,
            pids_max: "256".into(),
            io_weight: 100,
            io_max: Vec::new(),
        }
        .validate()
        .map_err(|_| unavailable())?;
        let lock =
            crate::storage::RootLock::acquire(&prerequisites.root).map_err(|_| unavailable())?;
        let mut retained = None;
        let result = (|| {
            let root = BoundDir::open_root(&prerequisites.root)?;
            root.verify_private_directory()?;
            let active = match dirfd::stat_at(root.fd(), c"active") {
                Ok(_) => root.child(c"active")?,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    root.create_child(c"active", 0o700)?
                }
                Err(error) => return Err(io_error(error)),
            };
            active.verify_private_directory()?;
            if !dirfd::directory_entries(active.fd())?.is_empty() {
                return Err(unavailable());
            }
            let mut cgroups = super::cgroup::CgroupRoot::open_delegated(&prerequisites.cgroup)?;
            // The dedicated unit supplies these exact global limits. Production
            // validates readback and evacuates this test process before launch.
            cgroups.prepare_supervisor(&limits)?;
            let attempt = AttemptIdentity::new();
            let attempt_name = CString::new(attempt.component()).map_err(|_| unavailable())?;
            let attempt_root = active.create_child(&attempt_name, 0o700)?;
            let bound_rootfs = attempt_root.create_child(c"rootfs", 0o700)?;
            let state = attempt_root.create_child(c"rootlesskit", 0o700)?;
            for (name, target) in [
                ("work", "/work"),
                ("tmp", "/tmp"),
                ("home", "/home/chimera"),
                ("run", "/run/chimera"),
                ("docker", "/home/chimera/.docker"),
                ("docker-data", "/var/lib/chimera/docker"),
                ("docker-exec", "/run/chimera/docker-exec"),
            ] {
                let name = CString::new(name).map_err(|_| unavailable())?;
                let directory = attempt_root.create_child(&name, 0o700)?;
                rootfs.inputs.push(super::rootfs::MountInput::writable(
                    directory.bound_path(),
                    target,
                )?);
            }
            rootfs.staging_root = bound_rootfs.bound_path();
            install_fd_probe(&attempt_root.child(c"work")?)?;
            let cgroup = cgroups.create_attempt(attempt, &limits)?;
            let cgroup_name = CString::new(format!("attempt-{}", attempt.component()))
                .map_err(|_| unavailable())?;
            let domain_path = prerequisites
                .cgroup
                .join(cgroup_name.to_str().map_err(|_| unavailable())?)
                .join("domain");
            let input = super::rootfs::MountInput::writable(domain_path, "/sys/fs/cgroup");
            match input {
                Ok(input) => rootfs.inputs.push(input),
                Err(error) => {
                    retained = Some(StrictPartialCleanup::Cgroup(cgroup));
                    return Err(error);
                }
            }
            let builder = StrictBackendBuilder {
                cgroup,
                launch: LaunchSpec {
                    attempt,
                    rootfs,
                    bound_rootfs,
                    executable: prerequisites.binary,
                    rootlesskit: "/usr/bin/rootlesskit".into(),
                    state_directory: state.bound_path(),
                    hostname: "chimera-native".into(),
                    network: NetworkLaunch::Disconnected,
                },
                mapped_cleanup: Some((prerequisites.map.range(), worker)),
                runtime_socket: None,
            };
            let parts = match builder.build() {
                Ok(parts) => parts,
                Err(failure) => {
                    let (error, cleanup) = failure.into_parts();
                    retained = cleanup;
                    return Err(error);
                }
            };
            retained = Some(StrictPartialCleanup::Record(Box::new(parts.cleanup)));
            let Some(StrictPartialCleanup::Record(record)) = retained.as_ref() else {
                unreachable!()
            };
            let launcher_fd =
                unsafe { libc::fcntl(record.kernel().pidfd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if launcher_fd < 0 {
                return Err(io_error(io::Error::last_os_error()));
            }
            let launcher_pidfd = unsafe { OwnedFd::from_raw_fd(launcher_fd) };
            let cgroup_root = BoundDir::open_root(&prerequisites.cgroup)?;
            let attempt_cgroup = cgroup_root.child(&cgroup_name)?;
            let cleanup_cgroup_name = CString::new(format!("cleanup-{}", attempt.component()))
                .map_err(|_| unavailable())?;
            Ok((
                active,
                attempt_root.bound_path(),
                attempt_name,
                cgroup_name,
                cleanup_cgroup_name,
                launcher_pidfd,
                cgroup_root,
                attempt_cgroup,
            ))
        })();
        match result {
            Ok((
                active,
                attempt_path,
                attempt_name,
                cgroup_name,
                cleanup_cgroup_name,
                launcher_pidfd,
                cgroup_root,
                attempt_cgroup,
            )) => {
                let Some(StrictPartialCleanup::Record(record)) = retained.take() else {
                    unreachable!()
                };
                Ok(Self {
                    cleanup: Some(*record),
                    lock: Some(lock),
                    active,
                    cgroup_root,
                    attempt_cgroup,
                    attempt_path,
                    attempt_name,
                    cgroup_name,
                    cleanup_cgroup_name,
                    launcher_pidfd,
                    report: None,
                    command_id: 0,
                })
            }
            Err(error) => {
                // If construction failed after publication, retry through the
                // production owner. Keep the lock even on an early partial tree:
                // a failed prepare never advertises a clean fixture.
                if let Some(cleanup) = retained.as_mut() {
                    let _ = cleanup.retry();
                }
                quarantine(lock, retained);
                Err(error)
            }
        }
    }

    pub(super) fn kernel(&self) -> &KernelDomain {
        self.cleanup
            .as_ref()
            .expect("fixture already destroyed")
            .kernel()
    }

    pub(super) async fn run(&mut self, script: &str) -> CommandOutcome {
        self.run_checked(Self::shell_spec(script))
            .unwrap_or_else(|error| panic!("native command protocol failed: {error:?}"))
    }

    // Native teardown tests use this only for a command that must remain
    // active through Shutdown, preventing PID 1 from exiting before cgroup
    // escalation is observed.
    pub(super) async fn run_until_started(
        &mut self,
        script: &str,
    ) -> Result<(), ExecutionDomainError> {
        self.start_checked(Self::shell_spec(script)).map(|_| ())
    }

    pub(super) async fn wait_for_live_processes(
        &self,
        minimum: usize,
        timeout: Duration,
    ) -> Result<bool, ExecutionDomainError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.inventory()?.live_processes >= minimum {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(super) async fn wait_for_heartbeat_growth(
        &self,
        timeout: Duration,
    ) -> Result<bool, ExecutionDomainError> {
        let deadline = Instant::now() + timeout;
        let mut previous = self.heartbeat_size()?;
        loop {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            let current = self.heartbeat_size()?;
            if current > previous {
                return Ok(true);
            }
            previous = current;
        }
    }

    fn heartbeat_size(&self) -> Result<usize, ExecutionDomainError> {
        let work = self.active.child(&self.attempt_name)?.child(c"work")?;
        match dirfd::stat_at(work.fd(), c"native-detached-heartbeat") {
            Ok(_) => Ok(work
                .read_regular(c"native-detached-heartbeat", 64 * 1024)?
                .len()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(0),
            Err(error) => Err(io_error(error)),
        }
    }

    fn shell_spec(script: &str) -> CommandSpec {
        CommandSpec {
            target: CommandTarget::Sandboxed {
                program: DomainPath::parse("/usr/bin/dash").expect("fixed shell path"),
                args: vec!["-c".into(), format!("set -eu\n{script}")],
                cwd: DomainPath::parse("/work").expect("fixed work path"),
            },
            env: Default::default(),
            timeout: Duration::from_secs(30),
            state: None,
        }
    }

    fn run_checked(&mut self, spec: CommandSpec) -> Result<CommandOutcome, ExecutionDomainError> {
        let (command_id, deadline) = self.start_checked(spec)?;
        loop {
            match self
                .cleanup
                .as_mut()
                .ok_or_else(not_ready)?
                .kernel_mut()
                .control
                .receive(deadline)?
            {
                Message::Response(Response::Output {
                    command_id: actual, ..
                }) if actual == command_id => {}
                Message::Response(Response::CommandFinished {
                    command_id: actual,
                    outcome,
                }) if actual == command_id => return Ok(outcome),
                _ => return Err(unavailable()),
            }
        }
    }

    fn start_checked(&mut self, spec: CommandSpec) -> Result<(u64, Instant), ExecutionDomainError> {
        self.command_id += 1;
        let command_id = self.command_id;
        let kernel = self.cleanup.as_mut().ok_or_else(not_ready)?.kernel_mut();
        let deadline = Instant::now() + Duration::from_secs(40);
        match kernel
            .control
            .request_until(Request::Run { command_id, spec }, deadline)?
        {
            Response::CommandStarted { command_id: actual } if actual == command_id => {}
            _ => return Err(unavailable()),
        }
        Ok((command_id, deadline))
    }

    pub(super) async fn probe_control_fds(&mut self) -> CommandOutcome {
        // The probe must be the first executable after workflow hardening:
        // a shell could close a leaked descriptor before the probe sees it.
        self.run_checked(control_fd_probe_spec().expect("fixed probe paths"))
            .unwrap_or_else(|error| panic!("native probe protocol failed: {error:?}"))
    }

    pub(super) async fn destroy(&mut self) -> Result<DestroyReport, ExecutionDomainError> {
        if let Some(report) = &self.report {
            return Ok(report.clone());
        }
        let report = self.cleanup.as_mut().ok_or_else(not_ready)?.destroy()?;
        self.report = Some(report.clone());
        self.cleanup.take();
        Ok(report)
    }

    pub(super) fn snapshot(&self) -> NativeSnapshot {
        self.inventory()
            .expect("native resource inventory must be readable")
    }

    fn inventory(&self) -> Result<NativeSnapshot, ExecutionDomainError> {
        self.active.verify_binding()?;
        self.cgroup_root.verify_binding()?;
        let mut snapshot = NativeSnapshot {
            live_processes: 0,
            cgroups: 0,
            mounts: 0,
            entries: dirfd::directory_entries(self.active.fd())?.len(),
        };
        for name in [&self.cgroup_name, &self.cleanup_cgroup_name] {
            match dirfd::stat_at(self.cgroup_root.fd(), name) {
                Ok(_) => {
                    if name == &self.cgroup_name {
                        self.attempt_cgroup.verify_binding()?;
                    }
                    inventory_cgroup(&self.cgroup_root.child(name)?, &mut snapshot, 0)?;
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        let mut poll = libc::pollfd {
            fd: self.launcher_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        if ready == 0 && snapshot.live_processes == 0 {
            snapshot.live_processes += 1;
        }
        if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(unavailable());
        }
        let mountinfo = fs::read("/proc/self/mountinfo").map_err(io_error)?;
        for line in mountinfo.split(|byte| *byte == b'\n') {
            let Some(field) = line.split(|byte| *byte == b' ').nth(4) else {
                continue;
            };
            let point = super::unescape_mountinfo(field)?;
            let path = self.attempt_path.as_os_str().as_encoded_bytes();
            if point == path
                || point
                    .strip_prefix(path)
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
            {
                snapshot.mounts += 1;
            }
        }
        Ok(snapshot)
    }

    pub(super) async fn assert_no_resources(&self) -> Result<(), ExecutionDomainError> {
        if self.report.is_none() || self.cleanup.is_some() {
            return Err(not_ready());
        }
        self.active.refuse_entry(&self.attempt_name)?;
        let inventory = self.inventory()?;
        if inventory
            != (NativeSnapshot {
                live_processes: 0,
                cgroups: 0,
                mounts: 0,
                entries: 0,
            })
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

pub(super) fn control_fd_probe_spec() -> Result<CommandSpec, ExecutionDomainError> {
    Ok(CommandSpec {
        target: CommandTarget::Sandboxed {
            program: DomainPath::parse("/work/native-fd-probe")?,
            args: Vec::new(),
            cwd: DomainPath::parse("/work")?,
        },
        env: Default::default(),
        timeout: Duration::from_secs(30),
        state: None,
    })
}

impl Drop for NativeDomainFixture {
    fn drop(&mut self) {
        let retained = self.cleanup.take().and_then(|mut cleanup| {
            cleanup
                .destroy()
                .err()
                .map(|_| StrictPartialCleanup::Record(Box::new(cleanup)))
        });
        let clean = self.inventory().is_ok_and(|inventory| {
            inventory
                == (NativeSnapshot {
                    live_processes: 0,
                    cgroups: 0,
                    mounts: 0,
                    entries: 0,
                })
        });
        if (retained.is_some() || !clean)
            && let Some(lock) = self.lock.take()
        {
            quarantine(lock, retained);
        }
    }
}

fn quarantine(lock: crate::storage::RootLock, cleanup: Option<StrictPartialCleanup>) {
    QUARANTINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(QuarantinedFixture {
            _lock: lock,
            _cleanup: cleanup,
        });
}

fn install_fd_probe(work: &BoundDir) -> Result<(), ExecutionDomainError> {
    let executable = work.write_new(
        c"native-fd-probe",
        include_bytes!(concat!(env!("OUT_DIR"), "/chimera-native-fd-probe")),
    )?;
    if unsafe { libc::fchmod(executable.as_raw_fd(), 0o700) } < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    work.verify_binding()
}

fn inventory_cgroup(
    directory: &BoundDir,
    snapshot: &mut NativeSnapshot,
    depth: usize,
) -> Result<(), ExecutionDomainError> {
    use std::io::Read;
    if depth >= 64 || snapshot.cgroups >= 4096 {
        return Err(unavailable());
    }
    directory.verify_binding()?;
    snapshot.cgroups += 1;
    let fd = dirfd::open_at(
        directory.fd(),
        c"cgroup.procs",
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
        dirfd::RESOLVE_POLICY,
    )?;
    let mut members = String::new();
    fs::File::from(fd)
        .take(1024 * 1024 + 1)
        .read_to_string(&mut members)
        .map_err(io_error)?;
    if members.len() > 1024 * 1024 {
        return Err(unavailable());
    }
    for member in members.split_whitespace() {
        if member.parse::<u32>().ok().is_none_or(|pid| pid == 0) {
            return Err(unavailable());
        }
        snapshot.live_processes += 1;
    }
    for name in dirfd::directory_entries(directory.fd())? {
        let metadata = dirfd::stat_at(directory.fd(), &name).map_err(io_error)?;
        if u32::from(metadata.stx_mode) & libc::S_IFMT == libc::S_IFDIR {
            inventory_cgroup(&directory.child(&name)?, snapshot, depth + 1)?;
        }
    }
    directory.verify_binding()
}

fn canonical_required(path: Option<PathBuf>) -> Result<PathBuf, ExecutionDomainError> {
    let path = path.ok_or_else(not_ready)?;
    if !path.is_absolute() {
        return Err(unavailable());
    }
    let canonical = path.canonicalize().map_err(io_error)?;
    if canonical != path {
        return Err(unavailable());
    }
    Ok(canonical)
}

fn verify_private_root(path: &Path) -> Result<(), ExecutionDomainError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(unavailable());
    }
    // Scaffolding survives a successful case; stale or quarantined attempts do
    // not. RootLock validates the lock file again when acquiring ownership.
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        match entry.file_name().to_str() {
            Some(".chimera.lock") => {}
            Some("active") => {
                let active = BoundDir::open_root(&entry.path())?;
                active.verify_private_directory()?;
                if !dirfd::directory_entries(active.fd())?.is_empty() {
                    return Err(unavailable());
                }
            }
            _ => return Err(unavailable()),
        }
    }
    Ok(())
}

fn verify_binary(path: &Path) -> Result<(), ExecutionDomainError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(unavailable());
    }
    Ok(())
}

fn verify_delegation(path: &Path) -> Result<(), ExecutionDomainError> {
    if !path.starts_with("/sys/fs/cgroup") || path == Path::new("/sys/fs/cgroup") {
        return Err(unavailable());
    }
    // systemd owns the unit's kill control. The production cgroup builder
    // pins it with O_PATH and validates kill authority on each new attempt.
    super::cgroup::CgroupRoot::open_delegated(path)?;
    Ok(())
}

fn verify_helpers() -> Result<(), ExecutionDomainError> {
    for name in ["newuidmap", "newgidmap"] {
        let path = Path::new("/usr/bin").join(name);
        verify_binary(&path)?;
        if fs::metadata(&path).map_err(io_error)?.permissions().mode() & 0o4000 == 0 {
            return Err(unavailable());
        }
    }
    Ok(())
}

fn verify_kernel_primitives() -> Result<(), ExecutionDomainError> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    if raw < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let _pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let result = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_void>(),
            0usize,
        )
    };
    if result != -1 || io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
        return Err(unavailable());
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            -1i32,
            std::ptr::null::<libc::c_char>(),
            0u32,
            std::ptr::null::<libc::c_void>(),
            0usize,
        )
    };
    if result != -1 || io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
        return Err(unavailable());
    }
    Ok(())
}

fn service_user(uid: u32) -> Result<String, ExecutionDomainError> {
    let passwd = fs::read_to_string("/etc/passwd").map_err(io_error)?;
    let mut matching = passwd.lines().filter_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4 || fields[2].parse::<u32>().ok()? != uid {
            return None;
        }
        Some(fields[0].to_owned())
    });
    let user = matching.next().ok_or_else(unavailable)?;
    if matching.next().is_some() {
        return Err(unavailable());
    }
    Ok(user)
}

pub(super) fn installed_rootlesskit_235(status: &str) -> bool {
    status.split("\n\n").any(|paragraph| {
        let mut name = None;
        let mut version = None;
        let mut installed = false;
        for line in paragraph.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                name = Some(value);
            } else if let Some(value) = line.strip_prefix("Version: ") {
                version = Some(value);
            } else if line == "Status: install ok installed" {
                installed = true;
            }
        }
        name == Some("rootlesskit")
            && version.is_some_and(|value| value == "2.3.5" || value.starts_with("2.3.5-"))
            && installed
    })
}

fn io_error(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Launch,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

fn unavailable() -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Launch,
        category: FailureCategory::Unavailable,
        errno: None,
    }
}

fn not_ready() -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Launch,
        category: FailureCategory::NotReady,
        errno: None,
    }
}
