use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory, Stage};

const MEMBERSHIP_FD: i32 = 3;
pub(super) const STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(super) enum NetworkLaunch {
    Disconnected,
    #[cfg(test)]
    Slirp,
}

pub(super) fn rootlesskit_arguments(
    attempt: &AttemptIdentity,
    executable: &Path,
    state: &Path,
    network: NetworkLaunch,
) -> Result<Vec<OsString>, ExecutionDomainError> {
    // Slirp is a contract reserved for Plan D, not an unfiltered network bypass.
    match network {
        NetworkLaunch::Disconnected => {}
        #[cfg(test)]
        NetworkLaunch::Slirp => return Err(failure(FailureCategory::NotReady)),
    }
    let mut state_arg = OsString::from("--state-dir=");
    state_arg.push(state);
    Ok(vec![
        state_arg,
        "--net=none".into(),
        "--port-driver=none".into(),
        "--pidns".into(),
        "--cgroupns".into(),
        "--ipcns".into(),
        "--utsns".into(),
        "--propagation=rprivate".into(),
        "--evacuate-cgroup2=init".into(),
        "--".into(),
        executable.as_os_str().to_owned(),
        "--internal-domain-bootstrap".into(),
        attempt.component().into(),
    ])
}

pub(in crate::job::execution_domain) fn internal_entry() -> Option<i32> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    dispatch_internal(&arguments)
}

pub(super) fn dispatch_internal(arguments: &[OsString]) -> Option<i32> {
    let mode = arguments.first()?;
    if mode != "--internal-domain-launch" && mode != "--internal-domain-bootstrap" {
        return None;
    }
    let result = if mode == "--internal-domain-launch" {
        launch_entry(arguments)
    } else {
        bootstrap_entry(arguments)
    };
    // Internal protocol/paths/argv are never printed, including parse failures.
    Some(result.unwrap_or(78))
}

fn parse_attempt(value: &OsStr) -> Result<AttemptIdentity, ExecutionDomainError> {
    let value = value
        .to_str()
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| failure(FailureCategory::InvalidInput))?;
    let attempt = AttemptIdentity::from_uuid(uuid)?;
    if attempt.component() != value {
        return Err(failure(FailureCategory::InvalidInput));
    }
    Ok(attempt)
}

fn canonical(value: &OsStr) -> Result<PathBuf, ExecutionDomainError> {
    let path = Path::new(value);
    if !path.is_absolute() || value.as_bytes().contains(&0) {
        return Err(failure(FailureCategory::InvalidInput));
    }
    let resolved = path.canonicalize().map_err(io_failure)?;
    if resolved != path {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(resolved)
}

fn launch_entry(arguments: &[OsString]) -> Result<i32, ExecutionDomainError> {
    if arguments.len() != 5 {
        return Err(failure(FailureCategory::InvalidInput));
    }
    let attempt = parse_attempt(&arguments[1])?;
    let rootlesskit = canonical(&arguments[2])?;
    let executable = canonical(&arguments[3])?;
    let state = canonical(&arguments[4])?;
    let argv = rootlesskit_arguments(&attempt, &executable, &state, NetworkLaunch::Disconnected)?;
    let executable = CString::new(rootlesskit.as_os_str().as_bytes())
        .map_err(|_| failure(FailureCategory::InvalidInput))?;
    let mut strings = Vec::with_capacity(argv.len() + 1);
    strings.push(executable.clone());
    for value in argv {
        strings.push(
            CString::new(value.as_bytes()).map_err(|_| failure(FailureCategory::InvalidInput))?,
        );
    }
    let mut pointers: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // RootlessKit needs the standard subordinate-ID utilities. No supervisor
    // environment (tokens, Docker authority or socket activation) is inherited.
    let environment = [
        c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr(),
        c"LANG=C".as_ptr(),
        std::ptr::null(),
    ];
    if unsafe { libc::fcntl(MEMBERSHIP_FD, libc::F_GETFD) } < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let membership = unsafe { OwnedFd::from_raw_fd(MEMBERSHIP_FD) };
    join_cgroup(std::os::fd::AsFd::as_fd(&membership))?;
    drop(membership);
    unsafe { libc::execve(executable.as_ptr(), pointers.as_ptr(), environment.as_ptr()) };
    Err(io_failure(io::Error::last_os_error()))
}

pub(super) fn join_cgroup(fd: BorrowedFd<'_>) -> Result<(), ExecutionDomainError> {
    let raw = fd.as_raw_fd();
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(raw, filesystem.as_mut_ptr()) } < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    if unsafe { filesystem.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(raw, metadata.as_mut_ptr()) } < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let metadata = unsafe { metadata.assume_init() };
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let target = std::fs::read_link(format!("/proc/self/fd/{raw}")).map_err(io_failure)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
        || flags & libc::O_ACCMODE == libc::O_RDONLY
        || target.file_name() != Some(OsStr::new("cgroup.procs"))
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    let result = unsafe { libc::write(raw, b"0\n".as_ptr().cast(), 2) };
    if result != 2 {
        return Err(if result < 0 {
            io_failure(io::Error::last_os_error())
        } else {
            failure(FailureCategory::Io)
        });
    }
    Ok(())
}

pub(super) fn duplicate_control(fd: BorrowedFd<'_>) -> Result<OwnedFd, ExecutionDomainError> {
    let raw = fd.as_raw_fd();
    let mut domain: i32 = 0;
    let mut kind: i32 = 0;
    for (option, value) in [(libc::SO_DOMAIN, &mut domain), (libc::SO_TYPE, &mut kind)] {
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                option,
                (value as *mut i32).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io_failure(io::Error::last_os_error()));
        }
        if length as usize != std::mem::size_of::<i32>() {
            return Err(failure(FailureCategory::Protocol));
        }
    }
    if domain != libc::AF_UNIX || kind != libc::SOCK_STREAM {
        return Err(failure(FailureCategory::Protocol));
    }
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_un>::zeroed();
    let mut length = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::getpeername(raw, address.as_mut_ptr().cast(), &mut length) } < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    if unsafe { address.assume_init() }.sun_family as i32 != libc::AF_UNIX {
        return Err(failure(FailureCategory::Protocol));
    }
    let duplicated = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn bootstrap_entry(arguments: &[OsString]) -> Result<i32, ExecutionDomainError> {
    if arguments.len() != 2 {
        return Err(failure(FailureCategory::InvalidInput));
    }
    let attempt = parse_attempt(&arguments[1])?;
    let control = duplicate_control(unsafe { BorrowedFd::borrow_raw(0) })?;
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if null < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let null = unsafe { OwnedFd::from_raw_fd(null) };
    if unsafe { libc::dup2(null.as_raw_fd(), 0) } < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    drop(null);
    if unsafe { libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) } < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    super::init::install_signal_handlers()?;
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    if child == 0 {
        let code = match super::init::run(UnixStream::from(control), attempt) {
            Ok(()) => 0,
            Err(_) => 78,
        };
        // This entry runs before runtime/threads; never run inherited destructors.
        unsafe { libc::_exit(code) }
    }
    drop(control);
    super::init::wait_for_init(child)
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Launch,
        category,
        errno: None,
    }
}
fn io_failure(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Launch,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

// B3/B4 resources stay staged until manager ownership is implemented in Task 9.
#[cfg(test)]
pub(super) struct LaunchSpec {
    pub attempt: AttemptIdentity,
    pub rootfs: super::rootfs::RootfsPlan,
    pub bound_rootfs: super::dirfd::BoundDir,
    pub executable: PathBuf,
    pub rootlesskit: PathBuf,
    pub state_directory: PathBuf,
    pub hostname: String,
    pub network: NetworkLaunch,
}

#[cfg(test)]
pub(super) struct KernelDomain {
    pub control: super::super::protocol::ControlConnection,
    pub launcher: std::process::Child,
    pub pidfd: OwnedFd,
    pub deadline: std::time::Instant,
}

#[cfg(test)]
pub(super) fn launch<F: super::cgroup::CgroupFilesystem>(
    cgroup: &super::cgroup::AttemptCgroup<F>,
    spec: &LaunchSpec,
) -> Result<KernelDomain, ExecutionDomainError> {
    cgroup.limits_match()?;
    spec.bound_rootfs.verify_binding()?;
    canonical(spec.rootfs.staging_root.as_os_str())?;
    use std::os::unix::fs::MetadataExt;
    let expected = super::dirfd::metadata(spec.bound_rootfs.fd())?;
    let named = std::fs::metadata(&spec.rootfs.staging_root).map_err(io_failure)?;
    let device = libc::makedev(expected.stx_dev_major, expected.stx_dev_minor);
    if named.dev() != device || named.ino() != expected.stx_ino {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    spawn_launcher(cgroup.launch_membership_fd(), spec)
}

#[cfg(test)]
impl KernelDomain {
    pub(super) fn bootstrap(
        &mut self,
        spec: super::super::protocol::BootstrapSpec,
    ) -> Result<(), ExecutionDomainError> {
        use super::super::protocol::{Request, Response};
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let status = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if status < 0 {
            return Err(io_failure(io::Error::last_os_error()));
        }
        if status > 0 || self.launcher.try_wait().map_err(io_failure)?.is_some() {
            return Err(failure(FailureCategory::Unavailable));
        }
        match self
            .control
            .request_until(Request::Bootstrap { spec }, self.deadline)?
        {
            Response::Bootstrapped => Ok(()),
            _ => Err(failure(FailureCategory::Protocol)),
        }
    }
}

#[cfg(test)]
fn spawn_launcher(
    membership: BorrowedFd<'_>,
    spec: &LaunchSpec,
) -> Result<KernelDomain, ExecutionDomainError> {
    use super::super::protocol::{BootstrapSpec, ControlConnection};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let deadline = std::time::Instant::now() + STARTUP_TIMEOUT;
    canonical(spec.executable.as_os_str())?;
    canonical(spec.rootlesskit.as_os_str())?;
    canonical(spec.state_directory.as_os_str())?;
    rootlesskit_arguments(
        &spec.attempt,
        &spec.executable,
        &spec.state_directory,
        spec.network,
    )?;
    let (manager, bootstrap) = UnixStream::pair().map_err(io_failure)?;
    let membership_raw = unsafe { libc::fcntl(membership.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
    if membership_raw < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let membership = unsafe { OwnedFd::from_raw_fd(membership_raw) };
    let mut command = Command::new(&spec.executable);
    command
        .args([
            OsStr::new("--internal-domain-launch"),
            OsStr::new(&spec.attempt.component()),
            spec.rootlesskit.as_os_str(),
            spec.executable.as_os_str(),
            spec.state_directory.as_os_str(),
        ])
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(bootstrap)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(membership_raw, MEMBERSHIP_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            // No allocation, logging or locks after the supervisor forks.
            if libc::close(membership_raw) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_close_range,
                4u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let control = ControlConnection::new(manager, spec.attempt)?;
    let mut child = command.spawn().map_err(io_failure)?;
    drop(membership);
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
    if pidfd < 0 {
        let error = io_failure(io::Error::last_os_error());
        child.kill().map_err(io_failure)?;
        child.wait().map_err(io_failure)?;
        return Err(error);
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    let mut domain = KernelDomain {
        control,
        launcher: child,
        pidfd,
        deadline,
    };
    let bootstrap = domain.bootstrap(BootstrapSpec {
        attempt: spec.attempt,
        rootfs: spec.rootfs.clone(),
        hostname: spec.hostname.clone(),
    });
    if let Err(error) = bootstrap {
        // Cgroup-wide verified teardown remains the manager's responsibility.
        // A failed handshake must not silently detach the directly owned child.
        domain.launcher.kill().map_err(io_failure)?;
        domain.launcher.wait().map_err(io_failure)?;
        return Err(error);
    }
    Ok(domain)
}
