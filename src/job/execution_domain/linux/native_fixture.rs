use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::super::{ExecutionDomainError, FailureCategory, Stage};
use super::cleanup::IdMapSpec;

pub(super) struct NativePrerequisites {
    root: PathBuf,
    cgroup: PathBuf,
    binary: PathBuf,
    _map: IdMapSpec,
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
            _map: map,
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

// The existing private builder cannot yet receive a pinned cleanup-worker
// executable/helper capability. A successful preflight is not permission to
// start a domain that the fixture cannot safely tear down.
pub(super) struct NativeDomainFixture;

impl NativeDomainFixture {
    pub(super) async fn prepare() -> Result<Self, ExecutionDomainError> {
        let prerequisites = NativePrerequisites::from_environment()?;
        let _ = (
            prerequisites.root,
            prerequisites.cgroup,
            prerequisites.binary,
        );
        Err(not_ready())
    }
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
        || fs::read_dir(path).map_err(io_error)?.next().is_some()
    {
        return Err(unavailable());
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
    let directory = fs::File::open(path).map_err(io_error)?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(unavailable());
    }
    let controllers = fs::read_to_string(path.join("cgroup.controllers")).map_err(io_error)?;
    if !["cpu", "io", "memory", "pids"].iter().all(|name| {
        controllers
            .split_ascii_whitespace()
            .any(|value| value == *name)
    }) {
        return Err(unavailable());
    }
    for name in ["cgroup.procs", "cgroup.subtree_control", "cgroup.kill"] {
        fs::OpenOptions::new()
            .write(true)
            .open(path.join(name))
            .map_err(io_error)?;
    }
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
