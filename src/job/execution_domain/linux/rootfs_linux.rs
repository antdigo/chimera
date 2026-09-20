use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{MountInput, RootfsPlan};
#[cfg(test)]
use crate::job::execution_domain::DomainPath;
use crate::job::execution_domain::{ExecutionDomainError, FailureCategory, Stage};

const SYSTEM_INPUTS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/share/zoneinfo",
    "/usr/share/locale",
    "/etc/ssl/certs/ca-certificates.crt",
];
const WRITABLE_INPUTS: &[(&str, &str)] = &[
    ("work", "/work"),
    ("tmp", "/tmp"),
    ("home", "/home/chimera"),
    ("run", "/run/chimera"),
    ("docker", "/home/chimera/.docker"),
    ("docker-data", "/var/lib/chimera/docker"),
    ("docker-exec", "/run/chimera/docker-exec"),
];
const ALIASES: &[(&str, &str)] = &[
    ("bin", "/usr/bin"),
    ("sbin", "/usr/sbin"),
    ("lib", "/usr/lib"),
    ("lib64", "/usr/lib64"),
];

// The supervisor promotes this builder with its ownership capabilities in B9.
#[cfg(test)]
pub(in crate::job::execution_domain::linux) struct ImmutableInputs {
    pub tool_cache: PathBuf,
    pub actions_cache: PathBuf,
    pub extra_tools: Vec<PathBuf>,
}

impl MountInput {
    #[cfg(test)]
    pub(in crate::job::execution_domain::linux) fn readonly(
        source: impl AsRef<Path>,
        target: &str,
    ) -> Result<Self, ExecutionDomainError> {
        Self::capture(source.as_ref(), target, true)
    }

    #[cfg(test)]
    pub(in crate::job::execution_domain::linux) fn writable(
        source: impl AsRef<Path>,
        target: &str,
    ) -> Result<Self, ExecutionDomainError> {
        Self::capture(source.as_ref(), target, false)
    }

    #[cfg(test)]
    fn capture(source: &Path, target: &str, readonly: bool) -> Result<Self, ExecutionDomainError> {
        let source = source.canonicalize().map_err(io_failure)?;
        let metadata = fs::metadata(&source).map_err(io_failure)?;
        Ok(Self {
            source,
            target: DomainPath::parse(target)?,
            readonly,
            expected_device: metadata.dev(),
            expected_inode: metadata.ino(),
        })
    }
}

impl RootfsPlan {
    #[cfg(test)]
    pub(in crate::job::execution_domain::linux) fn debian(
        inputs: &ImmutableInputs,
    ) -> Result<Self, ExecutionDomainError> {
        let mut mounts = Vec::new();
        for source in SYSTEM_INPUTS {
            if Path::new(source).try_exists().map_err(io_failure)? {
                mounts.push(MountInput::readonly(source, source)?);
            }
        }
        mounts.push(MountInput::readonly(
            &inputs.tool_cache,
            "/opt/hostedtoolcache",
        )?);
        mounts.push(MountInput::readonly(
            &inputs.actions_cache,
            "/opt/chimera-actions",
        )?);
        for source in &inputs.extra_tools {
            let name = source
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(invalid)?;
            mounts.push(MountInput::readonly(
                source,
                &format!("/opt/chimera-tools/{name}"),
            )?);
        }
        validate_inputs(&mounts)?;
        for input in &mounts {
            verify_immutable(input)?;
        }
        Ok(Self {
            inputs: mounts,
            staging_root: PathBuf::new(),
        })
    }

    #[cfg(test)]
    pub(in crate::job::execution_domain::linux) fn validate(
        &self,
    ) -> Result<(), ExecutionDomainError> {
        self.validate_for(false)
    }

    fn validate_for(&self, namespace: bool) -> Result<(), ExecutionDomainError> {
        self.validate_layout()?;
        canonical(&self.staging_root)?;
        let metadata = fs::metadata(&self.staging_root).map_err(io_failure)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || fs::read_dir(&self.staging_root)
                .map_err(io_failure)?
                .next()
                .is_some()
        {
            return Err(invalid());
        }
        for input in &self.inputs {
            let metadata = checked_metadata(input)?;
            if input.readonly {
                if !namespace {
                    verify_immutable(input)?;
                }
            } else if input.target.as_str() == "/sys/fs/cgroup" {
                let fd = open_path(&input.source)?;
                let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
                checked(unsafe { libc::fstatfs(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
                if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
                    return Err(invalid());
                }
            } else if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(in crate::job::execution_domain::linux) fn validate_layout(
        &self,
    ) -> Result<(), ExecutionDomainError> {
        validate_inputs(&self.inputs)?;
        let attempt = self.staging_root.parent().ok_or_else(invalid)?;
        let component = attempt
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(invalid)?;
        if self
            .staging_root
            .file_name()
            .is_none_or(|name| name != "rootfs")
            || component.len() != 32
            || !component
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || component.bytes().all(|b| b == b'0')
            || attempt
                .parent()
                .and_then(Path::file_name)
                .is_none_or(|name| name != "active")
        {
            return Err(invalid());
        }
        let active = attempt.parent().ok_or_else(invalid)?;
        for input in &self.inputs {
            if input.readonly {
                if input.source.starts_with(active) || active.starts_with(&input.source) {
                    return Err(invalid());
                }
            } else if input.target.as_str() == "/sys/fs/cgroup" {
                if !input.source.starts_with("/sys/fs/cgroup")
                    || input.source.file_name().is_none_or(|name| name != "domain")
                    || input
                        .source
                        .parent()
                        .and_then(Path::file_name)
                        .is_none_or(|name| name != format!("attempt-{component}").as_str())
                {
                    return Err(invalid());
                }
            } else {
                let (name, _) = WRITABLE_INPUTS
                    .iter()
                    .find(|(_, target)| *target == input.target.as_str())
                    .ok_or_else(invalid)?;
                if input.source != attempt.join(name) {
                    return Err(invalid());
                }
            }
        }
        for target in [
            "/usr/bin",
            "/usr/lib",
            "/opt/hostedtoolcache",
            "/opt/chimera-actions",
            "/sys/fs/cgroup",
        ]
        .into_iter()
        .chain(WRITABLE_INPUTS.iter().map(|(_, target)| *target))
        {
            if !self.inputs.iter().any(|i| i.target.as_str() == target) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub(in crate::job::execution_domain::linux) fn validate_inputs(
    inputs: &[MountInput],
) -> Result<(), ExecutionDomainError> {
    let mut targets = BTreeSet::new();
    for input in inputs {
        let target = input.target.as_str();
        if !targets.insert(target) || !input.source.is_absolute() {
            return Err(invalid());
        }
        let broad = [
            "/",
            "/usr",
            "/usr/local",
            "/home",
            "/root",
            "/run",
            "/var",
            "/var/run",
            "/etc",
            "/dev",
            "/sys",
            "/proc",
        ];
        if broad.iter().any(|s| input.source == Path::new(s)) {
            return Err(invalid());
        }
        if input.readonly {
            let system = SYSTEM_INPUTS.contains(&target) && input.source == Path::new(target);
            let cache = matches!(target, "/opt/hostedtoolcache" | "/opt/chimera-actions");
            let extra = Path::new(target).parent() == Some(Path::new("/opt/chimera-tools"));
            if !system && !cache && !extra {
                return Err(invalid());
            }
            // A fixed system root cannot be repurposed as an arbitrary cache/tool export.
            if !system && SYSTEM_INPUTS.iter().any(|s| input.source == Path::new(s)) {
                return Err(invalid());
            }
        } else if !WRITABLE_INPUTS.iter().any(|(_, path)| *path == target)
            && target != "/sys/fs/cgroup"
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(in crate::job::execution_domain::linux) fn generated_etc(
    hostname: &str,
) -> Result<BTreeMap<String, Vec<u8>>, ExecutionDomainError> {
    if hostname.is_empty()
        || hostname.len() > 63
        || !hostname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(invalid());
    }
    Ok(BTreeMap::from([
        (
            "passwd".into(),
            b"root:x:0:0:root:/home/chimera:/bin/sh\n".to_vec(),
        ),
        ("group".into(), b"root:x:0:\n".to_vec()),
        (
            "nsswitch.conf".into(),
            b"passwd: files\ngroup: files\nhosts: files dns\n".to_vec(),
        ),
        (
            "hosts".into(),
            format!("127.0.0.1 localhost {hostname}\n::1 localhost\n").into_bytes(),
        ),
        ("hostname".into(), format!("{hostname}\n").into_bytes()),
    ]))
}

pub(in crate::job::execution_domain::linux) fn verify_immutable(
    input: &MountInput,
) -> Result<(), ExecutionDomainError> {
    let root = checked_metadata(input)?;
    let mut pending = vec![input.source.clone()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(io_failure)?;
        if metadata.file_type().is_symlink() {
            // System symlinks are interpreted after pivot, so links into omitted
            // host /etc remain absent. In particular Debian's lib/ssl/private
            // must not cause that host directory to become an exported input.
            if SYSTEM_INPUTS.contains(&input.target.as_str()) {
                continue;
            }
            let resolved = path.canonicalize().map_err(io_failure)?;
            if !resolved.starts_with(&input.source) {
                return Err(invalid());
            }
            continue;
        }
        if !metadata.is_dir() && !metadata.is_file()
            || metadata.dev() != root.dev()
            || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
            || metadata.mode() & 0o022 != 0
            || metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o200 != 0
        {
            return Err(invalid());
        }
        if metadata.is_dir() {
            for child in fs::read_dir(path).map_err(io_failure)? {
                pending.push(child.map_err(io_failure)?.path());
            }
        }
    }
    checked_metadata(input)?;
    Ok(())
}

fn canonical(path: &Path) -> Result<(), ExecutionDomainError> {
    if path.canonicalize().map_err(io_failure)? != path {
        return Err(invalid());
    }
    Ok(())
}
fn checked_metadata(input: &MountInput) -> Result<fs::Metadata, ExecutionDomainError> {
    canonical(&input.source)?;
    let metadata = fs::symlink_metadata(&input.source).map_err(io_failure)?;
    if metadata.dev() != input.expected_device || metadata.ino() != input.expected_inode {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    Ok(metadata)
}
fn cpath(path: &Path) -> Result<CString, ExecutionDomainError> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| invalid())
}
fn open_path(path: &Path) -> Result<OwnedFd, ExecutionDomainError> {
    let path = cpath(path)?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if fd < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
fn checked(result: i32) -> Result<(), ExecutionDomainError> {
    if result < 0 {
        Err(io_failure(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
fn invalid() -> ExecutionDomainError {
    failure(FailureCategory::InvalidInput)
}
fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Rootfs,
        category,
        errno: None,
    }
}
fn io_failure(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Rootfs,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

pub(in crate::job::execution_domain::linux) struct RootfsProof {
    _private: (),
}

struct MountLine {
    root: PathBuf,
    target: PathBuf,
    filesystem: String,
    options: BTreeSet<String>,
    propagation: bool,
}

pub(in crate::job::execution_domain::linux) struct ExpectedMount {
    pub target: PathBuf,
    pub root: PathBuf,
    pub filesystem: String,
    pub readonly: bool,
    pub nodev: bool,
    pub noexec: bool,
}

fn unescape_mount(value: &str) -> Result<PathBuf, ExecutionDomainError> {
    let mut bytes = Vec::new();
    let mut remaining = value.as_bytes();
    while let Some((&first, rest)) = remaining.split_first() {
        if first != b'\\' {
            bytes.push(first);
            remaining = rest;
            continue;
        }
        if rest.len() < 3 || !rest[..3].iter().all(|b| (b'0'..=b'7').contains(b)) {
            return Err(invalid());
        }
        let byte = (rest[0] - b'0') * 64 + (rest[1] - b'0') * 8 + rest[2] - b'0';
        if !matches!(byte, b' ' | b'\t' | b'\n' | b'\\') {
            return Err(invalid());
        }
        bytes.push(byte);
        remaining = &rest[3..];
    }
    use std::os::unix::ffi::OsStringExt;
    Ok(std::ffi::OsString::from_vec(bytes).into())
}

fn parse_mountinfo(text: &str) -> Result<Vec<MountLine>, ExecutionDomainError> {
    text.lines()
        .map(|line| {
            let (left, right) = line.split_once(" - ").ok_or_else(invalid)?;
            let left: Vec<_> = left.split_whitespace().collect();
            let right: Vec<_> = right.split_whitespace().collect();
            if left.len() < 6 || right.len() != 3 {
                return Err(invalid());
            }
            Ok(MountLine {
                root: unescape_mount(left[3])?,
                target: unescape_mount(left[4])?,
                filesystem: right[0].into(),
                options: left[5].split(',').map(str::to_owned).collect(),
                propagation: left[6..].iter().any(|s| {
                    s.starts_with("shared:")
                        || s.starts_with("master:")
                        || s.starts_with("propagate_from:")
                }),
            })
        })
        .collect()
}

pub(in crate::job::execution_domain::linux) fn verify_mountinfo(
    text: &str,
    expected: &[ExpectedMount],
) -> Result<(), ExecutionDomainError> {
    let actual = parse_mountinfo(text)?;
    if actual.len() != expected.len() {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    let mut seen = BTreeSet::new();
    for line in actual {
        let expected = expected
            .iter()
            .find(|e| e.target == line.target)
            .ok_or_else(invalid)?;
        if !seen.insert(line.target)
            || line.propagation
            || line.root != expected.root
            || line.filesystem != expected.filesystem
            || !line.options.contains("nosuid")
            || expected.readonly && !line.options.contains("ro")
            || !expected.readonly && !line.options.contains("rw")
            || expected.nodev && !line.options.contains("nodev")
            || expected.noexec && !line.options.contains("noexec")
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
    }
    Ok(())
}

fn expected_bind(
    source: &Path,
    target: &Path,
    readonly: bool,
    nodev: bool,
    host_mounts: &[MountLine],
) -> Result<Vec<ExpectedMount>, ExecutionDomainError> {
    let covering = host_mounts
        .iter()
        .filter(|m| source.starts_with(&m.target))
        .max_by_key(|m| m.target.components().count())
        .ok_or_else(invalid)?;
    let root = covering.root.join(
        source
            .strip_prefix(&covering.target)
            .map_err(|_| invalid())?,
    );
    let result = vec![ExpectedMount {
        target: target.into(),
        root,
        filesystem: covering.filesystem.clone(),
        readonly,
        nodev,
        noexec: false,
    }];
    if host_mounts
        .iter()
        .any(|m| m.target != source && m.target.starts_with(source))
    {
        // No host mount below an immutable input may import another host subtree.
        // Fail closed instead of treating recursive readonly as an export allowlist.
        return Err(invalid());
    }
    Ok(result)
}

fn mounted(
    target: &str,
    filesystem: &str,
    readonly: bool,
    nodev: bool,
    noexec: bool,
) -> ExpectedMount {
    ExpectedMount {
        target: target.into(),
        root: "/".into(),
        filesystem: filesystem.into(),
        readonly,
        nodev,
        noexec,
    }
}

pub(in crate::job::execution_domain::linux) fn assemble_and_pivot(
    plan: &RootfsPlan,
    control: BorrowedFd<'_>,
    hostname: &str,
) -> Result<RootfsProof, ExecutionDomainError> {
    // This function must never mutate a supervisor's namespace or run after Tokio.
    if unsafe { libc::getpid() } != 1
        || fs::read_dir("/proc/self/task").map_err(io_failure)?.count() != 1
    {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    let mount_namespace = fs::metadata("/proc/self/ns/mnt").map_err(io_failure)?.ino();
    if mount_namespace == fs::metadata("/proc/1/ns/mnt").map_err(io_failure)?.ino() {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    let pid_namespace = fs::metadata("/proc/self/ns/pid").map_err(io_failure)?.ino();
    let control_copy = super::super::launcher::duplicate_control(control)?;
    drop(control_copy);
    plan.validate_for(true)?;
    let etc = generated_etc(hostname)?;
    let host_mounts =
        parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").map_err(io_failure)?)?;
    let mut expected = vec![mounted("/", "tmpfs", true, true, false)];
    let mut pinned = Vec::new();
    for input in &plan.inputs {
        let fd = open_path(&input.source)?;
        let metadata =
            fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(io_failure)?;
        if metadata.dev() != input.expected_device || metadata.ino() != input.expected_inode {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        expected.extend(expected_bind(
            &input.source,
            Path::new(input.target.as_str()),
            input.readonly,
            true,
            &host_mounts,
        )?);
        pinned.push((input, fd, metadata.is_dir()));
    }
    let mut aliases = Vec::new();
    for &(alias, target) in ALIASES {
        let path = PathBuf::from(format!("/{alias}"));
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && path.canonicalize().map_err(io_failure)? == Path::new(target)
                    && plan.inputs.iter().any(|i| i.target.as_str() == target) =>
            {
                aliases.push((alias, target))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(invalid()),
        }
    }
    checked_mount_private_recursive()?;
    mount(
        None,
        &plan.staging_root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=0755"),
    )?;
    for (input, fd, directory) in &pinned {
        let target = plan
            .staging_root
            .join(input.target.as_str().trim_start_matches('/'));
        create_target(&target, *directory)?;
        mount(
            Some(&PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))),
            &target,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )?;
        mount_attributes(&target, input.readonly, true, false, true)?;
    }
    // No source descriptor may survive pivot_root, even when it refers to a readonly input.
    drop(pinned);
    for (alias, target) in aliases {
        std::os::unix::fs::symlink(target, plan.staging_root.join(alias)).map_err(io_failure)?;
    }
    let etc_path = plan.staging_root.join("etc");
    fs::create_dir_all(&etc_path).map_err(io_failure)?;
    for (name, bytes) in etc {
        fs::write(etc_path.join(name), bytes).map_err(io_failure)?;
    }
    checked(unsafe { libc::sethostname(hostname.as_ptr().cast(), hostname.len()) })?;
    // Only private attempt backing directories have their modes changed.
    for (target, mode) in [
        ("tmp", 0o1777),
        ("home/chimera", 0o700),
        ("run/chimera", 0o700),
    ] {
        fs::set_permissions(
            plan.staging_root.join(target),
            fs::Permissions::from_mode(mode),
        )
        .map_err(io_failure)?;
    }
    mount_proc_dev_sys(plan, &host_mounts, &mut expected)?;
    create_oldroot_directory(&plan.staging_root)?;
    checked_chdir_to_new_root(&plan.staging_root)?;
    checked_pivot_root()?;
    checked_chdir_root()?;
    checked_umount_oldroot()?;
    checked_rmdir_oldroot()?;
    // The tmpfs root and generated /etc are immutable, while each explicit writable
    // bind retains its own mount flags. A recursive root remount would break those.
    mount_attributes(Path::new("/"), true, true, false, false)?;
    close_oldroot_descriptors(control.as_raw_fd())?;
    verify_private_mountinfo(
        &expected,
        mount_namespace,
        pid_namespace,
        control.as_raw_fd(),
    )?;
    Ok(RootfsProof { _private: () })
}

fn mount(
    source: Option<&Path>,
    target: &Path,
    filesystem: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), ExecutionDomainError> {
    let source = source.map(cpath).transpose()?;
    let target = cpath(target)?;
    let filesystem = filesystem
        .map(|s| CString::new(s).map_err(|_| invalid()))
        .transpose()?;
    let data = data
        .map(|s| CString::new(s).map_err(|_| invalid()))
        .transpose()?;
    checked(unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            filesystem.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    })
}

fn mount_attributes(
    path: &Path,
    readonly: bool,
    nodev: bool,
    noexec: bool,
    recursive: bool,
) -> Result<(), ExecutionDomainError> {
    let path = cpath(path)?;
    let mut attributes: libc::mount_attr = unsafe { std::mem::zeroed() };
    attributes.attr_set = libc::MOUNT_ATTR_NOSUID;
    if readonly {
        attributes.attr_set |= libc::MOUNT_ATTR_RDONLY;
    }
    if nodev {
        attributes.attr_set |= libc::MOUNT_ATTR_NODEV;
    }
    if noexec {
        attributes.attr_set |= libc::MOUNT_ATTR_NOEXEC;
    }
    // No top-level remount fallback: nested mounts must receive the same policy.
    checked(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path.as_ptr(),
            if recursive { libc::AT_RECURSIVE } else { 0 },
            &attributes,
            std::mem::size_of_val(&attributes),
        ) as i32
    })
}

fn create_target(path: &Path, directory: bool) -> Result<(), ExecutionDomainError> {
    if directory {
        fs::create_dir_all(path).map_err(io_failure)
    } else {
        fs::create_dir_all(path.parent().ok_or_else(invalid)?).map_err(io_failure)?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io_failure)?;
        Ok(())
    }
}

fn checked_mount_private_recursive() -> Result<(), ExecutionDomainError> {
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )
}
fn create_oldroot_directory(root: &Path) -> Result<(), ExecutionDomainError> {
    fs::create_dir(root.join(".oldroot")).map_err(io_failure)
}
fn checked_chdir_to_new_root(root: &Path) -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::chdir(cpath(root)?.as_ptr()) })
}
fn checked_pivot_root() -> Result<(), ExecutionDomainError> {
    checked(unsafe {
        libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".oldroot".as_ptr()) as i32
    })
}
fn checked_chdir_root() -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::chdir(c"/".as_ptr()) })
}
fn checked_umount_oldroot() -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH) })
}
fn checked_rmdir_oldroot() -> Result<(), ExecutionDomainError> {
    checked(unsafe { libc::rmdir(c"/.oldroot".as_ptr()) })
}

fn mount_proc_dev_sys(
    plan: &RootfsPlan,
    host_mounts: &[MountLine],
    expected: &mut Vec<ExpectedMount>,
) -> Result<(), ExecutionDomainError> {
    let root = &plan.staging_root;
    create_target(&root.join("proc"), true)?;
    mount(
        None,
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    expected.push(mounted("/proc", "proc", false, true, true));
    create_target(&root.join("dev"), true)?;
    mount(
        None,
        &root.join("dev"),
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("mode=0755"),
    )?;
    expected.push(mounted("/dev", "tmpfs", true, false, true));
    for device in ["null", "zero", "full", "random", "urandom"] {
        let source = PathBuf::from(format!("/dev/{device}"));
        let target = root.join(format!("dev/{device}"));
        create_target(&target, false)?;
        let metadata = fs::metadata(&source).map_err(io_failure)?;
        let minor = match device {
            "null" => 3,
            "zero" => 5,
            "full" => 7,
            "random" => 8,
            "urandom" => 9,
            _ => return Err(invalid()),
        };
        if metadata.mode() & libc::S_IFMT != libc::S_IFCHR
            || libc::major(metadata.rdev()) != 1
            || libc::minor(metadata.rdev()) != minor
        {
            return Err(invalid());
        }
        let fd = open_path(&source)?;
        mount(
            Some(&PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))),
            &target,
            None,
            libc::MS_BIND,
            None,
        )?;
        mount_attributes(&target, false, false, true, false)?;
        let mut item = expected_bind(
            &source,
            &PathBuf::from(format!("/dev/{device}")),
            false,
            false,
            host_mounts,
        )?;
        item[0].noexec = true;
        expected.extend(item);
    }
    create_target(&root.join("dev/pts"), true)?;
    mount(
        None,
        &root.join("dev/pts"),
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )?;
    expected.push(mounted("/dev/pts", "devpts", false, false, true));
    create_target(&root.join("dev/shm"), true)?;
    mount(
        None,
        &root.join("dev/shm"),
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("mode=1777"),
    )?;
    expected.push(mounted("/dev/shm", "tmpfs", false, true, true));
    for (name, target) in [
        ("ptmx", "pts/ptmx"),
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        std::os::unix::fs::symlink(target, root.join("dev").join(name)).map_err(io_failure)?;
    }
    for relative in [
        "proc/sys",
        "proc/sysrq-trigger",
        "proc/kcore",
        "proc/keys",
        "proc/timer_list",
        "proc/acpi",
        "proc/scsi",
    ] {
        let target = root.join(relative);
        match fs::metadata(&target) {
            Ok(metadata) if metadata.is_dir() => {
                mount(
                    None,
                    &target,
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    Some("mode=000"),
                )?;
                mount_attributes(&target, true, true, true, true)?;
                expected.push(mounted(&format!("/{relative}"), "tmpfs", true, true, true));
            }
            Ok(_) => {
                mount(
                    Some(&root.join("dev/null")),
                    &target,
                    None,
                    libc::MS_BIND,
                    None,
                )?;
                mount_attributes(&target, true, true, true, true)?;
                let mut item = expected_bind(
                    Path::new("/dev/null"),
                    &PathBuf::from(format!("/{relative}")),
                    true,
                    true,
                    host_mounts,
                )?;
                item[0].noexec = true;
                expected.extend(item);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_failure(error)),
        }
    }
    // /sys is only generated directories plus the already-bound exact domain subtree.
    // The enclosing root mount is made readonly after pivot.
    mount_attributes(&root.join("dev"), true, false, true, false)?;
    Ok(())
}

fn close_oldroot_descriptors(control: RawFd) -> Result<(), ExecutionDomainError> {
    // RootlessKit output is deliberately discarded; reopen stdio from the new /dev.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if null < 0 {
        return Err(io_failure(io::Error::last_os_error()));
    }
    let null = unsafe { OwnedFd::from_raw_fd(null) };
    for fd in 0..=2 {
        checked(unsafe { libc::dup2(null.as_raw_fd(), fd) })?;
    }
    drop(null);
    if control < 3 {
        return Err(invalid());
    }
    if control > 3 {
        checked(unsafe {
            libc::syscall(libc::SYS_close_range, 3u32, (control - 1) as u32, 0u32) as i32
        })?;
    }
    checked(unsafe {
        libc::syscall(libc::SYS_close_range, (control + 1) as u32, u32::MAX, 0u32) as i32
    })?;
    checked(unsafe { libc::fcntl(control, libc::F_SETFD, libc::FD_CLOEXEC) })
}

fn verify_private_mountinfo(
    expected: &[ExpectedMount],
    mount_namespace: u64,
    pid_namespace: u64,
    control: RawFd,
) -> Result<(), ExecutionDomainError> {
    verify_mountinfo(
        &fs::read_to_string("/proc/self/mountinfo").map_err(io_failure)?,
        expected,
    )?;
    for (kind, expected) in [("mnt", mount_namespace), ("pid", pid_namespace)] {
        for process in ["self", "1"] {
            if fs::metadata(format!("/proc/{process}/ns/{kind}"))
                .map_err(io_failure)?
                .ino()
                != expected
            {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
        }
    }
    if fs::read_link("/proc/self/cwd").map_err(io_failure)? != Path::new("/")
        || fs::read_link("/proc/1/root").map_err(io_failure)? != Path::new("/")
        || Path::new("/.oldroot").try_exists().map_err(io_failure)?
    {
        return Err(invalid());
    }
    let fds: Vec<_> = fs::read_dir("/proc/self/fd")
        .map_err(io_failure)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<io::Result<_>>()
        .map_err(io_failure)?;
    for name in fds {
        let fd: i32 = name
            .to_str()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        // read_dir's descriptor has already been closed.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
        {
            continue;
        }
        if fd > 2 && fd != control {
            return Err(invalid());
        }
        if fd <= 2
            && fs::read_link(format!("/proc/self/fd/{fd}")).map_err(io_failure)?
                != Path::new("/dev/null")
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "rootfs_native_test.rs"]
mod native_test;
