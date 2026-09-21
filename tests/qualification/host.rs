//! E0 owns only preflight storage and reports. No native workload is launched.
#![allow(dead_code)] // Native entrypoints are consumed by Task 8.
use super::catalog::{Reason, validate_coverage};
use super::report::{EvidenceMode, QualificationReport, Verdict, valid_identity, write_report_at};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

const LOCK: &str = "/run/lock/chimera-qualification.lock";
const MARKER: &str = "/run/lock/chimera-qualification.active";
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    pub root: PathBuf,
    pub driver: PathBuf,
    pub report_root: PathBuf,
    pub lock_file: PathBuf,
    pub active_marker: PathBuf,
    pub max_case_ms: u64,
    pub cleanup_deadline_ms: u64,
    pub production_sentinel: SocketAddr,
    pub negative_sentinels: Vec<NegativeSentinel>,
    pub public_registry_url: String,
    pub sentinel_p99_ms: u64,
    pub execution_resources: chimera::config::resources::ExecutionResources,
    pub minimum_production_memory_bytes: u64,
    pub maximum_chimera_memory_bytes: u64,
    pub maximum_chimera_pids: u64,
    pub max_parallel_builds: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum SentinelRole {
    Loopback,
    Host,
    Lan,
    Production,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeSentinel {
    pub role: SentinelRole,
    pub address: SocketAddr,
    pub denied_prefix: String,
}

impl NativeConfig {
    pub fn validate(&self) -> Result<(), Reason> {
        if self.lock_file.as_os_str() != Path::new(LOCK).as_os_str()
            || self.active_marker.as_os_str() != Path::new(MARKER).as_os_str()
            || [
                self.max_case_ms,
                self.cleanup_deadline_ms,
                self.sentinel_p99_ms,
                self.minimum_production_memory_bytes,
                self.maximum_chimera_memory_bytes,
                self.maximum_chimera_pids,
            ]
            .contains(&0)
            || self.cleanup_deadline_ms > self.max_case_ms
            || !(1..=40).contains(&self.max_parallel_builds)
            || !endpoint_valid(self.production_sentinel)
        {
            return Err(Reason::InvalidConfig);
        }
        self.execution_resources
            .global
            .validate()
            .map_err(|_| Reason::InvalidConfig)?;
        self.execution_resources
            .attempt
            .validate()
            .map_err(|_| Reason::InvalidConfig)?;
        let roles: BTreeSet<_> = self.negative_sentinels.iter().map(|s| s.role).collect();
        if roles.len() != 4 || self.negative_sentinels.len() > 128 {
            return Err(Reason::InvalidConfig);
        }
        let mut endpoints = BTreeSet::new();
        for sentinel in &self.negative_sentinels {
            if !endpoint_valid(sentinel.address)
                || sentinel.address == self.production_sentinel
                || !endpoints.insert(sentinel.address)
                || !prefix_contains(&sentinel.denied_prefix, sentinel.address.ip())
                || (sentinel.role == SentinelRole::Loopback && !sentinel.address.ip().is_loopback())
            {
                return Err(Reason::InvalidConfig);
            }
        }
        let url =
            reqwest::Url::parse(&self.public_registry_url).map_err(|_| Reason::InvalidConfig)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self
                .public_registry_url
                .split_once("://")
                .is_none_or(|(_, rest)| {
                    rest.split(['/', '?', '#'])
                        .next()
                        .is_none_or(|authority| authority.contains('@'))
                })
        {
            return Err(Reason::InvalidConfig);
        }
        Ok(())
    }
    /// Hash effective production limits, so equivalent byte spellings agree.
    pub fn digest(&self) -> Result<String, Reason> {
        self.validate()?;
        let mut value = serde_json::to_value(self).map_err(|_| Reason::InvalidConfig)?;
        value["execution_resources"] = serde_json::json!({
            "global": self.execution_resources.global.validate().map_err(|_| Reason::InvalidConfig)?.writes(),
            "attempt": self.execution_resources.attempt.validate().map_err(|_| Reason::InvalidConfig)?.writes(),
        });
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&value).map_err(|_| Reason::InvalidConfig)?)
        ))
    }
}
fn endpoint_valid(address: SocketAddr) -> bool {
    address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast()
}
fn prefix_contains(prefix: &str, address: IpAddr) -> bool {
    let Some((network, bits)) = prefix.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(bits)) = (network.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(network) & !mask == 0 && u32::from(address) & mask == u32::from(network)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(network) & !mask == 0 && u128::from(address) & mask == u128::from(network)
        }
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}
fn identity(file: &File) -> Result<DirectoryIdentity, Reason> {
    let metadata = file.metadata().map_err(|_| Reason::InvalidConfig)?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorIdentity {
    pid: u32,
    start_ticks: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveMarker {
    run_id: uuid::Uuid,
    boot_id: uuid::Uuid,
    supervisor: SupervisorIdentity,
    cgroup: Option<DirectoryIdentity>,
    report_directory: DirectoryIdentity,
}

pub struct NativeLease {
    lock: File,
    run_directory: PathBuf,
    marker: File,
    lock_parent: File,
    marker_name: CString,
    marker_bytes: Vec<u8>,
    report_directory: File,
    run_id: uuid::Uuid,
    boot_id: uuid::Uuid,
    config_digest: String,
    supervisor_pid: u32,
    mode: EvidenceMode,
    report_chain: PinnedChain,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationStage {
    BeforeWrite,
    AfterWrite,
    BeforeClaim,
    AfterClaim,
}
impl NativeLease {
    pub fn run_directory(&self) -> &Path {
        &self.run_directory
    }
    /// The only E0 release path: a complete blocked report and no runtime activity.
    /// Dropping this lease, including on error, deliberately preserves the marker.
    pub fn publish_blocked_and_release(self, report: &QualificationReport) -> Result<(), Reason> {
        self.publish_with_hook(report, |_| {})
    }
    pub(super) fn publish_with_hook(
        self,
        report: &QualificationReport,
        mut hook: impl FnMut(PublicationStage),
    ) -> Result<(), Reason> {
        let valid = std::process::id() == self.supervisor_pid
            && report.schema_version == 1
            && !report.activation_available
            && report.cleanup_confirmed
            && report.driver_digest.is_empty()
            && valid_identity(&report.identity)
            && report.identity.run_id == self.run_id
            && report.identity.host_boot_id == self.boot_id
            && report.identity.mode == self.mode
            && report.identity.config_digest == self.config_digest
            && validate_coverage(&report.results).is_ok()
            && report.results.iter().all(|row| {
                row.verdict == Verdict::Blocked
                    && row.reason.is_some()
                    && row.checks.is_empty()
                    && row.provenance.identity == report.identity
                    && row.provenance.key == row.key
                    && row.provenance.driver_commit == report.identity.commit
                    && row.provenance.driver_digest.is_empty()
            });
        hook(PublicationStage::BeforeWrite);
        if !valid || !self.marker_matches() || !self.report_chain.unchanged() {
            return Err(Reason::CleanupUnconfirmed);
        }
        write_report_at(&self.report_directory, report).map_err(|_| Reason::CleanupUnconfirmed)?;
        hook(PublicationStage::AfterWrite);
        if !self.marker_matches() || !self.report_chain.unchanged() {
            return Err(Reason::CleanupUnconfirmed);
        }
        hook(PublicationStage::BeforeClaim);
        if !self.report_chain.unchanged() {
            return Err(Reason::CleanupUnconfirmed);
        }
        // The durable fixed guard closes the crash gap when the active name is
        // moved away. Never unlink by a previously checked shared pathname.
        let claim_name = sibling_name(&self.marker_name, ".claim");
        if unsafe { libc::mkdirat(self.lock_parent.as_raw_fd(), claim_name.as_ptr(), 0o700) } != 0 {
            return Err(Reason::CleanupUnconfirmed);
        }
        let claim = open_at(
            &self.lock_parent,
            &claim_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .map_err(|_| Reason::CleanupUnconfirmed)?;
        claim
            .sync_all()
            .and_then(|_| self.lock_parent.sync_all())
            .map_err(|_| Reason::CleanupUnconfirmed)?;
        let claimed_name = CString::new("marker").unwrap();
        // Destination is in a newly created 0700 owned directory. A replacement
        // at the active name is moved intact, then compared, never deleted.
        if unsafe {
            libc::renameat(
                self.lock_parent.as_raw_fd(),
                self.marker_name.as_ptr(),
                claim.as_raw_fd(),
                claimed_name.as_ptr(),
            )
        } != 0
        {
            return Err(Reason::CleanupUnconfirmed);
        }
        claim
            .sync_all()
            .and_then(|_| self.lock_parent.sync_all())
            .map_err(|_| Reason::CleanupUnconfirmed)?;
        hook(PublicationStage::AfterClaim);
        if !self.marker_matches_at(&claim, &claimed_name)
            || !self.report_chain.unchanged()
            || absent_entry(&self.lock_parent, &self.marker_name).is_err()
            || !entry_matches(&self.lock_parent, &claim_name, &claim)
        {
            return Err(Reason::CleanupUnconfirmed);
        }
        let completed_name =
            sibling_name(&self.marker_name, &format!(".completed.{}", self.run_id));
        // Keep the claimed inode as an audit record. Atomic no-replace rename
        // cannot overwrite an unexpected completed record, unlike precheck+rename.
        rename_no_replace(&self.lock_parent, &claim_name, &completed_name)?;
        self.lock_parent
            .sync_all()
            .map_err(|_| Reason::CleanupUnconfirmed)
    }
    fn marker_matches(&self) -> bool {
        self.marker_matches_at(&self.lock_parent, &self.marker_name)
    }
    fn marker_matches_at(&self, parent: &File, name: &CString) -> bool {
        if !entry_matches(parent, name, &self.marker) {
            return false;
        }
        let Ok(metadata) = self.marker.metadata() else {
            return false;
        };
        if metadata.len() != self.marker_bytes.len() as u64
            || metadata.nlink() != 1
            || metadata.uid() != uid()
            || metadata.mode() & 0o7777 != 0o600
        {
            return false;
        }
        let mut bytes = vec![0; self.marker_bytes.len()];
        self.marker.read_exact_at(&mut bytes, 0).is_ok() && bytes == self.marker_bytes
    }
}

fn sibling_name(name: &CString, suffix: &str) -> CString {
    let mut bytes = name.as_bytes().to_vec();
    bytes.extend_from_slice(suffix.as_bytes());
    CString::new(bytes).expect("fixed suffix contains no NUL")
}
fn rename_no_replace(parent: &File, from: &CString, to: &CString) -> Result<(), Reason> {
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let result = -1;
    if result == 0 {
        Ok(())
    } else {
        Err(Reason::CleanupUnconfirmed)
    }
}

struct PinnedEdge {
    parent: File,
    name: CString,
    child: File,
}
struct PinnedChain {
    edges: Vec<PinnedEdge>,
}
impl PinnedChain {
    fn capture(path: &Path) -> Result<Self, Reason> {
        if !normalized(path) {
            return Err(Reason::InvalidConfig);
        }
        let mut parent = directory(Path::new("/"))?;
        let mut edges = Vec::new();
        for component in path.components() {
            if let Component::Normal(part) = component {
                let name = CString::new(part.as_bytes()).map_err(|_| Reason::InvalidConfig)?;
                let child = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                let next = child.try_clone().map_err(|_| Reason::InvalidConfig)?;
                edges.push(PinnedEdge {
                    parent,
                    name,
                    child,
                });
                parent = next;
            }
        }
        let chain = Self { edges };
        if chain.unchanged() {
            Ok(chain)
        } else {
            Err(Reason::InvalidConfig)
        }
    }
    fn unchanged(&self) -> bool {
        self.edges.iter().all(|edge| {
            let (Ok(parent), Ok(child)) = (edge.parent.metadata(), edge.child.metadata()) else {
                return false;
            };
            // POSIX provides no atomic transaction across an ancestry chain.
            // Exclude untrusted writers; the service UID and root must honor
            // the held qualification lock and not mutate this ancestry.
            let protected_parent = parent.mode() & 0o022 == 0
                || (parent.uid() == 0 && parent.mode() & u32::from(libc::S_ISVTX) != 0);
            let protected_child = child.mode() & 0o022 == 0
                || (child.uid() == 0 && child.mode() & u32::from(libc::S_ISVTX) != 0);
            [0, uid()].contains(&parent.uid())
                && [0, uid()].contains(&child.uid())
                && protected_parent
                && protected_child
                && entry_matches(&edge.parent, &edge.name, &edge.child)
        })
    }
    fn ends_at(&self, directory: &File) -> bool {
        self.edges
            .last()
            .is_some_and(|edge| identity(&edge.child).ok() == identity(directory).ok())
    }
}
#[derive(Debug)]
pub struct HostSnapshot {
    pub boot_id: uuid::Uuid,
    pub kernel: String,
    pub systemd_version: String,
    pub cgroup_v2: bool,
    pub container: bool,
    pub service_uid: u32,
    pub service_name: String,
}
pub fn inspect_host() -> Result<HostSnapshot, Reason> {
    if !cfg!(target_os = "linux") {
        return Err(Reason::PlatformUnsupported);
    }
    fn read(path: &str) -> Result<String, Reason> {
        std::fs::read_to_string(path).map_err(|_| Reason::MissingEvidence)
    }
    let release = read("/etc/os-release")?;
    let pid1 = read("/proc/1/comm")?;
    let mountinfo = read("/proc/self/mountinfo")?;
    let init_cgroup = read("/proc/1/cgroup")?;
    let self_cgroup = read("/proc/self/cgroup")?;
    if !release
        .lines()
        .any(|line| line == "ID=debian" || line == "ID=\"debian\"")
        || pid1.trim() != "systemd"
        || uid() == 0
        || !mountinfo
            .lines()
            .any(|line| line.contains(" /sys/fs/cgroup ") && line.contains(" - cgroup2 "))
        || mountinfo.lines().any(|line| line.contains(" - cgroup "))
        || !init_cgroup.trim().starts_with("0::")
        || !self_cgroup.trim().starts_with("0::")
        || ["docker", "kubepods", "lxc", "containerd", "libpod"]
            .iter()
            .any(|token| {
                mountinfo.contains(token)
                    || init_cgroup.contains(token)
                    || self_cgroup.contains(token)
            })
        || [
            "/.dockerenv",
            "/run/.containerenv",
            "/run/systemd/container",
        ]
        .iter()
        .any(|path| std::fs::symlink_metadata(path).is_ok())
    {
        return Err(Reason::MissingEvidence);
    }
    // E0's observation cannot qualify a release: an authenticated operator
    // manifest and actual runtime/cgroup authority remain E1 prerequisites.
    let virtualization = std::process::Command::new("/usr/bin/systemd-detect-virt")
        .env_clear()
        .output()
        .map_err(|_| Reason::MissingEvidence)?;
    if virtualization.status.code() != Some(1) || virtualization.stdout != b"none\n" {
        return Err(Reason::MissingEvidence);
    }
    let systemd = std::process::Command::new("/usr/bin/systemctl")
        .arg("--version")
        .env_clear()
        .output()
        .map_err(|_| Reason::MissingEvidence)?;
    if !systemd.status.success() {
        return Err(Reason::MissingEvidence);
    }
    let service_name = self_cgroup
        .trim()
        .split('/')
        .find(|part| part.ends_with(".service"))
        .filter(|name| {
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
        })
        .ok_or(Reason::MissingEvidence)?
        .to_owned();
    let boot_id = read("/proc/sys/kernel/random/boot_id")?
        .trim()
        .parse::<uuid::Uuid>()
        .map_err(|_| Reason::MissingEvidence)?;
    if boot_id.is_nil() {
        return Err(Reason::MissingEvidence);
    }
    Ok(HostSnapshot {
        boot_id,
        kernel: read("/proc/sys/kernel/osrelease")?.trim().into(),
        systemd_version: String::from_utf8(systemd.stdout)
            .map_err(|_| Reason::MissingEvidence)?
            .lines()
            .next()
            .ok_or(Reason::MissingEvidence)?
            .into(),
        cgroup_v2: true,
        container: false,
        service_uid: uid(),
        service_name,
    })
}

pub fn acquire_native(config: &NativeConfig, run_id: uuid::Uuid) -> Result<NativeLease, Reason> {
    config.validate()?;
    let host = inspect_host()?;
    let start_ticks = process_start_ticks()?;
    let parent = lock_parent(Path::new(LOCK), true)?;
    let lock = open_lock(&parent, &name(Path::new(LOCK))?, false)?;
    acquire(
        config,
        run_id,
        host.boot_id,
        start_ticks,
        parent,
        lock,
        name(Path::new(MARKER))?,
        EvidenceMode::NativeDebian,
    )
}
pub fn recover_unfinished(config: &NativeConfig) -> Result<(), Reason> {
    config.validate()?;
    if !cfg!(target_os = "linux") {
        return Err(Reason::PlatformUnsupported);
    }
    let parent = lock_parent(Path::new(LOCK), true)?;
    let _lock = open_lock(&parent, &name(Path::new(LOCK))?, false)?;
    absent_marker(&parent, &name(Path::new(MARKER))?)
}
fn process_start_ticks() -> Result<u64, Reason> {
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| Reason::MissingEvidence)?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|ticks| *ticks != 0)
        .ok_or(Reason::MissingEvidence)
}

fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}
fn name(path: &Path) -> Result<CString, Reason> {
    CString::new(path.file_name().ok_or(Reason::InvalidConfig)?.as_bytes())
        .map_err(|_| Reason::InvalidConfig)
}
/// Traverse with pinned no-follow handles; no pathname component may redirect us.
fn directory(path: &Path) -> Result<File, Reason> {
    if !normalized(path) {
        return Err(Reason::InvalidConfig);
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .map_err(|_| Reason::InvalidConfig)?;
    for component in path.components() {
        if let Component::Normal(part) = component {
            let part = CString::new(part.as_bytes()).map_err(|_| Reason::InvalidConfig)?;
            current = open_at(&current, &part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
    }
    Ok(current)
}
pub(super) fn private_directory(path: &Path) -> Result<File, Reason> {
    let file = directory(path)?;
    let metadata = file.metadata().map_err(|_| Reason::InvalidConfig)?;
    if metadata.uid() != uid() || metadata.mode() & 0o022 != 0 {
        return Err(Reason::InvalidConfig);
    }
    Ok(file)
}
fn open_at(parent: &File, name: &CString, flags: i32, mode: libc::mode_t) -> Result<File, Reason> {
    // SAFETY: owned parent FD and NUL-terminated single-component name; transfer
    // the returned descriptor exactly once. O_NONBLOCK also rejects FIFO hangs.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Reason::InvalidConfig);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn lock_parent(path: &Path, native: bool) -> Result<File, Reason> {
    if !normalized(path) {
        return Err(Reason::InvalidConfig);
    }
    let parent = path.parent().ok_or(Reason::InvalidConfig)?;
    if !native {
        return private_directory(parent);
    }
    if parent != Path::new("/run/lock") {
        return Err(Reason::InvalidConfig);
    }
    let file = directory(parent)?;
    let metadata = file.metadata().map_err(|_| Reason::InvalidConfig)?;
    if metadata.uid() != 0 || metadata.mode() & u32::from(libc::S_ISVTX) == 0 {
        return Err(Reason::InvalidConfig);
    }
    Ok(file)
}
fn open_lock(parent: &File, name: &CString, create: bool) -> Result<File, Reason> {
    let file = open_at(
        parent,
        name,
        libc::O_RDWR | if create { libc::O_CREAT } else { 0 },
        0o600,
    )?;
    let metadata = file.metadata().map_err(|_| Reason::InvalidConfig)?;
    if !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(Reason::InvalidConfig);
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
            Reason::HostBusy
        } else {
            Reason::InvalidConfig
        });
    }
    if !entry_matches(parent, name, &file) {
        return Err(Reason::InvalidConfig);
    }
    Ok(file)
}
fn entry_matches(parent: &File, name: &CString, file: &File) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return false;
    }
    let stat = unsafe { stat.assume_init() };
    file.metadata().is_ok_and(|metadata| {
        metadata.dev() == stat.st_dev as u64
            && metadata.ino() == stat.st_ino as u64
            && metadata.mode() == stat.st_mode as u32
    })
}
fn absent_marker(parent: &File, name: &CString) -> Result<(), Reason> {
    absent_entry(parent, name)?;
    absent_entry(parent, &sibling_name(name, ".claim"))
}
fn absent_entry(parent: &File, name: &CString) -> Result<(), Reason> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(Reason::UnfinishedRun)
    }
}
#[cfg(test)]
pub(super) fn lock_exclusive(path: &Path) -> Result<File, Reason> {
    open_lock(&lock_parent(path, false)?, &name(path)?, true)
}
#[cfg(test)]
pub(super) fn acquire_fixture(
    config: &NativeConfig,
    run_id: uuid::Uuid,
    boot: uuid::Uuid,
    lock: &Path,
    marker: &Path,
) -> Result<NativeLease, Reason> {
    if lock.parent() != marker.parent() {
        return Err(Reason::InvalidConfig);
    }
    let parent = lock_parent(lock, false)?;
    let lock = open_lock(&parent, &name(lock)?, true)?;
    // Synthetic supervisor identity is never emitted as native evidence.
    acquire(
        config,
        run_id,
        boot,
        1,
        parent,
        lock,
        name(marker)?,
        EvidenceMode::Fixture,
    )
}
#[cfg(test)]
pub(super) fn recover_fixture(lock: &Path, marker: &Path) -> Result<(), Reason> {
    if lock.parent() != marker.parent() {
        return Err(Reason::InvalidConfig);
    }
    let parent = lock_parent(lock, false)?;
    let _lock = open_lock(&parent, &name(lock)?, true)?;
    absent_marker(&parent, &name(marker)?)
}
fn safe_paths(config: &NativeConfig) -> Result<(File, File), Reason> {
    if !normalized(&config.root)
        || !normalized(&config.report_root)
        || !normalized(&config.driver)
        || [Path::new("/"), Path::new("/tmp"), Path::new("/private/tmp")]
            .contains(&config.root.as_path())
        || dirs::home_dir().is_some_and(|home| {
            config.root == home || home.canonicalize().is_ok_and(|home| config.root == home)
        })
        || config.report_root == config.root
        || !config.report_root.starts_with(&config.root)
        || config.driver.starts_with(&config.root)
    {
        return Err(Reason::InvalidConfig);
    }
    let root = private_directory(&config.root)?;
    let report = private_directory(&config.report_root)?;
    let ancestry = PinnedChain::capture(&config.report_root)?;
    if !ancestry.ends_at(&report) {
        return Err(Reason::InvalidConfig);
    }
    let driver_parent = directory(config.driver.parent().ok_or(Reason::InvalidConfig)?)?;
    let parent_metadata = driver_parent
        .metadata()
        .map_err(|_| Reason::InvalidConfig)?;
    if ![0, uid()].contains(&parent_metadata.uid()) || parent_metadata.mode() & 0o022 != 0 {
        return Err(Reason::InvalidConfig);
    }
    let driver_name = name(&config.driver)?;
    // A missing leaf is a normal E0 BackendUnavailable report, not authority to
    // run anything. Inspect without following links: a dangling symlink must
    // not masquerade as an absent executable. E1 must pin again before use.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            driver_parent.as_raw_fd(),
            driver_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok((root, report))
        } else {
            Err(Reason::InvalidConfig)
        };
    }
    let driver = open_at(&driver_parent, &driver_name, libc::O_RDONLY, 0)?;
    let metadata = driver.metadata().map_err(|_| Reason::InvalidConfig)?;
    if !metadata.is_file()
        || ![0, uid()].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o6000 != 0
    {
        return Err(Reason::InvalidConfig);
    }
    Ok((root, report))
}
fn owned_run(parent: &File, run_name: &CString, run_id: uuid::Uuid) -> Result<File, Reason> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), run_name.as_ptr(), 0o700) } != 0 {
        return Err(Reason::InvalidConfig);
    }
    let directory = open_at(parent, run_name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let mut owner = open_at(
        &directory,
        &CString::new(".qualification-owner").unwrap(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    owner
        .write_all(run_id.to_string().as_bytes())
        .and_then(|_| owner.sync_all())
        .and_then(|_| directory.sync_all())
        .and_then(|_| parent.sync_all())
        .map_err(|_| Reason::InvalidConfig)?;
    Ok(directory)
}
#[allow(clippy::too_many_arguments)]
fn acquire(
    config: &NativeConfig,
    run_id: uuid::Uuid,
    boot_id: uuid::Uuid,
    start_ticks: u64,
    lock_parent: File,
    lock: File,
    marker_name: CString,
    mode: EvidenceMode,
) -> Result<NativeLease, Reason> {
    config.validate()?;
    if run_id.is_nil() || boot_id.is_nil() {
        return Err(Reason::InvalidConfig);
    }
    absent_marker(&lock_parent, &marker_name)?;
    let (root, report_parent) = safe_paths(config)?;
    let run_name = CString::new(run_id.to_string()).unwrap();
    let _attempt_directory = owned_run(&root, &run_name, run_id)?;
    let report_directory = owned_run(&report_parent, &run_name, run_id)?;
    let run_directory = config.report_root.join(run_id.to_string());
    let report_chain = PinnedChain::capture(&run_directory)?;
    if !report_chain.ends_at(&report_directory) {
        return Err(Reason::CleanupUnconfirmed);
    }
    let marker_bytes = serde_json::to_vec(&ActiveMarker {
        run_id,
        boot_id,
        supervisor: SupervisorIdentity {
            pid: std::process::id(),
            start_ticks,
        },
        cgroup: None,
        report_directory: identity(&report_directory)?,
    })
    .map_err(|_| Reason::InvalidConfig)?;
    let mut marker = open_at(
        &lock_parent,
        &marker_name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(|_| Reason::UnfinishedRun)?;
    marker
        .write_all(&marker_bytes)
        .and_then(|_| marker.sync_all())
        .and_then(|_| lock_parent.sync_all())
        .map_err(|_| Reason::CleanupUnconfirmed)?;
    Ok(NativeLease {
        lock,
        run_directory,
        marker,
        lock_parent,
        marker_name,
        marker_bytes,
        report_directory,
        run_id,
        boot_id,
        config_digest: config.digest()?,
        supervisor_pid: std::process::id(),
        mode,
        report_chain,
    })
}
