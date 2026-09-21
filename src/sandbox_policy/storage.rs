use std::path::{Path, PathBuf};

use crate::config::{StorageBoundConfig, StorageMechanism};
use crate::sandbox_policy::PolicyError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageIdentity {
    pub device: u64,
    pub inode: u64,
    pub mount_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageObservation {
    pub root: StorageIdentity,
    pub mount_point: PathBuf,
    pub filesystem_root: PathBuf,
    pub filesystem_type: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub parent_device: u64,
    pub writable_nested_mounts: Vec<PathBuf>,
    pub aliases_outside_root: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageBoundEvidence {
    identity: StorageIdentity,
    hard_limit_bytes: u64,
}

impl StorageBoundEvidence {
    pub fn hard_limit_bytes(&self) -> u64 {
        self.hard_limit_bytes
    }
    pub fn identity(&self) -> &StorageIdentity {
        &self.identity
    }
}

pub fn validate_storage_bound(
    config: &StorageBoundConfig,
    observation: &StorageObservation,
) -> Result<StorageBoundEvidence, PolicyError> {
    if config.mechanism != StorageMechanism::DedicatedFilesystem {
        return Err(PolicyError::UnsupportedStorageProbe);
    }
    if observation.root.device == 0
        || observation.root.inode == 0
        || observation.root.mount_id == 0
        || !observation.mount_point.is_absolute()
        || observation.filesystem_root != Path::new("/")
        || !matches!(observation.filesystem_type.as_str(), "ext4" | "xfs")
        || observation.total_bytes == 0
        || observation.total_bytes > config.max_bytes.get()
        || observation.available_bytes > observation.total_bytes
        || observation.parent_device == observation.root.device
        || !observation.writable_nested_mounts.is_empty()
        || !observation.aliases_outside_root.is_empty()
    {
        return Err(PolicyError::StorageBoundMismatch);
    }
    Ok(StorageBoundEvidence {
        identity: observation.root.clone(),
        hard_limit_bytes: observation.total_bytes,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::{self, File};
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;

    pub(super) const MAX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;

    #[derive(Debug)]
    pub(super) struct MountRecord {
        pub id: u64,
        pub device: u64,
        pub root: PathBuf,
        pub point: PathBuf,
        pub writable: bool,
        pub filesystem_type: String,
    }

    fn inconclusive() -> PolicyError {
        PolicyError::StorageProbeInconclusive
    }
    fn mismatch() -> PolicyError {
        PolicyError::StorageBoundMismatch
    }

    pub(super) fn checked_capacity(blocks: u64, fragment_size: u64) -> Result<u64, PolicyError> {
        blocks
            .checked_mul(fragment_size)
            .filter(|bytes| *bytes != 0)
            .ok_or_else(inconclusive)
    }

    pub(super) fn read_mountinfo_limited(reader: &mut impl Read) -> Result<Vec<u8>, PolicyError> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_MOUNTINFO_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| inconclusive())?;
        if bytes.len() > MAX_MOUNTINFO_BYTES {
            return Err(inconclusive());
        }
        Ok(bytes)
    }

    fn unescape(input: &[u8]) -> Result<PathBuf, PolicyError> {
        let mut output = Vec::with_capacity(input.len());
        let mut position = 0;
        while position < input.len() {
            if input[position] != b'\\' {
                output.push(input[position]);
                position += 1;
                continue;
            }
            if position + 3 >= input.len() {
                return Err(inconclusive());
            }
            let escape = &input[position + 1..position + 4];
            output.push(match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(inconclusive()),
            });
            position += 4;
        }
        if output.contains(&0) {
            return Err(inconclusive());
        }
        Ok(std::ffi::OsString::from_vec(output).into())
    }

    fn decimal(value: &[u8]) -> Result<u64, PolicyError> {
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(inconclusive());
        }
        std::str::from_utf8(value)
            .map_err(|_| inconclusive())?
            .parse()
            .map_err(|_| inconclusive())
    }

    pub(super) fn parse_mountinfo(input: &[u8]) -> Result<Vec<MountRecord>, PolicyError> {
        let mut records = Vec::new();
        for line in input
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let (left, right) = line
                .windows(3)
                .position(|bytes| bytes == b" - ")
                .map(|at| (&line[..at], &line[at + 3..]))
                .ok_or_else(inconclusive)?;
            let fields: Vec<_> = left
                .split(|byte| *byte == b' ')
                .filter(|field| !field.is_empty())
                .collect();
            let after: Vec<_> = right
                .split(|byte| *byte == b' ')
                .filter(|field| !field.is_empty())
                .collect();
            if fields.len() < 6 || after.len() != 3 {
                return Err(inconclusive());
            }
            let id = decimal(fields[0])?;
            let _parent_id = decimal(fields[1])?;
            let colon = fields[2]
                .iter()
                .position(|byte| *byte == b':')
                .ok_or_else(inconclusive)?;
            let (major, minor_with_colon) = fields[2].split_at(colon);
            let minor = &minor_with_colon[1..];
            let major = u32::try_from(decimal(major)?).map_err(|_| inconclusive())?;
            let minor = u32::try_from(decimal(minor)?).map_err(|_| inconclusive())?;
            let filesystem_type = std::str::from_utf8(after[0])
                .map_err(|_| inconclusive())?
                .to_owned();
            let writable = fields[5]
                .split(|byte| *byte == b',')
                .any(|option| option == b"rw");
            let readonly = fields[5]
                .split(|byte| *byte == b',')
                .any(|option| option == b"ro");
            if writable == readonly {
                return Err(inconclusive());
            }
            records.push(MountRecord {
                id,
                device: libc::makedev(major, minor) as u64,
                root: unescape(fields[3])?,
                point: unescape(fields[4])?,
                writable,
                filesystem_type,
            });
        }
        if records.is_empty() {
            return Err(inconclusive());
        }
        Ok(records)
    }

    fn identity(file: &File) -> Result<StorageIdentity, PolicyError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(inconclusive());
        }
        let stat = unsafe { stat.assume_init() };
        let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
            .map_err(|_| inconclusive())?;
        let mount_id = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:\t"))
            .ok_or_else(inconclusive)?
            .parse()
            .map_err(|_| inconclusive())?;
        Ok(StorageIdentity {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            mount_id,
        })
    }

    pub(super) fn path_identity(root: &Path) -> Result<StorageIdentity, PolicyError> {
        let file = crate::storage::open_existing_root(root).map_err(|_| inconclusive())?;
        identity(&file)
    }

    pub(super) fn verify_pinned_identity(
        root: &Path,
        expected: &StorageIdentity,
    ) -> Result<(), PolicyError> {
        if &path_identity(root)? != expected {
            return Err(mismatch());
        }
        Ok(())
    }

    pub(super) fn mount_conflicts(
        mounts: &[MountRecord],
        point: &Path,
        mount_id: u64,
        device: u64,
    ) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let nested = mounts
            .iter()
            .filter(|other| {
                other.point != point && other.point.starts_with(point) && other.writable
            })
            .map(|other| other.point.clone())
            .collect();
        let aliases = mounts
            .iter()
            .filter(|other| {
                other.id != mount_id && other.device == device && !other.point.starts_with(point)
            })
            .map(|other| other.point.clone())
            .collect();
        (nested, aliases)
    }

    pub(super) fn probe(root: &Path) -> Result<StorageObservation, PolicyError> {
        let file = crate::storage::open_existing_root(root).map_err(|_| inconclusive())?;
        let first = identity(&file)?;
        let point = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| inconclusive())?;
        if !point.is_absolute() {
            return Err(inconclusive());
        }
        let parent = point.parent().ok_or_else(inconclusive)?;
        let parent_device = fs::metadata(parent).map_err(|_| inconclusive())?.dev();
        let mut vfs = MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(file.as_raw_fd(), vfs.as_mut_ptr()) } != 0 {
            return Err(inconclusive());
        }
        let vfs = unsafe { vfs.assume_init() };
        let total_bytes = checked_capacity(vfs.f_blocks as u64, vfs.f_frsize as u64)?;
        let available_bytes = (vfs.f_bavail as u64)
            .checked_mul(vfs.f_frsize as u64)
            .ok_or_else(inconclusive)?;
        let mut mount_file = File::open("/proc/self/mountinfo").map_err(|_| inconclusive())?;
        let mounts = parse_mountinfo(&read_mountinfo_limited(&mut mount_file)?)?;
        let exact: Vec<_> = mounts.iter().filter(|mount| mount.point == point).collect();
        if exact.len() != 1 {
            return Err(mismatch());
        }
        let mount = exact[0];
        if mount.id != first.mount_id
            || mount.device != first.device
            || mount.root != Path::new("/")
        {
            return Err(mismatch());
        }
        let (writable_nested_mounts, aliases_outside_root) =
            mount_conflicts(&mounts, &point, mount.id, mount.device);
        let last = identity(&file)?;
        if first != last
            || verify_pinned_identity(root, &first).is_err()
            || fs::metadata(parent).map_err(|_| inconclusive())?.dev() != parent_device
        {
            return Err(mismatch());
        }
        let observation = StorageObservation {
            root: first,
            mount_point: point,
            filesystem_root: mount.root.clone(),
            filesystem_type: mount.filesystem_type.clone(),
            total_bytes,
            available_bytes,
            parent_device,
            writable_nested_mounts,
            aliases_outside_root,
        };
        if !observation.writable_nested_mounts.is_empty()
            || !observation.aliases_outside_root.is_empty()
        {
            return Err(mismatch());
        }
        Ok(observation)
    }

    pub(super) fn revalidate(
        root: &Path,
        evidence: &StorageBoundEvidence,
    ) -> Result<(), PolicyError> {
        verify_pinned_identity(root, &evidence.identity)?;
        let observation = probe(root)?;
        if observation.root != evidence.identity
            || observation.total_bytes != evidence.hard_limit_bytes
        {
            return Err(mismatch());
        }
        Ok(())
    }
}

pub fn probe_storage(root: &Path) -> Result<StorageObservation, PolicyError> {
    #[cfg(target_os = "linux")]
    {
        linux::probe(root)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(PolicyError::UnsupportedPlatform)
    }
}

pub fn revalidate_storage_identity(
    root: &Path,
    evidence: &StorageBoundEvidence,
) -> Result<(), PolicyError> {
    #[cfg(target_os = "linux")]
    {
        linux::revalidate(root, evidence)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, evidence);
        Err(PolicyError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
use linux::{MAX_MOUNTINFO_BYTES, checked_capacity, parse_mountinfo, read_mountinfo_limited};

#[cfg(test)]
#[path = "storage_test.rs"]
mod storage_test;
