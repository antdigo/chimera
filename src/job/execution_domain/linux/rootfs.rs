use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::super::DomainPath;

// Deserializing a plan is never an isolation proof. Linux validates both the
// source identities and the complete allowlist again before creating mounts.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::job::execution_domain) struct RootfsPlan {
    pub inputs: Vec<MountInput>,
    pub staging_root: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::job::execution_domain) struct MountInput {
    pub source: PathBuf,
    pub target: DomainPath,
    pub readonly: bool,
    pub expected_device: u64,
    pub expected_inode: u64,
}

#[cfg(target_os = "linux")]
#[path = "rootfs_linux.rs"]
pub(super) mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::assemble_and_pivot;
#[cfg(all(target_os = "linux", test))]
pub(super) use linux::{generated_etc, validate_inputs, verify_immutable};
