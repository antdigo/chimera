use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::super::DomainPath;

// Records only. Mount validation and the proof required for KernelReady belong
// to rootfs assembly; deserializing this plan is never an isolation proof.
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
