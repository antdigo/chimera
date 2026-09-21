use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

use super::resources::ExecutionResources;
use super::{network::NetworkPolicyConfig, storage::StorageBoundConfig};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionProfile {
    #[default]
    TrustedHost,
    Sandboxed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default)]
    pub profile: ExecutionProfile,
    #[serde(default = "default_max_active_domains")]
    pub max_active_domains: NonZeroUsize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ExecutionResources>,
    #[serde(default)]
    pub network: Option<NetworkPolicyConfig>,
    #[serde(default)]
    pub storage: Option<StorageBoundConfig>,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            profile: ExecutionProfile::TrustedHost,
            max_active_domains: default_max_active_domains(),
            resources: None,
            network: None,
            storage: None,
        }
    }
}

fn default_max_active_domains() -> NonZeroUsize {
    NonZeroUsize::new(1).unwrap()
}

#[cfg(test)]
#[path = "execution_test.rs"]
mod execution_test;
