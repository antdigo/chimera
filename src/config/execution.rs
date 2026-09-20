use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

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
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            profile: ExecutionProfile::TrustedHost,
            max_active_domains: default_max_active_domains(),
        }
    }
}

fn default_max_active_domains() -> NonZeroUsize {
    NonZeroUsize::new(1).unwrap()
}

#[cfg(test)]
#[path = "execution_test.rs"]
mod execution_test;
