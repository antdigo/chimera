use std::num::NonZeroU64;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::sandbox_policy::PolicyError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBoundConfig {
    pub mechanism: StorageMechanism,
    pub max_bytes: StorageBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageMechanism {
    DedicatedFilesystem,
    ProjectQuota,
    BtrfsQuota,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageBytes(NonZeroU64);

impl StorageBytes {
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

fn checked_bytes(value: u64, multiplier: u64) -> Result<StorageBytes, PolicyError> {
    let bytes = value
        .checked_mul(multiplier)
        .and_then(NonZeroU64::new)
        .ok_or(PolicyError::InvalidStorageLimit)?;
    Ok(StorageBytes(bytes))
}

impl FromStr for StorageBytes {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (digits, multiplier) = [
            ("KiB", 1024_u64),
            ("MiB", 1024_u64.pow(2)),
            ("GiB", 1024_u64.pow(3)),
            ("TiB", 1024_u64.pow(4)),
            ("B", 1),
        ]
        .into_iter()
        .find_map(|(suffix, multiplier)| {
            value
                .strip_suffix(suffix)
                .map(|digits| (digits, multiplier))
        })
        .ok_or(PolicyError::InvalidStorageLimit)?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PolicyError::InvalidStorageLimit);
        }
        checked_bytes(
            digits
                .parse()
                .map_err(|_| PolicyError::InvalidStorageLimit)?,
            multiplier,
        )
    }
}

impl Serialize for StorageBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}B", self.get()))
    }
}

impl<'de> Deserialize<'de> for StorageBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[path = "storage_test.rs"]
mod storage_test;
