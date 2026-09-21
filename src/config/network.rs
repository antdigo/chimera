use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::sandbox_policy::PolicyError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpCidr {
    address: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = mask_v4(self.prefix);
                u32::from(candidate) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate))
                if candidate.to_ipv4_mapped().is_none() =>
            {
                let mask = mask_v6(self.prefix);
                u128::from(candidate) & mask == u128::from(network)
            }
            _ => false,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl FromStr for IpCidr {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or(PolicyError::InvalidCidr)?;
        if prefix.contains('/') || value.trim() != value {
            return Err(PolicyError::InvalidCidr);
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| PolicyError::InvalidCidr)?;
        let prefix = prefix.parse::<u8>().map_err(|_| PolicyError::InvalidCidr)?;
        let valid = match address {
            IpAddr::V4(ip) => prefix <= 32 && u32::from(ip) & !mask_v4(prefix) == 0,
            IpAddr::V6(ip) => {
                ip.to_ipv4_mapped().is_none()
                    && prefix <= 128
                    && u128::from(ip) & !mask_v6(prefix) == 0
            }
        };
        if !valid {
            return Err(PolicyError::InvalidCidr);
        }
        Ok(Self { address, prefix })
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

impl Serialize for IpCidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyConfig {
    pub production_cidrs: Vec<IpCidr>,
}

#[cfg(test)]
#[path = "network_test.rs"]
mod network_test;
