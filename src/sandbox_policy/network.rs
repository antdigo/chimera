use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::config::{IpCidr, NetworkPolicyConfig};
use crate::sandbox_policy::PolicyError;

pub struct HostAddresses {
    pub addresses: Vec<IpAddr>,
}

pub struct NetworkPolicy {
    denied: Vec<IpCidr>,
    required_probe_prefixes: Vec<IpCidr>,
    digest: String,
}

const BASE_DENIALS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::/0",
];

pub fn compile_network(
    config: &NetworkPolicyConfig,
    host: &HostAddresses,
) -> Result<NetworkPolicy, PolicyError> {
    if host.addresses.is_empty() {
        return Err(PolicyError::EmptyHostInventory);
    }

    let mut denied = BTreeMap::new();
    let mut required = BTreeMap::new();
    for cidr in BASE_DENIALS {
        insert(&mut denied, cidr.parse()?);
    }
    insert(&mut required, "127.0.0.0/8".parse()?);

    for &address in &host.addresses {
        let prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let cidr: IpCidr = format!("{address}/{prefix}").parse()?;
        insert(&mut denied, cidr.clone());
        insert(&mut required, cidr);
    }
    for cidr in &config.production_cidrs {
        insert(&mut denied, cidr.clone());
        insert(&mut required, cidr.clone());
    }

    let denied: Vec<IpCidr> = denied.into_values().collect();
    let required_probe_prefixes: Vec<IpCidr> = required.into_values().collect();
    let mut hash_input = String::from("chimera-network-policy-v1\n");
    for cidr in &denied {
        hash_input.push_str(&format!("{cidr}\n"));
    }
    hash_input.push_str("required-probes\n");
    for cidr in &required_probe_prefixes {
        hash_input.push_str(&format!("{cidr}\n"));
    }
    let digest = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    Ok(NetworkPolicy {
        denied,
        required_probe_prefixes,
        digest,
    })
}

fn insert(set: &mut BTreeMap<String, IpCidr>, cidr: IpCidr) {
    set.insert(cidr.to_string(), cidr);
}

impl NetworkPolicy {
    pub fn denied(&self) -> &[IpCidr] {
        &self.denied
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn permits(&self, address: IpAddr) -> bool {
        if matches!(address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
            return false;
        }
        !self.denied.iter().any(|cidr| cidr.contains(address))
    }

    pub fn required_probe_prefixes(&self) -> &[IpCidr] {
        &self.required_probe_prefixes
    }
}

#[cfg(test)]
#[path = "network_test.rs"]
mod network_test;
