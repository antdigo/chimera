use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{IpCidr, NetworkPolicyConfig};
use crate::sandbox_policy::ConnectOutcome;
use crate::sandbox_policy::PolicyError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGeneration {
    pub boot_id: Uuid,
    pub invocation_id: String,
    pub control_group: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppliedNetworkPolicy {
    pub generation: ServiceGeneration,
    pub denied: Vec<IpCidr>,
    pub allowed: Vec<IpCidr>,
    pub bpf_attached: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentinelObservation {
    pub address: SocketAddr,
    pub control_before: bool,
    pub control_after: bool,
    pub observed: ConnectOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeBatch {
    pub generation: ServiceGeneration,
    pub negative: Vec<SentinelObservation>,
    pub public_registry_ok: bool,
}

pub fn validate_network_evidence(
    expected: &NetworkPolicy,
    applied: &AppliedNetworkPolicy,
    probes: &ProbeBatch,
) -> Result<(), PolicyError> {
    let generation = &applied.generation;
    if generation.boot_id.is_nil()
        || generation.invocation_id.len() != 32
        || !generation
            .invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || generation.control_group != "/system.slice/chimera.service"
        || generation != &probes.generation
        || !applied.bpf_attached
        || !applied.allowed.is_empty()
        || expected.denied().iter().any(|required| {
            !applied.denied.iter().any(|effective| {
                effective.prefix() <= required.prefix() && effective.contains(required.address())
            })
        })
    {
        return Err(PolicyError::PolicyMismatch);
    }
    if !probes.public_registry_ok || probes.negative.is_empty() {
        return Err(PolicyError::ProbeInconclusive);
    }
    for probe in &probes.negative {
        if !probe.control_before || !probe.control_after || expected.permits(probe.address.ip()) {
            return Err(PolicyError::ProbeInconclusive);
        }
        match probe.observed {
            ConnectOutcome::Connected => return Err(PolicyError::ProbeAllowedForbidden),
            ConnectOutcome::Refused | ConnectOutcome::Unreachable => {
                return Err(PolicyError::ProbeInconclusive);
            }
            ConnectOutcome::Denied | ConnectOutcome::TimedOut => {}
        }
    }
    let mut prefixes: Vec<&IpCidr> = expected.required_probe_prefixes().iter().collect();
    prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.prefix()));
    let mut sentinel_addresses: Vec<IpAddr> = probes
        .negative
        .iter()
        .map(|probe| probe.address.ip())
        .collect();
    sentinel_addresses.sort_unstable();
    sentinel_addresses.dedup();
    for prefix in prefixes {
        let Some(index) = sentinel_addresses
            .iter()
            .position(|address| prefix.contains(*address))
        else {
            return Err(PolicyError::ProbeInconclusive);
        };
        sentinel_addresses.swap_remove(index);
    }
    Ok(())
}

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
        return Err(PolicyError::InvalidObservation("host_addresses"));
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
