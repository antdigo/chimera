use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Serialize;

use crate::config::{ChimeraConfig, ChimeraPaths, StorageMechanism, load_config_if_exists};
use crate::sandbox_policy::{
    HostAddresses, InstallPlan, PolicyError, compile_network, probe_storage, render_install_plan,
    validate_storage_bound,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Satisfied,
    Failed,
    Unverified,
}

#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub category: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub activation_available: bool,
    pub checks: Vec<DoctorCheck>,
    pub policy_digest: Option<String>,
}

fn check(id: &str, status: CheckStatus, category: &str) -> DoctorCheck {
    DoctorCheck {
        id: id.into(),
        status,
        category: category.into(),
    }
}

fn config(root: &Path) -> Result<ChimeraConfig, PolicyError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|_| PolicyError::MissingRoot)?;
    if !metadata.file_type().is_dir() {
        return Err(PolicyError::MissingRoot);
    }
    load_config_if_exists(&ChimeraPaths::new(root.to_path_buf()).config_file())
        .map_err(|_| PolicyError::InvalidConfig)?
        .ok_or(PolicyError::MissingConfig)
}

struct InterfaceList(*mut libc::ifaddrs);
impl Drop for InterfaceList {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) };
    }
}

fn host_addresses() -> Result<HostAddresses, PolicyError> {
    let mut first = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 || first.is_null() {
        return Err(PolicyError::HostInventoryUnavailable);
    }
    let guard = InterfaceList(first);
    let mut addresses = Vec::new();
    let mut current = guard.0;
    while !current.is_null() {
        let addr = unsafe { (*current).ifa_addr };
        if !addr.is_null() {
            let family = unsafe { (*addr).sa_family as i32 };
            if family == libc::AF_INET {
                let ipv4 = unsafe { &*(addr as *const libc::sockaddr_in) };
                addresses.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    ipv4.sin_addr.s_addr,
                ))));
            } else if family == libc::AF_INET6 {
                let ipv6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
                addresses.push(IpAddr::V6(Ipv6Addr::from(ipv6.sin6_addr.s6_addr)));
            }
        }
        current = unsafe { (*current).ifa_next };
    }
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(PolicyError::HostInventoryUnavailable);
    }
    Ok(HostAddresses { addresses })
}

#[cfg(any(target_os = "linux", test))]
fn classify_linux_platform(
    boot_ok: bool,
    cgroup: Option<&str>,
    systemd: bool,
    container: bool,
    unified_mount: bool,
) -> (DoctorCheck, bool) {
    let unified_membership = cgroup.is_some_and(|value| {
        let mut lines = value.lines();
        lines.next().is_some_and(|line| line.starts_with("0::/")) && lines.next().is_none()
    });
    let in_service = unified_mount
        && unified_membership
        && cgroup.is_some_and(|value| value.trim_end() == "0::/system.slice/chimera.service");
    let (status, category) = if !boot_ok || cgroup.is_none() || !systemd {
        (CheckStatus::Failed, "linux_prerequisites_missing")
    } else if !unified_mount || !unified_membership {
        (CheckStatus::Failed, "cgroup_v2_unavailable")
    } else if container {
        (CheckStatus::Failed, "container_environment")
    } else {
        (CheckStatus::Satisfied, "linux_prerequisites_observed")
    };
    (check("platform", status, category), in_service)
}

#[cfg(target_os = "linux")]
fn platform() -> (DoctorCheck, bool) {
    let boot_ok = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .and_then(|value| uuid::Uuid::parse_str(value.trim()).ok())
        .is_some_and(|id| !id.is_nil());
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok();
    let container = Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || cgroup.as_deref().is_some_and(|value| {
            ["docker", "containerd", "kubepods"]
                .iter()
                .any(|needle| value.contains(needle))
        });
    classify_linux_platform(
        boot_ok,
        cgroup.as_deref(),
        Path::new("/run/systemd/system").is_dir(),
        container,
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
    )
}

#[cfg(not(target_os = "linux"))]
fn platform() -> (DoctorCheck, bool) {
    (
        check("platform", CheckStatus::Failed, "unsupported_platform"),
        false,
    )
}

pub fn inspect_policy(root: &Path) -> Result<DoctorReport, PolicyError> {
    let config = config(root)?;
    let (platform, in_service) = platform();
    let mut checks = vec![platform];
    let mut policy_digest = None;
    let network_check = match &config.execution.network {
        None => check(
            "network_config",
            CheckStatus::Failed,
            "missing_network_config",
        ),
        Some(network) => match host_addresses().and_then(|host| compile_network(network, &host)) {
            Ok(policy) => {
                policy_digest = Some(policy.digest().to_owned());
                check(
                    "network_config",
                    CheckStatus::Satisfied,
                    "network_policy_compiled",
                )
            }
            Err(_) => check(
                "network_config",
                CheckStatus::Unverified,
                "host_inventory_unavailable",
            ),
        },
    };
    checks.push(network_check);
    let live_category = if in_service {
        "live_enforcement_evidence_unavailable"
    } else {
        "outside_service_cgroup"
    };
    checks.push(check(
        "network_effective",
        CheckStatus::Unverified,
        live_category,
    ));
    checks.push(check(
        "network_negative_probes",
        CheckStatus::Unverified,
        live_category,
    ));
    let storage_check = match &config.execution.storage {
        None => check(
            "storage_bound",
            CheckStatus::Failed,
            "missing_storage_config",
        ),
        Some(storage) if storage.mechanism != StorageMechanism::DedicatedFilesystem => check(
            "storage_bound",
            CheckStatus::Unverified,
            "storage_mechanism_unsupported",
        ),
        Some(storage) => match probe_storage(root) {
            Ok(observation) if validate_storage_bound(storage, &observation).is_ok() => check(
                "storage_bound",
                CheckStatus::Satisfied,
                "dedicated_filesystem_observed",
            ),
            Ok(_) => check(
                "storage_bound",
                CheckStatus::Failed,
                "storage_bound_mismatch",
            ),
            Err(error) => classify_storage_probe_error(error),
        },
    };
    checks.push(storage_check);
    checks.push(check(
        "capability_bridge",
        CheckStatus::Unverified,
        "runtime_bridge_unavailable",
    ));
    checks.push(check(
        "activation",
        CheckStatus::Failed,
        "sandboxed_unavailable",
    ));
    Ok(DoctorReport {
        schema_version: 1,
        activation_available: false,
        checks,
        policy_digest,
    })
}

fn classify_storage_probe_error(error: PolicyError) -> DoctorCheck {
    match error {
        PolicyError::StorageBoundMismatch => check(
            "storage_bound",
            CheckStatus::Failed,
            "storage_bound_mismatch",
        ),
        _ => check(
            "storage_bound",
            CheckStatus::Unverified,
            "storage_probe_unavailable",
        ),
    }
}

pub fn inspect_install_plan(root: &Path) -> Result<InstallPlan, PolicyError> {
    let config = config(root)?;
    let network = config
        .execution
        .network
        .as_ref()
        .ok_or(PolicyError::MissingNetworkConfig)?;
    let host = host_addresses()?;
    let policy = compile_network(network, &host)?;
    Ok(render_install_plan(&policy))
}

#[cfg(test)]
#[path = "doctor_test.rs"]
mod doctor_test;
