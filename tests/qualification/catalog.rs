use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::report::CaseResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ScenarioId {
    #[serde(rename = "S-01")]
    S01,
    #[serde(rename = "S-02")]
    S02,
    #[serde(rename = "S-03")]
    S03,
    #[serde(rename = "S-04")]
    S04,
    #[serde(rename = "S-05")]
    S05,
    #[serde(rename = "S-06")]
    S06,
    #[serde(rename = "S-07")]
    S07,
    #[serde(rename = "S-08")]
    S08,
    #[serde(rename = "S-09")]
    S09,
    #[serde(rename = "S-10")]
    S10,
    #[serde(rename = "S-11")]
    S11,
    #[serde(rename = "S-12")]
    S12,
    #[serde(rename = "S-13")]
    S13,
    #[serde(rename = "S-14")]
    S14,
    #[serde(rename = "S-15")]
    S15,
    #[serde(rename = "S-16")]
    S16,
}

impl ScenarioId {
    pub const ALL: [Self; 16] = [
        Self::S01,
        Self::S02,
        Self::S03,
        Self::S04,
        Self::S05,
        Self::S06,
        Self::S07,
        Self::S08,
        Self::S09,
        Self::S10,
        Self::S11,
        Self::S12,
        Self::S13,
        Self::S14,
        Self::S15,
        Self::S16,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Wave {
    Cold,
    Warm,
    Failure,
    Cancel,
    Restart,
    NextTenant,
    Idle,
}

impl Wave {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Failure => "failure",
            Self::Cancel => "cancel",
            Self::Restart => "restart",
            Self::NextTenant => "next-tenant",
            Self::Idle => "idle",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CaseKey {
    pub scenario: ScenarioId,
    pub case: String,
    pub wave: Wave,
    pub concurrency: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckId {
    PreflightRejectedBeforePolling,
    RollbackConfirmed,
    HostFilesystemDenied,
    PeerFilesystemDenied,
    ProcessIsolated,
    NetworkPolicyEnforced,
    OutsideControlAvailable,
    PublicRegistryReachable,
    DockerApiCompatible,
    BuildxCompatible,
    ChangedHostSemanticsContained,
    ResourceLimitEnforced,
    ProductionReservePreserved,
    CancellationBounded,
    RestartReconciled,
    CapacityBounded,
    DistinctStateConfirmed,
    ExtraAdmissionBlocked,
    NextTenantClean,
    IdleZero,
    NativeMetricsComplete,
    CleanupConfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    BackendUnavailable,
    PlatformUnsupported,
    HostBusy,
    InvalidConfig,
    MissingEvidence,
    StaleEvidence,
    UnfinishedRun,
    BoundaryViolation,
    DeadlineExceeded,
    CleanupUnconfirmed,
    SloExceeded,
    ProtocolViolation,
}

const S01_CHECKS: &[CheckId] = &[
    CheckId::PreflightRejectedBeforePolling,
    CheckId::RollbackConfirmed,
];
const S02_CHECKS: &[CheckId] = &[CheckId::RollbackConfirmed, CheckId::CleanupConfirmed];
const S03_CHECKS: &[CheckId] = &[
    CheckId::HostFilesystemDenied,
    CheckId::PeerFilesystemDenied,
    CheckId::CleanupConfirmed,
];
const S04_CHECKS: &[CheckId] = &[CheckId::ProcessIsolated, CheckId::CleanupConfirmed];
const S05_CHECKS: &[CheckId] = &[
    CheckId::NetworkPolicyEnforced,
    CheckId::OutsideControlAvailable,
    CheckId::PublicRegistryReachable,
    CheckId::CleanupConfirmed,
];
const S06_CHECKS: &[CheckId] = &[CheckId::DockerApiCompatible, CheckId::CleanupConfirmed];
const S07_CHECKS: &[CheckId] = &[
    CheckId::DockerApiCompatible,
    CheckId::BuildxCompatible,
    CheckId::CleanupConfirmed,
];
const S08_CHECKS: &[CheckId] = &[
    CheckId::NetworkPolicyEnforced,
    CheckId::ChangedHostSemanticsContained,
    CheckId::CleanupConfirmed,
];
const S09_CHECKS: &[CheckId] = &[
    CheckId::ResourceLimitEnforced,
    CheckId::ProductionReservePreserved,
    CheckId::NativeMetricsComplete,
    CheckId::CleanupConfirmed,
];
const S10_CHECKS: &[CheckId] = &[CheckId::CancellationBounded, CheckId::CleanupConfirmed];
const S11_CHECKS: &[CheckId] = &[CheckId::RestartReconciled, CheckId::CleanupConfirmed];
const S12_CHECKS: &[CheckId] = &[
    CheckId::HostFilesystemDenied,
    CheckId::PeerFilesystemDenied,
    CheckId::CleanupConfirmed,
];
const S13_CHECKS: &[CheckId] = &[
    CheckId::CapacityBounded,
    CheckId::DistinctStateConfirmed,
    CheckId::ExtraAdmissionBlocked,
    CheckId::CleanupConfirmed,
];
const S14_CHECKS: &[CheckId] = &[CheckId::NextTenantClean, CheckId::CleanupConfirmed];
const S15_CHECKS: &[CheckId] = &[CheckId::IdleZero, CheckId::CleanupConfirmed];
const S16_CHECKS: &[CheckId] = &[
    CheckId::ResourceLimitEnforced,
    CheckId::NativeMetricsComplete,
    CheckId::CleanupConfirmed,
];

pub fn required_cases() -> Vec<CaseKey> {
    let mut cases = Vec::new();
    append_cases(
        &mut cases,
        ScenarioId::S01,
        &[
            "no-userns",
            "no-cgroup-v2",
            "no-ebpf",
            "no-storage-bound",
            "unsupported-container",
            "unsupported-platform",
        ],
        &[Wave::Cold],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S02,
        &[
            "after-journal",
            "after-cgroup",
            "after-namespaces",
            "after-rootfs",
            "after-pivot",
            "after-init",
            "after-dockerd",
            "after-probes",
        ],
        &[Wave::Failure],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S03,
        &[
            "host-files",
            "peer-files",
            "supervisor-credentials",
            "bind-host",
            "bind-peer",
        ],
        &[Wave::Cold],
        &[2],
    );
    append_cases(
        &mut cases,
        ScenarioId::S04,
        &[
            "pid-visibility",
            "signal-peer",
            "ipc-peer",
            "uts-private",
            "init-control-fd",
        ],
        &[Wave::Cold],
        &[2],
    );
    append_cases(
        &mut cases,
        ScenarioId::S05,
        &[
            "loopback",
            "host-addresses",
            "lan",
            "production-cidrs",
            "public-registry",
            "scoped-capabilities",
        ],
        &[Wave::Cold],
        &[2],
    );
    append_cases(
        &mut cases,
        ScenarioId::S06,
        &[
            "pull-push-login-logout",
            "run-exec",
            "images",
            "volumes",
            "networks",
            "bind-own",
            "job-container",
            "service-container",
            "docker-action",
        ],
        &[Wave::Cold],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S07,
        &["pinned-buildx-login-build-push"],
        &[Wave::Cold, Wave::Warm],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S08,
        &["privileged", "network-host", "published-port"],
        &[Wave::Cold],
        &[2],
    );
    append_cases(
        &mut cases,
        ScenarioId::S09,
        &["memory-oom", "pids", "cpu", "io"],
        &[Wave::Cold],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S10,
        &[
            "step",
            "post",
            "buildkit",
            "teardown",
            "stale-cancel",
            "lease-loss",
            "post-failure",
            "shutdown",
        ],
        &[Wave::Cancel],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S11,
        &[
            "reserved",
            "provisioning",
            "ready",
            "running",
            "cleaning",
            "destroying",
        ],
        &[Wave::Restart],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S12,
        &[
            "symlink-root",
            "symlink-command-file",
            "inode-replacement",
            "path-replacement",
            "unknown-resource",
        ],
        &[Wave::Failure],
        &[1],
    );
    append_cases(
        &mut cases,
        ScenarioId::S13,
        &["capacity-and-distinct-state"],
        &[
            Wave::Cold,
            Wave::Warm,
            Wave::Failure,
            Wave::Cancel,
            Wave::Restart,
        ],
        &[20, 40],
    );
    for source_wave in [
        Wave::Cold,
        Wave::Warm,
        Wave::Failure,
        Wave::Cancel,
        Wave::Restart,
    ] {
        for concurrency in [20, 40] {
            cases.push(case(
                ScenarioId::S14,
                format!("next-tenant-clean-after-{}", source_wave.as_str()),
                Wave::NextTenant,
                concurrency,
            ));
            cases.push(case(
                ScenarioId::S15,
                format!("zero-domain-processes-after-{}", source_wave.as_str()),
                Wave::Idle,
                concurrency,
            ));
        }
    }
    append_cases(
        &mut cases,
        ScenarioId::S16,
        &["native-storage"],
        &[Wave::Cold, Wave::Warm],
        &[1, 20, 40],
    );
    cases
}

pub fn required_checks(key: &CaseKey) -> &'static [CheckId] {
    assert!(
        required_cases().contains(key),
        "case key is not catalogue allowlisted: {key:?}"
    );
    match key.scenario {
        ScenarioId::S01 => S01_CHECKS,
        ScenarioId::S02 => S02_CHECKS,
        ScenarioId::S03 => S03_CHECKS,
        ScenarioId::S04 => S04_CHECKS,
        ScenarioId::S05 => S05_CHECKS,
        ScenarioId::S06 => S06_CHECKS,
        ScenarioId::S07 => S07_CHECKS,
        ScenarioId::S08 => S08_CHECKS,
        ScenarioId::S09 => S09_CHECKS,
        ScenarioId::S10 => S10_CHECKS,
        ScenarioId::S11 => S11_CHECKS,
        ScenarioId::S12 => S12_CHECKS,
        ScenarioId::S13 => S13_CHECKS,
        ScenarioId::S14 => S14_CHECKS,
        ScenarioId::S15 => S15_CHECKS,
        ScenarioId::S16 => S16_CHECKS,
    }
}

pub fn validate_coverage(results: &[CaseResult]) -> Result<(), Reason> {
    let actual: BTreeSet<_> = results.iter().map(|result| result.key.clone()).collect();
    if actual.len() != results.len() {
        return Err(Reason::MissingEvidence);
    }
    let expected: BTreeSet<_> = required_cases().into_iter().collect();
    if actual != expected {
        return Err(Reason::MissingEvidence);
    }
    Ok(())
}

fn append_cases(
    cases: &mut Vec<CaseKey>,
    scenario: ScenarioId,
    names: &[&str],
    waves: &[Wave],
    concurrencies: &[u16],
) {
    for name in names {
        for wave in waves {
            for concurrency in concurrencies {
                cases.push(case(scenario, (*name).to_owned(), *wave, *concurrency));
            }
        }
    }
}

fn case(scenario: ScenarioId, case: impl Into<String>, wave: Wave, concurrency: u16) -> CaseKey {
    CaseKey {
        scenario,
        case: case.into(),
        wave,
        concurrency,
    }
}
