//! Fixture evaluation only. A driver envelope does not authenticate live collectors.
//! E1 must replace caller-supplied policy inventory, controls and snapshots with
//! independently captured, run-bound evidence before native checks can pass.
use super::catalog::{CaseKey, CheckId, Reason, ScenarioId, required_cases, required_checks};
use super::driver::{AuthenticatedResponse, Operation, Recipe};
use super::fixtures::make_canaries;
use super::host::SentinelRole;
use super::report::{Check, EvidenceMode};
use chimera::config::NetworkPolicyConfig;
use chimera::sandbox_policy::{
    AppliedNetworkPolicy, ConnectOutcome, HostAddresses, NetworkPolicy, PolicyError, ProbeBatch,
    compile_network, validate_network_evidence,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationTarget {
    HostFile,
    PeerFile,
    SupervisorCredential,
    HostBind,
    PeerBind,
    HostProcess,
    PeerSignal,
    PeerIpc,
    Hostname,
    InitControlFd,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationOutcome {
    Denied,
    Absent,
    Visible,
    Modified,
    Signalled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationObservation {
    pub target: IsolationTarget,
    pub outcome: IsolationOutcome,
}

// NetworkPolicy is deliberately not deserializable. The wire carries compilation
// inputs and a digest, then the harness compiles the expected D0 policy locally.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkWireFacts {
    run_id: Uuid,
    key: CaseKey,
    policy_config: NetworkPolicyConfig,
    host_addresses: Vec<IpAddr>,
    expected_digest: String,
    applied: AppliedNetworkPolicy,
    probes: ProbeBatch,
    sentinels: Vec<FixtureSentinel>,
    probe_deadline_ms: u64,
    elapsed_ms: Vec<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureSentinel {
    role: SentinelRole,
    address: SocketAddr,
}

pub struct QualificationNetworkFacts {
    pub expected: NetworkPolicy,
    pub applied: AppliedNetworkPolicy,
    pub probes: ProbeBatch,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolationWireFacts {
    setup_confirmed: bool,
    outside_control_before: bool,
    outside_control_after: bool,
    network: Option<NetworkWireFacts>,
    observations: Vec<IsolationObservation>,
    peer_unchanged: bool,
    polling_started: bool,
    rollback_confirmed: bool,
    cleanup_confirmed: bool,
    path: Option<PathFacts>,
    capabilities: Option<CapabilityFacts>,
}
pub struct IsolationFacts {
    pub setup_confirmed: bool,
    pub outside_control_before: bool,
    pub outside_control_after: bool,
    pub network: Option<QualificationNetworkFacts>,
    pub observations: Vec<IsolationObservation>,
    pub peer_unchanged: bool,
    pub polling_started: bool,
    pub rollback_confirmed: bool,
    pub cleanup_confirmed: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    content_digest: String,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum PathResolution {
    Rejected,
    Quarantined,
    Removed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathFacts {
    case: String,
    before: FileSnapshot,
    after: FileSnapshot,
    host_outcome: IsolationOutcome,
    peer_outcome: IsolationOutcome,
    resolution: PathResolution,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum CapabilityOutcome {
    Denied,
    Granted,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityFacts {
    owner: Uuid,
    peer: Uuid,
    credential_hash: String,
    cross_attempt: CapabilityOutcome,
    after_revoke: CapabilityOutcome,
}

fn supported(key: &CaseKey) -> bool {
    matches!(
        key.scenario,
        ScenarioId::S01 | ScenarioId::S03 | ScenarioId::S04 | ScenarioId::S05 | ScenarioId::S12
    ) && required_cases().contains(key)
}

/// Closed fixture identifiers denote purpose-built driver operations, never shell
/// commands or caller paths. The E0 native orchestrator must not execute them.
/// E1 resolves canaries only within run-owned fixture roots outside private rootfs;
/// sentinels use existing operator-configured addresses, never route/alias changes.
pub fn isolation_recipe(key: &CaseKey, attempts: &[Uuid]) -> Result<Recipe, Reason> {
    if !supported(key)
        || attempts.len() != usize::from(key.concurrency)
        || attempts.iter().any(Uuid::is_nil)
        || attempts.iter().collect::<BTreeSet<_>>().len() != attempts.len()
    {
        return Err(Reason::InvalidConfig);
    }
    let mut operations = Vec::new();
    if key.scenario == ScenarioId::S01 {
        // Driver capability-inventory fault injection; no host prerequisite changes.
        operations.push(Operation::Preflight {
            missing: key.case.clone(),
        });
        operations.extend([Operation::Observe, Operation::Reconcile]);
    } else {
        for &attempt in attempts {
            operations.push(Operation::Provision {
                attempt,
                fail_after: None,
            });
        }
        operations.push(Operation::RunFixture {
            attempt: attempts[0],
            fixture: format!("isolation/{}", key.case),
        });
        operations.push(Operation::Observe);
        for &attempt in attempts.iter().rev() {
            operations.push(Operation::Destroy { attempt });
        }
    }
    operations.push(Operation::Observe);
    Ok(Recipe {
        operations,
        deadline_ms: 30_000,
    })
}

fn checks(ids: &[CheckId]) -> Vec<Check> {
    ids.iter().map(|&id| Check { id, passed: true }).collect()
}
fn denied(outcome: IsolationOutcome) -> Result<(), Reason> {
    match outcome {
        IsolationOutcome::Denied | IsolationOutcome::Absent => Ok(()),
        IsolationOutcome::Visible | IsolationOutcome::Modified | IsolationOutcome::Signalled => {
            Err(Reason::BoundaryViolation)
        }
    }
}

pub(super) fn evaluate_boundary_observations(
    key: &CaseKey,
    observations: &[IsolationObservation],
) -> Result<Vec<Check>, Reason> {
    use IsolationTarget::*;
    let (target, ids): (_, &[CheckId]) = match (key.scenario, key.case.as_str()) {
        (ScenarioId::S03, name) => (
            match name {
                "host-files" => HostFile,
                "peer-files" => PeerFile,
                "supervisor-credentials" => SupervisorCredential,
                "bind-host" => HostBind,
                "bind-peer" => PeerBind,
                _ => return Err(Reason::InvalidConfig),
            },
            &[CheckId::HostFilesystemDenied, CheckId::PeerFilesystemDenied],
        ),
        (ScenarioId::S04, name) => (
            match name {
                "pid-visibility" => HostProcess,
                "signal-peer" => PeerSignal,
                "ipc-peer" => PeerIpc,
                "uts-private" => Hostname,
                "init-control-fd" => InitControlFd,
                _ => return Err(Reason::InvalidConfig),
            },
            &[CheckId::ProcessIsolated],
        ),
        _ => return Err(Reason::InvalidConfig),
    };
    if observations.is_empty() {
        return Err(Reason::MissingEvidence);
    }
    if observations.len() != 1 || observations[0].target != target {
        return Err(Reason::ProtocolViolation);
    }
    denied(observations[0].outcome)?;
    Ok(checks(ids))
}

// Called only after the authenticated envelope and network inventory are checked.
// D0 outcomes are retained verbatim: refusal/unreachability cannot prove denial.
pub(super) fn evaluate_network_facts(facts: &IsolationFacts) -> Result<Vec<Check>, Reason> {
    if !facts.setup_confirmed || !facts.outside_control_before || !facts.outside_control_after {
        return Err(Reason::MissingEvidence);
    }
    let network = facts.network.as_ref().ok_or(Reason::MissingEvidence)?;
    validate_network_evidence(&network.expected, &network.applied, &network.probes).map_err(
        |error| match error {
            PolicyError::ProbeAllowedForbidden => Reason::BoundaryViolation,
            PolicyError::PolicyMismatch => Reason::StaleEvidence,
            _ => Reason::MissingEvidence,
        },
    )?;
    Ok(checks(&[
        CheckId::NetworkPolicyEnforced,
        CheckId::OutsideControlAvailable,
        CheckId::PublicRegistryReachable,
    ]))
}

fn network_facts(
    wire: NetworkWireFacts,
    key: &CaseKey,
    run_id: Uuid,
    boot_id: Uuid,
) -> Result<QualificationNetworkFacts, Reason> {
    if wire.run_id != run_id || &wire.key != key || wire.applied.generation.boot_id != boot_id {
        return Err(Reason::StaleEvidence);
    }
    let expected = compile_network(
        &wire.policy_config,
        &HostAddresses {
            addresses: wire.host_addresses.clone(),
        },
    )
    .map_err(|_| Reason::StaleEvidence)?;
    let expected_denied: BTreeSet<_> = expected.denied().iter().map(ToString::to_string).collect();
    let applied_denied: BTreeSet<_> = wire
        .applied
        .denied
        .iter()
        .map(ToString::to_string)
        .collect();
    if expected.digest() != wire.expected_digest
        || applied_denied != expected_denied
        || applied_denied.len() != wire.applied.denied.len()
    {
        return Err(Reason::StaleEvidence);
    }
    if wire.probes.negative.is_empty()
        || !(1..=10_000).contains(&wire.probe_deadline_ms)
        || wire.elapsed_ms.len() != wire.probes.negative.len()
    {
        return Err(Reason::MissingEvidence);
    }
    let roles: BTreeSet<_> = wire.sentinels.iter().map(|s| s.role).collect();
    if roles.len() != 4
        || wire.sentinels.len() != wire.probes.negative.len()
        || wire
            .sentinels
            .iter()
            .map(|s| s.address)
            .collect::<BTreeSet<_>>()
            .len()
            != wire.sentinels.len()
    {
        return Err(Reason::StaleEvidence);
    }
    for ((sentinel, probe), elapsed) in wire
        .sentinels
        .iter()
        .zip(&wire.probes.negative)
        .zip(&wire.elapsed_ms)
    {
        let address = sentinel.address.ip();
        let role_matches = match sentinel.role {
            SentinelRole::Loopback => address.is_loopback(),
            SentinelRole::Host => wire.host_addresses.contains(&address),
            SentinelRole::Lan => matches!(address,IpAddr::V4(ip) if ip.is_private()),
            SentinelRole::Production => wire
                .policy_config
                .production_cidrs
                .iter()
                .any(|prefix| prefix.contains(address)),
        };
        if probe.address != sentinel.address
            || sentinel.address.port() == 0
            || !role_matches
            || expected.permits(address)
        {
            return Err(Reason::StaleEvidence);
        }
        if *elapsed > wire.probe_deadline_ms + 1000
            || (probe.observed == ConnectOutcome::TimedOut && *elapsed < wire.probe_deadline_ms)
        {
            return Err(Reason::MissingEvidence);
        }
    }
    Ok(QualificationNetworkFacts {
        expected,
        applied: wire.applied,
        probes: wire.probes,
    })
}

fn evaluate_path(key: &CaseKey, path: Option<PathFacts>, run_id: Uuid) -> Result<(), Reason> {
    let path = path.ok_or(Reason::MissingEvidence)?;
    if path.case != key.case {
        return Err(Reason::StaleEvidence);
    }
    let expected_digest = blake3::hash(make_canaries(run_id).peer.as_bytes())
        .to_hex()
        .to_string();
    if path.before.inode == 0 || path.before.content_digest != expected_digest {
        return Err(Reason::MissingEvidence);
    }
    if path.before != path.after {
        return Err(Reason::BoundaryViolation);
    }
    denied(path.host_outcome)?;
    denied(path.peer_outcome)?;
    let expected = if key.case == "unknown-resource" {
        PathResolution::Quarantined
    } else {
        PathResolution::Rejected
    };
    if path.resolution != expected {
        return Err(Reason::BoundaryViolation);
    }
    Ok(())
}
fn evaluate_capabilities(
    facts: Option<CapabilityFacts>,
    run_id: Uuid,
    peer_id: Uuid,
) -> Result<(), Reason> {
    let facts = facts.ok_or(Reason::MissingEvidence)?;
    let expected_hash = blake3::hash(make_canaries(run_id).credential.as_bytes())
        .to_hex()
        .to_string();
    // Fixture-only known synthetic IDs; E1 must bind actual attempt grants.
    if facts.owner != run_id
        || facts.peer != peer_id
        || facts.owner == facts.peer
        || facts.credential_hash != expected_hash
    {
        return Err(Reason::StaleEvidence);
    }
    if facts.cross_attempt != CapabilityOutcome::Denied
        || facts.after_revoke != CapabilityOutcome::Denied
    {
        return Err(Reason::BoundaryViolation);
    }
    Ok(())
}

pub fn evaluate_isolation(
    key: &CaseKey,
    response: &AuthenticatedResponse,
) -> Result<Vec<Check>, Reason> {
    let provenance = response.provenance();
    if provenance.identity.mode != EvidenceMode::Fixture {
        // No independent collector/authority exists in E0, even for an otherwise
        // authentic native driver. Nested smoke is also not native proof.
        return Err(Reason::BackendUnavailable);
    }
    if !supported(key) {
        return Err(Reason::InvalidConfig);
    }
    if &provenance.key != key {
        return Err(Reason::StaleEvidence);
    }
    let observations = response.observations();
    if observations.is_empty() {
        return Err(Reason::MissingEvidence);
    }
    if observations.len() != 1 || observations[0].name != "isolation" {
        return Err(Reason::ProtocolViolation);
    }
    let raw = &observations[0].value;
    let wire: IsolationWireFacts =
        serde_json::from_value(raw.clone()).map_err(|_| Reason::ProtocolViolation)?;
    // D0's nested types predate deny_unknown_fields. A lossless roundtrip also
    // rejects omitted Option members and unknown fields nested inside D0 types.
    if serde_json::to_value(&wire).map_err(|_| Reason::ProtocolViolation)? != *raw {
        return Err(Reason::ProtocolViolation);
    }
    let network_case = key.scenario == ScenarioId::S05;
    let path_case = key.scenario == ScenarioId::S12;
    let capability_case = network_case && key.case == "scoped-capabilities";
    if (!network_case && wire.network.is_some())
        || (!path_case && wire.path.is_some())
        || (!capability_case && wire.capabilities.is_some())
        || (!matches!(key.scenario, ScenarioId::S03 | ScenarioId::S04)
            && !wire.observations.is_empty())
    {
        return Err(Reason::ProtocolViolation);
    }
    let network = wire
        .network
        .map(|n| {
            network_facts(
                n,
                key,
                provenance.identity.run_id,
                provenance.identity.host_boot_id,
            )
        })
        .transpose()?;
    let facts = IsolationFacts {
        setup_confirmed: wire.setup_confirmed,
        outside_control_before: wire.outside_control_before,
        outside_control_after: wire.outside_control_after,
        network,
        observations: wire.observations,
        peer_unchanged: wire.peer_unchanged,
        polling_started: wire.polling_started,
        rollback_confirmed: wire.rollback_confirmed,
        cleanup_confirmed: wire.cleanup_confirmed,
    };
    if !facts.setup_confirmed {
        return Err(Reason::MissingEvidence);
    }
    if !facts.cleanup_confirmed {
        return Err(Reason::CleanupUnconfirmed);
    }
    if !facts.peer_unchanged {
        return Err(Reason::BoundaryViolation);
    }
    match key.scenario {
        ScenarioId::S01 => {
            if facts.polling_started {
                return Err(Reason::BoundaryViolation);
            }
            if !facts.rollback_confirmed {
                return Err(Reason::CleanupUnconfirmed);
            }
        }
        ScenarioId::S03 | ScenarioId::S04 => {
            evaluate_boundary_observations(key, &facts.observations)?;
        }
        ScenarioId::S05 => {
            evaluate_network_facts(&facts)?;
            if capability_case {
                evaluate_capabilities(
                    wire.capabilities,
                    provenance.identity.run_id,
                    provenance.identity.host_boot_id,
                )?;
            }
        }
        ScenarioId::S12 => {
            evaluate_path(key, wire.path, provenance.identity.run_id)?;
        }
        _ => return Err(Reason::InvalidConfig),
    }
    Ok(checks(required_checks(key)))
}
