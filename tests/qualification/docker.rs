//! E0 checks fixture intentions and typed observations, never live Docker proof.
//! E1 resolves these closed operation IDs through the real job engine and owns
//! all objects in the requested attempts. RegistryStart uses SyntheticRegistry
//! inside the primary attempt with no host publish/egress override. PinnedWorkflow
//! copies only the three fixture context files, runs the exact three pins, then
//! verifies pull-by-digest. Checkout/hadolint compatibility remains separate (#49).
//!
//! PrivilegedCanaries runs `--privileged` and probes the synthetic host and peer
//! canaries. NetworkHostListeners runs `--network host` against domain, host and
//! peer listeners: host means the *domain's* network namespace. PublishedPortProbes
//! runs `-p` and probes from the domain, outside host and peer. All S-08 fixtures
//! require before/after positive controls for the outside host and peer listeners.
//! A successful CLI exit alone proves none of these boundaries. Observe after
//! explicit Destroy must account for all owned builders, containers and volumes.
use super::catalog::{CaseKey, Reason, ScenarioId, required_cases, required_checks};
use super::driver::{AuthenticatedResponse, Operation, Recipe};
use super::report::{Check, EvidenceMode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPin {
    pub owner: String,
    pub repository: String,
    pub commit: String,
}

pub fn action_pins() -> [ActionPin; 3] {
    [
        (
            "setup-buildx-action",
            "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
        ),
        ("login-action", "650006c6eb7dba73a995cc03b0b2d7f5ca915bee"),
        (
            "build-push-action",
            "f9f3042f7e2789586610d6e8b85c8f03e5195baf",
        ),
    ]
    .map(|(repository, commit)| ActionPin {
        owner: "docker".into(),
        repository: repository.into(),
        commit: commit.into(),
    })
}
impl ActionPin {
    fn reference(&self) -> String {
        format!("{}/{}@{}", self.owner, self.repository, self.commit)
    }
}

/// Validate parsed content against the closed synthetic workload. Extra steps,
/// keys, mutable refs, different credentials and different contexts fail closed.
pub fn validate_workload(
    actions: &str,
    workflow: &str,
    dockerfile: &str,
    payload: &str,
) -> Result<(), Reason> {
    let pins: [ActionPin; 3] = serde_json::from_str(actions).map_err(|_| Reason::InvalidConfig)?;
    if pins != action_pins()
        || pins
            .iter()
            .any(|p| p.commit.len() != 40 || !p.commit.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(Reason::InvalidConfig);
    }
    let expected = json!({"name":"synthetic-sandbox-qualification","on":"workflow_dispatch","jobs":{"build":{
    "runs-on":"self-hosted","steps":[
            {"uses":pins[0].reference(),"with":{"driver":"docker-container","driver-opts":"network=${{ env.QUALIFICATION_NETWORK }}"}},
        {"uses":pins[1].reference(),"with":{"registry":"${{ env.QUALIFICATION_REGISTRY }}","username":"${{ env.QUALIFICATION_USER }}","password":"${{ secrets.QUALIFICATION_PASSWORD }}"}},
        {"id":"build","uses":pins[2].reference(),"with":{"context":".","push":true,"tags":"${{ env.QUALIFICATION_REGISTRY }}/synthetic:qualification"}},
        {"name":"verify-pull-by-digest","env":{"PUSHED_DIGEST":"${{ steps.build.outputs.digest }}"},"run":concat!(
            "set -eu\n",
            "image=\"$QUALIFICATION_REGISTRY/synthetic@$PUSHED_DIGEST\"\n",
            "docker pull \"$image\"\n",
            "test \"$(docker image inspect --format '{{index .RepoDigests 0}}' \"$image\")\" = \"$image\"\n")}
    ]}}});
    // Parsing a YAML Mapping first rejects duplicate keys before conversion to
    // JSON Value can collapse them. Neither schema accepts arbitrary execution.
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(workflow).map_err(|_| Reason::InvalidConfig)?;
    let actual = serde_json::to_value(yaml).map_err(|_| Reason::InvalidConfig)?;
    if actual != expected
        || dockerfile != "FROM scratch\nCOPY payload.txt /payload.txt\n"
        || payload != "chimera-qualification-synthetic-payload\n"
    {
        return Err(Reason::InvalidConfig);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DockerCommand {
    RegistryStart,
    Login,
    Pull,
    Push,
    PullByDigest,
    Logout,
    Run,
    Exec,
    ContainerRemove,
    ImageLoad,
    ImageList,
    ImageInspect,
    ImageTag,
    ImageRemove,
    VolumeCreate,
    VolumeWriteRead,
    VolumeInspect,
    VolumeRemove,
    NetworkCreate,
    NetworkConnect,
    NetworkInspect,
    NetworkDisconnect,
    NetworkRemove,
    BindOwnWriteRead,
    JobContainer,
    ServiceContainer,
    DockerAction,
    PinnedWorkflow,
    ActionPosts,
    PrivilegedCanaries,
    NetworkHostListeners,
    PublishedPortProbes,
}

pub fn docker_commands(key: &CaseKey) -> Result<Vec<DockerCommand>, Reason> {
    use DockerCommand::*;
    if !matches!(
        key.scenario,
        ScenarioId::S06 | ScenarioId::S07 | ScenarioId::S08
    ) || !required_cases().contains(key)
    {
        return Err(Reason::InvalidConfig);
    }
    Ok(match key.case.as_str() {
        "pull-push-login-logout" => vec![RegistryStart, Login, Pull, Push, PullByDigest, Logout],
        "run-exec" => vec![Run, Exec, ContainerRemove],
        "images" => vec![ImageLoad, ImageList, ImageInspect, ImageTag, ImageRemove],
        "volumes" => vec![VolumeCreate, VolumeWriteRead, VolumeInspect, VolumeRemove],
        "networks" => vec![
            NetworkCreate,
            NetworkConnect,
            NetworkInspect,
            NetworkDisconnect,
            NetworkRemove,
        ],
        "bind-own" => vec![BindOwnWriteRead],
        "job-container" => vec![JobContainer],
        "service-container" => vec![ServiceContainer],
        "docker-action" => vec![DockerAction],
        "pinned-buildx-login-build-push" => {
            vec![RegistryStart, PinnedWorkflow, PullByDigest, ActionPosts]
        }
        "privileged" => vec![PrivilegedCanaries],
        "network-host" => vec![NetworkHostListeners],
        "published-port" => vec![PublishedPortProbes],
        _ => return Err(Reason::InvalidConfig),
    })
}
fn validate_attempts(key: &CaseKey, attempts: &[Uuid]) -> Result<(), Reason> {
    if attempts.len() != usize::from(key.concurrency)
        || attempts.iter().any(Uuid::is_nil)
        || attempts.iter().collect::<BTreeSet<_>>().len() != attempts.len()
    {
        return Err(Reason::InvalidConfig);
    }
    Ok(())
}

pub fn docker_recipe(key: &CaseKey, attempts: &[Uuid]) -> Result<Recipe, Reason> {
    let commands = docker_commands(key)?;
    validate_attempts(key, attempts)?;
    validate_workload(
        include_str!("../fixtures/qualification/actions.json"),
        include_str!("../fixtures/qualification/workflows/pinned-build.yml"),
        include_str!("../fixtures/qualification/workflows/Dockerfile"),
        include_str!("../fixtures/qualification/workflows/payload.txt"),
    )?;
    let mut operations: Vec<_> = attempts
        .iter()
        .map(|&attempt| Operation::Provision {
            attempt,
            fail_after: None,
        })
        .collect();
    for command in commands {
        let name = serde_json::to_value(command).map_err(|_| Reason::InvalidConfig)?;
        operations.push(Operation::RunFixture {
            attempt: attempts[0],
            fixture: format!("docker/{}", name.as_str().ok_or(Reason::InvalidConfig)?),
        });
    }
    operations.push(Operation::Observe);
    operations.extend(
        attempts
            .iter()
            .rev()
            .map(|&attempt| Operation::Destroy { attempt }),
    );
    operations.push(Operation::Observe);
    Ok(Recipe {
        operations,
        deadline_ms: 300_000,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerFacts {
    pub attempts: Vec<Uuid>,
    pub operations: Vec<DockerCommand>,
    pub operation_exit_codes: Vec<i32>,
    pub pushed_digest: Option<String>,
    pub pulled_digest: Option<String>,
    pub builder_driver: Option<String>,
    pub post_order: Vec<String>,
    pub host_canary_reached: bool,
    pub peer_canary_reached: bool,
    pub host_port_reached: bool,
    pub peer_port_reached: bool,
    pub domain_port_reached: bool,
    pub remaining_owned_objects: u64,
    pub cleanup_confirmed: bool,
    registry: Option<RegistryFacts>,
    outside_controls: Option<OutsideControls>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFacts {
    attempt: Uuid,
    address: String,
    buildkit_reachable: bool,
    synthetic_credentials: bool,
    logout_confirmed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutsideControls {
    host_before: bool,
    host_after: bool,
    peer_before: bool,
    peer_after: bool,
}
fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn evaluate_docker(
    key: &CaseKey,
    attempts: &[Uuid],
    response: &AuthenticatedResponse,
) -> Result<Vec<Check>, Reason> {
    if response.provenance().identity.mode != EvidenceMode::Fixture {
        return Err(Reason::BackendUnavailable);
    }
    let commands = docker_commands(key)?;
    validate_attempts(key, attempts)?;
    if &response.provenance().key != key {
        return Err(Reason::StaleEvidence);
    }
    let observations = response.observations();
    if observations.is_empty() {
        return Err(Reason::MissingEvidence);
    }
    if observations.len() != 1 || observations[0].name != "docker" {
        return Err(Reason::ProtocolViolation);
    }
    let raw = &observations[0].value;
    let facts: DockerFacts =
        serde_json::from_value(raw.clone()).map_err(|_| Reason::ProtocolViolation)?;
    // Also require explicit null optional members, so omissions cannot silently
    // turn into evidence that an operation or control was not applicable.
    if serde_json::to_value(&facts).map_err(|_| Reason::ProtocolViolation)? != *raw {
        return Err(Reason::ProtocolViolation);
    }
    if facts.attempts != attempts {
        return Err(Reason::StaleEvidence);
    }
    // Explicit failures outrank absent supporting observations.
    if !facts.cleanup_confirmed
        || facts.remaining_owned_objects != 0
        || facts.registry.as_ref().is_some_and(|r| !r.logout_confirmed)
    {
        return Err(Reason::CleanupUnconfirmed);
    }
    if facts.host_canary_reached
        || facts.peer_canary_reached
        || facts.host_port_reached
        || facts.peer_port_reached
        || facts.operation_exit_codes.iter().any(|&code| code != 0)
    {
        return Err(Reason::BoundaryViolation);
    }
    if facts.operations.is_empty() || facts.operation_exit_codes.len() != commands.len() {
        return Err(Reason::MissingEvidence);
    }
    if facts.operations != commands {
        return Err(Reason::ProtocolViolation);
    }
    let registry_case = commands.contains(&DockerCommand::RegistryStart);
    if registry_case {
        let registry = facts.registry.as_ref().ok_or(Reason::MissingEvidence)?;
        if registry.attempt != attempts[0] {
            return Err(Reason::StaleEvidence);
        }
        if registry.address != "qualification-registry:5000" || !registry.synthetic_credentials {
            return Err(Reason::BoundaryViolation);
        }
        if !registry.buildkit_reachable
            || !facts.pushed_digest.as_deref().is_some_and(valid_digest)
            || facts.pushed_digest != facts.pulled_digest
        {
            return Err(Reason::MissingEvidence);
        }
    } else if facts.registry.is_some()
        || facts.pushed_digest.is_some()
        || facts.pulled_digest.is_some()
    {
        return Err(Reason::ProtocolViolation);
    }
    if key.scenario == ScenarioId::S07 {
        let posts: Vec<_> = action_pins()
            .iter()
            .rev()
            .map(ActionPin::reference)
            .collect();
        if facts.builder_driver.as_deref() != Some("docker-container") || facts.post_order != posts
        {
            return Err(Reason::MissingEvidence);
        }
    } else if facts.builder_driver.is_some() || !facts.post_order.is_empty() {
        return Err(Reason::ProtocolViolation);
    }
    if key.scenario == ScenarioId::S08 {
        let controls = facts.outside_controls.ok_or(Reason::MissingEvidence)?;
        if !controls.host_before
            || !controls.host_after
            || !controls.peer_before
            || !controls.peer_after
            || !facts.domain_port_reached
        {
            return Err(Reason::MissingEvidence);
        }
    } else if facts.outside_controls.is_some() || facts.domain_port_reached {
        return Err(Reason::ProtocolViolation);
    }
    Ok(required_checks(key)
        .iter()
        .map(|&id| Check { id, passed: true })
        .collect())
}
