//! Deterministic E0 fixture recipes and evaluation only. No signal, cgroup or
//! native recovery authority exists here. E1 must authenticate a live supervisor
//! by boot/start identity and retain exact resource authority before using these
//! intentions on a native host. A fixture acknowledgement is never that authority.
use super::catalog::{CaseKey, Reason, ScenarioId, Wave, required_cases, required_checks};
use super::driver::{AuthenticatedResponse, Operation, Recipe};
use super::fixtures::tenant_canaries;
use super::report::{CaseResult, Check, EvidenceMode, RunIdentity, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Trusted expected identities supplied by the fixture orchestrator, never
/// inferred from observations. S-15 reuses S-14's identities for enumeration only.
#[derive(Clone, Debug)]
pub struct LifecycleInput {
    pub attempts: Vec<Uuid>,
    pub previous_attempts: Vec<Uuid>,
    pub extra_attempt: Option<Uuid>,
    pub deadline_ms: u64,
}

const RESOURCES: &[&str] = &["cgroup", "namespaces", "rootfs", "pivot", "init", "dockerd"];
fn created_at(site: &str) -> &[&str] {
    let count = match site {
        "after-journal" => 0,
        "after-cgroup" => 1,
        "after-namespaces" => 2,
        "after-rootfs" => 3,
        "after-pivot" => 4,
        "after-init" => 5,
        "after-dockerd" | "after-probes" => 6,
        _ => 0,
    };
    &RESOURCES[..count]
}

pub fn rollback_matches(created: &[String], removed: &[String]) -> bool {
    created.iter().all(|s| RESOURCES.contains(&s.as_str()))
        && created.iter().collect::<BTreeSet<_>>().len() == created.len()
        && created.iter().rev().eq(removed.iter())
}
fn duplicates<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() != values.len()
}
fn validate(key: &CaseKey, input: &LifecycleInput) -> Result<(), Reason> {
    if !matches!(
        key.scenario,
        ScenarioId::S02
            | ScenarioId::S10
            | ScenarioId::S11
            | ScenarioId::S13
            | ScenarioId::S14
            | ScenarioId::S15
    ) || !required_cases().contains(key)
        || input.attempts.len() != usize::from(key.concurrency)
        || !(1..=300_000).contains(&input.deadline_ms)
    {
        return Err(Reason::InvalidConfig);
    }
    let previous_count = if matches!(key.scenario, ScenarioId::S14 | ScenarioId::S15) {
        usize::from(key.concurrency)
    } else {
        usize::from(key.case == "stale-cancel")
    };
    let ids: Vec<_> = input
        .attempts
        .iter()
        .chain(&input.previous_attempts)
        .chain(input.extra_attempt.iter())
        .copied()
        .collect();
    if input.previous_attempts.len() != previous_count
        || input.extra_attempt.is_some() != (key.scenario == ScenarioId::S13)
        || ids.iter().any(Uuid::is_nil)
        || duplicates(&ids)
    {
        return Err(Reason::InvalidConfig);
    }
    Ok(())
}
fn fixture(attempt: Uuid, name: impl Into<String>) -> Operation {
    Operation::RunFixture {
        attempt,
        fixture: format!("lifecycle/{}", name.into()),
    }
}
fn cache_variant(key: &CaseKey) -> &'static str {
    match key.wave {
        Wave::Cold => "empty-owned",
        Wave::Warm => "approved-immutable-only",
        _ => "isolated-writable",
    }
}

/// Closed fixture commands carry scope through UUIDs, never host paths/PIDs.
/// Barrier commands must acknowledge the phase before the following operation.
/// CrashSupervisor means fixture SIGKILL simulation until E1 provides authority.
pub fn lifecycle_recipe(key: &CaseKey, input: &LifecycleInput) -> Result<Recipe, Reason> {
    validate(key, input)?;
    let primary = input.attempts[0];
    if key.scenario == ScenarioId::S02 {
        return Ok(Recipe {
            operations: vec![
                Operation::Provision {
                    attempt: primary,
                    fail_after: Some(key.case.clone()),
                },
                Operation::Observe,
                Operation::Reconcile,
                Operation::Observe,
            ],
            deadline_ms: input.deadline_ms,
        });
    }
    let mut operations = Vec::new();
    if key.scenario != ScenarioId::S15 {
        operations.push(fixture(primary, format!("cache/{}", cache_variant(key))));
        if key.scenario == ScenarioId::S11 {
            // Provision is an asynchronous fixture request once a phase is
            // armed; it cannot advance past Reserved/Provisioning/etc. before
            // barrier acknowledgement and the simulated exact-identity kill.
            operations.push(fixture(primary, format!("arm-phase/{}", key.case)));
        }
        operations.extend(input.attempts.iter().map(|&attempt| Operation::Provision {
            attempt,
            fail_after: None,
        }));
    }
    match key.scenario {
        ScenarioId::S10 => {
            if key.case == "stale-cancel" {
                operations.push(fixture(
                    primary,
                    format!("retired-identity/{}", input.previous_attempts[0]),
                ));
            }
            operations.push(fixture(primary, format!("barrier/{}", key.case)));
            // Cancel.phase is the closed trigger: cancel, lease loss, failed post
            // or shutdown. The stale case deliberately targets the retired UUID.
            operations.push(Operation::Cancel {
                attempt: input.previous_attempts.first().copied().unwrap_or(primary),
                phase: key.case.clone(),
            });
        }
        ScenarioId::S11 => {
            operations.push(fixture(primary, format!("barrier/{}", key.case)));
            operations.push(Operation::CrashSupervisor {
                phase: key.case.clone(),
            });
            operations.push(Operation::Reconcile);
            operations.push(Operation::Observe);
        }
        ScenarioId::S13 => {
            for &attempt in &input.attempts {
                operations.push(fixture(attempt, "seed-tenant-canaries"));
            }
            operations.push(fixture(primary, "barrier/simultaneous-ready-running"));
            operations.push(Operation::Provision {
                attempt: input.extra_attempt.ok_or(Reason::InvalidConfig)?,
                fail_after: None,
            });
            operations.push(fixture(primary, "assert-extra-blocked-until-destroy"));
            operations.push(Operation::Observe);
            match key.wave {
                Wave::Failure => operations.push(fixture(primary, "wave/failure")),
                Wave::Cancel => {
                    for &attempt in &input.attempts {
                        operations.push(Operation::Cancel {
                            attempt,
                            phase: "running".into(),
                        });
                    }
                }
                Wave::Restart => {
                    operations.push(fixture(primary, "barrier/running"));
                    operations.push(Operation::CrashSupervisor {
                        phase: "running".into(),
                    });
                    operations.push(Operation::Reconcile);
                }
                Wave::Cold | Wave::Warm => operations.push(fixture(primary, "wave/complete")),
                Wave::NextTenant | Wave::Idle => return Err(Reason::InvalidConfig),
            }
        }
        ScenarioId::S14 => {
            // Register the closed previous-wave manifest once. Each new attempt
            // scans every registered canary and rejects old cross-capabilities.
            for &previous in &input.previous_attempts {
                operations.push(fixture(primary, format!("scan-manifest/{previous}")));
            }
            for &attempt in &input.attempts {
                operations.push(fixture(attempt, "scan-prior-tenant-and-capabilities"));
            }
        }
        ScenarioId::S15 => {
            for &attempt in input.attempts.iter().chain(&input.previous_attempts) {
                operations.push(fixture(
                    attempt,
                    "enumerate-owned-descendants-and-writable-state",
                ));
            }
        }
        _ => return Err(Reason::InvalidConfig),
    }
    if key.scenario != ScenarioId::S15 {
        operations.extend(
            input
                .attempts
                .iter()
                .rev()
                .map(|&attempt| Operation::Destroy { attempt }),
        );
        if let Some(attempt) = input.extra_attempt {
            operations.push(Operation::Destroy { attempt });
        }
    }
    operations.push(Operation::Observe);
    Ok(Recipe {
        operations,
        deadline_ms: input.deadline_ms,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleFacts {
    pub attempt_ids: Vec<Uuid>,
    pub previous_attempt_ids: Vec<Uuid>,
    pub endpoint_ids: Vec<String>,
    pub state_ids: Vec<String>,
    pub provisioned: Vec<String>,
    pub rolled_back: Vec<String>,
    pub barrier: String,
    pub wave_trigger: String,
    pub active_peak: u16,
    pub simultaneous_ids: Vec<Uuid>,
    pub completed_ids: Vec<Uuid>,
    pub extra_attempt: Option<Uuid>,
    pub extra_admission_blocked: bool,
    pub extra_online_before_destroy: bool,
    pub revoked_before_destroy: bool,
    pub destroy_before_completion: bool,
    pub elapsed_ms: u64,
    pub deadline_ms: u64,
    pub remaining_processes: u64,
    pub remaining_mounts: u64,
    pub remaining_sockets: u64,
    pub remaining_writable_roots: u64,
    pub remaining_docker_objects: u64,
    pub owned_enumeration_complete: bool,
    pub seeded_canaries: Vec<TenantCanaries>,
    pub scan_manifest: Vec<TenantCanaries>,
    pub tenant_scans: Vec<TenantScan>,
    pub next_tenant_canaries: Vec<String>,
    pub peer_unchanged: bool,
    pub cross_capability_rejected: bool,
    pub artifact_checked: bool,
    pub cancel_target: Option<Uuid>,
    pub root_poisoned: bool,
    pub cleanup_confirmed: bool,
    pub cache_variant: String,
    restart: Option<RestartFacts>,
}

/// A source row acknowledges the seven exact synthetic marker contents seeded
/// in one attempt. S-14 uses these source rows as its shared scan manifest.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCanaries {
    pub attempt: Uuid,
    pub canaries: Vec<String>,
}

/// Fixture-only compact destination × source × category evidence. Each element
/// corresponds to the same-index source in scan_manifest. Bits 0..6 represent
/// filesystem/process/environment/Docker/cache/artifact/credential, respectively.
/// Every element must equal 0x7f. This preserves the full matrix within the
/// protocol's 64 KiB observation cap; it is not live/native proof.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantScan {
    pub attempt: Uuid,
    pub categories: Vec<u8>,
}

fn duplicate_canary_rows(rows: &[TenantCanaries]) -> bool {
    duplicates(&rows.iter().map(|row| row.attempt).collect::<Vec<_>>())
        || rows.iter().any(|row| duplicates(&row.canaries))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartFacts {
    phase: String,
    acknowledged: bool,
    supervisor_id: Uuid,
    boot_id: Uuid,
    start_time: u64,
    signalled_supervisor_id: Uuid,
    signalled_boot_id: Uuid,
    signalled_start_time: u64,
    signal: String,
    same_root: bool,
    reconciled_before_work: bool,
}

fn decode(
    key: &CaseKey,
    input: &LifecycleInput,
    response: &AuthenticatedResponse,
) -> Result<LifecycleFacts, Reason> {
    if response.provenance().identity.mode != EvidenceMode::Fixture {
        return Err(Reason::BackendUnavailable);
    }
    validate(key, input)?;
    if &response.provenance().key != key {
        return Err(Reason::StaleEvidence);
    }
    let observations = response.observations();
    if observations.is_empty() {
        return Err(Reason::MissingEvidence);
    }
    if observations.len() != 1 || observations[0].name != "lifecycle" {
        return Err(Reason::ProtocolViolation);
    }
    let raw = &observations[0].value;
    let facts: LifecycleFacts =
        serde_json::from_value(raw.clone()).map_err(|_| Reason::ProtocolViolation)?;
    if serde_json::to_value(&facts).map_err(|_| Reason::ProtocolViolation)? != *raw {
        return Err(Reason::ProtocolViolation);
    }
    Ok(facts)
}

pub fn evaluate_lifecycle(
    key: &CaseKey,
    input: &LifecycleInput,
    response: &AuthenticatedResponse,
) -> Result<Vec<Check>, Reason> {
    let facts = decode(key, input, response)?;
    evaluate_facts(key, input, response, &facts)?;
    Ok(required_checks(key)
        .iter()
        .map(|&id| Check { id, passed: true })
        .collect())
}
fn evaluate_facts(
    key: &CaseKey,
    input: &LifecycleInput,
    response: &AuthenticatedResponse,
    f: &LifecycleFacts,
) -> Result<(), Reason> {
    // Trusted envelope and closed schema first; thereafter never hide an explicit
    // stop condition behind stale identities or absent positive evidence.
    if !f.cleanup_confirmed
        || f.root_poisoned
        || !f.owned_enumeration_complete
        || [
            f.remaining_processes,
            f.remaining_mounts,
            f.remaining_sockets,
            f.remaining_writable_roots,
            f.remaining_docker_objects,
        ]
        .iter()
        .any(|&n| n != 0)
    {
        return Err(Reason::CleanupUnconfirmed);
    }
    if !f.revoked_before_destroy
        || !f.destroy_before_completion
        || !f.peer_unchanged
        || !f.cross_capability_rejected
        || !f.next_tenant_canaries.is_empty()
        || f.active_peak > key.concurrency
        || f.extra_online_before_destroy
        || (key.scenario == ScenarioId::S13 && !f.extra_admission_blocked)
        || duplicates(&f.attempt_ids)
        || duplicates(&f.previous_attempt_ids)
        || duplicates(&f.endpoint_ids)
        || duplicates(&f.state_ids)
        || duplicates(&f.simultaneous_ids)
        || duplicates(&f.completed_ids)
        || duplicate_canary_rows(&f.seeded_canaries)
        || duplicate_canary_rows(&f.scan_manifest)
        || duplicates(
            &f.tenant_scans
                .iter()
                .map(|row| row.attempt)
                .collect::<Vec<_>>(),
        )
        || f.tenant_scans
            .iter()
            .any(|row| row.categories.iter().any(|mask| mask & !0x7f != 0))
        || !rollback_matches(&f.provisioned, &f.rolled_back)
        || f.cache_variant != cache_variant(key)
        || f.restart.as_ref().is_some_and(|r| {
            r.signalled_supervisor_id != r.supervisor_id
                || r.signalled_boot_id != r.boot_id
                || r.signalled_start_time != r.start_time
                || r.signal != "SIGKILL"
                || !r.same_root
                || !r.reconciled_before_work
        })
    {
        return Err(Reason::BoundaryViolation);
    }
    let expected_endpoints: Vec<_> = input
        .attempts
        .iter()
        .map(|id| format!("endpoint:{id}"))
        .collect();
    let expected_state: Vec<_> = input
        .attempts
        .iter()
        .map(|id| format!("writable:{id}"))
        .collect();
    // Empty collections are missing; nonempty foreign identities are stale.
    let foreign =
        |actual: &[Uuid], expected: &[Uuid]| actual.iter().any(|id| !expected.contains(id));
    let seed_attempts = if key.scenario == ScenarioId::S13 {
        input.attempts.as_slice()
    } else {
        &[]
    };
    let scan_attempts = if key.scenario == ScenarioId::S14 {
        input.attempts.as_slice()
    } else {
        &[]
    };
    let previous_attempts = if key.scenario == ScenarioId::S14 {
        input.previous_attempts.as_slice()
    } else {
        &[]
    };
    let cancel = if key.scenario == ScenarioId::S10 {
        Some(
            input
                .previous_attempts
                .first()
                .copied()
                .unwrap_or(input.attempts[0]),
        )
    } else {
        None
    };
    if foreign(&f.attempt_ids, &input.attempts)
        || foreign(&f.previous_attempt_ids, &input.previous_attempts)
        || foreign(&f.simultaneous_ids, &input.attempts)
        || foreign(&f.completed_ids, &input.attempts)
        || f.seeded_canaries.iter().any(|row| {
            !seed_attempts.contains(&row.attempt)
                || row
                    .canaries
                    .iter()
                    .any(|marker| !tenant_canaries(&[row.attempt]).contains(marker))
        })
        || f.tenant_scans
            .iter()
            .any(|row| !scan_attempts.contains(&row.attempt))
        || f.scan_manifest
            .iter()
            .zip(previous_attempts)
            .any(|(row, expected)| row.attempt != *expected)
        || f.scan_manifest.iter().any(|row| {
            !previous_attempts.contains(&row.attempt)
                || row
                    .canaries
                    .iter()
                    .any(|marker| !tenant_canaries(&[row.attempt]).contains(marker))
                || row
                    .canaries
                    .iter()
                    .zip(tenant_canaries(&[row.attempt]))
                    .any(|(marker, expected)| marker != &expected)
        })
        || f.endpoint_ids
            .iter()
            .any(|id| !expected_endpoints.contains(id))
        || f.state_ids.iter().any(|id| !expected_state.contains(id))
        || f.extra_attempt != input.extra_attempt
        || f.cancel_target != cancel
        || f.deadline_ms != input.deadline_ms
        || f.restart.as_ref().is_some_and(|r| {
            r.supervisor_id != input.attempts[0]
                || r.boot_id != response.provenance().identity.host_boot_id
        })
    {
        return Err(Reason::StaleEvidence);
    }
    if f.elapsed_ms > input.deadline_ms {
        return Err(Reason::DeadlineExceeded);
    }
    let restart_required = key.scenario == ScenarioId::S11
        || (key.scenario == ScenarioId::S13 && key.wave == Wave::Restart);
    if restart_required {
        let r = f.restart.as_ref().ok_or(Reason::MissingEvidence)?;
        let phase = if key.scenario == ScenarioId::S11 {
            key.case.as_str()
        } else {
            "running"
        };
        if !r.acknowledged || r.start_time == 0 || r.phase != phase {
            return Err(Reason::MissingEvidence);
        }
    } else if f.restart.is_some() {
        return Err(Reason::ProtocolViolation);
    }
    let barrier = if key.scenario == ScenarioId::S13 {
        "simultaneous-ready-running"
    } else {
        key.case.as_str()
    };
    if f.attempt_ids != input.attempts
        || f.previous_attempt_ids != input.previous_attempts
        || f.endpoint_ids != expected_endpoints
        || f.state_ids != expected_state
        || f.completed_ids != input.attempts
        || f.barrier != barrier
        || f.wave_trigger != key.wave.as_str()
        // Membership and uniqueness were checked above. Cardinalities finish
        // seed coverage; scan masks cover canonical source/category positions.
        || f.seeded_canaries.len() != seed_attempts.len()
        || f.seeded_canaries.iter().any(|row| row.canaries.len() != tenant_canaries(&[row.attempt]).len())
        || f.tenant_scans.len() != scan_attempts.len()
        || f.scan_manifest.len() != previous_attempts.len()
        || f.scan_manifest.iter().any(|row|row.canaries.len()!=7)
        || f.tenant_scans.iter().any(|row| row.categories.len() != previous_attempts.len() || row.categories.iter().any(|&mask|mask!=0x7f))
        || (key.scenario == ScenarioId::S13
            && (f.active_peak != key.concurrency || f.simultaneous_ids != input.attempts))
        || f.provisioned.iter().map(String::as_str).collect::<Vec<_>>() != created_at(&key.case)
        || (key.scenario == ScenarioId::S14 && !f.artifact_checked)
    {
        return Err(Reason::MissingEvidence);
    }
    Ok(())
}

/// Fixture-only accept/stop model, not a native executor or recovery mechanism.
/// Retains typed partial rows. Unknown cleanup poisons this model permanently;
/// constructing another model cannot clear a native lease/unfinished marker.
#[derive(Default)]
pub struct FixtureSequence {
    results: Vec<CaseResult>,
    poisoned: bool,
    halted: bool,
    identity: Option<RunIdentity>,
    driver_digest: Option<String>,
    pending: Option<PendingWave>,
    used: BTreeSet<Uuid>,
}

struct PendingWave {
    key: CaseKey,
    input: LifecycleInput,
    // Accepted source observations, not a regenerated expectation. Only an
    // S-13 Passed result can populate this manifest for the next tenant wave.
    seeded_canaries: Vec<TenantCanaries>,
}

impl FixtureSequence {
    pub fn results(&self) -> &[CaseResult] {
        &self.results
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn accept(
        &mut self,
        key: &CaseKey,
        input: &LifecycleInput,
        response: &AuthenticatedResponse,
    ) -> Result<Vec<Check>, Reason> {
        if self.halted {
            return Err(Reason::UnfinishedRun);
        }
        let evaluated = evaluate_lifecycle(key, input, response);
        // Evaluate affirmative stop conditions before wave association checks.
        if let Err(reason) = evaluated {
            self.poisoned = matches!(
                reason,
                Reason::CleanupUnconfirmed | Reason::ProtocolViolation | Reason::MissingEvidence
            );
            self.halted = true;
            self.record(key, response, Err(reason), 0);
            return Err(reason);
        }
        if self
            .identity
            .as_ref()
            .is_some_and(|id| id != &response.provenance().identity)
            || self
                .driver_digest
                .as_ref()
                .is_some_and(|digest| digest != &response.provenance().driver_digest)
        {
            return Err(Reason::StaleEvidence);
        }
        let facts = decode(key, input, response)?;
        match key.scenario {
            ScenarioId::S14 | ScenarioId::S15 => {
                let pending = self.pending.as_ref().ok_or(Reason::MissingEvidence)?;
                let (previous, expected) = (&pending.key, &pending.input);
                let valid = if key.scenario == ScenarioId::S14 {
                    previous.scenario == ScenarioId::S13
                        && key.case == format!("next-tenant-clean-after-{}", previous.wave.as_str())
                        && input.previous_attempts == expected.attempts
                        && !pending.seeded_canaries.is_empty()
                        && facts.scan_manifest.len() == pending.seeded_canaries.len()
                        && facts
                            .scan_manifest
                            .iter()
                            .zip(&pending.seeded_canaries)
                            .all(|(scan, seed)| {
                                scan.attempt == seed.attempt && scan.canaries == seed.canaries
                            })
                } else {
                    previous.scenario == ScenarioId::S14
                        && key.case
                            == previous
                                .case
                                .replace("next-tenant-clean", "zero-domain-processes")
                        && input.attempts == expected.attempts
                        && input.previous_attempts == expected.previous_attempts
                };
                if !valid || key.concurrency != previous.concurrency {
                    return Err(Reason::StaleEvidence);
                }
            }
            _ if self.pending.is_some() => return Err(Reason::MissingEvidence),
            _ => {}
        }
        if key.scenario != ScenarioId::S15
            && input
                .attempts
                .iter()
                .chain(input.extra_attempt.iter())
                .any(|id| self.used.contains(id))
        {
            return Err(Reason::StaleEvidence);
        }
        self.identity = Some(response.provenance().identity.clone());
        self.driver_digest = Some(response.provenance().driver_digest.clone());
        self.used.extend(
            input
                .attempts
                .iter()
                .chain(input.extra_attempt.iter())
                .copied(),
        );
        // Canonicalize the validated observed seeds, preserving their actual
        // content. S-14 must supply this retained manifest in exactly this order.
        let mut seeded_canaries = facts.seeded_canaries;
        seeded_canaries.sort_by_key(|row| input.attempts.iter().position(|id| id == &row.attempt));
        for row in &mut seeded_canaries {
            let expected = tenant_canaries(&[row.attempt]);
            row.canaries
                .sort_by_key(|marker| expected.iter().position(|item| item == marker));
        }
        self.pending = if matches!(key.scenario, ScenarioId::S13 | ScenarioId::S14) {
            Some(PendingWave {
                key: key.clone(),
                input: input.clone(),
                seeded_canaries,
            })
        } else {
            None
        };
        self.record(key, response, evaluated.clone(), facts.elapsed_ms);
        evaluated
    }
    fn record(
        &mut self,
        key: &CaseKey,
        response: &AuthenticatedResponse,
        result: Result<Vec<Check>, Reason>,
        duration_ms: u64,
    ) {
        let (verdict, reason, checks) = match result {
            Ok(checks) => (Verdict::Passed, None, checks),
            Err(reason) => (Verdict::Failed, Some(reason), vec![]),
        };
        self.results.push(CaseResult {
            key: key.clone(),
            verdict,
            reason,
            provenance: response.provenance().clone(),
            checks,
            duration_ms,
        });
    }
}
