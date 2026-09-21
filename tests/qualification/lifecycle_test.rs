use super::catalog::{CaseKey, CheckId, Reason, ScenarioId, Wave, required_cases, required_checks};
use super::driver::{AuthenticatedResponse, DriverRequest, Operation, PinnedDriver, run_driver};
use super::lifecycle::{
    FixtureSequence, LifecycleInput, evaluate_lifecycle, lifecycle_recipe, rollback_matches,
};
use super::report::RunIdentity;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use uuid::Uuid;

fn cases() -> Vec<CaseKey> {
    required_cases()
        .into_iter()
        .filter(|k| {
            matches!(
                k.scenario,
                ScenarioId::S02
                    | ScenarioId::S10
                    | ScenarioId::S11
                    | ScenarioId::S13
                    | ScenarioId::S14
                    | ScenarioId::S15
            )
        })
        .collect()
}
fn key(name: &str) -> CaseKey {
    cases().into_iter().find(|k| k.case == name).unwrap()
}
fn input(key: &CaseKey) -> LifecycleInput {
    LifecycleInput {
        attempts: (0..key.concurrency).map(|_| Uuid::new_v4()).collect(),
        previous_attempts: if matches!(key.scenario, ScenarioId::S14 | ScenarioId::S15) {
            (0..key.concurrency).map(|_| Uuid::new_v4()).collect()
        } else if key.case == "stale-cancel" {
            vec![Uuid::new_v4()]
        } else {
            vec![]
        },
        extra_attempt: (key.scenario == ScenarioId::S13).then(Uuid::new_v4),
        deadline_ms: 30_000,
    }
}
fn canaries(ids: &[Uuid]) -> Vec<String> {
    ids.iter()
        .flat_map(|id| {
            [
                "filesystem",
                "process",
                "environment",
                "docker",
                "cache",
                "artifact",
                "credential",
            ]
            .map(|kind| format!("chimera-qualification:{id}:{kind}"))
        })
        .collect()
}
fn resources(name: &str) -> Vec<&'static str> {
    let n = match name {
        "after-journal" => 0,
        "after-cgroup" => 1,
        "after-namespaces" => 2,
        "after-rootfs" => 3,
        "after-pivot" => 4,
        "after-init" => 5,
        "after-dockerd" | "after-probes" => 6,
        _ => 0,
    };
    vec!["cgroup", "namespaces", "rootfs", "pivot", "init", "dockerd"][..n].to_vec()
}
fn good(key: &CaseKey, input: &LifecycleInput, identity: &RunIdentity) -> Value {
    let created = resources(&key.case);
    let restart = key.scenario == ScenarioId::S11
        || (key.scenario == ScenarioId::S13 && key.wave == Wave::Restart);
    let mut facts = json!({"attempt_ids":input.attempts,"previous_attempt_ids":input.previous_attempts,
        "endpoint_ids":input.attempts.iter().map(|id| format!("endpoint:{id}")).collect::<Vec<_>>(),
        "state_ids":input.attempts.iter().map(|id| format!("writable:{id}")).collect::<Vec<_>>(),
        "provisioned":created,"rolled_back":created.iter().rev().collect::<Vec<_>>(),
        "barrier":if key.scenario == ScenarioId::S13 {"simultaneous-ready-running"} else {key.case.as_str()},
        "wave_trigger":key.wave.as_str(),
        "active_peak":key.concurrency,"simultaneous_ids":input.attempts,"completed_ids":input.attempts,
        "extra_attempt":input.extra_attempt,"extra_admission_blocked":true,"extra_online_before_destroy":false,
        "revoked_before_destroy":true,"destroy_before_completion":true,"elapsed_ms":10,"deadline_ms":input.deadline_ms,
        "remaining_processes":0,"remaining_mounts":0,"remaining_sockets":0,"remaining_writable_roots":0,"remaining_docker_objects":0});
    let rest = json!({
        "owned_enumeration_complete":true,
        "seeded_canaries":if key.scenario == ScenarioId::S13 {seed_rows(&input.attempts)} else {json!([])},
        "scan_manifest":if key.scenario == ScenarioId::S14 {seed_rows(&input.previous_attempts)} else {json!([])},
        "tenant_scans":if key.scenario == ScenarioId::S14 {scan_rows(input)} else {json!([])},
        "next_tenant_canaries":[],"peer_unchanged":true,"cross_capability_rejected":true,"artifact_checked":true,
        "cancel_target":if key.case == "stale-cancel" {Some(input.previous_attempts[0])} else if key.scenario == ScenarioId::S10 {Some(input.attempts[0])} else {None},
        "root_poisoned":false,"cleanup_confirmed":true,
        "cache_variant":if key.wave == Wave::Cold {"empty-owned"} else if key.wave == Wave::Warm {"approved-immutable-only"} else {"isolated-writable"},
        "restart":restart.then(||json!({"phase":if key.scenario == ScenarioId::S11 {key.case.as_str()} else {"running"},
            "acknowledged":true,"supervisor_id":input.attempts[0],"boot_id":identity.host_boot_id,"start_time":123,
            "signalled_supervisor_id":input.attempts[0],"signalled_boot_id":identity.host_boot_id,"signalled_start_time":123,
            "signal":"SIGKILL","same_root":true,"reconciled_before_work":true}))});
    facts
        .as_object_mut()
        .unwrap()
        .extend(rest.as_object().unwrap().clone());
    facts
}

// Inert transport fixture: authenticates through the real pinned-driver protocol.
// No lifecycle operations, daemon signals or native recovery are performed.
// Bound host-side transport subprocesses independently of the 20/40 logical
// attempt cardinality in each recipe. Unbounded parallel table tests can starve
// the existing short-deadline protocol tests during a default full-suite run.
static FIXTURE_TRANSPORTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

async fn response(
    key: &CaseKey,
    input: &LifecycleInput,
    identity: RunIdentity,
    facts: Value,
) -> AuthenticatedResponse {
    response_variant(key, input, identity, facts, false).await
}
async fn response_variant(
    key: &CaseKey,
    input: &LifecycleInput,
    identity: RunIdentity,
    facts: Value,
    different_driver: bool,
) -> AuthenticatedResponse {
    let _permit = FIXTURE_TRANSPORTS.acquire().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("driver");
    let payload = serde_json::to_string(&json!([{"name":"lifecycle","value":facts}])).unwrap();
    let script = r##"#!/usr/bin/python3
import hashlib,json,sys
digest=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
if sys.argv[1]=='--qualification-hello=1':
 print(json.dumps({'schema_version':1,'commit':'a'*40,'binary_digest':digest,'backend':'sandboxed','supported':['S-02','S-10','S-11','S-13','S-14','S-15']})); sys.exit(0)
r=json.load(sys.stdin)
print(json.dumps({'schema_version':1,'run_id':r['identity']['run_id'],'commit':r['identity']['commit'],'config_digest':r['identity']['config_digest'],'host_boot_id':r['identity']['host_boot_id'],'driver_digest':digest,'key':r['key'],'observations':json.load(open(__file__+'.json'))}))
"##;
    std::fs::write(path.with_extension("json"), payload).unwrap();
    std::fs::write(&path, format!("{script}# variant={different_driver}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let driver = PinnedDriver::open_fixture(&path).unwrap();
    run_driver(
        &driver,
        &DriverRequest {
            schema_version: 1,
            identity,
            key: key.clone(),
            recipe: lifecycle_recipe(key, input).unwrap(),
        },
    )
    .await
    .unwrap()
}
async fn result(
    key: &CaseKey,
    input: &LifecycleInput,
    facts: Value,
) -> Result<Vec<super::report::Check>, Reason> {
    let response = response(key, input, super::report_test::identity(), facts).await;
    evaluate_lifecycle(key, input, &response)
}

#[test]
fn lifecycle_reverse_rollback_counts_resources_not_journal_intent() {
    let created = vec!["cgroup".into(), "namespaces".into(), "rootfs".into()];
    assert!(rollback_matches(
        &created,
        &["rootfs".into(), "namespaces".into(), "cgroup".into()]
    ));
    assert!(!rollback_matches(&created, &created));
    for bad in [
        vec!["journal".into()],
        vec!["cgroup".into(), "cgroup".into()],
        vec!["unknown".into()],
    ] {
        assert!(!rollback_matches(&bad, &bad));
    }
    assert!(rollback_matches(&[], &[]));
}

#[tokio::test]
async fn lifecycle_every_catalogue_case_produces_exact_checks_and_bounded_recipe() {
    assert_eq!(cases().len(), 52);
    for key in cases() {
        let input = input(&key);
        let identity = super::report_test::identity();
        let facts = good(&key, &input, &identity);
        let response = response(&key, &input, identity, facts).await;
        let checks = evaluate_lifecycle(&key, &input, &response).unwrap();
        assert_eq!(
            checks.iter().map(|c| c.id).collect::<Vec<_>>(),
            required_checks(&key)
        );
        assert!(checks.iter().all(|c| c.passed));
        if key.scenario == ScenarioId::S13 {
            assert!(
                checks
                    .iter()
                    .any(|c| c.id == CheckId::DistinctStateConfirmed)
            );
            assert!(
                checks
                    .iter()
                    .any(|c| c.id == CheckId::ExtraAdmissionBlocked)
            );
        }
        let recipe = lifecycle_recipe(&key, &input).unwrap();
        assert!(recipe.operations.len() <= 1024);
        assert_eq!(recipe.deadline_ms, input.deadline_ms);
        assert!(matches!(recipe.operations.last(), Some(Operation::Observe)));
        if key.scenario == ScenarioId::S02 {
            assert!(
                matches!(&recipe.operations[..], [Operation::Provision {fail_after:Some(site),..},Operation::Observe,Operation::Reconcile,Operation::Observe] if site == &key.case)
            );
        }
        if key.scenario == ScenarioId::S11 {
            let ops = serde_json::to_value(&recipe.operations).unwrap();
            let ops = ops.as_array().unwrap();
            let crash = ops
                .iter()
                .position(|o| o.get("CrashSupervisor").is_some())
                .unwrap();
            assert!(
                ops[crash - 1]["RunFixture"]["fixture"]
                    .as_str()
                    .unwrap()
                    .starts_with("lifecycle/barrier/")
            );
            assert_eq!(ops[crash + 1], json!("Reconcile"));
        }
    }
}

#[tokio::test]
async fn lifecycle_faults_require_exact_created_prefix_and_reverse_rollback() {
    for key in cases()
        .into_iter()
        .filter(|k| k.scenario == ScenarioId::S02)
    {
        let input = input(&key);
        let mut facts = good(&key, &input, &super::report_test::identity());
        facts["provisioned"] = json!(["journal"]);
        facts["rolled_back"] = json!(["journal"]);
        assert_eq!(
            result(&key, &input, facts).await,
            Err(Reason::BoundaryViolation)
        );
        if key.case != "after-journal" {
            let mut facts = good(&key, &input, &super::report_test::identity());
            facts["provisioned"] = json!([]);
            facts["rolled_back"] = json!([]);
            assert_eq!(
                result(&key, &input, facts).await,
                Err(Reason::MissingEvidence)
            );
        }
    }
}

#[tokio::test]
async fn lifecycle_cancel_order_deadline_and_stale_target_are_enforced() {
    for key in cases()
        .into_iter()
        .filter(|k| k.scenario == ScenarioId::S10)
    {
        let input = input(&key);
        for field in [
            "revoked_before_destroy",
            "destroy_before_completion",
            "peer_unchanged",
        ] {
            let mut facts = good(&key, &input, &super::report_test::identity());
            facts[field] = json!(false);
            assert_eq!(
                result(&key, &input, facts).await,
                Err(Reason::BoundaryViolation)
            );
        }
        let recipe = lifecycle_recipe(&key, &input).unwrap();
        let cancel = recipe
            .operations
            .iter()
            .position(|o| matches!(o, Operation::Cancel { .. }))
            .unwrap();
        assert!(matches!(
            recipe.operations[cancel - 1],
            Operation::RunFixture { .. }
        ));
        assert!(matches!(
            recipe.operations[cancel + 1],
            Operation::Destroy { .. }
        ));
        if let Operation::Cancel { attempt, .. } = recipe.operations[cancel] {
            assert_eq!(
                attempt,
                if key.case == "stale-cancel" {
                    input.previous_attempts[0]
                } else {
                    input.attempts[0]
                }
            );
        }
    }
    let key = key("stale-cancel");
    let input = input(&key);
    for (field, value, reason) in [
        ("elapsed_ms", json!(30_001), Reason::DeadlineExceeded),
        ("deadline_ms", json!(40_000), Reason::StaleEvidence),
        (
            "cancel_target",
            json!(input.attempts[0]),
            Reason::StaleEvidence,
        ),
    ] {
        let mut facts = good(&key, &input, &super::report_test::identity());
        facts[field] = value;
        assert_eq!(result(&key, &input, facts).await, Err(reason));
    }
}

#[tokio::test]
async fn lifecycle_restart_rejects_pid_reuse_unacknowledged_phase_and_work_before_reconcile() {
    for key in cases()
        .into_iter()
        .filter(|k| k.scenario == ScenarioId::S11)
    {
        let input = input(&key);
        let identity = super::report_test::identity();
        for (field, value, reason) in [
            ("acknowledged", json!(false), Reason::MissingEvidence),
            (
                "signalled_start_time",
                json!(124),
                Reason::BoundaryViolation,
            ),
            (
                "signalled_boot_id",
                json!(Uuid::new_v4()),
                Reason::BoundaryViolation,
            ),
            (
                "signalled_supervisor_id",
                json!(Uuid::new_v4()),
                Reason::BoundaryViolation,
            ),
            ("same_root", json!(false), Reason::BoundaryViolation),
            (
                "reconciled_before_work",
                json!(false),
                Reason::BoundaryViolation,
            ),
        ] {
            let mut facts = good(&key, &input, &identity);
            facts["restart"][field] = value;
            let response = response(&key, &input, identity.clone(), facts).await;
            assert_eq!(evaluate_lifecycle(&key, &input, &response), Err(reason));
        }
    }
}

#[tokio::test]
async fn lifecycle_capacity_distinct_state_and_extra_admission_cannot_be_self_declared() {
    let key = cases()
        .into_iter()
        .find(|k| k.scenario == ScenarioId::S13 && k.concurrency == 40)
        .unwrap();
    let input = input(&key);
    for (field, value, reason) in [
        ("active_peak", json!(41), Reason::BoundaryViolation),
        ("active_peak", json!(39), Reason::MissingEvidence),
        (
            "extra_admission_blocked",
            json!(false),
            Reason::BoundaryViolation,
        ),
        (
            "extra_online_before_destroy",
            json!(true),
            Reason::BoundaryViolation,
        ),
        ("simultaneous_ids", json!([]), Reason::MissingEvidence),
        ("completed_ids", json!([]), Reason::MissingEvidence),
        (
            "endpoint_ids",
            json!(vec!["duplicate"; 40]),
            Reason::BoundaryViolation,
        ),
        (
            "state_ids",
            json!(vec!["duplicate"; 40]),
            Reason::BoundaryViolation,
        ),
        (
            "attempt_ids",
            json!(vec![input.attempts[0]; 40]),
            Reason::BoundaryViolation,
        ),
        (
            "attempt_ids",
            json!((0..40).map(|_| Uuid::new_v4()).collect::<Vec<_>>()),
            Reason::StaleEvidence,
        ),
        (
            "endpoint_ids",
            json!((0..40).map(|i| format!("foreign:{i}")).collect::<Vec<_>>()),
            Reason::StaleEvidence,
        ),
        (
            "extra_attempt",
            json!(Uuid::new_v4()),
            Reason::StaleEvidence,
        ),
        (
            "cache_variant",
            json!("host-cache-flush"),
            Reason::BoundaryViolation,
        ),
    ] {
        let mut facts = good(&key, &input, &super::report_test::identity());
        facts[field] = value;
        assert_eq!(result(&key, &input, facts).await, Err(reason), "{field}");
    }
}

#[tokio::test]
async fn lifecycle_next_tenant_scans_all_previous_canaries_and_idle_has_no_owned_residuals() {
    let key = key("next-tenant-clean-after-cold");
    let input = input(&key);
    for (field, value, reason) in [
        ("tenant_scans", json!([]), Reason::MissingEvidence),
        (
            "next_tenant_canaries",
            json!([format!(
                "chimera-qualification:{}:credential",
                input.previous_attempts[0]
            )]),
            Reason::BoundaryViolation,
        ),
        (
            "cross_capability_rejected",
            json!(false),
            Reason::BoundaryViolation,
        ),
        ("artifact_checked", json!(false), Reason::MissingEvidence),
        (
            "previous_attempt_ids",
            json!(vec![Uuid::new_v4(); 20]),
            Reason::BoundaryViolation,
        ),
    ] {
        let mut facts = good(&key, &input, &super::report_test::identity());
        facts[field] = value;
        assert_eq!(result(&key, &input, facts).await, Err(reason));
    }
    for key in cases()
        .into_iter()
        .filter(|k| matches!(k.scenario, ScenarioId::S14 | ScenarioId::S15))
    {
        let input = super::lifecycle_test::input(&key);
        for field in [
            "remaining_processes",
            "remaining_mounts",
            "remaining_sockets",
            "remaining_writable_roots",
            "remaining_docker_objects",
        ] {
            let mut facts = good(&key, &input, &super::report_test::identity());
            facts[field] = json!(1);
            assert_eq!(
                result(&key, &input, facts).await,
                Err(Reason::CleanupUnconfirmed)
            );
        }
    }
}

#[tokio::test]
async fn lifecycle_stop_conditions_outrank_stale_and_missing_evidence() {
    let key = key("capacity-and-distinct-state");
    let input = input(&key);
    for cleanup in [false, true] {
        let mut facts = good(&key, &input, &super::report_test::identity());
        facts["attempt_ids"] = json!([Uuid::new_v4()]);
        facts["completed_ids"] = json!([]);
        facts["extra_online_before_destroy"] = json!(true);
        facts["cleanup_confirmed"] = json!(cleanup);
        assert_eq!(
            result(&key, &input, facts).await,
            Err(if cleanup {
                Reason::BoundaryViolation
            } else {
                Reason::CleanupUnconfirmed
            })
        );
    }
    let mut facts = good(&key, &input, &super::report_test::identity());
    facts["attempt_ids"] = json!([Uuid::new_v4()]);
    facts["completed_ids"] = json!([]);
    assert_eq!(
        result(&key, &input, facts).await,
        Err(Reason::StaleEvidence)
    );
}

#[test]
fn lifecycle_inputs_reject_reused_foreign_shape_and_unbounded_deadline() {
    for key in cases() {
        let original = input(&key);
        for invalid in 0..4 {
            let mut bad = original.clone();
            match invalid {
                0 => bad.attempts[0] = Uuid::nil(),
                1 => bad.attempts.push(bad.attempts[0]),
                2 => bad.deadline_ms = 0,
                _ => bad.deadline_ms = 300_001,
            }
            assert_eq!(
                lifecycle_recipe(&key, &bad).unwrap_err(),
                Reason::InvalidConfig
            );
        }
        if !original.previous_attempts.is_empty() {
            let mut bad = original.clone();
            bad.previous_attempts[0] = bad.attempts[0];
            assert_eq!(
                lifecycle_recipe(&key, &bad).unwrap_err(),
                Reason::InvalidConfig
            );
        }
    }
}

#[tokio::test]
async fn lifecycle_schema_is_closed() {
    let key = key("step");
    let input = input(&key);
    let identity = super::report_test::identity();
    for change in [0, 1] {
        let mut facts = good(&key, &input, &identity);
        if change == 0 {
            facts["passed"] = json!(true);
        } else {
            facts.as_object_mut().unwrap().remove("restart");
        }
        assert_eq!(
            result(&key, &input, facts).await,
            Err(Reason::ProtocolViolation)
        );
    }
}

#[tokio::test]
async fn lifecycle_requires_wave_trigger_and_each_next_tenant_scan() {
    for (name, field, value) in [
        ("capacity-and-distinct-state", "wave_trigger", json!("")),
        ("next-tenant-clean-after-cold", "tenant_scans", json!([])),
    ] {
        let key = key(name);
        let input = input(&key);
        let mut facts = good(&key, &input, &super::report_test::identity());
        facts[field] = value;
        assert_eq!(
            result(&key, &input, facts).await,
            Err(Reason::MissingEvidence)
        );
    }
}

#[tokio::test]
async fn lifecycle_sequence_rejects_changed_driver_before_next_wave() {
    let key = key("capacity-and-distinct-state");
    let input = input(&key);
    let identity = super::report_test::identity();
    let mut sequence = FixtureSequence::default();
    let initial = response(
        &key,
        &input,
        identity.clone(),
        good(&key, &input, &identity),
    )
    .await;
    sequence.accept(&key, &input, &initial).unwrap();
    let next = super::lifecycle_test::key("next-tenant-clean-after-cold");
    let mut next_input = super::lifecycle_test::input(&next);
    next_input.previous_attempts = input.attempts;
    let changed = response_variant(
        &next,
        &next_input,
        identity.clone(),
        good(&next, &next_input, &identity),
        true,
    )
    .await;
    assert_eq!(
        sequence.accept(&next, &next_input, &changed),
        Err(Reason::StaleEvidence)
    );
}

#[test]
fn lifecycle_restart_arms_early_phase_before_provisioning_can_pass_it() {
    for key in cases()
        .into_iter()
        .filter(|k| k.scenario == ScenarioId::S11)
    {
        let input = input(&key);
        let recipe = lifecycle_recipe(&key, &input).unwrap();
        let provision = recipe
            .operations
            .iter()
            .position(|op| matches!(op, Operation::Provision { .. }))
            .unwrap();
        assert!(recipe.operations[..provision].iter().any(|op|matches!(op,
            Operation::RunFixture{fixture,..} if fixture == &format!("lifecycle/arm-phase/{}",key.case))));
    }
}

#[tokio::test]
async fn lifecycle_fixture_sequence_enforces_wave_dependencies_and_poison_stops_followups() {
    for capacity in [20, 40] {
        for wave in [
            Wave::Cold,
            Wave::Warm,
            Wave::Failure,
            Wave::Cancel,
            Wave::Restart,
        ] {
            let mut sequence = FixtureSequence::default();
            let source = cases()
                .into_iter()
                .find(|k| {
                    k.scenario == ScenarioId::S13 && k.wave == wave && k.concurrency == capacity
                })
                .unwrap();
            let source_input = input(&source);
            let identity = super::report_test::identity();
            let source_response = response(
                &source,
                &source_input,
                identity.clone(),
                good(&source, &source_input, &identity),
            )
            .await;
            sequence
                .accept(&source, &source_input, &source_response)
                .unwrap();
            let next = cases()
                .into_iter()
                .find(|k| {
                    k.scenario == ScenarioId::S14
                        && k.concurrency == capacity
                        && k.case.ends_with(wave.as_str())
                })
                .unwrap();
            let mut next_input = input(&next);
            let wrong = response(
                &next,
                &next_input,
                identity.clone(),
                good(&next, &next_input, &identity),
            )
            .await;
            assert_eq!(
                sequence.accept(&next, &next_input, &wrong),
                Err(Reason::StaleEvidence)
            );
            next_input.previous_attempts = source_input.attempts.clone();
            let next_response = response(
                &next,
                &next_input,
                identity.clone(),
                good(&next, &next_input, &identity),
            )
            .await;
            sequence.accept(&next, &next_input, &next_response).unwrap();
            let idle = cases()
                .into_iter()
                .find(|k| {
                    k.scenario == ScenarioId::S15
                        && k.concurrency == capacity
                        && k.case.ends_with(wave.as_str())
                })
                .unwrap();
            let idle_input = next_input.clone();
            let idle_response = response(
                &idle,
                &idle_input,
                identity.clone(),
                good(&idle, &idle_input, &identity),
            )
            .await;
            sequence.accept(&idle, &idle_input, &idle_response).unwrap();
            assert_eq!(sequence.results().len(), 3);
            assert!(!sequence.poisoned());
        }
    }
    let key = key("buildkit");
    let input = input(&key);
    let identity = super::report_test::identity();
    let mut facts = good(&key, &input, &identity);
    facts["remaining_processes"] = json!(1);
    facts["cleanup_confirmed"] = json!(false);
    let bad = response(&key, &input, identity.clone(), facts).await;
    let mut sequence = FixtureSequence::default();
    assert_eq!(
        sequence.accept(&key, &input, &bad),
        Err(Reason::CleanupUnconfirmed)
    );
    assert!(sequence.poisoned());
    assert_eq!(sequence.results().len(), 1);
    assert_eq!(
        sequence.results()[0].reason,
        Some(Reason::CleanupUnconfirmed)
    );
    let clean = response(
        &key,
        &input,
        identity.clone(),
        good(&key, &input, &identity),
    )
    .await;
    assert_eq!(
        sequence.accept(&key, &input, &clean),
        Err(Reason::UnfinishedRun)
    );
    assert_eq!(sequence.results().len(), 1);
}

fn seed_rows(ids: &[Uuid]) -> Value {
    json!(
        ids.iter()
            .map(|id| json!({"attempt":id,"canaries":canaries(&[*id])}))
            .collect::<Vec<_>>()
    )
}
fn scan_rows(input: &LifecycleInput) -> Value {
    json!(
        input
            .attempts
            .iter()
            .map(|id| json!({"attempt":id,"categories":vec![127u8;input.previous_attempts.len()]}))
            .collect::<Vec<_>>()
    )
}

#[tokio::test]
async fn lifecycle_sequence_requires_seeded_source_manifest() {
    let source = key("capacity-and-distinct-state");
    let input = input(&source);
    let identity = super::report_test::identity();
    for mutation in 0..7 {
        let mut facts = good(&source, &input, &identity);
        facts["seeded_canaries"] = seed_rows(&input.attempts);
        let reason = match mutation {
            0 => {
                facts.as_object_mut().unwrap().remove("seeded_canaries");
                Reason::ProtocolViolation
            }
            1 => {
                facts["seeded_canaries"] = json!([]);
                Reason::MissingEvidence
            }
            2 => {
                facts["seeded_canaries"].as_array_mut().unwrap().pop();
                Reason::MissingEvidence
            }
            3 => {
                facts["seeded_canaries"][0]["canaries"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
                Reason::MissingEvidence
            }
            4 => {
                facts["seeded_canaries"][0]["canaries"][0] = json!("wrong-seed-content");
                Reason::StaleEvidence
            }
            5 => {
                facts["seeded_canaries"][0] = facts["seeded_canaries"][1].clone();
                Reason::BoundaryViolation
            }
            _ => {
                facts["seeded_canaries"][0]["canaries"][0] =
                    facts["seeded_canaries"][0]["canaries"][1].clone();
                Reason::BoundaryViolation
            }
        };
        let observed = response(&source, &input, identity.clone(), facts).await;
        let mut sequence = FixtureSequence::default();
        assert_eq!(
            sequence.accept(&source, &input, &observed),
            Err(reason),
            "mutation {mutation}"
        );
        let next = key("next-tenant-clean-after-cold");
        let mut next_input = super::lifecycle_test::input(&next);
        next_input.previous_attempts = input.attempts.clone();
        let fabricated = response(
            &next,
            &next_input,
            identity.clone(),
            good(&next, &next_input, &identity),
        )
        .await;
        assert_eq!(
            sequence.accept(&next, &next_input, &fabricated),
            Err(Reason::UnfinishedRun)
        );
    }
}

#[tokio::test]
async fn lifecycle_sequence_requires_every_destination_source_category_pair() {
    let source = key("capacity-and-distinct-state");
    let source_input = input(&source);
    let identity = super::report_test::identity();
    let next = key("next-tenant-clean-after-cold");
    let mut input = input(&next);
    input.previous_attempts = source_input.attempts.clone();
    for mutation in 0..12 {
        let mut sequence = FixtureSequence::default();
        let seeded = response(
            &source,
            &source_input,
            identity.clone(),
            good(&source, &source_input, &identity),
        )
        .await;
        sequence.accept(&source, &source_input, &seeded).unwrap();
        let mut facts = good(&next, &input, &identity);
        facts["tenant_scans"] = scan_rows(&input);
        let reason = match mutation {
            0 => {
                facts.as_object_mut().unwrap().remove("tenant_scans");
                Reason::ProtocolViolation
            }
            1 => {
                facts["tenant_scans"].as_array_mut().unwrap().pop();
                Reason::MissingEvidence
            }
            2 => {
                facts["tenant_scans"][0]["categories"][0] = json!(126);
                Reason::MissingEvidence
            }
            3 => {
                facts["tenant_scans"][0]["categories"][0] = json!(0);
                Reason::MissingEvidence
            }
            4 => {
                facts["tenant_scans"][0] = facts["tenant_scans"][1].clone();
                Reason::BoundaryViolation
            }
            5 => {
                facts["tenant_scans"][0]["categories"][0] = json!(255);
                Reason::BoundaryViolation
            }
            6 => {
                facts["scan_manifest"][0]["canaries"][0] = json!("unseeded-canary");
                Reason::StaleEvidence
            }
            7 => {
                facts["scan_manifest"].as_array_mut().unwrap().reverse();
                Reason::StaleEvidence
            }
            8 => {
                facts["scan_manifest"].as_array_mut().unwrap().pop();
                Reason::MissingEvidence
            }
            9 => {
                facts["tenant_scans"][0]["categories"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
                Reason::MissingEvidence
            }
            10 => {
                facts["tenant_scans"][0]["categories"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(127));
                Reason::MissingEvidence
            }
            _ => {
                // The union still has every destination and marker, but the
                // first two destinations each searched only half the manifest.
                let count = input.previous_attempts.len();
                facts["tenant_scans"][0]["categories"] = json!(
                    (0..count)
                        .map(|i| if i < count / 2 { 127 } else { 0 })
                        .collect::<Vec<_>>()
                );
                facts["tenant_scans"][1]["categories"] = json!(
                    (0..count)
                        .map(|i| if i >= count / 2 { 127 } else { 0 })
                        .collect::<Vec<_>>()
                );
                Reason::MissingEvidence
            }
        };
        let observed = response(&next, &input, identity.clone(), facts).await;
        assert_eq!(
            sequence.accept(&next, &input, &observed),
            Err(reason),
            "mutation {mutation}"
        );
    }
}

#[tokio::test]
async fn lifecycle_canonicalizes_seed_rows_and_preserves_destination_association() {
    let source = key("capacity-and-distinct-state");
    let source_input = input(&source);
    let identity = super::report_test::identity();
    let mut facts = good(&source, &source_input, &identity);
    facts["seeded_canaries"] = seed_rows(&source_input.attempts);
    facts["seeded_canaries"].as_array_mut().unwrap().reverse();
    for row in facts["seeded_canaries"].as_array_mut().unwrap() {
        row["canaries"].as_array_mut().unwrap().reverse();
    }
    let observed = response(&source, &source_input, identity.clone(), facts).await;
    let mut sequence = FixtureSequence::default();
    sequence.accept(&source, &source_input, &observed).unwrap();
    let next = key("next-tenant-clean-after-cold");
    let mut input = input(&next);
    input.previous_attempts = source_input.attempts;
    let mut facts = good(&next, &input, &identity);
    facts["tenant_scans"] = scan_rows(&input);
    facts["tenant_scans"].as_array_mut().unwrap().reverse();
    let observed = response(&next, &input, identity, facts).await;
    sequence.accept(&next, &input, &observed).unwrap();
}

#[tokio::test]
async fn lifecycle_manifest_failures_preserve_cleanup_boundary_stale_missing_priority() {
    for name in [
        "capacity-and-distinct-state",
        "next-tenant-clean-after-cold",
    ] {
        let key = key(name);
        let input = input(&key);
        for (cleanup, peer, reason) in [
            (true, true, Reason::StaleEvidence),
            (true, false, Reason::BoundaryViolation),
            (false, false, Reason::CleanupUnconfirmed),
        ] {
            let mut facts = good(&key, &input, &super::report_test::identity());
            let field = if key.scenario == ScenarioId::S13 {
                "seeded_canaries"
            } else {
                "scan_manifest"
            };
            facts[field][0]["canaries"]
                .as_array_mut()
                .unwrap()
                .push(json!("foreign-extra-marker"));
            facts["completed_ids"] = json!([]);
            facts["cleanup_confirmed"] = json!(cleanup);
            facts["peer_unchanged"] = json!(peer);
            assert_eq!(result(&key, &input, facts).await, Err(reason));
        }
    }
}
