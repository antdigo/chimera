use super::catalog::{CaseKey, CheckId, Reason, ScenarioId, required_cases};
use super::docker::{
    action_pins, docker_commands, docker_recipe, evaluate_docker, validate_workload,
};
use super::driver::{DriverRequest, PinnedDriver, run_driver};
use super::fixtures::SyntheticRegistry;
use super::report::{EvidenceMode, RunIdentity};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use uuid::Uuid;

const ACTIONS: &str = include_str!("../fixtures/qualification/actions.json");
const WORKFLOW: &str = include_str!("../fixtures/qualification/workflows/pinned-build.yml");
const DOCKERFILE: &str = include_str!("../fixtures/qualification/workflows/Dockerfile");
const PAYLOAD: &str = include_str!("../fixtures/qualification/workflows/payload.txt");

fn cases() -> Vec<CaseKey> {
    required_cases()
        .into_iter()
        .filter(|k| {
            matches!(
                k.scenario,
                ScenarioId::S06 | ScenarioId::S07 | ScenarioId::S08
            )
        })
        .collect()
}
fn key(name: &str) -> CaseKey {
    cases().into_iter().find(|k| k.case == name).unwrap()
}
fn attempts(key: &CaseKey) -> Vec<Uuid> {
    (0..key.concurrency).map(|_| Uuid::new_v4()).collect()
}
fn commands(name: &str) -> Vec<&'static str> {
    match name {
        "pull-push-login-logout" => vec![
            "registry-start",
            "login",
            "pull",
            "push",
            "pull-by-digest",
            "logout",
        ],
        "run-exec" => vec!["run", "exec", "container-remove"],
        "images" => vec![
            "image-load",
            "image-list",
            "image-inspect",
            "image-tag",
            "image-remove",
        ],
        "volumes" => vec![
            "volume-create",
            "volume-write-read",
            "volume-inspect",
            "volume-remove",
        ],
        "networks" => vec![
            "network-create",
            "network-connect",
            "network-inspect",
            "network-disconnect",
            "network-remove",
        ],
        "bind-own" => vec!["bind-own-write-read"],
        "job-container" => vec!["job-container"],
        "service-container" => vec!["service-container"],
        "docker-action" => vec!["docker-action"],
        "pinned-buildx-login-build-push" => vec![
            "registry-start",
            "pinned-workflow",
            "pull-by-digest",
            "action-posts",
        ],
        "privileged" => vec!["privileged-canaries"],
        "network-host" => vec!["network-host-listeners"],
        "published-port" => vec!["published-port-probes"],
        _ => unreachable!(),
    }
}
fn good(key: &CaseKey, ids: &[Uuid]) -> Value {
    let registry_case = matches!(
        key.case.as_str(),
        "pull-push-login-logout" | "pinned-buildx-login-build-push"
    );
    let digest = format!("sha256:{}", "a".repeat(64));
    json!({"attempts":ids,"operations":commands(&key.case),
        "operation_exit_codes":vec![0;commands(&key.case).len()],
        "pushed_digest":registry_case.then_some(&digest),"pulled_digest":registry_case.then_some(&digest),
        "builder_driver":(key.scenario == ScenarioId::S07).then_some("docker-container"),
        "post_order":if key.scenario == ScenarioId::S07 {vec![
            "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
            "docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee",
            "docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5"]} else {vec![]},
        "host_canary_reached":false,"peer_canary_reached":false,"host_port_reached":false,"peer_port_reached":false,
        "domain_port_reached":key.scenario == ScenarioId::S08,
        "outside_controls":if key.scenario == ScenarioId::S08 {json!({"host_before":true,"host_after":true,"peer_before":true,"peer_after":true})} else {Value::Null},
        "registry":registry_case.then(||json!({"attempt":ids[0],"address":"qualification-registry:5000","buildkit_reachable":true,"synthetic_credentials":true,"logout_confirmed":true})),
        "remaining_owned_objects":0,"cleanup_confirmed":true})
}

// Inert executable drives the real authenticated protocol; it runs no Docker,
// network listener or host operation. Tests exercise decoding and evaluation.
async fn evaluate(
    key: &CaseKey,
    ids: &[Uuid],
    identity: RunIdentity,
    observations: Value,
    evaluation_key: &CaseKey,
) -> Result<Vec<super::report::Check>, Reason> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("driver");
    let payload = serde_json::to_string(&observations).unwrap();
    let script = format!(
        r##"#!/usr/bin/python3
import hashlib,json,sys
digest=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
if sys.argv[1]=='--qualification-hello=1':
 print(json.dumps({{'schema_version':1,'commit':'a'*40,'binary_digest':digest,'backend':'sandboxed','supported':['S-06','S-07','S-08']}})); sys.exit(0)
r=json.load(sys.stdin)
print(json.dumps({{'schema_version':1,'run_id':r['identity']['run_id'],'commit':r['identity']['commit'],'config_digest':r['identity']['config_digest'],'host_boot_id':r['identity']['host_boot_id'],'driver_digest':digest,'key':r['key'],'observations':json.loads({payload:?})}}))
"##
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let driver = PinnedDriver::open_fixture(&path).unwrap();
    let response = run_driver(
        &driver,
        &DriverRequest {
            schema_version: 1,
            identity,
            key: key.clone(),
            recipe: docker_recipe(key, ids).unwrap(),
        },
    )
    .await?;
    evaluate_docker(evaluation_key, ids, &response)
}
async fn result(
    key: &CaseKey,
    ids: &[Uuid],
    facts: Value,
) -> Result<Vec<super::report::Check>, Reason> {
    evaluate(
        key,
        ids,
        super::report_test::identity(),
        json!([{"name":"docker","value":facts}]),
        key,
    )
    .await
}

#[test]
fn docker_exact_pins_and_strict_synthetic_workload() {
    let pins = action_pins();
    assert_eq!(
        pins.iter()
            .map(|p| (p.owner.as_str(), p.repository.as_str(), p.commit.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (
                "docker",
                "setup-buildx-action",
                "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5"
            ),
            (
                "docker",
                "login-action",
                "650006c6eb7dba73a995cc03b0b2d7f5ca915bee"
            ),
            (
                "docker",
                "build-push-action",
                "f9f3042f7e2789586610d6e8b85c8f03e5195baf"
            )
        ]
    );
    validate_workload(ACTIONS, WORKFLOW, DOCKERFILE, PAYLOAD).unwrap();
    for replacement in ["main", "v3", &"g".repeat(40), &"a".repeat(40)] {
        assert_eq!(
            validate_workload(
                &ACTIONS.replace(&pins[0].commit, replacement),
                &WORKFLOW.replace(&pins[0].commit, replacement),
                DOCKERFILE,
                PAYLOAD
            ),
            Err(Reason::InvalidConfig)
        );
    }
    for bad in [
        WORKFLOW.replace("docker-container", "docker"),
        WORKFLOW.replace(
            "          driver-opts: network=${{ env.QUALIFICATION_NETWORK }}\n",
            "",
        ),
        WORKFLOW.replace("context: .", "context: /host"),
        WORKFLOW.replace("push: true", "push: false"),
        WORKFLOW.replace("docker pull", "echo"),
        WORKFLOW.replace(
            "password: ${{ secrets.QUALIFICATION_PASSWORD }}",
            "password: literal",
        ),
        format!("{WORKFLOW}\nunexpected: true\n"),
    ] {
        assert_eq!(
            validate_workload(ACTIONS, &bad, DOCKERFILE, PAYLOAD),
            Err(Reason::InvalidConfig)
        );
    }
    assert_eq!(
        validate_workload(ACTIONS, WORKFLOW, "FROM alpine\n", PAYLOAD),
        Err(Reason::InvalidConfig)
    );
    assert_eq!(
        validate_workload(ACTIONS, WORKFLOW, DOCKERFILE, "real payload"),
        Err(Reason::InvalidConfig)
    );
    let extra = ACTIONS.replacen("\"owner\":", "\"unknown\":true,\"owner\":", 1);
    assert_eq!(
        validate_workload(&extra, WORKFLOW, DOCKERFILE, PAYLOAD),
        Err(Reason::InvalidConfig)
    );
}

#[test]
fn docker_recipes_cover_every_operation_and_destroy_each_owned_attempt() {
    for key in cases() {
        let ids = attempts(&key);
        let typed = docker_commands(&key).unwrap();
        assert_eq!(
            serde_json::to_value(&typed).unwrap(),
            json!(commands(&key.case))
        );
        let recipe = docker_recipe(&key, &ids).unwrap();
        let mut expected: Vec<_> = ids
            .iter()
            .map(|id| json!({"Provision":{"attempt":id,"fail_after":null}}))
            .collect();
        expected.extend(commands(&key.case).iter().map(
            |name| json!({"RunFixture":{"attempt":ids[0],"fixture":format!("docker/{name}")}}),
        ));
        expected.push(json!("Observe"));
        expected.extend(ids.iter().rev().map(|id| json!({"Destroy":{"attempt":id}})));
        expected.push(json!("Observe"));
        assert_eq!(
            serde_json::to_value(&recipe.operations).unwrap(),
            json!(expected)
        );
        assert!((1..=300_000).contains(&recipe.deadline_ms));
        assert_eq!(docker_recipe(&key, &[]).unwrap_err(), Reason::InvalidConfig);
        assert_eq!(
            docker_recipe(&key, &vec![Uuid::nil(); ids.len()]).unwrap_err(),
            Reason::InvalidConfig
        );
        if ids.len() == 2 {
            assert_eq!(
                docker_recipe(&key, &[ids[0], ids[0]]).unwrap_err(),
                Reason::InvalidConfig
            );
        }
    }
    let mut bad = key("privileged");
    bad.concurrency = 1;
    assert_eq!(
        docker_recipe(&bad, &[Uuid::new_v4()]).unwrap_err(),
        Reason::InvalidConfig
    );
}

#[test]
fn docker_registry_credentials_are_fresh_masked_and_attempt_local() {
    let id = Uuid::new_v4();
    let a = SyntheticRegistry::new(id).unwrap();
    let b = SyntheticRegistry::new(id).unwrap();
    assert!(a.password() != b.password());
    assert_eq!(a.attempt, id);
    assert_eq!(a.address, "qualification-registry:5000");
    assert_eq!(a.network, format!("qualification-{}", id.simple()));
    assert_eq!(a.username(), "synthetic-qualification");
    assert_eq!(
        a.redact(&format!("password={}", a.password())),
        "password=***"
    );
    assert!(SyntheticRegistry::new(Uuid::nil()).is_err());
    let recipe = serde_json::to_string(
        &docker_recipe(&key("pinned-buildx-login-build-push"), &[id]).unwrap(),
    )
    .unwrap();
    assert!(!recipe.contains(a.password()));
}

#[tokio::test]
async fn docker_fixture_evaluator_covers_exact_catalogue_checks() {
    for key in cases() {
        let ids = attempts(&key);
        let checks = result(&key, &ids, good(&key, &ids)).await.unwrap();
        let expected = match key.scenario {
            ScenarioId::S06 => vec![CheckId::DockerApiCompatible, CheckId::CleanupConfirmed],
            ScenarioId::S07 => vec![
                CheckId::DockerApiCompatible,
                CheckId::BuildxCompatible,
                CheckId::CleanupConfirmed,
            ],
            ScenarioId::S08 => vec![
                CheckId::NetworkPolicyEnforced,
                CheckId::ChangedHostSemanticsContained,
                CheckId::CleanupConfirmed,
            ],
            _ => unreachable!(),
        };
        assert_eq!(checks.iter().map(|c| c.id).collect::<Vec<_>>(), expected);
        assert!(checks.iter().all(|c| c.passed));
    }
}

#[tokio::test]
async fn docker_rejects_missing_wrong_or_failed_operations_and_cleanup() {
    for key in cases() {
        let ids = attempts(&key);
        for (field, value, reason) in [
            ("operation_exit_codes", json!([]), Reason::MissingEvidence),
            ("operations", json!([]), Reason::MissingEvidence),
            (
                "cleanup_confirmed",
                json!(false),
                Reason::CleanupUnconfirmed,
            ),
            (
                "remaining_owned_objects",
                json!(1),
                Reason::CleanupUnconfirmed,
            ),
        ] {
            let mut facts = good(&key, &ids);
            facts[field] = value;
            assert_eq!(result(&key, &ids, facts).await.unwrap_err(), reason);
        }
        let mut facts = good(&key, &ids);
        facts["operation_exit_codes"][0] = json!(1);
        assert_eq!(
            result(&key, &ids, facts).await.unwrap_err(),
            Reason::BoundaryViolation
        );
    }
    let key = key("run-exec");
    let ids = attempts(&key);
    for operations in [
        json!(["exec", "run", "container-remove"]),
        json!(["run", "run", "container-remove"]),
    ] {
        let mut facts = good(&key, &ids);
        facts["operations"] = operations;
        assert_eq!(
            result(&key, &ids, facts).await.unwrap_err(),
            Reason::ProtocolViolation
        );
    }
}

#[tokio::test]
async fn docker_registry_requires_same_attempt_and_matching_immutable_digest() {
    for name in ["pull-push-login-logout", "pinned-buildx-login-build-push"] {
        let key = key(name);
        let ids = attempts(&key);
        for digest in [
            Value::Null,
            json!("latest"),
            json!("sha256:abcd"),
            json!(format!("sha256:{}", "g".repeat(64))),
            json!(format!("sha256:{}", "b".repeat(64))),
        ] {
            let mut facts = good(&key, &ids);
            facts["pulled_digest"] = digest;
            assert_eq!(
                result(&key, &ids, facts).await.unwrap_err(),
                Reason::MissingEvidence
            );
        }
        for (field, value, reason) in [
            ("attempt", json!(Uuid::new_v4()), Reason::StaleEvidence),
            (
                "address",
                json!("host.docker.internal:5000"),
                Reason::BoundaryViolation,
            ),
            ("buildkit_reachable", json!(false), Reason::MissingEvidence),
            (
                "synthetic_credentials",
                json!(false),
                Reason::BoundaryViolation,
            ),
            ("logout_confirmed", json!(false), Reason::CleanupUnconfirmed),
        ] {
            let mut facts = good(&key, &ids);
            facts["registry"][field] = value;
            assert_eq!(result(&key, &ids, facts).await.unwrap_err(), reason);
        }
    }
}

#[tokio::test]
async fn docker_buildx_requires_exact_reverse_posts_and_container_driver() {
    let key = key("pinned-buildx-login-build-push");
    let ids = attempts(&key);
    for value in [Value::Null, json!("docker"), json!("remote")] {
        let mut facts = good(&key, &ids);
        facts["builder_driver"] = value;
        assert_eq!(
            result(&key, &ids, facts).await.unwrap_err(),
            Reason::MissingEvidence
        );
    }
    for kind in 0..4 {
        let mut facts = good(&key, &ids);
        let posts = facts["post_order"].as_array_mut().unwrap();
        match kind {
            0 => posts.reverse(),
            1 => {
                posts.pop();
            }
            2 => posts.push(posts[0].clone()),
            _ => posts[0] = json!("unrelated"),
        };
        assert_eq!(
            result(&key, &ids, facts).await.unwrap_err(),
            Reason::MissingEvidence
        );
    }
}

#[tokio::test]
async fn docker_changed_host_semantics_require_controls_and_domain_port() {
    for name in ["privileged", "network-host", "published-port"] {
        let key = key(name);
        let ids = attempts(&key);
        for field in [
            "host_canary_reached",
            "peer_canary_reached",
            "host_port_reached",
            "peer_port_reached",
        ] {
            let mut facts = good(&key, &ids);
            facts[field] = json!(true);
            facts["outside_controls"]["host_before"] = json!(false);
            assert_eq!(
                result(&key, &ids, facts).await.unwrap_err(),
                Reason::BoundaryViolation
            );
        }
        for field in ["host_before", "host_after", "peer_before", "peer_after"] {
            let mut facts = good(&key, &ids);
            facts["outside_controls"][field] = json!(false);
            assert_eq!(
                result(&key, &ids, facts).await.unwrap_err(),
                Reason::MissingEvidence
            );
        }
        let mut facts = good(&key, &ids);
        facts["domain_port_reached"] = json!(false);
        assert_eq!(
            result(&key, &ids, facts).await.unwrap_err(),
            Reason::MissingEvidence
        );
        for observed in [
            json!([ids[1], ids[0]]),
            json!([ids[0]]),
            json!([ids[0], Uuid::new_v4()]),
        ] {
            let mut facts = good(&key, &ids);
            facts["attempts"] = observed;
            assert_eq!(
                result(&key, &ids, facts).await.unwrap_err(),
                Reason::StaleEvidence
            );
        }
    }
}

#[tokio::test]
async fn docker_wire_is_strict_and_fixture_cannot_become_release_evidence() {
    let key = key("run-exec");
    let ids = attempts(&key);
    for field in ["unknown", "password", "checks"] {
        let mut facts = good(&key, &ids);
        facts[field] = json!(true);
        assert_eq!(
            result(&key, &ids, facts).await.unwrap_err(),
            Reason::ProtocolViolation
        );
    }
    let mut facts = good(&key, &ids);
    facts.as_object_mut().unwrap().remove("pushed_digest");
    assert_eq!(
        result(&key, &ids, facts).await.unwrap_err(),
        Reason::ProtocolViolation
    );
    for mode in [EvidenceMode::NativeDebian, EvidenceMode::NestedSmoke] {
        let mut identity = super::report_test::identity();
        identity.mode = mode;
        assert_eq!(
            evaluate(
                &key,
                &ids,
                identity,
                json!([{"name":"docker","value":good(&key,&ids)}]),
                &key
            )
            .await
            .unwrap_err(),
            Reason::PlatformUnsupported
        );
    }
    for observations in [
        json!([]),
        json!([{"name":"unrelated","value":good(&key,&ids)}]),
        json!([{"name":"docker","value":good(&key,&ids)},{"name":"docker","value":good(&key,&ids)}]),
    ] {
        assert!(
            evaluate(
                &key,
                &ids,
                super::report_test::identity(),
                observations,
                &key
            )
            .await
            .is_err()
        );
    }
    let other = cases().into_iter().find(|k| k.case == "images").unwrap();
    assert_eq!(
        evaluate(
            &key,
            &ids,
            super::report_test::identity(),
            json!([{"name":"docker","value":good(&key,&ids)}]),
            &other
        )
        .await
        .unwrap_err(),
        Reason::StaleEvidence
    );
}
