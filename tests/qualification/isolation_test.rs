use super::catalog::{CaseKey, CheckId, Reason, ScenarioId, required_cases};
use super::driver::{DriverRequest, Operation, PinnedDriver, Recipe, run_driver};
use super::isolation::{evaluate_isolation, isolation_recipe};
use super::report::{EvidenceMode, RunIdentity};
use chimera::config::NetworkPolicyConfig;
use chimera::sandbox_policy::{HostAddresses, compile_network};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;

fn cases() -> Vec<CaseKey> {
    required_cases()
        .into_iter()
        .filter(|key| {
            matches!(
                key.scenario,
                ScenarioId::S01
                    | ScenarioId::S03
                    | ScenarioId::S04
                    | ScenarioId::S05
                    | ScenarioId::S12
            )
        })
        .collect()
}
fn key(scenario: ScenarioId, name: &str) -> CaseKey {
    cases()
        .into_iter()
        .find(|key| key.scenario == scenario && key.case == name)
        .unwrap()
}
fn target(key: &CaseKey) -> Option<&'static str> {
    match key.case.as_str() {
        "host-files" => Some("HostFile"),
        "peer-files" => Some("PeerFile"),
        "supervisor-credentials" => Some("SupervisorCredential"),
        "bind-host" => Some("HostBind"),
        "bind-peer" => Some("PeerBind"),
        "pid-visibility" => Some("HostProcess"),
        "signal-peer" => Some("PeerSignal"),
        "ipc-peer" => Some("PeerIpc"),
        "uts-private" => Some("Hostname"),
        "init-control-fd" => Some("InitControlFd"),
        _ => None,
    }
}
fn good(key: &CaseKey, identity: &RunIdentity) -> Value {
    let mut facts = json!({"setup_confirmed":true,"outside_control_before":false,
        "outside_control_after":false,"network":null,"observations":[],"peer_unchanged":true,
        "polling_started":false,"rollback_confirmed":true,"cleanup_confirmed":true,
        "path":null,"capabilities":null});
    if let Some(target) = target(key) {
        facts["observations"] = json!([{"target":target,"outcome":"Denied"}]);
    }
    if key.scenario == ScenarioId::S05 {
        let config: NetworkPolicyConfig =
            serde_json::from_value(json!({"production_cidrs":["198.51.100.0/24"]})).unwrap();
        let policy = compile_network(
            &config,
            &HostAddresses {
                addresses: vec!["192.0.2.1".parse().unwrap()],
            },
        )
        .unwrap();
        let generation = json!({"boot_id":identity.host_boot_id,"invocation_id":"a".repeat(32),"control_group":"/system.slice/chimera.service"});
        let addresses = [
            "127.0.0.1:18080",
            "192.0.2.1:18080",
            "10.0.0.1:18080",
            "198.51.100.1:18080",
        ];
        facts["outside_control_before"] = json!(true);
        facts["outside_control_after"] = json!(true);
        facts["network"] = json!({
            "run_id":identity.run_id,"key":key,"policy_config":config,"host_addresses":["192.0.2.1"],
            "expected_digest":policy.digest(),"probe_deadline_ms":100,"elapsed_ms":[100,100,100,100],
            "sentinels": addresses.iter().zip(["loopback","host","lan","production"]).map(|(address,role)| json!({"address":address,"role":role})).collect::<Vec<_>>(),
            "applied":{"generation":generation,"denied":policy.denied(),"allowed":[],"bpf_attached":true},
            "probes":{"generation":generation,"public_registry_ok":true,"negative":addresses.iter().map(|address|json!({"address":address,"control_before":true,"control_after":true,"observed":"TimedOut"})).collect::<Vec<_>>()}
        });
        if key.case == "scoped-capabilities" {
            facts["capabilities"] = json!({"owner":identity.run_id,"peer":identity.host_boot_id,
                "credential_hash":blake3::hash(format!("chimera-qualification:{}:credential",identity.run_id).as_bytes()).to_hex().to_string(),
                "cross_attempt":"Denied","after_revoke":"Denied"});
        }
    }
    if key.scenario == ScenarioId::S12 {
        let digest =
            blake3::hash(format!("chimera-qualification:{}:peer", identity.run_id).as_bytes())
                .to_hex()
                .to_string();
        let snapshot = json!({"device":1,"inode":42,"content_digest":digest});
        facts["path"] = json!({"case":key.case,"before":snapshot,"after":snapshot,
            "host_outcome":"Denied","peer_outcome":"Denied","resolution":if key.case == "unknown-resource" {"Quarantined"} else {"Rejected"}});
    }
    facts
}

// Execute an inert temporary fixture through the actual pinned protocol. The
// payload cannot itself construct AuthenticatedResponse or native provenance.
async fn evaluate(
    key: &CaseKey,
    identity: RunIdentity,
    observations: Value,
) -> Result<Vec<super::report::Check>, Reason> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("driver");
    let payload = serde_json::to_string(&observations).unwrap();
    let script = format!(
        r##"#!/usr/bin/python3
import hashlib,json,sys
digest=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
if sys.argv[1]=='--qualification-hello=1':
 print(json.dumps({{'schema_version':1,'commit':'a'*40,'binary_digest':digest,'backend':'sandboxed','supported':['S-01','S-03','S-04','S-05','S-12']}})); sys.exit(0)
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
            recipe: Recipe {
                operations: vec![Operation::Observe],
                deadline_ms: 5000,
            },
        },
    )
    .await?;
    evaluate_isolation(key, &response)
}
async fn facts_result(
    key: &CaseKey,
    identity: &RunIdentity,
    facts: Value,
) -> Result<Vec<super::report::Check>, Reason> {
    evaluate(
        key,
        identity.clone(),
        json!([{"name":"isolation","value":facts}]),
    )
    .await
}

#[test]
fn isolation_recipes_cover_exact_catalogue_and_reject_bad_attempts() {
    for key in cases() {
        let attempts: Vec<_> = (0..key.concurrency).map(|_| uuid::Uuid::new_v4()).collect();
        let recipe = isolation_recipe(&key, &attempts).unwrap();
        assert!((1..=300_000).contains(&recipe.deadline_ms));
        if key.scenario == ScenarioId::S01 {
            assert!(
                matches!(&recipe.operations[0], Operation::Preflight {missing} if missing == &key.case)
            );
            assert!(
                !recipe
                    .operations
                    .iter()
                    .any(|op| matches!(op, Operation::Provision { .. }))
            );
        } else {
            assert!(recipe.operations.iter().any(|op|matches!(op, Operation::RunFixture {attempt,fixture} if *attempt == attempts[0] && fixture == &format!("isolation/{}",key.case))));
            let destroyed: Vec<_> = recipe
                .operations
                .iter()
                .filter_map(|op| {
                    if let Operation::Destroy { attempt } = op {
                        Some(*attempt)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                destroyed,
                attempts.iter().rev().copied().collect::<Vec<_>>()
            );
        }
        assert!(matches!(recipe.operations.last(), Some(Operation::Observe)));
        assert_eq!(
            isolation_recipe(&key, &[]).unwrap_err(),
            Reason::InvalidConfig
        );
        assert_eq!(
            isolation_recipe(&key, &vec![uuid::Uuid::nil(); attempts.len()]).unwrap_err(),
            Reason::InvalidConfig
        );
        if attempts.len() > 1 {
            assert_eq!(
                isolation_recipe(&key, &vec![attempts[0]; attempts.len()]).unwrap_err(),
                Reason::InvalidConfig
            );
        }
        let mut invalid = key;
        invalid.case = "../../host; shell".into();
        assert_eq!(
            isolation_recipe(&invalid, &attempts).unwrap_err(),
            Reason::InvalidConfig
        );
    }
}

#[tokio::test]
async fn isolation_each_case_requires_its_typed_evidence() {
    let identity = super::report_test::identity();
    for key in cases() {
        let checks = facts_result(&key, &identity, good(&key, &identity))
            .await
            .unwrap();
        let expected: &[CheckId] = match key.scenario {
            ScenarioId::S01 => &[
                CheckId::PreflightRejectedBeforePolling,
                CheckId::RollbackConfirmed,
            ],
            ScenarioId::S03 | ScenarioId::S12 => &[
                CheckId::HostFilesystemDenied,
                CheckId::PeerFilesystemDenied,
                CheckId::CleanupConfirmed,
            ],
            ScenarioId::S04 => &[CheckId::ProcessIsolated, CheckId::CleanupConfirmed],
            ScenarioId::S05 => &[
                CheckId::NetworkPolicyEnforced,
                CheckId::OutsideControlAvailable,
                CheckId::PublicRegistryReachable,
                CheckId::CleanupConfirmed,
            ],
            _ => unreachable!(),
        };
        assert_eq!(checks.iter().map(|c| c.id).collect::<Vec<_>>(), expected);
        assert!(checks.iter().all(|c| c.passed));
    }
}

#[tokio::test]
async fn isolation_boundary_requires_exact_target_and_rejects_every_escape() {
    let identity = super::report_test::identity();
    for key in cases()
        .into_iter()
        .filter(|k| matches!(k.scenario, ScenarioId::S03 | ScenarioId::S04))
    {
        for (outcome, want) in [
            ("Absent", None),
            ("Visible", Some(Reason::BoundaryViolation)),
            ("Modified", Some(Reason::BoundaryViolation)),
            ("Signalled", Some(Reason::BoundaryViolation)),
        ] {
            let mut facts = good(&key, &identity);
            facts["observations"][0]["outcome"] = json!(outcome);
            let result = facts_result(&key, &identity, facts).await;
            if let Some(want) = want {
                assert_eq!(result.unwrap_err(), want);
            } else {
                assert!(result.is_ok());
            }
        }
        for observations in [
            json!([]),
            json!([{"target":"HostFile","outcome":"Denied"},{"target":"HostFile","outcome":"Denied"}]),
            json!([{"target":if target(&key)==Some("PeerFile") {"HostFile"} else {"PeerFile"},"outcome":"Denied"}]),
        ] {
            let mut facts = good(&key, &identity);
            facts["observations"] = observations;
            assert!(facts_result(&key, &identity, facts).await.is_err());
        }
    }
}

#[tokio::test]
async fn isolation_network_preserves_typed_outcomes_controls_and_binding() {
    let identity = super::report_test::identity();
    let key = key(ScenarioId::S05, "loopback");
    for (outcome, want) in [
        ("Denied", None),
        ("TimedOut", None),
        ("Refused", Some(Reason::MissingEvidence)),
        ("Unreachable", Some(Reason::MissingEvidence)),
        ("Connected", Some(Reason::BoundaryViolation)),
    ] {
        let mut facts = good(&key, &identity);
        facts["network"]["probes"]["negative"][0]["observed"] = json!(outcome);
        let result = facts_result(&key, &identity, facts).await;
        if let Some(want) = want {
            assert_eq!(result.unwrap_err(), want);
        } else {
            assert!(result.is_ok());
        }
    }
    for (pointer, value, want) in [
        (
            "/outside_control_before",
            json!(false),
            Reason::MissingEvidence,
        ),
        (
            "/outside_control_after",
            json!(false),
            Reason::MissingEvidence,
        ),
        (
            "/network/probes/negative/0/control_before",
            json!(false),
            Reason::MissingEvidence,
        ),
        (
            "/network/probes/negative/0/control_after",
            json!(false),
            Reason::MissingEvidence,
        ),
        (
            "/network/probes/public_registry_ok",
            json!(false),
            Reason::MissingEvidence,
        ),
        (
            "/network/expected_digest",
            json!("c".repeat(64)),
            Reason::StaleEvidence,
        ),
        (
            "/network/run_id",
            json!(uuid::Uuid::new_v4()),
            Reason::StaleEvidence,
        ),
        ("/network/key/case", json!("lan"), Reason::StaleEvidence),
        (
            "/network/applied/generation/boot_id",
            json!(uuid::Uuid::new_v4()),
            Reason::StaleEvidence,
        ),
        (
            "/network/probes/generation/invocation_id",
            json!("b".repeat(32)),
            Reason::StaleEvidence,
        ),
        (
            "/network/probes/negative/0/address",
            json!("127.0.0.2:18080"),
            Reason::StaleEvidence,
        ),
        (
            "/network/sentinels/0/role",
            json!("lan"),
            Reason::StaleEvidence,
        ),
        ("/network/applied/denied", json!([]), Reason::StaleEvidence),
        (
            "/network/probe_deadline_ms",
            json!(0),
            Reason::MissingEvidence,
        ),
        ("/network/elapsed_ms/0", json!(1), Reason::MissingEvidence),
        (
            "/network/probes/negative",
            json!([]),
            Reason::MissingEvidence,
        ),
    ] {
        let mut facts = good(&key, &identity);
        *facts.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            facts_result(&key, &identity, facts).await.unwrap_err(),
            want,
            "{pointer}"
        );
    }
}

#[tokio::test]
async fn isolation_preflight_failure_precedence_covers_combined_facts() {
    let identity = super::report_test::identity();
    let key = key(ScenarioId::S01, "no-userns");
    for setup in [false, true] {
        for cleanup in [false, true] {
            for rollback in [false, true] {
                for polling in [false, true] {
                    for peer in [false, true] {
                        let mut facts = good(&key, &identity);
                        facts["setup_confirmed"] = json!(setup);
                        facts["cleanup_confirmed"] = json!(cleanup);
                        facts["rollback_confirmed"] = json!(rollback);
                        facts["polling_started"] = json!(polling);
                        facts["peer_unchanged"] = json!(peer);
                        let want = if !cleanup || !rollback {
                            Some(Reason::CleanupUnconfirmed)
                        } else if polling || !peer {
                            Some(Reason::BoundaryViolation)
                        } else if !setup {
                            Some(Reason::MissingEvidence)
                        } else {
                            None
                        };
                        assert_eq!(
                            facts_result(&key, &identity, facts).await.err(),
                            want,
                            "setup={setup} cleanup={cleanup} rollback={rollback} polling={polling} peer={peer}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn isolation_network_failure_precedence_retains_cleanup_and_peer_failures() {
    let identity = super::report_test::identity();
    let key = key(ScenarioId::S05, "loopback");
    for stale in [false, true] {
        for setup in [false, true] {
            for cleanup in [false, true] {
                for peer in [false, true] {
                    let mut facts = good(&key, &identity);
                    facts["setup_confirmed"] = json!(setup);
                    facts["cleanup_confirmed"] = json!(cleanup);
                    facts["peer_unchanged"] = json!(peer);
                    if stale {
                        facts["network"]["expected_digest"] = json!("c".repeat(64));
                    } else {
                        facts["network"] = Value::Null;
                    }
                    let want = if !cleanup {
                        Reason::CleanupUnconfirmed
                    } else if !peer {
                        Reason::BoundaryViolation
                    } else if stale {
                        Reason::StaleEvidence
                    } else {
                        Reason::MissingEvidence
                    };
                    assert_eq!(
                        facts_result(&key, &identity, facts).await.unwrap_err(),
                        want,
                        "stale={stale} setup={setup} cleanup={cleanup} peer={peer}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn isolation_preflight_rollback_and_cleanup_cannot_be_omitted() {
    let identity = super::report_test::identity();
    let key = key(ScenarioId::S01, "no-userns");
    for (field, want) in [
        ("polling_started", Reason::BoundaryViolation),
        ("rollback_confirmed", Reason::CleanupUnconfirmed),
        ("cleanup_confirmed", Reason::CleanupUnconfirmed),
        ("setup_confirmed", Reason::MissingEvidence),
    ] {
        let mut facts = good(&key, &identity);
        facts[field] = json!(field == "polling_started");
        assert_eq!(
            facts_result(&key, &identity, facts).await.unwrap_err(),
            want
        );
    }
}

#[tokio::test]
async fn isolation_hostile_paths_require_unchanged_identity_content_and_quarantine() {
    let identity = super::report_test::identity();
    for key in cases()
        .into_iter()
        .filter(|k| k.scenario == ScenarioId::S12)
    {
        for (pointer, value, want) in [
            ("/path/after/inode", json!(43), Reason::BoundaryViolation),
            ("/path/after/device", json!(2), Reason::BoundaryViolation),
            (
                "/path/after/content_digest",
                json!("b".repeat(64)),
                Reason::BoundaryViolation,
            ),
            (
                "/path/host_outcome",
                json!("Visible"),
                Reason::BoundaryViolation,
            ),
            (
                "/path/peer_outcome",
                json!("Modified"),
                Reason::BoundaryViolation,
            ),
            ("/peer_unchanged", json!(false), Reason::BoundaryViolation),
            (
                "/path/resolution",
                json!("Removed"),
                Reason::BoundaryViolation,
            ),
            ("/path", Value::Null, Reason::MissingEvidence),
        ] {
            let mut facts = good(&key, &identity);
            *facts.pointer_mut(pointer).unwrap() = value;
            assert_eq!(
                facts_result(&key, &identity, facts).await.unwrap_err(),
                want,
                "{pointer}"
            );
        }
    }
}

#[tokio::test]
async fn isolation_capabilities_require_scope_identity_hash_and_revocation() {
    let identity = super::report_test::identity();
    let key = key(ScenarioId::S05, "scoped-capabilities");
    for (pointer, value, want) in [
        (
            "/capabilities/cross_attempt",
            json!("Granted"),
            Reason::BoundaryViolation,
        ),
        (
            "/capabilities/after_revoke",
            json!("Granted"),
            Reason::BoundaryViolation,
        ),
        (
            "/capabilities/owner",
            json!(uuid::Uuid::new_v4()),
            Reason::StaleEvidence,
        ),
        (
            "/capabilities/credential_hash",
            json!("d".repeat(64)),
            Reason::StaleEvidence,
        ),
        ("/capabilities", Value::Null, Reason::MissingEvidence),
    ] {
        let mut facts = good(&key, &identity);
        *facts.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            facts_result(&key, &identity, facts).await.unwrap_err(),
            want
        );
    }
}

#[tokio::test]
async fn isolation_strict_schema_rejects_missing_unknown_unrelated_and_generic_booleans() {
    let identity = super::report_test::identity();
    let key = key(ScenarioId::S03, "host-files");
    let mut samples = vec![json!(true), json!({"passed":true})];
    let mut unknown = good(&key, &identity);
    unknown["passed"] = json!(true);
    samples.push(unknown);
    let mut missing = good(&key, &identity);
    missing.as_object_mut().unwrap().remove("peer_unchanged");
    samples.push(missing);
    let mut generic = good(&key, &identity);
    generic["observations"] = json!([{"target":"HostFile","outcome":true}]);
    samples.push(generic);
    let mut unrelated = good(&key, &identity);
    unrelated["path"] =
        good(&self::key(ScenarioId::S12, "symlink-root"), &identity)["path"].clone();
    samples.push(unrelated);
    for facts in samples {
        assert_eq!(
            facts_result(&key, &identity, facts).await.unwrap_err(),
            Reason::ProtocolViolation
        );
    }
    for observations in [
        json!([]),
        json!([{"name":"unknown","value":good(&key,&identity)}]),
        json!([{"name":"isolation","value":good(&key,&identity)},{"name":"other","value":true}]),
    ] {
        assert!(
            evaluate(&key, identity.clone(), observations)
                .await
                .is_err()
        );
    }
    let network_key = self::key(ScenarioId::S05, "lan");
    let mut facts = good(&network_key, &identity);
    facts["network"]["probes"]["negative"][0]["reached"] = json!(false);
    assert_eq!(
        facts_result(&network_key, &identity, facts)
            .await
            .unwrap_err(),
        Reason::ProtocolViolation
    );
}

#[tokio::test]
async fn isolation_fixture_transport_cannot_claim_native_or_nested_evidence() {
    let key = key(ScenarioId::S01, "no-userns");
    for mode in [EvidenceMode::NativeDebian, EvidenceMode::NestedSmoke] {
        let mut identity = super::report_test::identity();
        identity.mode = mode;
        assert_eq!(
            facts_result(&key, &identity, good(&key, &identity))
                .await
                .unwrap_err(),
            Reason::PlatformUnsupported
        );
    }
}
