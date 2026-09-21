use std::collections::BTreeSet;

use super::catalog::{
    CaseKey, CheckId, ScenarioId, Wave, required_cases, required_checks, validate_coverage,
};
use super::report::{CaseResult, EvidenceMode, EvidenceProvenance, RunIdentity, Verdict};

fn key(scenario: ScenarioId, case: &str, wave: Wave, concurrency: u16) -> CaseKey {
    CaseKey {
        scenario,
        case: case.to_owned(),
        wave,
        concurrency,
    }
}

fn complete_results() -> Vec<super::report::CaseResult> {
    let identity = RunIdentity {
        run_id: uuid::Uuid::nil(),
        commit: "fixture-commit".to_owned(),
        config_digest: "fixture-config".to_owned(),
        host_boot_id: uuid::Uuid::nil(),
        mode: EvidenceMode::Fixture,
    };
    required_cases()
        .into_iter()
        .map(|key| CaseResult {
            provenance: EvidenceProvenance {
                identity: identity.clone(),
                key: key.clone(),
                driver_commit: "fixture-driver".to_owned(),
                driver_digest: "fixture-digest".to_owned(),
            },
            key,
            verdict: Verdict::Passed,
            reason: None,
            checks: Vec::new(),
            duration_ms: 1,
        })
        .collect()
}

#[test]
fn catalogue_has_all_sixteen_ids_and_no_duplicate_keys() {
    let cases = required_cases();
    let ids: BTreeSet<_> = cases.iter().map(|case| case.scenario).collect();
    assert_eq!(ids.into_iter().collect::<Vec<_>>(), ScenarioId::ALL);
    let keys: BTreeSet<_> = cases
        .iter()
        .map(|case| {
            (
                case.scenario,
                case.case.clone(),
                case.wave,
                case.concurrency,
            )
        })
        .collect();
    assert_eq!(keys.len(), cases.len());
    assert!(
        cases
            .iter()
            .any(|case| case.scenario == ScenarioId::S13 && case.concurrency == 40)
    );
}

#[test]
fn lifecycle_waves_include_every_twenty_and_forty_source_dependency() {
    let cases = required_cases();
    for wave in [
        Wave::Cold,
        Wave::Warm,
        Wave::Failure,
        Wave::Cancel,
        Wave::Restart,
    ] {
        for concurrency in [20, 40] {
            assert!(cases.iter().any(|case| {
                case == &key(
                    ScenarioId::S13,
                    "capacity-and-distinct-state",
                    wave,
                    concurrency,
                )
            }));
            let source = wave.as_str();
            assert!(cases.iter().any(|case| {
                case == &key(
                    ScenarioId::S14,
                    &format!("next-tenant-clean-after-{source}"),
                    Wave::NextTenant,
                    concurrency,
                )
            }));
            assert!(cases.iter().any(|case| {
                case == &key(
                    ScenarioId::S15,
                    &format!("zero-domain-processes-after-{source}"),
                    Wave::Idle,
                    concurrency,
                )
            }));
        }
    }
}

#[test]
fn coverage_rejects_missing_duplicate_and_wrong_dimension_rows() {
    let complete = complete_results();
    assert_eq!(validate_coverage(&complete), Ok(()));

    let mut missing = complete.clone();
    let index = missing
        .iter()
        .position(|result| result.key.scenario == ScenarioId::S14)
        .unwrap();
    missing.remove(index);
    assert!(validate_coverage(&missing).is_err());

    let mut duplicate = complete.clone();
    let s07 = duplicate
        .iter()
        .find(|result| result.key.scenario == ScenarioId::S07)
        .cloned()
        .unwrap();
    duplicate.push(s07);
    assert!(validate_coverage(&duplicate).is_err());

    let mut wrong_dimension = complete;
    let result = wrong_dimension
        .iter_mut()
        .find(|result| result.key.scenario == ScenarioId::S13 && result.key.concurrency == 40)
        .unwrap();
    result.key.concurrency = 39;
    assert!(validate_coverage(&wrong_dimension).is_err());
}

#[test]
fn every_case_has_a_sorted_unique_required_checklist() {
    for case in required_cases() {
        let checks = required_checks(&case);
        assert!(!checks.is_empty(), "{case:?}");
        assert!(checks.windows(2).all(|pair| pair[0] < pair[1]), "{case:?}");
        if case.scenario != ScenarioId::S01 {
            assert!(checks.contains(&CheckId::CleanupConfirmed), "{case:?}");
        }
    }
}

#[test]
fn representative_cases_pin_the_exact_required_evidence() {
    assert_eq!(
        required_checks(&key(ScenarioId::S01, "no-userns", Wave::Cold, 1)),
        &[
            CheckId::PreflightRejectedBeforePolling,
            CheckId::RollbackConfirmed
        ]
    );
    assert_eq!(
        required_checks(&key(ScenarioId::S05, "lan", Wave::Cold, 2)),
        &[
            CheckId::NetworkPolicyEnforced,
            CheckId::OutsideControlAvailable,
            CheckId::PublicRegistryReachable,
            CheckId::CleanupConfirmed,
        ]
    );
    for case_name in ["cpu", "io"] {
        assert_eq!(
            required_checks(&key(ScenarioId::S09, case_name, Wave::Cold, 1)),
            &[
                CheckId::ResourceLimitEnforced,
                CheckId::ProductionReservePreserved,
                CheckId::NativeMetricsComplete,
                CheckId::CleanupConfirmed,
            ]
        );
    }
    assert_eq!(
        required_checks(&key(
            ScenarioId::S13,
            "capacity-and-distinct-state",
            Wave::Restart,
            40,
        )),
        &[
            CheckId::CapacityBounded,
            CheckId::DistinctStateConfirmed,
            CheckId::ExtraAdmissionBlocked,
            CheckId::CleanupConfirmed,
        ]
    );
    assert_eq!(
        required_checks(&key(
            ScenarioId::S14,
            "next-tenant-clean-after-cancel",
            Wave::NextTenant,
            20,
        )),
        &[CheckId::NextTenantClean, CheckId::CleanupConfirmed]
    );
    assert_eq!(
        required_checks(&key(
            ScenarioId::S15,
            "zero-domain-processes-after-failure",
            Wave::Idle,
            40,
        )),
        &[CheckId::IdleZero, CheckId::CleanupConfirmed]
    );
    assert_eq!(
        required_checks(&key(ScenarioId::S16, "native-storage", Wave::Warm, 40)),
        &[
            CheckId::ResourceLimitEnforced,
            CheckId::NativeMetricsComplete,
            CheckId::CleanupConfirmed,
        ]
    );
}

#[test]
fn every_s13_wave_requires_distinct_state_and_rejects_an_extra_admission() {
    for case in required_cases()
        .into_iter()
        .filter(|case| case.scenario == ScenarioId::S13)
    {
        let checks = required_checks(&case);
        assert!(
            checks.contains(&CheckId::DistinctStateConfirmed),
            "{case:?}"
        );
        assert!(checks.contains(&CheckId::ExtraAdmissionBlocked), "{case:?}");
    }
}

#[test]
fn report_data_shapes_are_inert_and_record_fixture_identity() {
    let result = complete_results().pop().unwrap();
    assert_eq!(result.provenance.identity.mode, EvidenceMode::Fixture);
}
