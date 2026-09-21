use super::catalog::{CheckId, Reason, ScenarioId, required_cases, required_checks};
use super::report::*;

pub(super) fn identity() -> RunIdentity {
    RunIdentity {
        run_id: uuid::Uuid::new_v4(),
        commit: "a".repeat(40),
        config_digest: "b".repeat(64),
        host_boot_id: uuid::Uuid::new_v4(),
        mode: EvidenceMode::Fixture,
    }
}

fn complete() -> QualificationReport {
    let identity = identity();
    let digest = "c".repeat(64);
    let results = required_cases()
        .into_iter()
        .map(|key| CaseResult {
            provenance: EvidenceProvenance {
                identity: identity.clone(),
                key: key.clone(),
                driver_commit: identity.commit.clone(),
                driver_digest: digest.clone(),
            },
            checks: required_checks(&key)
                .iter()
                .map(|id| Check {
                    id: *id,
                    passed: true,
                })
                .collect(),
            key,
            verdict: Verdict::Passed,
            reason: None,
            duration_ms: 1,
        })
        .collect();
    QualificationReport {
        schema_version: 1,
        identity,
        driver_digest: digest,
        activation_available: false,
        results,
        cleanup_confirmed: true,
        resource_summaries: vec![],
    }
}

#[test]
fn report_fixture_nested_and_caller_labelled_native_never_qualify() {
    let mut report = complete();
    assert_eq!(validate_report_structure(&report), Ok(()));
    for mode in [
        EvidenceMode::Fixture,
        EvidenceMode::NestedSmoke,
        EvidenceMode::NativeDebian,
    ] {
        report.identity.mode = mode;
        for row in &mut report.results {
            row.provenance.identity.mode = mode;
        }
        assert!(!qualifies(&report)); // No authenticated native collector exists in E0.
    }
}

#[test]
fn report_rejects_missing_duplicate_or_unexpected_checks_and_cases() {
    let mut original = complete();
    original.identity.mode = EvidenceMode::NativeDebian;
    for row in &mut original.results {
        row.provenance.identity.mode = EvidenceMode::NativeDebian;
    }
    let mut variants = Vec::new();
    let mut r = original.clone();
    r.results.pop();
    variants.push(r);
    let mut r = original.clone();
    r.results.push(r.results[0].clone());
    variants.push(r);
    let mut r = original.clone();
    r.results[0].checks.pop();
    variants.push(r);
    let mut r = original.clone();
    let check = r.results[0].checks[0].clone();
    r.results[0].checks.push(check);
    variants.push(r);
    let mut r = original.clone();
    r.results[0].checks.push(Check {
        id: CheckId::IdleZero,
        passed: true,
    });
    variants.push(r);
    let mut r = original.clone();
    r.results[0].checks[0].passed = false;
    variants.push(r);
    let mut r = original.clone();
    r.results[0].checks.reverse();
    variants.push(r);
    for verdict in [Verdict::Blocked, Verdict::Inconclusive, Verdict::Failed] {
        let mut r = original.clone();
        r.results[0].verdict = verdict;
        variants.push(r);
    }
    let mut r = original.clone();
    r.cleanup_confirmed = false;
    variants.push(r);
    let mut r = original.clone();
    r.activation_available = true;
    variants.push(r);
    let mut r = original.clone();
    r.schema_version = 2;
    variants.push(r);
    let mut r = original.clone();
    r.driver_digest.clear();
    variants.push(r);
    let mut r = original;
    r.results[0].reason = Some(Reason::MissingEvidence);
    variants.push(r);
    for report in variants {
        assert!(validate_report_structure(&report).is_err());
        assert!(!qualifies(&report));
    }
}

#[test]
fn report_writer_replaces_destination_symlink_without_following_it() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let sentinel = outside.path().join("sentinel");
    std::fs::write(&sentinel, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&sentinel, dir.path().join("report.json")).unwrap();
    write_report(dir.path(), &complete()).unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
    assert!(
        !std::fs::symlink_metadata(dir.path().join("report.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let link = outside.path().join("run-link");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();
    assert!(write_report(&link, &complete()).is_err());
}

#[test]
fn report_rejects_every_provenance_dimension_mismatch() {
    for field in [
        "run",
        "commit",
        "config",
        "boot",
        "mode",
        "key",
        "driver_commit",
        "digest",
    ] {
        let mut report = complete();
        let p = &mut report.results[0].provenance;
        match field {
            "run" => p.identity.run_id = uuid::Uuid::new_v4(),
            "commit" => p.identity.commit = "d".repeat(40),
            "config" => p.identity.config_digest = "d".repeat(64),
            "boot" => p.identity.host_boot_id = uuid::Uuid::new_v4(),
            "mode" => p.identity.mode = EvidenceMode::NativeDebian,
            "key" => p.key = required_cases()[1].clone(),
            "driver_commit" => p.driver_commit = "d".repeat(40),
            "digest" => p.driver_digest = "d".repeat(64),
            _ => unreachable!(),
        }
        assert!(validate_report_structure(&report).is_err(), "{field}");
    }
}

#[test]
fn report_atomic_writer_roundtrips_and_shows_all_scenarios_and_incomplete_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut report: QualificationReport = serde_json::from_str(include_str!(
        "../fixtures/qualification/report-incomplete.json"
    ))
    .unwrap();
    write_report(dir.path(), &report).unwrap();
    let stored: QualificationReport =
        serde_json::from_slice(&std::fs::read(dir.path().join("report.json")).unwrap()).unwrap();
    assert_eq!(stored, report);
    let markdown = std::fs::read_to_string(dir.path().join("report.md")).unwrap();
    assert!(markdown.contains("FIXTURE / NOT RELEASE EVIDENCE"));
    for scenario in ScenarioId::ALL {
        assert!(markdown.contains(serde_json::to_string(&scenario).unwrap().trim_matches('"')));
    }
    report.identity.mode = EvidenceMode::NativeDebian;
    write_report(dir.path(), &report).unwrap();
    assert!(
        std::fs::read_to_string(dir.path().join("report.md"))
            .unwrap()
            .contains("NATIVE / INCOMPLETE")
    );
    assert!(!stored.cleanup_confirmed);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn report_rejects_unknown_fields_and_does_not_render_workload_strings() {
    let mut report = complete();
    report.results[0].key.case = "SECRET_WORKLOAD_PATH".into();
    let dir = tempfile::tempdir().unwrap();
    assert!(write_report(dir.path(), &report).is_err());
    let mut value = serde_json::to_value(complete()).unwrap();
    value["stdout"] = "secret".into();
    assert!(serde_json::from_value::<QualificationReport>(value).is_err());
}

#[test]
fn resources_report_requires_exact_native_summaries_and_never_promotes_fixture_data() {
    use super::resources::{CaseMetrics, summarize_resources};
    let mut report = complete();
    for key in required_cases()
        .into_iter()
        .filter(|k| matches!(k.scenario, ScenarioId::S09 | ScenarioId::S16))
    {
        let (_, _, facts) = super::resources_test::fixture(&key);
        report.resource_summaries.push(CaseMetrics {
            key,
            summary: summarize_resources(&facts).unwrap(),
        });
    }
    assert_eq!(validate_report_structure(&report), Ok(()));
    assert!(!qualifies(&report));
    report.identity.mode = EvidenceMode::NativeDebian;
    for row in &mut report.results {
        row.provenance.identity.mode = EvidenceMode::NativeDebian;
    }
    assert_eq!(validate_report_structure(&report), Ok(()));
    assert!(!qualifies(&report)); // No native collector exists in E0.
    let mut variants = vec![];
    let mut bad = report.clone();
    bad.resource_summaries.pop();
    variants.push(bad);
    let mut bad = report.clone();
    bad.resource_summaries
        .push(bad.resource_summaries[0].clone());
    variants.push(bad);
    let mut bad = report.clone();
    bad.resource_summaries[0].key = required_cases()[0].clone();
    variants.push(bad);
    for rate in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        let mut bad = report.clone();
        bad.resource_summaries[0].summary.write_iops = rate;
        variants.push(bad);
    }
    for bad in variants {
        assert!(validate_report_structure(&bad).is_err());
        assert!(!qualifies(&bad));
    }
    let dir = tempfile::tempdir().unwrap();
    write_report(dir.path(), &report).unwrap();
    let json = std::fs::read_to_string(dir.path().join("report.json")).unwrap();
    let md = std::fs::read_to_string(dir.path().join("report.md")).unwrap();
    assert!(json.contains("peak_pss_bytes") && json.contains("total_cpu_usage_usec"));
    for unit in [
        "PSS (bytes)",
        "CPU (µs)",
        "Startup (ms)",
        "Read (ops/s)",
        "Cleanup (ms)",
    ] {
        assert!(md.contains(unit), "{unit}");
    }
    // A failed stress case still retains safe numeric forensic measurements.
    let metric_key = report.resource_summaries[0].key.clone();
    let row = report
        .results
        .iter_mut()
        .find(|row| row.key == metric_key)
        .unwrap();
    row.verdict = Verdict::Failed;
    row.reason = Some(Reason::BoundaryViolation);
    assert!(!qualifies(&report));
    assert!(write_report(dir.path(), &report).is_ok());
}
