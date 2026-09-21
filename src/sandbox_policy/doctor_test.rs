use super::*;

#[test]
fn report_cannot_turn_diagnostics_into_activation() {
    let report = DoctorReport {
        schema_version: 1,
        activation_available: false,
        policy_digest: None,
        checks: vec![DoctorCheck {
            id: "activation".into(),
            status: CheckStatus::Failed,
            category: "sandboxed_unavailable".into(),
        }],
    };
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["activation_available"], false);
    assert_eq!(json["schema_version"], 1);
}

#[test]
fn cgroup_v1_cannot_satisfy_linux_platform() {
    let (check, in_service) = classify_linux_platform(
        true,
        Some("11:memory:/system.slice/chimera.service\n10:cpu:/system.slice/chimera.service\n"),
        true,
        false,
        true,
    );
    assert_eq!(check.status, CheckStatus::Failed);
    assert_eq!(check.category, "cgroup_v2_unavailable");
    assert!(!in_service);
}

#[test]
fn cgroup_v2_requires_unified_mount_before_platform_satisfaction() {
    let (check, in_service) = classify_linux_platform(
        true,
        Some("0::/system.slice/chimera.service\n"),
        true,
        false,
        false,
    );
    assert_eq!(check.status, CheckStatus::Failed);
    assert_eq!(check.category, "cgroup_v2_unavailable");
    assert!(!in_service);
}

#[test]
fn known_storage_mismatch_is_failed_not_unverified() {
    for error in [
        PolicyError::StorageUnbounded,
        PolicyError::StorageIdentityChanged,
    ] {
        let check = classify_storage_probe_error(error);
        assert_eq!(check.status, CheckStatus::Failed);
        assert_eq!(check.category, "storage_bound_mismatch");
    }
    let inconclusive = classify_storage_probe_error(PolicyError::InvalidObservation("storage"));
    assert_eq!(inconclusive.status, CheckStatus::Unverified);
}

#[test]
fn policy_io_error_preserves_cause_without_displaying_sensitive_detail() {
    let error = PolicyError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "synthetic_secret_do_not_echo",
    ));
    assert!(!error.to_string().contains("synthetic_secret_do_not_echo"));
    assert!(!format!("{error:?}").contains("synthetic_secret_do_not_echo"));
    assert!(
        matches!(error, PolicyError::Io(cause) if cause.kind() == std::io::ErrorKind::PermissionDenied)
    );
}
