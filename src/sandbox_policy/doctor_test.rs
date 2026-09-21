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
