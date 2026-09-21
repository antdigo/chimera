use super::fixtures::make_canaries;

#[test]
fn fixtures_canaries_are_synthetic_distinct_and_bound_to_the_run() {
    let run = uuid::Uuid::new_v4();
    let canaries = make_canaries(run);
    assert_eq!(canaries.run_id, run);
    for (role, value) in [
        ("host", canaries.host),
        ("peer", canaries.peer),
        ("supervisor", canaries.supervisor),
        ("credential", canaries.credential),
    ] {
        assert_eq!(value, format!("chimera-qualification:{run}:{role}"));
        assert!(!value.contains('/'));
    }
    assert_ne!(
        make_canaries(run).credential,
        make_canaries(uuid::Uuid::new_v4()).credential
    );
}
