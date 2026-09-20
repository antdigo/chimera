use super::{DomainEnvironment, StepStateSnapshot};

#[test]
fn snapshot_reuses_workspace_case_and_heredoc_semantics() {
    let parsed = StepStateSnapshot {
        env: "TOKEN<<E\na\nb\nE\ntoken=other\n".into(),
        path: "/work/bin\r\n\n /literal \n".into(),
        output: "Name=one\nname=two\n".into(),
        state: "Saved=one\nsaved<<END\na\nb\nEND\n".into(),
        summary: "CANARY summary\n".into(),
    }
    .parse()
    .unwrap();
    assert_eq!(parsed.env["TOKEN"], "a\nb");
    assert_eq!(parsed.env["token"], "other");
    assert_eq!(parsed.path, ["/work/bin", " /literal "]);
    assert_eq!(parsed.output.len(), 1);
    assert_eq!(parsed.output["Name"], "two");
    assert_eq!(parsed.state["Saved"], "a\nb");
    assert_eq!(parsed.summary, "CANARY summary\n");
    assert!(!format!("{parsed:?}").contains("CANARY"));
}

#[test]
fn returned_env_cannot_replace_private_endpoint() {
    let snapshot = StepStateSnapshot {
        env: "DOCKER_HOST=unix:///CANARY.sock\n".into(),
        path: String::new(),
        output: String::new(),
        state: String::new(),
        summary: String::new(),
    };
    let parsed = snapshot.parse().unwrap();
    assert!(
        DomainEnvironment::sandboxed()
            .merge(&parsed.env, "GITHUB_ENV")
            .is_err()
    );
}
