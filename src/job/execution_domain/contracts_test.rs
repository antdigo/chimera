use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

use super::contracts::{
    AttemptIdentity, DomainEnvironment, DomainPath, DomainPaths, FailureCategory, Stage,
    StepFilesId, StepStateSnapshot,
};
use super::{
    CancelReason, CommandEvent, CommandOutcome, CommandSpec, CommandTarget, DestroyReport,
    ExecutionDomainError,
};

#[test]
fn contract_paths_and_identity_are_unambiguous() {
    assert!(AttemptIdentity::from_uuid(Uuid::nil()).is_err());
    let id = AttemptIdentity::from_uuid(Uuid::from_u128(7)).unwrap();
    assert_eq!(id.component(), "00000000000000000000000000000007");

    for invalid in [
        "relative",
        "//work",
        "/work/../run",
        "/work//x",
        "/work/./x",
        "/work/",
        "/x\0y",
    ] {
        assert!(DomainPath::parse(invalid).is_err(), "{invalid:?}");
    }

    assert_eq!(
        DomainPath::parse("/work")
            .unwrap()
            .join("a/b")
            .unwrap()
            .as_str(),
        "/work/a/b"
    );
    for invalid in ["", "/run", "a//b", "a/./b", "a/../b", "a/b/", "a\0b"] {
        assert!(
            DomainPath::parse("/work").unwrap().join(invalid).is_err(),
            "{invalid:?}"
        );
    }
}

#[test]
fn domain_path_deserialization_revalidates_untrusted_input() {
    let path = DomainPath::parse("/work/project").unwrap();
    let encoded = serde_json::to_string(&path).unwrap();

    assert_eq!(encoded, r#""/work/project""#);
    assert_eq!(serde_json::from_str::<DomainPath>(&encoded).unwrap(), path);
    for invalid in [json!("relative"), json!("/work/../secret"), json!("//work")] {
        assert!(serde_json::from_value::<DomainPath>(invalid).is_err());
    }
}

#[test]
fn attempt_and_step_ids_reject_nil_during_deserialization() {
    let attempt = AttemptIdentity::from_uuid(Uuid::from_u128(9)).unwrap();
    assert_eq!(
        serde_json::from_value::<AttemptIdentity>(json!(attempt.uuid())).unwrap(),
        attempt
    );
    assert!(serde_json::from_value::<AttemptIdentity>(json!(Uuid::nil())).is_err());

    let step = StepFilesId::new();
    assert_ne!(step.uuid(), Uuid::nil());
    assert_eq!(
        serde_json::from_value::<StepFilesId>(json!(step.uuid())).unwrap(),
        step
    );
    assert!(serde_json::from_value::<StepFilesId>(json!(Uuid::nil())).is_err());
}

#[test]
fn sandbox_paths_are_deterministic_and_keep_socket_separate_from_run_directory() {
    let paths = DomainPaths::sandboxed();

    assert_eq!(paths.work.as_str(), "/work");
    assert_eq!(paths.tmp.as_str(), "/tmp");
    assert_eq!(paths.home.as_str(), "/home/chimera");
    assert_eq!(paths.run.as_str(), "/run/chimera");
    assert_eq!(paths.docker_config.as_str(), "/home/chimera/.docker");
    assert_eq!(paths.docker_data.as_str(), "/var/lib/chimera/docker");
    assert_eq!(paths.docker_exec.as_str(), "/run/chimera/docker-exec");
    assert_eq!(paths.docker_socket().as_str(), "/run/chimera/docker.sock");
    assert_ne!(paths.docker_socket(), &paths.run);
    assert_eq!(paths, DomainPaths::sandboxed());
}

#[test]
fn sandbox_environment_owns_reserved_values_and_never_prints_secrets() {
    let environment = DomainEnvironment::sandboxed();
    let supplied = HashMap::from([("PATH".to_owned(), "/usr/bin".to_owned())]);

    let merged = environment.merge(&supplied, "GITHUB_ENV").unwrap();
    assert_eq!(merged["PATH"], "/usr/bin");
    assert_eq!(merged["HOME"], "/home/chimera");
    assert_eq!(merged["XDG_RUNTIME_DIR"], "/run/chimera");
    assert_eq!(merged["DOCKER_CONFIG"], "/home/chimera/.docker");
    assert_eq!(merged["DOCKER_HOST"], "unix:///run/chimera/docker.sock");

    for expected_key in ["DOCKER_HOST", "DOCKER_CONFIG", "HOME", "XDG_RUNTIME_DIR"] {
        let supplied = HashMap::from([(expected_key.to_owned(), "CANARY_SECRET".to_owned())]);
        let error = environment.merge(&supplied, "GITHUB_ENV").unwrap_err();
        assert!(matches!(
            error,
            ExecutionDomainError::ReservedDomainEnvironment {
                ref key,
                source: "GITHUB_ENV"
            } if key == expected_key
        ));
        assert!(!format!("{error:?} {error}").contains("CANARY_SECRET"));
    }
    assert!(!format!("{environment:?}").contains("unix:///run/chimera/docker.sock"));
}

#[test]
fn matching_reserved_environment_values_are_idempotent() {
    let environment = DomainEnvironment::sandboxed();
    let supplied = HashMap::from([
        ("HOME".to_owned(), "/home/chimera".to_owned()),
        (
            "DOCKER_HOST".to_owned(),
            "unix:///run/chimera/docker.sock".to_owned(),
        ),
    ]);

    assert_eq!(
        environment.merge(&supplied, "base env").unwrap()["HOME"],
        "/home/chimera"
    );
}

#[test]
fn state_snapshot_debug_is_redacted_while_serde_preserves_transport_fields() {
    let snapshot = StepStateSnapshot {
        env: "TOKEN=CANARY_SECRET".to_owned(),
        path: "/secret/bin".to_owned(),
        output: "token=CANARY_SECRET".to_owned(),
        state: "secret=CANARY_SECRET".to_owned(),
        summary: "CANARY_SECRET".to_owned(),
    };

    assert_eq!(format!("{snapshot:?}"), "StepStateSnapshot");
    let encoded = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        serde_json::from_value::<StepStateSnapshot>(encoded).unwrap(),
        snapshot
    );
}

#[test]
fn backend_error_reports_only_structured_safe_fields() {
    let attempt = Uuid::from_u128(11);
    let error = ExecutionDomainError::Backend {
        attempt: Some(attempt),
        stage: Stage::Launch,
        category: FailureCategory::Unavailable,
        errno: Some(libc::EAGAIN),
    };

    let rendered = error.to_string();
    assert!(rendered.contains(&attempt.to_string()));
    assert!(rendered.contains("Launch"));
    assert!(rendered.contains("Unavailable"));
    assert!(rendered.contains(&libc::EAGAIN.to_string()));
}

#[cfg(unix)]
#[test]
fn trusted_command_target_preserves_native_values_without_debug_leaks() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let program = OsString::from_vec(b"/opt/CANARY_PROGRAM\xff".to_vec());
    let argument = OsString::from_vec(b"CANARY_ARGUMENT\xfe".to_vec());
    let cwd = PathBuf::from(OsString::from_vec(b"/work/CANARY_CWD\xfd".to_vec()));
    let target = CommandTarget::Trusted {
        program: program.clone(),
        args: vec![argument.clone()],
        cwd: cwd.clone(),
    };

    assert_eq!(format!("{target:?}"), "CommandTarget");
    match target {
        CommandTarget::Trusted {
            program: actual_program,
            args,
            cwd: actual_cwd,
        } => {
            assert_eq!(
                actual_program.as_os_str().as_bytes(),
                program.as_os_str().as_bytes()
            );
            assert_eq!(
                args[0].as_os_str().as_bytes(),
                argument.as_os_str().as_bytes()
            );
            assert_eq!(
                actual_cwd.as_os_str().as_bytes(),
                cwd.as_os_str().as_bytes()
            );
        }
        CommandTarget::Sandboxed { .. } => panic!("trusted target changed variant"),
    }
}

#[test]
fn sandboxed_command_target_retains_validated_paths_and_utf8_arguments() {
    let program = DomainPath::parse("/usr/bin/sh").unwrap();
    let cwd = DomainPath::parse("/work/project").unwrap();
    let target = CommandTarget::Sandboxed {
        program: program.clone(),
        args: vec!["-c".to_owned(), "printf CANARY_ARGUMENT".to_owned()],
        cwd: cwd.clone(),
    };

    assert_eq!(format!("{target:?}"), "CommandTarget");
    assert_eq!(
        target,
        CommandTarget::Sandboxed {
            program,
            args: vec!["-c".to_owned(), "printf CANARY_ARGUMENT".to_owned()],
            cwd,
        }
    );
}

#[test]
fn command_spec_debug_redacts_target_arguments_and_environment() {
    let spec = CommandSpec {
        target: CommandTarget::Sandboxed {
            program: DomainPath::parse("/opt/CANARY_PROGRAM").unwrap(),
            args: vec!["CANARY_ARGUMENT".to_owned()],
            cwd: DomainPath::parse("/work").unwrap(),
        },
        env: HashMap::from([("TOKEN".to_owned(), "CANARY_SECRET".to_owned())]),
        timeout: Duration::from_secs(7),
        state: Some(StepFilesId::new()),
    };

    assert_eq!(format!("{spec:?}"), "CommandSpec");
}

#[test]
fn command_events_redact_raw_output_while_outcomes_remain_comparable() {
    let event = CommandEvent::Stdout(b"CANARY_SECRET".to_vec());

    assert_eq!(format!("{event:?}"), "CommandEvent");
    assert_eq!(event, CommandEvent::Stdout(b"CANARY_SECRET".to_vec()));
    assert_ne!(event, CommandEvent::Stderr(b"CANARY_SECRET".to_vec()));
    assert_eq!(CommandOutcome::Exited(7), CommandOutcome::Exited(7));
    assert_eq!(CommandOutcome::Signalled(9), CommandOutcome::Signalled(9));
    assert_ne!(CommandOutcome::Cancelled, CommandOutcome::TimedOut);
}

#[test]
fn cancellation_and_destroy_reports_are_typed_values() {
    let reasons = [
        CancelReason::User,
        CancelReason::Timeout,
        CancelReason::Shutdown,
        CancelReason::HandleDropped,
        CancelReason::ProtocolFailure,
    ];
    assert_eq!(reasons[0], CancelReason::User);

    let attempt = AttemptIdentity::from_uuid(Uuid::from_u128(19)).unwrap();
    let report = DestroyReport {
        attempt,
        forced_kill: true,
    };
    assert_eq!(report.attempt, attempt);
    assert!(report.forced_kill);
}
