use std::fs;
use std::os::unix::fs::PermissionsExt;

use uuid::Uuid;

use super::ExecutionDomainError;
use super::journal::{DomainLifecycle, DomainState};

#[cfg(target_os = "linux")]
#[test]
fn linux_initial_journal_refuses_symlinked_parent() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("outside")).unwrap();
    fs::create_dir(temp.path().join("outside/attempt")).unwrap();
    fs::write(temp.path().join("outside/canary"), b"keep").unwrap();
    std::os::unix::fs::symlink(temp.path().join("outside"), temp.path().join("active")).unwrap();

    assert!(DomainLifecycle::create(&temp.path().join("active/attempt"), Uuid::new_v4()).is_err());
    assert!(!temp.path().join("outside/attempt/journal.json").exists());
    assert_eq!(
        fs::read(temp.path().join("outside/canary")).unwrap(),
        b"keep"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_journal_refuses_hardlinked_or_oversized_record() {
    for hardlink in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let canary = outside.path().join("canary");
        let body =
            br#"{"version":1,"attempt_id":"00000000-0000-0000-0000-000000000009","state":"ready"}"#;
        fs::write(&canary, body).unwrap();
        if hardlink {
            fs::hard_link(&canary, temp.path().join("journal.json")).unwrap();
        } else {
            let mut oversized = body.to_vec();
            oversized.extend(vec![b' '; 16 * 1024]);
            fs::write(temp.path().join("journal.json"), oversized).unwrap();
        }

        assert!(DomainLifecycle::load(temp.path()).is_err());
        assert_eq!(fs::read(canary).unwrap(), body);
    }
}

#[test]
fn accepts_the_normal_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(7)).unwrap();
    assert_eq!(
        DomainLifecycle::load(temp.path()).unwrap().state(),
        DomainState::Provisioning
    );
    for state in [
        DomainState::Ready,
        DomainState::Running,
        DomainState::Cleaning,
        DomainState::Destroying,
    ] {
        lifecycle.transition(state).unwrap();
        assert_eq!(DomainLifecycle::load(temp.path()).unwrap().state(), state);
    }
    fs::remove_dir_all(temp.path()).unwrap();
    lifecycle.complete_destroyed().unwrap();
    assert_eq!(lifecycle.state(), DomainState::Destroyed);
    assert!(!temp.path().exists());
}

#[test]
fn rejects_skipped_transition() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(8)).unwrap();
    let error = lifecycle.transition(DomainState::Running).unwrap_err();
    assert!(matches!(
        error,
        ExecutionDomainError::InvalidTransition { .. }
    ));
    assert_eq!(
        DomainLifecycle::load(temp.path()).unwrap().state(),
        DomainState::Provisioning
    );
    assert!(lifecycle.complete_destroyed().is_err());
}

#[test]
fn rejects_truncated_journal() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("journal.json"), b"{\"version\":1").unwrap();
    assert!(matches!(
        DomainLifecycle::load(temp.path()),
        Err(ExecutionDomainError::InvalidJournal { .. })
    ));
}

#[test]
fn rejects_unknown_journal_version() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("journal.json"),
        br#"{"version":2,"attempt_id":"00000000-0000-0000-0000-000000000009","state":"ready"}"#,
    )
    .unwrap();
    assert!(matches!(
        DomainLifecycle::load(temp.path()),
        Err(ExecutionDomainError::UnsupportedJournalVersion { version: 2, .. })
    ));
}

#[test]
fn rejects_symlinked_journal_without_touching_canary() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(10)).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let canary = outside.path().join("canary");
    fs::write(&canary, "secret-canary").unwrap();
    fs::remove_file(temp.path().join("journal.json")).unwrap();
    std::os::unix::fs::symlink(&canary, temp.path().join("journal.json")).unwrap();
    assert!(lifecycle.transition(DomainState::Ready).is_err());
    assert!(DomainLifecycle::load(temp.path()).is_err());
    assert_eq!(fs::read_to_string(canary).unwrap(), "secret-canary");
    assert!(!temp.path().join("journal.json.next").exists());
}

#[test]
fn refuses_existing_next_file_and_preserves_state() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(11)).unwrap();
    fs::write(temp.path().join("journal.json.next"), "unfinished").unwrap();
    assert!(lifecycle.transition(DomainState::Ready).is_err());
    assert!(DomainLifecycle::load(temp.path()).is_err());
    assert_eq!(lifecycle.state(), DomainState::Provisioning);
    assert_eq!(
        fs::read_to_string(temp.path().join("journal.json.next")).unwrap(),
        "unfinished"
    );
}

#[test]
fn refuses_existing_journal_on_creation() {
    let temp = tempfile::tempdir().unwrap();
    DomainLifecycle::create(temp.path(), Uuid::from_u128(12)).unwrap();
    let original = fs::read(temp.path().join("journal.json")).unwrap();
    assert!(DomainLifecycle::create(temp.path(), Uuid::from_u128(13)).is_err());
    assert_eq!(
        fs::read(temp.path().join("journal.json")).unwrap(),
        original
    );
}

#[test]
fn journals_are_private_and_contain_exact_attempt_identity() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(14)).unwrap();
    lifecycle.transition(DomainState::Ready).unwrap();
    let path = temp.path().join("journal.json");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let record: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(
        record,
        serde_json::json!({"version":1,"attempt_id":"00000000-0000-0000-0000-00000000000e","state":"ready"})
    );
}

#[test]
fn journal_errors_do_not_expose_body_secrets() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("journal.json"), br#"{"version":1,"attempt_id":"00000000-0000-0000-0000-000000000009","state":"credential-secret"}"#).unwrap();
    let error = DomainLifecycle::load(temp.path()).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("credential-secret"));
    assert!(
        !std::error::Error::source(&error)
            .unwrap()
            .to_string()
            .contains("credential-secret")
    );
}

#[test]
fn enforces_every_lifecycle_edge() {
    use DomainState::*;
    let states = [
        Provisioning,
        Ready,
        Running,
        Cleaning,
        Destroying,
        Destroyed,
        Quarantined,
    ];
    let names = [
        "provisioning",
        "ready",
        "running",
        "cleaning",
        "destroying",
        "destroyed",
        "quarantined",
    ];
    let allowed = [
        (Provisioning, Ready),
        (Provisioning, Destroying),
        (Ready, Running),
        (Ready, Destroying),
        (Running, Cleaning),
        (Running, Destroying),
        (Cleaning, Destroying),
        (Destroying, Quarantined),
    ];
    for (from, name) in states.into_iter().zip(names) {
        for to in states {
            let temp = tempfile::tempdir().unwrap();
            fs::write(temp.path().join("journal.json"), format!(
                r#"{{"version":1,"attempt_id":"00000000-0000-0000-0000-000000000009","state":"{name}"}}"#
            )).unwrap();
            let mut lifecycle = DomainLifecycle::load(temp.path()).unwrap();
            let result = lifecycle.transition(to);
            assert_eq!(
                result.is_ok(),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
            assert_eq!(
                DomainLifecycle::load(temp.path()).unwrap().state(),
                if result.is_ok() { to } else { from }
            );
        }
    }
}

#[test]
fn corrupt_or_mismatched_journal_prevents_transition() {
    for body in [
        "{",
        r#"{"version":1,"attempt_id":"00000000-0000-0000-0000-000000000099","state":"provisioning"}"#,
        r#"{"version":1,"attempt_id":"00000000-0000-0000-0000-000000000009","state":"running"}"#,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(9)).unwrap();
        fs::write(temp.path().join("journal.json"), body).unwrap();
        assert!(lifecycle.transition(DomainState::Ready).is_err());
        assert_eq!(lifecycle.state(), DomainState::Provisioning);
        assert_eq!(
            fs::read_to_string(temp.path().join("journal.json")).unwrap(),
            body
        );
    }
}

#[test]
fn refuses_next_symlink_without_touching_canary() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(15)).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let canary = outside.path().join("canary");
    fs::write(&canary, "secret-canary").unwrap();
    std::os::unix::fs::symlink(&canary, temp.path().join("journal.json.next")).unwrap();
    assert!(lifecycle.transition(DomainState::Ready).is_err());
    assert_eq!(fs::read_to_string(canary).unwrap(), "secret-canary");
}

#[test]
fn refuses_replaced_attempt_before_journal_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let attempt = temp.path().join("attempt");
    fs::create_dir(&attempt).unwrap();
    let mut lifecycle = DomainLifecycle::create(&attempt, Uuid::from_u128(16)).unwrap();
    fs::rename(&attempt, temp.path().join("moved")).unwrap();
    fs::create_dir(&attempt).unwrap();
    fs::write(attempt.join("journal.json"), "replacement-canary").unwrap();
    assert!(lifecycle.transition(DomainState::Ready).is_err());
    assert_eq!(
        fs::read_to_string(attempt.join("journal.json")).unwrap(),
        "replacement-canary"
    );
    assert_eq!(
        DomainLifecycle::load(&temp.path().join("moved"))
            .unwrap()
            .state(),
        DomainState::Provisioning
    );
}

#[test]
fn restrictive_umask_still_produces_readable_private_journals() {
    let temp = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "job::execution_domain::journal_test::restrictive_umask_child",
            "--nocapture",
        ])
        .env("CHIMERA_JOURNAL_UMASK_CHILD", temp.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::metadata(temp.path().join("journal.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        DomainLifecycle::load(temp.path()).unwrap().state(),
        DomainState::Ready
    );
}

#[test]
fn restrictive_umask_child() {
    let Some(path) = std::env::var_os("CHIMERA_JOURNAL_UMASK_CHILD") else {
        return;
    };
    unsafe {
        libc::umask(0o777);
    }
    let mut lifecycle =
        DomainLifecycle::create(std::path::Path::new(&path), Uuid::from_u128(17)).unwrap();
    lifecycle.transition(DomainState::Ready).unwrap();
}
