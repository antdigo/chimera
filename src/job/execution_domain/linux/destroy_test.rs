use std::time::Instant;

use uuid::Uuid;

use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory};
use super::destroy::{DestroyOps, ShutdownBounds, destroy_kernel, failure};

struct Harness {
    events: Vec<&'static str>,
    empty_before_kill: bool,
    empty_after_kill: bool,
    killed: bool,
    term_error: bool,
    fail_at: Option<&'static str>,
    empty_calls: usize,
}

impl Harness {
    fn new(empty_before_kill: bool, empty_after_kill: bool) -> Self {
        Self {
            events: Vec::new(),
            empty_before_kill,
            empty_after_kill,
            killed: false,
            term_error: false,
            fail_at: None,
            empty_calls: 0,
        }
    }

    fn event(&mut self, name: &'static str) -> Result<(), ExecutionDomainError> {
        self.events.push(name);
        if self.fail_at == Some(name) {
            Err(failure(FailureCategory::Io))
        } else {
            Ok(())
        }
    }
}

impl DestroyOps for Harness {
    fn close_admission(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("close-admission")
    }
    fn persist_destroying(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("persist-destroying")
    }
    fn graceful_shutdown(&mut self, _: Instant) -> Result<(), ExecutionDomainError> {
        self.event("shutdown-init")
    }
    fn term_members(&mut self, _: Instant) -> Result<(), ExecutionDomainError> {
        self.event("term")?;
        if self.term_error {
            Err(failure(FailureCategory::Io))
        } else {
            Ok(())
        }
    }
    fn recursively_empty_until(
        &mut self,
        _deadline: Instant,
    ) -> Result<bool, ExecutionDomainError> {
        self.events.push("empty");
        self.empty_calls += 1;
        if self.fail_at == Some("first-empty") && self.empty_calls == 1
            || self.fail_at == Some("second-empty") && self.empty_calls == 2
        {
            return Err(failure(FailureCategory::Io));
        }
        Ok(if self.killed {
            self.empty_after_kill
        } else {
            self.empty_before_kill
        })
    }
    fn kill_all(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("kill")?;
        self.killed = true;
        Ok(())
    }
    fn reap_launcher(&mut self, _: Instant) -> Result<(), ExecutionDomainError> {
        self.event("reap")
    }
    fn drain_diagnostics(&mut self, _: Instant) -> Result<(), ExecutionDomainError> {
        self.event("drain")
    }
    fn close_handles(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("close-handles")
    }
    fn prove_no_mounts(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("no-mounts")
    }
    fn remove_runtime_socket(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("socket")
    }
    fn remove_filesystem(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("unlink-state")
    }
    fn remove_cgroup(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("remove-cgroup")
    }
    fn fsync_root(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("fsync-root")
    }
    fn mark_destroyed(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("destroyed")
    }
}

fn attempt() -> AttemptIdentity {
    AttemptIdentity::from_uuid(Uuid::from_u128(10)).unwrap()
}

#[test]
fn destroy_kills_before_removing_files_and_reports_forced_kill() {
    let mut harness = Harness::new(false, true);

    let report = destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).unwrap();

    assert!(report.forced_kill);
    assert_eq!(
        harness.events,
        [
            "close-admission",
            "persist-destroying",
            "shutdown-init",
            "term",
            "empty",
            "kill",
            "empty",
            "reap",
            "drain",
            "close-handles",
            "no-mounts",
            "socket",
            "unlink-state",
            "remove-cgroup",
            "fsync-root",
            "destroyed",
        ]
    );
}

#[test]
fn graceful_empty_skips_cgroup_kill() {
    let mut harness = Harness::new(true, true);

    let report = destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).unwrap();

    assert!(!report.forced_kill);
    assert!(!harness.events.contains(&"kill"));
}

#[test]
fn term_error_still_reaches_kill_but_never_unlinks() {
    let mut harness = Harness::new(true, true);
    harness.term_error = true;

    assert!(destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).is_err());

    assert!(harness.events.contains(&"kill"));
    assert!(!harness.events.contains(&"unlink-state"));
}

#[test]
fn failed_empty_proof_never_unlinks() {
    let mut harness = Harness::new(false, false);

    assert!(destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).is_err());

    assert!(harness.events.contains(&"close-handles"));
    assert!(!harness.events.contains(&"unlink-state"));
}

#[test]
fn cgroup_read_error_is_retained_while_kill_and_safe_close_continue() {
    let mut harness = Harness::new(false, true);
    harness.fail_at = Some("first-empty");

    assert!(destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).is_err());

    assert!(harness.events.contains(&"kill"));
    assert!(harness.events.contains(&"close-handles"));
    assert!(harness.events.contains(&"no-mounts"));
    assert!(!harness.events.contains(&"unlink-state"));
}

#[test]
fn every_proof_failure_blocks_filesystem_mutation() {
    for stage in [
        "close-admission",
        "persist-destroying",
        "shutdown-init",
        "term",
        "kill",
        "reap",
        "drain",
        "close-handles",
        "no-mounts",
    ] {
        let mut harness = Harness::new(false, true);
        harness.fail_at = Some(stage);

        assert!(
            destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).is_err(),
            "{stage}"
        );
        assert!(!harness.events.contains(&"unlink-state"), "{stage}");
    }
}

#[test]
fn every_destructive_failure_is_reported_without_marking_destroyed() {
    for stage in ["socket", "unlink-state", "remove-cgroup", "fsync-root"] {
        let mut harness = Harness::new(false, true);
        harness.fail_at = Some(stage);

        assert!(
            destroy_kernel(&mut harness, attempt(), ShutdownBounds::default()).is_err(),
            "{stage}"
        );
        assert!(!harness.events.contains(&"destroyed"), "{stage}");
    }
}
