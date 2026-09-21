use std::time::{Duration, Instant};

use super::super::{AttemptIdentity, DestroyReport, ExecutionDomainError, FailureCategory, Stage};

#[derive(Clone, Copy)]
pub(super) struct ShutdownBounds {
    pub term: Duration,
    pub kill: Duration,
    pub drain: Duration,
}

impl Default for ShutdownBounds {
    fn default() -> Self {
        Self {
            term: Duration::from_secs(5),
            kill: Duration::from_secs(10),
            drain: Duration::from_secs(2),
        }
    }
}

pub(super) trait DestroyOps {
    fn close_admission(&mut self) -> Result<(), ExecutionDomainError>;
    fn persist_destroying(&mut self) -> Result<(), ExecutionDomainError>;
    fn graceful_shutdown(&mut self, deadline: Instant) -> Result<(), ExecutionDomainError>;
    fn term_members(&mut self, deadline: Instant) -> Result<(), ExecutionDomainError>;
    fn recursively_empty_until(&mut self, deadline: Instant) -> Result<bool, ExecutionDomainError>;
    fn kill_all(&mut self, deadline: Instant) -> Result<(), ExecutionDomainError>;
    fn reap_launcher(&mut self, deadline: Instant) -> Result<(), ExecutionDomainError>;
    fn drain_diagnostics(&mut self, deadline: Instant) -> Result<(), ExecutionDomainError>;
    fn close_handles(&mut self) -> Result<(), ExecutionDomainError>;
    fn prove_no_mounts(&mut self) -> Result<(), ExecutionDomainError>;
    fn remove_runtime_socket(&mut self) -> Result<(), ExecutionDomainError>;
    fn remove_filesystem(&mut self) -> Result<(), ExecutionDomainError>;
    fn remove_cgroup(&mut self) -> Result<(), ExecutionDomainError>;
    fn fsync_root(&mut self) -> Result<(), ExecutionDomainError>;
    fn mark_destroyed(&mut self) -> Result<(), ExecutionDomainError>;
}

/// Runs the only terminal cleanup sequence. The caller owns poisoning and the
/// admission permit; it may release capacity only after this function returns Ok.
pub(super) fn destroy_kernel<O: DestroyOps>(
    operations: &mut O,
    attempt: AttemptIdentity,
    bounds: ShutdownBounds,
) -> Result<DestroyReport, ExecutionDomainError> {
    let started = Instant::now();
    let term_deadline = started
        .checked_add(bounds.term)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let kill_deadline = term_deadline
        .checked_add(bounds.kill)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
    let drain_deadline = kill_deadline
        .checked_add(bounds.drain)
        .ok_or_else(|| failure(FailureCategory::InvalidInput))?;

    let mut first_error = operations.close_admission().err();
    retain_first(&mut first_error, operations.persist_destroying());
    retain_first(
        &mut first_error,
        operations.graceful_shutdown(term_deadline),
    );
    retain_first(&mut first_error, operations.term_members(term_deadline));

    let graceful_empty = match operations.recursively_empty_until(term_deadline) {
        Ok(empty) => empty,
        Err(error) => {
            retain_first(&mut first_error, Err(error));
            false
        }
    };
    // Any uncertainty before the empty proof (including a protocol/TERM
    // failure) requires the cgroup-wide KILL path even if the subsequent read
    // happens to report empty. An ACK or one observation cannot downgrade the
    // earlier failure.
    let forced_kill = !graceful_empty || first_error.is_some();
    let mut empty_proven = graceful_empty;
    if forced_kill {
        retain_first(&mut first_error, operations.kill_all(kill_deadline));
        match operations.recursively_empty_until(kill_deadline) {
            Ok(true) => empty_proven = true,
            Ok(false) => retain_first(&mut first_error, Err(failure(FailureCategory::Timeout))),
            Err(error) => retain_first(&mut first_error, Err(error)),
        }
    }

    if !empty_proven && first_error.is_none() {
        first_error = Some(failure(FailureCategory::Timeout));
    }

    retain_first(&mut first_error, operations.reap_launcher(drain_deadline));
    retain_first(
        &mut first_error,
        operations.drain_diagnostics(drain_deadline),
    );
    retain_first(&mut first_error, operations.close_handles());
    retain_first(&mut first_error, operations.prove_no_mounts());
    // Destructive filesystem cleanup is forbidden unless recursive cgroup
    // emptiness and every preceding ownership proof succeeded.
    if let Some(error) = first_error {
        return Err(error);
    }

    // A retained socket capability is checked before any generic tree removal.
    operations.remove_runtime_socket()?;
    operations.remove_filesystem()?;
    operations.remove_cgroup()?;
    operations.fsync_root()?;
    operations.mark_destroyed()?;

    Ok(DestroyReport {
        attempt,
        forced_kill,
    })
}

fn retain_first(
    first: &mut Option<ExecutionDomainError>,
    result: Result<(), ExecutionDomainError>,
) {
    if let Err(error) = result
        && first.is_none()
    {
        *first = Some(error);
    }
}

pub(super) fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Destroy,
        category,
        errno: None,
    }
}
