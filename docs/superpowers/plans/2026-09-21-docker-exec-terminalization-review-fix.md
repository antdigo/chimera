# Docker Exec Container Recovery Review Fix Plan

**Goal:** Recover a reusable job container after any interrupted or ambiguous Docker exec without trusting guest-side helpers or reading state while late writers may survive.

**Architecture:** Establish a command deadline plus one fixed outer lifecycle deadline before the first Docker RPC. Normal completion requires an exec inspection proving `running != true`. Cancellation, timeout, premature stream completion, or ambiguous create/start stops the whole job container, settles any in-flight RPC/log producer while stopped, proves the container and known exec are non-running, then restarts and re-inspects the same container. Recovery failures are typed unsafe errors and bypass the workflow-state snapshot.

**Constraints:**

- Work only in `/Users/antdigo/.codex/worktrees/task9-docker-recovery-fix/chimera` from `855026c`.
- No guest `setsid`, control file, shell, or helper-exec dependency in production recovery.
- A pre-cancelled call must not issue `create_exec` or any other Docker mutation.
- Preserve stdout workflow-command ordering before the validated command-file snapshot.
- Do not modify execution-domain manager or workspace-reader code.
- Produce one commit: `fix: recover job container after interrupted exec`.

## Task 1: Redesign Docker exec lifecycle

- [x] Add rootless-DinD regressions for a detached-session delayed writer, control-path tampering, cancel/timeout, premature attach termination, and next/post-like exec reuse in the restarted container.
- [x] Add proxy regressions that delay create/start responses past the command deadline.
- [x] Replace guest process-group handling with bounded container stop/prove/restart recovery.
- [x] Keep create/start futures alive while the container is stopped, settle them before restart, and inspect a known exec before returning.
- [x] Return typed unsafe errors for any recovery deadline/RPC/state failure; unsafe errors must skip `read_step`.

## Task 2: Positive end-to-end consumers

- [x] Replace the Docker-action transaction-helper test with a real `run_docker_metadata_action` invocation that proves stdout and command-file mutations apply exactly once.
- [x] Replace the manual Node post loop with an execute-job-level two-action test proving reverse post order, fresh transactions, and no replay.
- [x] Retain Node, composite, Docker exec, collision/PATH precedence, and malformed/replaced-state coverage.

## Task 3: Verification and delivery

- [x] Run scoped unit tests and focused rootless-DinD tests, including proxy deadline cases.
- [x] Run formatting, clippy, build, and the full feasible test suite.
- [x] Confirm nested/outer DinD cleanup and that manager/workspace-reader paths are untouched.
- [x] Commit once with the requested message and leave a clean tree.
