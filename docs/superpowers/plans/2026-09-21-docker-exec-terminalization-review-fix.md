# Docker Exec Terminalization Review Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Terminate only the interrupted Docker exec command, prove it is reaped before workflow state is read, and add positive exactly-once coverage for every action consumer.

**Architecture:** Wrap each Docker exec command in a dedicated Linux session/process group and publish its PGID through a unique in-container control file. On cancel, timeout, or premature log-stream termination, a bounded helper exec signals only that process group, the original producer is drained, and `inspect_exec` proves `running != true`; typed unsafe-terminal failures bypass state snapshotting. Existing private workflow-state transaction ownership and stdout-before-command-file precedence remain unchanged.

**Tech Stack:** Rust, Tokio, Bollard Docker API, shell process groups via `setsid`, rootless Docker-in-Docker integration tests.

**Spec:** Review findings supplied for base commit `e0195b5`.

## Global Constraints

- Work only in `/Users/antdigo/.codex/worktrees/task9-docker-terminal-fix/chimera`.
- Do not modify execution-domain manager or workspace-reader code.
- Do not kill the long-lived job container for ordinary command cancellation or timeout.
- Use one monotonic deadline for the whole terminalization sequence.
- Preserve atomic stdout-command then validated command-file snapshot ordering and the drain capability boundary.
- Produce one commit named `fix: terminalize docker exec commands safely`; do not push, merge, or open a PR.

## Review Focus

- Cancellation before the PGID file is published must either prove the original exec stopped or return a typed unsafe-terminal error without reading state.
- A command that closes stdout/stderr while still running must be terminalized rather than mistaken for completion.
- TERM-ignoring descendants must receive bounded KILL without affecting the job container or later execs.
- A terminalization RPC/deadline failure must not call `read_step` while the command may still write.
- Fresh reverse-order post transactions must consume their own commands exactly once without replay from prior main/post steps.

---

### Task 1: Command-scoped Docker exec lifecycle

**Files:**
- Modify: `src/docker/exec.rs`
- Modify: `src/docker/exec_test.rs`
- Modify: `src/job/execute.rs`
- Modify: `src/job/action/node.rs`
- Modify: `src/job/action/composite.rs`

**Interfaces:**
- Produces: a typed Docker terminalization error predicate used by `complete_docker_exec_transaction` to skip unsafe snapshots.
- Produces: command wrapping and terminalization helpers internal to `src/docker/exec.rs`.

- [ ] **Step 1: Write failing DinD tests**

Add real-engine tests that cancel and time out a delayed writer, then run both a normal next exec and a post-like exec in the same container. Add a command that closes stdout/stderr before sleeping and writing, proving early EOF is terminalized.

- [ ] **Step 2: Run focused tests and verify RED**

Run the exact ignored tests through `docs/testing-macos-docker.md`. Expected failures: the current implementation leaves the container stopped, so the next exec cannot start; early EOF permits a delayed state write.

- [ ] **Step 3: Implement the minimal command wrapper**

Wrap the original argv as:

```text
/bin/sh -c 'setsid /bin/sh -c '\''write $$; exec "$@"'\'' ... & wait; remove control file' wrapper CONTROL_PATH ORIGINAL_ARGV...
```

The inner shell becomes the process-group leader and preserves the original argv without interpolation.

- [ ] **Step 4: Implement bounded terminalization**

On cancel, timeout, stream error/panic, or EOF while `inspect_exec.running == true`, establish one `Instant` deadline. Under that same deadline: inspect, run the group-killer helper, await the log producer, inspect again, and require `running != true`. Return a typed deadline/RPC/still-running error when terminality cannot be proven.

- [ ] **Step 5: Prevent unsafe snapshot reads**

Add `complete_docker_exec_transaction` in `src/job/execute.rs`. It delegates safe results/errors to `complete_step_transaction`, but immediately returns typed unsafe-terminal failures without reading the command files. Route job-container, Node-container, and composite-container exec paths through it.

- [ ] **Step 6: Verify GREEN**

Run the focused rootless-DinD exec tests. Expected: delayed state never reaches the next snapshot, next/post-like execs succeed in the same container, early EOF is terminalized, and cleanup is empty.

### Task 2: Positive exactly-once consumers

**Files:**
- Modify: `src/job/action/node_test.rs`
- Modify: `src/job/action/composite_test.rs`
- Modify: `src/docker/exec_test.rs`
- Modify: `src/job/action/docker_test.rs`
- Modify: `src/job/execute_test.rs`

**Interfaces:**
- Consumes: existing private `complete_step_transaction` and action rekey behavior.
- Produces: behavioral regression coverage only; no new production API.

- [ ] **Step 1: Add Node and composite positive tests**

Each real action emits one stdout path command and one command-file path entry, then a fresh second transaction. Assert literal ordering and no replay: exactly `["/stdout/<class>", "/file/<class>"]`.

- [ ] **Step 2: Add Docker exec/action positive tests**

Use rootless DinD to assert one stdout path plus one file path is applied once, with file precedence for colliding values, followed by a clean transaction that does not replay either command.

- [ ] **Step 3: Add reverse-order post transaction test**

Run two actions whose post phases append literal markers and workflow paths. Assert posts execute in reverse registration order and each fresh transaction contributes exactly one non-replayed path.

- [ ] **Step 4: Run scoped suites**

Run Node, composite, Docker action, execution, and Docker exec filters. Expected: all positive and malformed/replaced-state cases pass together.

### Task 3: Final verification and delivery

**Files:**
- Verify all modified files above.

**Interfaces:**
- Consumes: completed Tasks 1–2.
- Produces: one clean reviewed commit.

- [ ] **Step 1: Run verification**

Run `cargo build`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, scoped tests, full `cargo test`, and focused rootless-DinD ignored filters. Confirm the nested daemon has no remaining containers or volumes.

- [ ] **Step 2: Audit constraints**

Run `git diff --check`, inspect changed paths, verify manager/workspace-reader files are untouched, and confirm workflow-state precedence/capability code has no new bypass.

- [ ] **Step 3: Commit once**

```bash
git add -- <reviewed files>
git commit -m "fix: terminalize docker exec commands safely"
```

- [ ] **Step 4: Confirm clean delivery**

Verify exactly one commit over `e0195b5`, record the full hash, and require empty `git status --short`.
