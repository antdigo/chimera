# Task 4 Report: Shared Exclusive Root Lock

## Status

Implemented and committed as `cd52c2e58d3ae05ebe31a267074960e9d99e09c1` (`feat: lock chimera root mutations`).

The agent worktree was first fast-forwarded to `worktree-registration-import`; `HEAD` was verified at the required base `8a92e4af55861489ed0f5d2816d380b375e6a9c7` before production files were read or changed.

## Implementation

- Added the crate-private `RootLock` / `RootLockError` primitive.
- Existing roots are validated with `symlink_metadata`: the final component must be a directory, not a symlink, owned by the effective user, and not group/world writable.
- Missing root components are created one at a time with mode `0700`; every newly created directory is explicitly set to `0700` before the next component is created. Components that appear concurrently are validated and are never chmodded. The final root is re-read and validated before use.
- `.chimera.lock` is opened with `create_new` plus an existing-file fallback, `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, and mode `0600`. Only a newly created lock file is explicitly chmodded. Existing lock files must be private regular files owned by the effective user.
- Lock acquisition uses nonblocking `flock(LOCK_EX | LOCK_NB)` and maps `EWOULDBLOCK` / `EAGAIN` to `RootLockError::Busy`. The file descriptor remains in `RootLock`; there is no unlink or custom `Drop`.
- Added `ChimeraPaths::root_lock_file()` returning `<root>/.chimera.lock`.
- Replaced `Daemon::new` with `Daemon::load`: it acquires the root lock before config loading, stores the guard for the complete daemon lifetime, and exposes `config()` for tracing/startup checks.
- Updated CLI startup so the locked `Daemon` exists before tracing reads daemon config and remains alive through `run_start` / `Daemon::run`.
- `register` acquires the lock before URL parsing, client creation, and the first HTTP request. `unregister` acquires it before checking or deleting the runner directory.
- Register/unregister config handling now propagates malformed config errors instead of using `unwrap_or_default()`.
- Kept `PidLock` unchanged for status/liveness behavior.
- Preserved Task 2 `pub mod import;` and Task 3 broker behavior.

The busy-lock conversion retains the typed `RootLockError` as the anyhow source while putting both the operation context and source message in the outer display. This is necessary because `anyhow::Context` alone displays only the context through `to_string()`, while the prescribed contention tests require `root storage is busy` to remain visible.

## Files

- Added `src/storage.rs`
- Added `src/storage_test.rs`
- Modified `src/config.rs`
- Modified `src/lib.rs`
- Modified `src/daemon.rs`
- Modified `src/daemon_test.rs`
- Modified `src/cli.rs`
- Modified `src/github/registration.rs`
- Modified `src/github/registration_test.rs`

No unrelated files or Docker spec files were changed.

## TDD Evidence

### RED

1. Command:

   ```text
   cargo test storage_test && cargo test github::registration::registration_test::unregister_refuses_busy_root -- --exact
   ```

   Result: exit 101. Compilation failed because `RootLock` and `RootLockError` did not exist, including the expected unresolved-type errors from `src/storage_test.rs`.

2. After implementing the isolated primitive, command:

   ```text
   cargo test github::registration::registration_test::unregister_refuses_busy_root -- --exact
   ```

   Result: exit 101. The new test failed at `unwrap_err()` because the old `unregister` returned `Ok(())` and deleted without honoring the held root lock.

3. After adding the prescribed daemon/path expectations, command:

   ```text
   cargo test daemon::daemon_test::daemon_load_refuses_busy_root_before_reading_config -- --exact
   ```

   Result: exit 101. Compilation failed with the expected missing `Daemon::load` (and, at that RED stage, missing `ChimeraPaths::root_lock_file`).

### GREEN

1. Command:

   ```text
   cargo test storage_test
   ```

   Result: 4 passed, 0 failed.

2. First integrated GREEN attempt exposed that plain `anyhow::Context` hid the busy cause from `Error::to_string()`. The daemon contention test failed its required `root storage is busy` assertion. The error wrapping was corrected while retaining the source chain.

3. Command:

   ```text
   cargo test storage_test && cargo test daemon::daemon_test::daemon_load_refuses_busy_root_before_reading_config -- --exact && cargo test daemon::daemon_test::daemon_holds_root_lock_for_its_lifetime -- --exact && cargo test github::registration::registration_test::unregister_refuses_busy_root -- --exact
   ```

   Result: exit 0; all prescribed storage, daemon ordering/lifetime, and unregister contention tests passed.

4. Command:

   ```text
   cargo test daemon_test && cargo test github::registration::registration_test
   ```

   Result: daemon module 18 passed, 0 failed; registration module 7 passed, 0 failed.

## Verification

- `cargo fmt -- --check && cargo build`: exit 0. Formatting is clean and the project builds.
- `cargo clippy -- -D warnings`: exit 101 only because of the 21 pre-existing/intermediate Task 2 `dead_code` diagnostics in `src/import.rs` and `src/import/source.rs`, which the brief explicitly forbids suppressing or bypassing.
- `cargo clippy --all-targets`: exit 0. It reported only those known Task 2 diagnostics (21 library warnings plus 2 test-target warnings in `src/import.rs` / `src/import/test_support.rs`); there were no Task 4 or other Clippy warnings.
- `cargo test`: exit 0. Across unit and integration targets, 573 passed, 0 failed, 15 ignored (4 ignored unit tests plus 11 Docker tests). Docker code was not changed, so the ignored suite was not required by the brief.
- IDE project build: successful; the IDE noted that detailed build messages were unavailable.
- `git diff --check`: exit 0 before commit.
- Final changed-file scope matched the nine files listed in Task 4 Step 7.

## Self-review

- Confirmed lock acquisition precedes daemon config reads, register network activity, and unregister directory checks/removal.
- Confirmed each guard remains in scope through the complete mutating lifecycle.
- Confirmed the lock inode is stable: no unlink and no lock-file replacement on release.
- Confirmed existing root directories and existing lock files are never chmodded.
- Confirmed the new root and lock modes are repaired after restrictive umask effects before subsequent writes/use.
- Confirmed symlink roots and symlink lock files are rejected without touching their targets.
- Confirmed concurrent writers fail immediately with `Busy` and acquisition succeeds after the first guard drops.
- Confirmed busy unregister leaves both runner data and config bytes/runner membership unchanged.
- Confirmed `PidLock` remains in daemon execution and remains covered by its existing tests.
- Confirmed malformed config fallback was removed only from register/unregister as required.
- Confirmed no new crate, no production `unwrap`/`expect`, no dead-code suppression, and no unrelated refactor.

## Concerns

- The strict `cargo clippy -- -D warnings` command cannot be green at the Task 4 base because Tasks 2–3 intentionally leave import code unwired. Its 21 failures are exclusively the known Task 2 `dead_code` diagnostics; Task 4 introduces no Clippy warnings, as verified by the complete `cargo clippy --all-targets` run.
- The 15 ignored tests were not run; 11 are Docker tests and this task did not modify Docker-related code.

# Fix Round 1

## Status and implementation

The three blocking findings were addressed without changing the lifecycle wiring or crate-public interfaces:

- Root resolution now starts from a pinned `/` descriptor and walks every component with `fstatat(AT_SYMLINK_NOFOLLOW)` and `openat(..., O_NOFOLLOW)`. Intermediate symlinks are expanded explicitly with bounded `readlinkat`; the final raw component is never followed.
- Every ancestor is checked from its opened inode. It must be owned by the effective user or root; group/world-writable ancestors must be sticky, and entries selected through sticky shared storage must be owned by the effective user or root. This prevents later pathname operations from being redirected through ancestry writable by an untrusted user.
- The selected root descriptor is retained in `RootLock` for the full guard lifetime, and `.chimera.lock` is opened relative to that descriptor. A deterministic rename/replacement test proves the lock open remains bound to the pinned root inode rather than a fresh pathname lookup.
- Missing components use `mkdirat`; the newly opened descriptor is checked against the created device/inode and receives its final mode with `fchmod`. If a restrictive umask removed owner-search permission, the only name-relative repair uses `fchmodat(..., AT_SYMLINK_NOFOLLOW)` beneath an already validated parent, followed immediately by `openat`, device/inode comparison, and descriptor-based `fchmod`.
- `linked-root/` and `linked-root/.` both resolve the symlink itself as the final raw component and are rejected.
- Relative roots are first anchored to `std::env::current_dir()`; no test or production code changes the process-global working directory.

Only `src/storage.rs` and `src/storage_test.rs` were changed in this fix round, in addition to this required report append. The existing `pub mod import;`, broker behavior, PID lock, and daemon/register/unregister wiring were left unchanged. No crate, public API, lint suppression, fake caller, or unrelated file was added.

## TDD evidence

### RED

Command:

```text
cargo test storage_test
```

Result: exit 101 against the pre-fix implementation. The two terminal-spelling tests reached `unwrap_err()` with an unexpected successful `RootLock`, while the missing multi-component relative-root test failed with the old `root has no existing ancestor` error. These failures directly reproduced findings 2 and 3 before the storage implementation was redesigned.

The critical substitution finding is covered deterministically by `opens_lock_file_relative_to_pinned_root_directory`: after opening the root descriptor, the test renames that directory and creates a replacement at the old pathname; the lock is created only inside the moved, pinned directory. `rejects_group_or_world_writable_non_sticky_ancestor` covers the untrusted-ancestry prerequisite of pathname-based lifecycle operations.

### GREEN

Command:

```text
cargo test storage_test && cargo test daemon_test && cargo test github::registration::registration_test
```

Result: exit 0. Storage: 9 passed; daemon: 18 passed; registration: 7 passed; no failures.

Restrictive-umask verification was performed without running Cargo under the restrictive umask. After compiling at the normal umask, the already-built test binary was run directly:

```text
umask 0777; target/debug/deps/chimera-ca0c5d33cf952d8a --exact storage::storage_test::creates_new_root_and_lock_with_private_modes
```

Result: exit 0; 1 passed, 0 failed. An earlier Cargo-under-umask probe had removed owner permissions from generated incremental artifacts; only those local artifacts were repaired with `chmod -R u+rwX target`, as authorized, before rebuilding normally. No tracked file was repaired or changed by that recovery.

## Verification

- `cargo fmt -- --check && cargo build`: exit 0. Formatting is clean and the build completed; output contains only the 21 known Task 2 `dead_code` warnings.
- `cargo test storage_test && cargo test daemon_test && cargo test github::registration::registration_test`: exit 0; 9 + 18 + 7 focused tests passed.
- `cargo test`: exit 0; 487 unit tests and 91 integration tests passed (578 total), 0 failed, 15 ignored (4 unit and 11 Docker tests).
- `cargo clippy -- -D warnings`: exit 101 solely for the same 21 known Task 2 `dead_code` diagnostics in `src/import.rs` and `src/import/source.rs`; there are no diagnostics in the Fix Round 1 files.
- `cargo clippy --all-targets`: exit 0 with only the known 21 library and 2 test-target Task 2 warnings.
- `git diff --check`: exit 0. Before this report append, the tracked diff contained exactly `src/storage.rs` and `src/storage_test.rs`.

## Self-review

- Confirmed no discarded pathname recheck is used as the lock identity guarantee: the descriptor returned by the fd-relative walk is the descriptor used by `openat` and retained by `RootLock`.
- Confirmed every opened directory is validated from `fstat`, every lookup is relative to a pinned parent, and every final open uses no-follow semantics.
- Confirmed a concurrent component that appears after `mkdirat` is never chmodded by the `AlreadyExists` path.
- Confirmed restrictive-umask repair is limited to a component just created beneath validated ancestry, does not follow a substituted symlink, verifies the opened inode identity, and ends with descriptor-based `fchmod`.
- Confirmed terminal slash/dot spellings cannot turn a final symlink into an accepted directory.
- Confirmed relative roots are anchored without mutating global cwd and the test reserves a unique path under the existing cwd for parallel-test safety.
- Confirmed all production paths remain free of `unwrap`/`expect`, and no known Task 2 warnings were hidden or bypassed.

## Concerns

- Strict Clippy remains red only because of the explicitly preserved 21 Task 2 `dead_code` diagnostics; all-target Clippy confirms this fix adds no warning.
- The 15 ignored tests were not run. Eleven require Docker, and this fix does not modify Docker code; the other four were already ignored at the base.
- The controller-deferred Minor coverage list was intentionally not expanded in this round.
