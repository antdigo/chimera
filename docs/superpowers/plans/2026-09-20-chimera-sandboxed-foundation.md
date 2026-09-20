# Sandboxed Execution Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the shallow job-Docker-config lifecycle with one execution-domain ownership seam, durable state, and admission control while preserving `trusted-host` behavior and keeping `sandboxed` impossible to activate.

**Architecture:** `ExecutionDomainRoot` owns global health and admission; a `DomainPermit` is acquired before Online polling and transfers its slot into one `ExecutionDomain`. The domain owns attempt paths, private Docker config, lifecycle journal, explicit destruction, and root poisoning. This plan deliberately does not create namespaces, cgroups, rootless dockerd, or network policy; later plans add those behind the same interface.

**Tech Stack:** Rust 2024, Tokio semaphore/watch, Serde/TOML/JSON, UUID, existing filesystem identity checks and Cargo test harness.

**Spec:** [`docs/superpowers/specs/2026-09-20-chimera-sandboxed-execution-domain.md`](../specs/2026-09-20-chimera-sandboxed-execution-domain.md)

## Global Constraints

- The production profile name is exactly `sandboxed`; `trusted-host` remains the backward-compatible default.
- Plan A must reject `profile = "sandboxed"` before runner sessions or cache listeners start.
- One lifecycle owner: `JobDockerConfig` is replaced by `ExecutionDomain`, not wrapped by a second owner.
- No shared/rootful Docker fallback is introduced or changed in this plan.
- Existing `trusted-host` job behavior, Docker config isolation, completion ordering, and fail-closed cleanup remain unchanged.
- One service account, one systemd unit, and one `subuid/subgid` range remain the target; Plan A does not mutate host configuration.
- A dropped or unsuccessfully destroyed domain poisons the shared root and prevents further job polling.
- Production code changes are test-first; every task ends with a focused test run and a commit.
- The `sandboxed` profile cannot become activatable until Plans B–E and release checks S-01…S-16 are complete.

## Review Focus

- Unknown profile spelling and `max_active_domains = 0` must fail config parsing rather than silently choosing a default; Task 2 adds both tests.
- Truncated, version-skewed, or symlinked journal files must never be treated as clean state; Task 4 adds corruption and replacement tests.
- Admission cancellation and root poisoning while a waiter is blocked must release/wake without leaking a permit; Task 5 adds both async tests.
- Existing symlink/inode replacement attacks during creation and destruction must remain fail-closed after the rename; Task 3 migrates and reruns the full adversarial suite.
- Job completion must still be published only after capability revocation and the domain destruction attempt returns; Task 6 adds an explicit ordering test, including the cleanup-failure downgrade path.

---

## File Structure

Files created by this plan:

- `src/config/execution.rs` — serialized profile and concurrency configuration only.
- `src/config/execution_test.rs` — config defaults, validation, and round-trip tests.
- `src/job/execution_domain/mod.rs` — narrow public domain/root/permit interface.
- `src/job/execution_domain/error.rs` — typed lifecycle and filesystem errors.
- `src/job/execution_domain/filesystem.rs` — private path creation, identity checks, and safe removal migrated from `docker_config.rs`.
- `src/job/execution_domain/journal.rs` — versioned lifecycle journal and transition validation.
- `src/job/execution_domain/journal_test.rs` — journal transition and corruption tests.
- `src/job/execution_domain/admission.rs` — semaphore-backed `DomainPermit`.
- `src/job/execution_domain/admission_test.rs` — blocking, cancellation, and poison tests.
- `src/job/execution_domain_test.rs` — migrated filesystem/domain tests.
- `tests/execution_domain_test.rs` — migrated public job-lifecycle integration tests.
- `tests/execution_domain_docker_test.rs` — renamed ignored Docker acceptance suite; behavior remains `trusted-host` in Plan A.

Files removed by this plan:

- `src/job/docker_config.rs`
- `src/job/docker_config_test.rs`
- `tests/job_docker_config_test.rs`
- `tests/job_docker_config_docker_test.rs`

Files modified by this plan:

- `src/config.rs` — embeds `ExecutionConfig` in `ChimeraConfig`.
- `src/config_test.rs` — default file assertions.
- `src/job.rs` — exports `execution_domain` instead of `docker_config`.
- `src/job/execute.rs`, `src/job/action/*.rs`, `src/runner/env.rs` — consume the renamed domain interface.
- `src/runner/instance.rs` — transfers `DomainPermit` through broker/job lifecycle and destroys the domain before completion.
- `src/runner/instance_test.rs` — admission and completion-order coverage.
- `src/daemon.rs`, `src/daemon_test.rs` — root construction and temporary `sandboxed` activation gate.
- `src/job/action/*_test.rs`, `src/job/execute_test.rs`, `src/runner/env_test.rs`, `tests/common/mod.rs` — test fixture migration.
- `README.md`, `docs/job-docker-config.md` — profile semantics and renamed lifecycle owner.

### Task 1: Commit the approved design baseline

**Files:**
- Add: `docs/superpowers/specs/2026-09-20-chimera-sandboxed-execution-domain.md`
- Add: `docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md`
- Add: `docs/superpowers/plans/2026-09-20-chimera-sandboxed-foundation.md`

**Interfaces:**
- Consumes: approved conversation decisions and spike evidence at commit `61abcb7809257eeb9bf840a82da5129e06603b2d`.
- Produces: immutable review baseline for every later code commit.

- [ ] **Step 1: Verify the documentation diff contains no whitespace errors**

Run:

```bash
git diff --check
```

Expected: exit 0 with no output.

- [ ] **Step 2: Verify all local evidence links resolve**

Run:

```bash
test -f prototypes/attempt-isolation/RESULTS.md
test -f prototypes/attempt-isolation/README.md
test -f docs/superpowers/reports/2026-09-20-chimera-attempt-isolation-related-issues.md
```

Expected: all commands exit 0.

- [ ] **Step 3: Commit the approved design and plan suite**

```bash
git add docs/superpowers/specs/2026-09-20-chimera-sandboxed-execution-domain.md docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md docs/superpowers/plans/2026-09-20-chimera-sandboxed-foundation.md
git commit -m "docs: design sandboxed execution domain"
```

Expected: one documentation-only commit.

### Task 2: Add execution profile configuration

**Files:**
- Create: `src/config/execution.rs`
- Create: `src/config/execution_test.rs`
- Modify: `src/config.rs:1-25`
- Modify: `src/config_test.rs:43-89`

**Interfaces:**
- Consumes: Serde/TOML configuration conventions from `ChimeraConfig`.
- Produces: `ExecutionConfig { profile: ExecutionProfile, max_active_domains: NonZeroUsize }`, with `ExecutionProfile::{TrustedHost, Sandboxed}`.

- [ ] **Step 1: Write failing profile/default/invalid-value tests**

Add `src/config/execution_test.rs`:

```rust
use std::num::NonZeroUsize;

use super::{ExecutionConfig, ExecutionProfile};

#[test]
fn defaults_to_trusted_host_with_one_reserved_slot() {
    let config = ExecutionConfig::default();
    assert_eq!(config.profile, ExecutionProfile::TrustedHost);
    assert_eq!(config.max_active_domains, NonZeroUsize::new(1).unwrap());
}

#[test]
fn parses_sandboxed_capacity() {
    let config: ExecutionConfig = toml::from_str(
        "profile = 'sandboxed'\nmax_active_domains = 40\n",
    )
    .unwrap();
    assert_eq!(config.profile, ExecutionProfile::Sandboxed);
    assert_eq!(config.max_active_domains.get(), 40);
}

#[test]
fn rejects_unknown_profile() {
    let error = toml::from_str::<ExecutionConfig>(
        "profile = 'isolated'\nmax_active_domains = 20\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown variant"));
}

#[test]
fn rejects_zero_capacity() {
    let error = toml::from_str::<ExecutionConfig>(
        "profile = 'sandboxed'\nmax_active_domains = 0\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("nonzero"));
}
```

Extend `config_load_save_roundtrip` to set `ExecutionProfile::Sandboxed` and
assert that both fields survive serialization. Extend the generated-default-file
test to require `[execution]`, `profile = "trusted-host"`, and
`max_active_domains = 1`.

- [ ] **Step 2: Run the focused tests and confirm the missing types fail**

Run:

```bash
cargo test config::execution_test -- --nocapture
```

Expected: compilation fails because `ExecutionConfig` and `ExecutionProfile` do
not exist.

- [ ] **Step 3: Implement the serialized configuration types**

Create `src/config/execution.rs`:

```rust
use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionProfile {
    #[default]
    TrustedHost,
    Sandboxed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default)]
    pub profile: ExecutionProfile,
    #[serde(default = "default_max_active_domains")]
    pub max_active_domains: NonZeroUsize,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            profile: ExecutionProfile::TrustedHost,
            max_active_domains: default_max_active_domains(),
        }
    }
}

fn default_max_active_domains() -> NonZeroUsize {
    NonZeroUsize::new(1).unwrap()
}

#[cfg(test)]
#[path = "execution_test.rs"]
mod execution_test;
```

In `src/config.rs`, add `pub mod execution;`, re-export both types, and add:

```rust
#[serde(default)]
pub execution: ExecutionConfig,
```

to `ChimeraConfig` between `daemon` and `cache`.

- [ ] **Step 4: Run focused and complete config tests**

Run:

```bash
cargo test config:: -- --nocapture
```

Expected: all config tests pass, including unknown profile and zero-capacity
rejection.

- [ ] **Step 5: Commit the configuration contract**

```bash
git add src/config.rs src/config/execution.rs src/config/execution_test.rs src/config_test.rs
git commit -m "feat: add execution profile configuration"
```

### Task 3: Replace the Docker-config module with the execution-domain seam

**Files:**
- Create: `src/job/execution_domain/mod.rs`
- Create: `src/job/execution_domain/error.rs`
- Create: `src/job/execution_domain/filesystem.rs`
- Create: `src/job/execution_domain_test.rs`
- Modify: `src/job.rs:1-16`
- Modify: all current consumers returned by `rg -l 'JobDockerConfig|JobResourceRoot|JobDockerConfigError|job::docker_config' src tests`
- Remove: `src/job/docker_config.rs`
- Remove: `src/job/docker_config_test.rs`
- Rename through patch: `tests/job_docker_config_test.rs` to `tests/execution_domain_test.rs`
- Rename through patch: `tests/job_docker_config_docker_test.rs` to `tests/execution_domain_docker_test.rs`

**Interfaces:**
- Consumes: every current invariant of `JobResourceRoot` and `JobDockerConfig`.
- Produces: `ExecutionDomainRoot`, `ExecutionDomain`, `ExecutionDomainError`, and `DOCKER_CONFIG_ENV`; no compatibility type aliases remain after this task.

- [ ] **Step 1: Add a failing public-interface test before moving code**

At the top of the migrated `src/job/execution_domain_test.rs`, add:

```rust
#[test]
fn execution_domain_owns_all_attempt_paths() {
    let (_temp, root) = prepared_root();
    let domain = root.create_domain().unwrap();

    assert_eq!(domain.docker_config_dir().parent(), Some(domain.attempt_dir()));
    assert_eq!(domain.private_tmp().parent(), Some(domain.attempt_dir()));
    assert_eq!(domain.work_dir().parent(), Some(domain.attempt_dir()));
    assert_ne!(domain.attempt_id(), uuid::Uuid::nil());
}
```

Change `prepared_root()` in the test to return `ExecutionDomainRoot`. Do not add
aliases for the old names.

- [ ] **Step 2: Run the focused test and confirm it fails to compile**

Run:

```bash
cargo test execution_domain_owns_all_attempt_paths -- --exact --nocapture
```

Expected: compilation fails because the new module and types are absent.

- [ ] **Step 3: Split the existing implementation by responsibility**

Use `apply_patch` to move code from `src/job/docker_config.rs` with this exact
mapping:

| Existing item | Destination | New name |
|---|---|---|
| `JobDockerConfigError` and both error wrappers | `execution_domain/error.rs` | `ExecutionDomainError`, `ExecutionDomainCleanupFatalError` |
| `DirectoryIdentity` and all path validation/removal helpers | `execution_domain/filesystem.rs` | names unchanged |
| `JobResourceState` | `execution_domain/mod.rs` | `ExecutionDomainState` |
| `JobResourceRoot` | `execution_domain/mod.rs` | `ExecutionDomainRoot` |
| `JobDockerConfig` | `execution_domain/mod.rs` | `ExecutionDomain` |
| `create_docker_config` | `execution_domain/mod.rs` | `create_domain` |
| `directory` | `execution_domain/mod.rs` | `docker_config_dir` |
| `cleanup` | `execution_domain/mod.rs` | `destroy` |

The external declaration in `src/job/execution_domain/mod.rs` must be:

```rust
mod error;
mod filesystem;

pub use error::{ExecutionDomainCleanupFatalError, ExecutionDomainError};

pub const DOCKER_CONFIG_ENV: &str = "DOCKER_CONFIG";

#[derive(Debug, Clone)]
pub struct ExecutionDomainRoot {
    canonical_path: PathBuf,
    identity: DirectoryIdentity,
    state: Arc<ExecutionDomainState>,
}

#[derive(Debug)]
pub struct ExecutionDomain {
    root: PathBuf,
    root_identity: DirectoryIdentity,
    state: Arc<ExecutionDomainState>,
    attempt_id: Uuid,
    attempt_dir: PathBuf,
    attempt_identity: DirectoryIdentity,
    docker_config_dir: PathBuf,
    docker_config_dir_env: String,
    docker_config_file: PathBuf,
    private_tmp: PathBuf,
    private_tmp_identity: DirectoryIdentity,
    work_dir: PathBuf,
    work_dir_identity: DirectoryIdentity,
    destroyed: bool,
}
```

Keep the existing filesystem algorithms unchanged in this task. Only adjust their
error type and visibility to `pub(super)` where `mod.rs` calls them.

- [ ] **Step 4: Migrate every consumer without compatibility aliases**

Apply these exact API replacements throughout `src/` and `tests/`:

```text
job::docker_config                         -> job::execution_domain
JobResourceRoot                           -> ExecutionDomainRoot
JobDockerConfig                           -> ExecutionDomain
JobDockerConfigError                      -> ExecutionDomainError
JobResourceCleanupFatalError              -> ExecutionDomainCleanupFatalError
create_docker_config()                    -> create_domain()
.directory()                              -> .docker_config_dir()
.cleanup()                                -> .destroy()
job_resources field/local                 -> execution_domains
docker_config parameter referring owner   -> domain
```

Do not rename plain `docker_config` variables that hold only a Docker config path
inside Docker CLI test helpers. After migration, this command must print nothing:

```bash
rg -n 'JobDockerConfig|JobResourceRoot|JobDockerConfigError|job::docker_config' src tests
```

Update `src/job.rs` to export `pub mod execution_domain;` and remove
`pub mod docker_config;`.

- [ ] **Step 5: Run the migrated unit and integration suites**

Run:

```bash
cargo test job::execution_domain -- --nocapture
cargo test --test execution_domain_test -- --nocapture
```

Expected: all migrated filesystem, environment, concurrency, cleanup, symlink,
inode-replacement, umask, and stale-root tests pass.

- [ ] **Step 6: Run compile-only coverage for every consumer**

Run:

```bash
cargo test --no-run
```

Expected: all unit and integration test targets compile under the new names.

- [ ] **Step 7: Commit the deep-module rename**

```bash
git add src/job.rs src/job/execution_domain src/job/execution_domain_test.rs src/job/execute.rs src/job/action src/runner src/daemon.rs src/daemon_test.rs src/config_test.rs tests/common tests/execution_domain_test.rs tests/execution_domain_docker_test.rs
git add -u src/job/docker_config.rs src/job/docker_config_test.rs tests/job_docker_config_test.rs tests/job_docker_config_docker_test.rs
git commit -m "refactor: establish execution domain ownership"
```

### Task 4: Add the durable lifecycle journal

**Files:**
- Create: `src/job/execution_domain/journal.rs`
- Create: `src/job/execution_domain/journal_test.rs`
- Modify: `src/job/execution_domain/mod.rs`
- Modify: `src/job/execution_domain/filesystem.rs`
- Modify: `src/job/execution_domain/error.rs`
- Modify: `src/job/execution_domain_test.rs`

**Interfaces:**
- Consumes: exact attempt UUID and private attempt directory from Task 3.
- Produces: `DomainLifecycle`, `DomainState`, `JournalRecord`, and checked transitions used by Runner in Task 6.

- [ ] **Step 1: Write failing transition and corruption tests**

Create `journal_test.rs` with these cases:

```rust
#[test]
fn accepts_the_normal_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(7)).unwrap();
    lifecycle.transition(DomainState::Ready).unwrap();
    lifecycle.transition(DomainState::Running).unwrap();
    lifecycle.transition(DomainState::Cleaning).unwrap();
    lifecycle.transition(DomainState::Destroying).unwrap();
    lifecycle.complete_destroyed().unwrap();
    assert_eq!(lifecycle.state(), DomainState::Destroyed);
}

#[test]
fn rejects_skipped_transition() {
    let temp = tempfile::tempdir().unwrap();
    let mut lifecycle = DomainLifecycle::create(temp.path(), Uuid::from_u128(8)).unwrap();
    let error = lifecycle.transition(DomainState::Running).unwrap_err();
    assert!(matches!(error, ExecutionDomainError::InvalidTransition { .. }));
}

#[test]
fn rejects_truncated_journal() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("journal.json"), b"{\"version\":1").unwrap();
    assert!(matches!(
        DomainLifecycle::load(temp.path()),
        Err(ExecutionDomainError::InvalidJournal { .. })
    ));
}

#[test]
fn rejects_unknown_journal_version() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("journal.json"),
        br#"{"version":2,"attempt_id":"00000000-0000-0000-0000-000000000009","state":"ready"}"#,
    )
    .unwrap();
    assert!(matches!(
        DomainLifecycle::load(temp.path()),
        Err(ExecutionDomainError::UnsupportedJournalVersion { version: 2, .. })
    ));
}
```

Add a Unix-only test that replaces `journal.json` with a symlink to an outside
canary and asserts transition failure without modifying the canary.

- [ ] **Step 2: Run the journal tests and confirm missing types fail**

Run:

```bash
cargo test job::execution_domain::journal_test -- --nocapture
```

Expected: compilation fails because lifecycle types do not exist.

- [ ] **Step 3: Implement the versioned state record and transition table**

Create `journal.rs` with this data contract:

```rust
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_FILE: &str = "journal.json";
const NEXT_JOURNAL_FILE: &str = "journal.json.next";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DomainState {
    Provisioning,
    Ready,
    Running,
    Cleaning,
    Destroying,
    Destroyed,
    Quarantined,
}

#[derive(Debug, Serialize, Deserialize)]
struct JournalRecord {
    version: u32,
    attempt_id: Uuid,
    state: DomainState,
}

pub(super) struct DomainLifecycle {
    attempt_dir: PathBuf,
    attempt_id: Uuid,
    state: DomainState,
}
```

Implement exactly this allowed-transition predicate:

```rust
fn transition_allowed(from: DomainState, to: DomainState) -> bool {
    matches!(
        (from, to),
        (DomainState::Provisioning, DomainState::Ready | DomainState::Destroying)
            | (DomainState::Ready, DomainState::Running | DomainState::Destroying)
            | (DomainState::Running, DomainState::Cleaning | DomainState::Destroying)
            | (DomainState::Cleaning, DomainState::Destroying)
            | (DomainState::Destroying, DomainState::Quarantined)
    )
}
```

`complete_destroyed()` is the only non-persisting terminal transition:

```rust
pub(super) fn complete_destroyed(&mut self) -> Result<(), ExecutionDomainError> {
    if self.state != DomainState::Destroying {
        return Err(ExecutionDomainError::InvalidTransition {
            from: self.state,
            to: DomainState::Destroyed,
        });
    }
    self.state = DomainState::Destroyed;
    Ok(())
}
```

`create()` writes version 1 in `Provisioning`. `transition()` creates
`journal.json.next` with mode `0600`, writes and `sync_all()`s JSON, renames it
over `journal.json`, then opens and `sync_all()`s the attempt directory. Opening
existing journal paths uses `O_NOFOLLOW | O_CLOEXEC`; unexpected `.next` is an
error rather than silently overwritten.

Add these variants to `ExecutionDomainError`:

```rust
InvalidTransition { from: DomainState, to: DomainState },
InvalidJournal { path: PathBuf, source: serde_json::Error },
UnsupportedJournalVersion { path: PathBuf, version: u32 },
```

Their `Display` output includes state/category and path only, never journal body.

- [ ] **Step 4: Integrate journal transitions into domain creation/destruction**

Add `lifecycle: DomainLifecycle` to `ExecutionDomain`. In `create_domain_with_id`:

```rust
let mut lifecycle = DomainLifecycle::create(&attempt_dir, attempt_id)?;
// Create docker/tmp/work paths and config.json using the existing safe helpers.
lifecycle.transition(DomainState::Ready)?;
```

Expose crate-private methods:

```rust
pub(crate) fn mark_running(&mut self) -> Result<(), ExecutionDomainError>;
pub(crate) fn mark_cleaning(&mut self) -> Result<(), ExecutionDomainError>;
```

At the beginning of `destroy()`, transition to `Destroying`. Validate and remove
the attempt directory while the durable state is still `Destroying`. After a
successful removal, `complete_destroyed()` changes only the in-memory state to
`Destroyed`, because the journal path no longer exists. If removal fails, attempt
a durable transition from `Destroying` to `Quarantined`, poison the shared root,
and return the original cleanup error with quarantine failure chained as context.

Update removal-tree validation to admit exactly `journal.json`; an unexpected
socket or special file at the attempt root must still fail.

- [ ] **Step 5: Run journal and adversarial filesystem tests**

Run:

```bash
cargo test job::execution_domain -- --nocapture
```

Expected: normal transitions persist, invalid/corrupt/symlinked journals fail
closed, and all pre-existing replacement/canary tests still pass.

- [ ] **Step 6: Commit durable lifecycle state**

```bash
git add src/job/execution_domain
git commit -m "feat: journal execution domain lifecycle"
```

### Task 5: Add admission permits with poison-aware waiting

**Files:**
- Create: `src/job/execution_domain/admission.rs`
- Create: `src/job/execution_domain/admission_test.rs`
- Modify: `src/job/execution_domain/mod.rs`
- Modify: `src/job/execution_domain/error.rs`

**Interfaces:**
- Consumes: `ExecutionDomainRoot::create_domain_with_id` and shared poison watch.
- Produces: `ExecutionDomainRoot::reserve() -> DomainPermit` and `DomainPermit::provision() -> ExecutionDomain`; the owned semaphore permit remains inside the domain until destruction.

- [ ] **Step 1: Write failing capacity, cancellation, and poison tests**

Create `admission_test.rs`:

```rust
#[tokio::test]
async fn second_reservation_waits_until_first_domain_is_destroyed() {
    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let first = root.reserve().await.unwrap().provision().unwrap();
    let waiting = tokio::spawn({
        let root = root.clone();
        async move { root.reserve().await }
    });

    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    first.destroy().unwrap();
    waiting.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelled_wait_does_not_consume_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let held = root.reserve().await.unwrap();
    let mut waiting = Box::pin(root.reserve());
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut waiting).await.is_err());
    drop(waiting);
    drop(held);
    tokio::time::timeout(Duration::from_secs(1), root.reserve())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn poisoning_wakes_blocked_waiter() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let _held = root.reserve().await.unwrap();
    let waiting = tokio::spawn({
        let root = root.clone();
        async move { root.reserve().await }
    });
    tokio::task::yield_now().await;
    root.poison_for_test();
    let error = waiting.await.unwrap().unwrap_err();
    assert!(matches!(error, ExecutionDomainError::PoisonedRoot { .. }));
}

#[tokio::test]
async fn dropping_undestroyed_domain_poisons_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let domain = root.reserve().await.unwrap().provision().unwrap();
    drop(domain);
    let error = root.reserve().await.unwrap_err();
    assert!(matches!(error, ExecutionDomainError::PoisonedRoot { .. }));
}
```

Keep `poison_for_test` behind `#[cfg(test)]` and crate-private.

- [ ] **Step 2: Run the focused tests and verify missing admission API fails**

Run:

```bash
cargo test job::execution_domain::admission_test -- --nocapture
```

Expected: compilation fails because capacity-aware `prepare`, `reserve`, and
`DomainPermit` are missing.

- [ ] **Step 3: Implement permit ownership**

In `admission.rs` define:

```rust
#[derive(Debug)]
pub(crate) struct DomainPermit {
    root: ExecutionDomainRoot,
    permit: OwnedSemaphorePermit,
}

impl DomainPermit {
    pub(crate) fn provision(self) -> Result<ExecutionDomain, ExecutionDomainError> {
        let mut domain = self.root.create_domain_with_id(Uuid::new_v4())?;
        domain.admission_permit = Some(self.permit);
        Ok(domain)
    }
}
```

Add `admission: Arc<Semaphore>` to `ExecutionDomainRoot` and
`admission_permit: Option<OwnedSemaphorePermit>` to `ExecutionDomain`.
`ExecutionDomainRoot::prepare` now accepts `NonZeroUsize` and constructs the
semaphore.

Remove the public `create_domain()` method at the end of this task. Keep
`create_domain_with_id()` private to the parent module so `DomainPermit` and the
child unit-test module can call it, but production callers cannot bypass
admission. Public integration fixtures must use `reserve().await.provision()`.

Implement `reserve()` so poison wakes a blocked waiter and a permit won in a race
is rejected after a second health check:

```rust
pub(crate) async fn reserve(&self) -> Result<DomainPermit, ExecutionDomainError> {
    self.ensure_healthy()?;
    let mut poisoned = self.poisoned_receiver();
    let permit = tokio::select! {
        changed = poisoned.changed() => {
            changed.map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.path().to_path_buf(),
            })?;
            return Err(ExecutionDomainError::PoisonedRoot {
                path: self.path().to_path_buf(),
            });
        }
        permit = Arc::clone(&self.admission).acquire_owned() => {
            permit.map_err(|_| ExecutionDomainError::AdmissionClosed {
                path: self.path().to_path_buf(),
            })?
        }
    };
    self.ensure_healthy()?;
    Ok(DomainPermit { root: self.clone(), permit })
}
```

Add `AdmissionClosed { path: PathBuf }` to the error enum. `destroy(self)` drops
the owned permit only after cleanup returns. `Drop for ExecutionDomain` poisons
the root when `destroyed == false`; it does not attempt async or recursive cleanup.

- [ ] **Step 4: Update all root test fixtures with explicit capacity**

Every existing `ExecutionDomainRoot::prepare(path)` call becomes:

```rust
ExecutionDomainRoot::prepare(path, NonZeroUsize::new(1).unwrap())
```

Concurrency tests that create two simultaneous domains use capacity 2. Tests that
exercise shared poisoning use capacity 1 unless they explicitly require a sibling.
In `tests/common/mod.rs` and public integration tests, replace direct creation with:

```rust
let domain = execution_domains.reserve().await?.provision()?;
```

Unit tests inside `execution_domain_test.rs` may call the private
`create_domain_with_id` when they specifically test collision or filesystem
rollback rather than admission.

- [ ] **Step 5: Run admission and full domain tests**

Run:

```bash
cargo test job::execution_domain -- --nocapture
```

Expected: blocked wait, cancellation, poison wakeup, drop poisoning, and all
filesystem tests pass.

- [ ] **Step 6: Commit admission ownership**

```bash
git add src/job/execution_domain tests/common/mod.rs tests/execution_domain_test.rs tests/execution_domain_docker_test.rs src/job/action src/job/execute_test.rs src/runner/env_test.rs
git commit -m "feat: reserve execution domain capacity"
```

### Task 6: Thread the permit through the runner lifecycle

**Files:**
- Modify: `src/runner/instance.rs:255-1090`
- Modify: `src/runner/instance_test.rs`
- Modify: `src/daemon.rs:207-225,455-515`
- Modify: `src/daemon_test.rs`
- Modify: `tests/common/mod.rs`

**Interfaces:**
- Consumes: `ExecutionDomainRoot::reserve`, `DomainPermit::provision`, lifecycle markers, and `ExecutionDomain::destroy`.
- Produces: exactly one permit/domain per accepted job; completion publication remains after capability revocation and confirmed destruction.

- [ ] **Step 1: Write a failing runner ordering test**

Replace the current `finish_job_after_cache_revoke` seam with a version that also
awaits a supplied destruction future. Test it with a oneshot gate and the existing
WireMock completion endpoint:

```rust
#[tokio::test]
async fn completion_waits_for_capability_revoke_and_domain_destroy() {
    let authority = Arc::new(CacheAuthority::new());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let manifest = finish_manifest(&server.uri());
    let scope = cache_scope_for_job(&manifest, "owner/test-repo");
    let id = register_job_cache_capability(
        &authority,
        &manifest,
        scope.clone(),
        Utc::now(),
    )
    .await
    .unwrap();
    let mut capability = JobCacheCapability::new(Arc::clone(&authority), id);
    let client = finish_client(&server).await;
    let (allow_destroy_tx, allow_destroy_rx) = tokio::sync::oneshot::channel();

    let finish = tokio::spawn(async move {
        finish_job_after_cache_revoke_and_destroy(
            &mut capability,
            async move {
                allow_destroy_rx.await.unwrap();
                Ok(())
            },
            &client,
            &manifest,
            Ok(JobExecutionOutcome {
                conclusion: JobConclusion::Succeeded,
                outputs: HashMap::new(),
            }),
        )
        .await
    });

    tokio::task::yield_now().await;
    assert_eq!(
        authority.authorize("job-token-xyz", &scope).await.unwrap_err(),
        CacheAuthError::Unauthorized,
    );
    assert!(server.received_requests().await.unwrap().is_empty());

    allow_destroy_tx.send(()).unwrap();
    finish.await.unwrap().unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
```

- [ ] **Step 2: Run the ordering test and verify it fails before refactoring**

Run:

```bash
cargo test runner::instance_test::completion_waits_for_capability_revoke_and_domain_destroy -- --exact --nocapture
```

Expected: compilation fails because the domain-aware finish seam does not exist.

- [ ] **Step 3: Acquire capacity before Online polling**

In the runner loop, acquire a permit before entering `poll_loop`:

```rust
let permit = tokio::select! {
    changed = shutdown_rx.changed() => {
        changed.context("watching shutdown before domain reservation")?;
        self.report_phase(RunnerPhase::Stopping).await;
        break;
    }
    permit = self.execution_domains.reserve() => permit?,
};

let result = self.poll_loop(&broker, &mut shutdown_rx).await;
```

If polling returns shutdown/error, drop the unused permit. If it returns a job
message, move the permit through these exact signatures:

```rust
async fn handle_job_message(
    &self,
    msg: &BrokerMessage,
    broker: &BrokerClient,
    client: &reqwest::Client,
    token_manager: Arc<TokenManager>,
    permit: DomainPermit,
) -> Result<()>;

async fn execute_job(
    &self,
    client: &reqwest::Client,
    token_manager: Arc<TokenManager>,
    runner_request_id: &str,
    run_service_url: &str,
    cancel_token: CancellationToken,
    permit: DomainPermit,
) -> Result<()>;

async fn run_job(
    &self,
    manifest: &JobManifest,
    job_client: &Arc<JobClient>,
    client: &reqwest::Client,
    cancel_token: CancellationToken,
    repo: &str,
    secret_masker: &SharedSecretMasker,
    permit: DomainPermit,
) -> Result<()>;
```

Parse/ack/acquire-manifest failures drop the permit and never create a directory.

- [ ] **Step 4: Provision and transition one domain inside `run_job`**

Replace `create_docker_config` with:

```rust
let mut domain = tokio::task::spawn_blocking(move || permit.provision())
    .await
    .context("joining execution domain provisioning task")?
    .context("provisioning execution domain")?;
let attempt_id = domain.attempt_id();
```

After cache capability registration succeeds, call `domain.mark_running()` before
`run_job_body`. After `run_job_body` returns, call `domain.mark_cleaning()` even
for failed/cancelled outcomes. Move `domain` into a destruction future:

```rust
let destroy = async move {
    let destroy_path = domain.attempt_dir().to_path_buf();
    tokio::task::spawn_blocking(move || domain.destroy())
        .await
        .unwrap_or_else(|source| {
            Err(ExecutionDomainError::Cleanup {
                path: destroy_path,
                source: io::Error::other(format!(
                    "execution domain destroy task failed: {source}"
                )),
            })
        })
};
```

Pass this future to the helper defined in Step 5, which revokes the capability,
awaits destruction, and only then invokes `finish_job`.

Every `run_job_body`, workspace, environment, and action call receives
`&ExecutionDomain` and uses `work_dir`, `private_tmp`, and `docker_config_dir`.

The cache-registration-error branch must destroy the domain before returning the
registration error. If destroy also fails, return the registration error with the
destroy category attached and leave the root poisoned.

- [ ] **Step 5: Preserve fatal cleanup classification**

Replace `finish_job_after_cache_revoke` with this exact ordering seam:

```rust
async fn finish_job_after_cache_revoke_and_destroy<F>(
    capability: &mut JobCacheCapability,
    destroy: F,
    job_client: &Arc<JobClient>,
    manifest: &JobManifest,
    execution_result: Result<JobExecutionOutcome>,
) -> Result<()>
where
    F: Future<Output = std::result::Result<(), ExecutionDomainError>>,
{
    capability.revoke().await;
    let destroy_result = destroy.await;
    finish_job(
        job_client,
        manifest,
        execution_result,
        destroy_result,
    )
    .await
}
```

Rename the existing wrapper to `ExecutionDomainCleanupFatalError` and keep this
logic in `finish_job`:

```rust
let destroy_error = destroy_result.err();
if destroy_error.is_some() {
    outcome.conclusion = conclusion_after_cleanup_failure(outcome.conclusion);
}
let outputs = outputs_to_variable_values(&outcome.outputs);
job_client
    .complete_job(
        &manifest.plan.plan_id,
        &manifest.plan.job_id,
        outcome.conclusion,
        &outputs,
        &[],
    )
    .await?;
match destroy_error {
    Some(source) => Err(anyhow::Error::new(ExecutionDomainCleanupFatalError { source })),
    None => Ok(()),
}
```

No completion request may occur before `destroy_result` exists.

- [ ] **Step 6: Set trusted-host admission capacity without changing concurrency**

In `Daemon::run`, calculate trusted capacity from configured runner identities:

```rust
let trusted_capacity = NonZeroUsize::new(self.config.runners.len().max(1)).unwrap();
let (_pid_lock, execution_domains) =
    prepare_daemon_root(&self.paths, trusted_capacity)?;
```

Pass the same cloned `ExecutionDomainRoot` to every Runner. Do not apply
`execution.max_active_domains` to `trusted-host`; doing so would silently reduce
existing concurrency.

- [ ] **Step 7: Run focused runner and public integration tests**

Run:

```bash
cargo test runner::instance_test -- --nocapture
cargo test --test execution_domain_test -- --nocapture
```

Expected: ordering, cancellation, sequential reuse, concurrent jobs, cleanup
failure, and poisoned-root tests pass.

- [ ] **Step 8: Commit runner integration**

```bash
git add src/runner/instance.rs src/runner/instance_test.rs src/daemon.rs src/daemon_test.rs tests/common/mod.rs
git commit -m "refactor: run jobs through execution domains"
```

### Task 7: Add the temporary activation gate and stale-state diagnostics

**Files:**
- Modify: `src/daemon.rs:425-470`
- Modify: `src/daemon_test.rs`
- Modify: `src/job/execution_domain/mod.rs`
- Modify: `src/job/execution_domain/error.rs`
- Modify: `src/job/execution_domain_test.rs`

**Interfaces:**
- Consumes: `ExecutionProfile` from Task 2 and prepared domain root from Tasks 3–6.
- Produces: fail-closed `sandboxed` startup error before side effects; stale attempt metadata remains untouched for later Plan B reconciliation.

- [ ] **Step 1: Write failing activation and stale-journal tests**

Add daemon tests:

```rust
#[test]
fn sandboxed_profile_is_rejected_before_runtime_start() {
    let config = ChimeraConfig {
        execution: ExecutionConfig {
            profile: ExecutionProfile::Sandboxed,
            max_active_domains: NonZeroUsize::new(20).unwrap(),
        },
        ..Default::default()
    };
    let error = validate_execution_profile(&config).unwrap_err();
    assert_eq!(error.to_string(), "sandboxed execution profile is not available in this build");
}
```

Add a domain test that creates a valid `journal.json` in an attempt directory,
calls `ExecutionDomainRoot::prepare`, and asserts `StaleJobResources` while the
journal bytes and attempt directory remain unchanged. Add parallel cases for a
truncated journal and a symlinked journal; Plan A must not auto-delete either.

- [ ] **Step 2: Run the tests and verify the gate is missing**

Run:

```bash
cargo test sandboxed_profile_is_rejected_before_runtime_start -- --exact --nocapture
cargo test stale_journal -- --nocapture
```

Expected: activation test fails to compile; stale tests retain current fail-closed
behavior after their fixture API is corrected.

- [ ] **Step 3: Validate profile before daemon-owned side effects**

Add a pure helper:

```rust
fn validate_execution_profile(config: &ChimeraConfig) -> Result<()> {
    match config.execution.profile {
        ExecutionProfile::TrustedHost => Ok(()),
        ExecutionProfile::Sandboxed => {
            anyhow::bail!("sandboxed execution profile is not available in this build")
        }
    }
}
```

Call it as the first statement in `Daemon::run`, before `prepare_daemon_root`,
cache initialization, cache listener creation, runner construction, or GitHub
session creation.

Do not add an environment-variable or CLI bypass. Plans B–D leave this gate in
place; Plan E removes it only after release qualification.

- [ ] **Step 4: Keep startup cleanup fail-closed in Plan A**

Retain the `ExecutionDomainRoot::prepare` rule that a non-empty active resource
root returns `StaleJobResources`. Improve the diagnostic to report only root path
and stale entry count by changing the variant to:

```rust
StaleJobResources { path: PathBuf, entries: usize },
```

Do not read/log journal body and do not delete entries.

The automatic cgroup-backed reconciliation described by the spec belongs to Plan
B, because filesystem state alone cannot prove that escaped processes are gone.

- [ ] **Step 5: Run daemon and domain suites**

Run:

```bash
cargo test daemon_test -- --nocapture
cargo test job::execution_domain -- --nocapture
```

Expected: `trusted-host` starts as before, `sandboxed` rejects before mutation,
and every stale/corrupt resource remains fail-closed and untouched.

- [ ] **Step 6: Commit the activation gate**

```bash
git add src/daemon.rs src/daemon_test.rs src/job/execution_domain
git commit -m "feat: fail closed on unavailable sandboxed profile"
```

### Task 8: Update operator documentation and verify Plan A

**Files:**
- Modify: `README.md:118-225`
- Modify: `docs/job-docker-config.md`
- Modify: `docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md`

**Interfaces:**
- Consumes: final Plan A config and lifecycle behavior.
- Produces: accurate operator-facing distinction between available `trusted-host` and reserved-but-unavailable `sandboxed`.

- [ ] **Step 1: Update README with exact profile semantics**

Add this configuration block and warning near the security/deployment section:

```toml
[execution]
profile = "trusted-host"
max_active_domains = 1
```

Document exactly:

```text
trusted-host is the ordinary self-hosted-runner trust model. The
max_active_domains field is reserved for sandboxed execution and does not reduce
trusted-host runner concurrency. sandboxed is intentionally rejected by this
release until its namespace, private-Docker, network, storage, and native release
gates are all present; Chimera never falls back from sandboxed to trusted-host.
```

Rename internal ownership references in `docs/job-docker-config.md` from
`JobDockerConfig`/`JobResourceRoot` to `ExecutionDomain`/`ExecutionDomainRoot`,
while stating that the documented Docker config behavior is unchanged in
`trusted-host`.

- [ ] **Step 2: Mark Plan A complete in the roadmap only after verification**

Run `git rev-parse --short HEAD`, copy the printed SHA, and add a Plan A status
line containing `Status: implemented and verified at commit` followed by that
exact SHA. Do not mark Plans B–E started.

- [ ] **Step 3: Run formatting and static analysis**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: both commands exit 0.

- [ ] **Step 4: Run the complete non-ignored suite**

Run:

```bash
cargo test --all-targets --all-features
```

Expected: exit 0 with no failed tests. Ignored native Docker acceptance tests are
not force-enabled in Plan A because this plan does not change Docker backend
behavior.

- [ ] **Step 5: Verify forbidden old names and accidental activation are absent**

Run:

```bash
rg -n 'JobDockerConfig|JobResourceRoot|JobDockerConfigError|job::docker_config' src tests
rg -n 'profile = "sandboxed"' README.md docs/job-docker-config.md
```

Expected: first command has no matches. The second may show documentation examples
only when adjacent text explicitly says the profile is unavailable in this
release.

- [ ] **Step 6: Commit documentation and final verification record**

```bash
git add README.md docs/job-docker-config.md docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md
git commit -m "docs: describe execution domain foundation"
```

- [ ] **Step 7: Inspect final history and worktree**

Run:

```bash
git log --oneline --decorate -8
git status --short
```

Expected: Task 1–8 commits are visible and the worktree is clean.
