# Sandboxed Qualification Harness (E0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the S-01…S-16 scenario catalogue, synthetic fixtures, native-host harness and evidence reporting while retaining the sandboxed activation gate.

**Architecture:** Put qualification-only code under one integration-test target and its private support modules. A versioned driver protocol separates scenario recipes from the eventual B–D runtime adapter; E0 supplies a fixture driver for harness tests and reports absent runtime support as blocked. Native evidence is independently checked against the single Debian host, fixed commit/config/tool identities, exclusive-run ownership and complete scenario coverage before a report can qualify a release.

**Tech Stack:** Rust integration tests using existing serde_json, tokio, libc, uuid, blake3, tempfile and reqwest; Bash native entrypoint; no new crates, no production feature or CLI that bypasses activation.

**Spec:** [CHM-08 sandboxed execution domain](../specs/2026-09-20-chimera-sandboxed-execution-domain.md), especially §15 S-01…S-16 and §16. Read the [roadmap](2026-09-20-chimera-sandboxed-execution-roadmap.md), [related-issues report](../reports/2026-09-20-chimera-attempt-isolation-related-issues.md), and [D0 policy plan](2026-09-20-chimera-sandboxed-policy-foundation.md). Implementation base: `origin/main@39585f17dc58bf108aefaf6efc0067d3371df166`.

## Global Constraints

- «Security acceptance выполняется на native Debian/systemd host.»
- «Privileged nested Docker может использоваться только как быстрый CI smoke test и не заменяет native gate.»
- «Exact action tests используют synthetic registry credentials и не выполняют production deploy.»
- «Release #54 требует cold, warm, failure, cancel и restart waves, затем повторную tenant wave.»
- «Startup и memory sizing принимаются только по PSS/native measurements, не по aggregate RSS nested VFS spike.»
- «Работа production services на том же server должна оставаться внутри заранее заданного reserve/SLO во всех resource stress tests.»
- One Debian host, one service account, one service unit; no VM or second-host prerequisite. Native destructive scenarios execute one at a time under one exclusive machine-wide lock. Attempts within the explicitly requested 20/40 wave remain concurrent.
- `sandboxed execution profile is not available in this build` remains effective. E0 does not add an environment override, feature-gated startup escape, test CLI in the production binary, or change to `Daemon::run`.
- Fixture, nested-smoke, missing, inconclusive and skipped results never count as native qualification. E0 completing does not mean S-01…S-16 passed.
- Production resources, Docker socket/store and real deploy credentials are out of scope. No global process kill, Docker prune, host-wide cache flush, remount or sysctl mutation.

## Review Focus

- A truncated report, duplicate ID, missing wave or fabricated fixture pass must fail overall qualification (Task 1 and Task 2).
- Two native invocations, including different checkout paths, must not run destructive tests together; an interrupted run with unproven cleanup blocks the next invocation (Task 3).
- A sentinel that was never listening must not produce a successful isolation test (Task 4).
- Crash/cancel/timeout must preserve forensic evidence and prove cleanup before starting the next case; stale IDs must not target a subsequent tenant (Task 6).
- Missing PSS/I/O/SLO samples and an early terminated 40-attempt wave must be reported as incomplete, not zero-cost success (Task 7 and Task 8).

---

## Boundaries, file map and protocol ownership

The existing tests exercise trusted-host execution. `tests/execution_domain_docker_test.rs` already carries exact action pins and cleanup checks; `tests/common/pinned_action.rs` safely installs SHA-pinned action archives. Do not rename those tests to imply sandbox qualification. The prototype explicitly did not run the pinned actions and used nested VFS; keep those results outside the native report.

| Files | Responsibility |
|---|---|
| `tests/sandboxed_qualification_test.rs` | One Cargo target, portable harness unit tests and one ignored native orchestrator |
| `tests/qualification/mod.rs` | Private module root and exports used by the integration target |
| `tests/qualification/catalog.rs`, `catalog_test.rs` | Fixed scenario/subcase/wave coverage |
| `tests/qualification/report.rs`, `report_test.rs` | Typed results, strict verdict, atomic JSON/Markdown output |
| `tests/qualification/driver.rs`, `driver_test.rs` | Bounded versioned request/observation protocol |
| `tests/qualification/host.rs`, `host_test.rs` | Global lock, durable fail-closed marker, native identity and safe qualification workspace; E1 adds exact-resource recovery |
| `tests/qualification/fixtures.rs`, `fixtures_test.rs` | Owned canaries, recipes and pinned action manifest |
| `tests/qualification/isolation.rs`, `isolation_test.rs` | S-01/S-03/S-04/S-05/S-12 observations and assertions |
| `tests/qualification/docker.rs`, `docker_test.rs` | S-06/S-07/S-08 command and action recipes |
| `tests/qualification/lifecycle.rs`, `lifecycle_test.rs` | S-02/S-10/S-11/S-13/S-14/S-15 sequences |
| `tests/qualification/resources.rs`, `resources_test.rs` | S-09/S-16 metrics and bound evaluators |
| `tests/fixtures/qualification/{config,driver-hello,report-incomplete,actions}.json` | Synthetic owned-format inputs, never production credentials |
| `tests/fixtures/qualification/workflows/pinned-build.yml`, `Dockerfile`, `payload.txt` | Exact-pinned synthetic workload |
| `scripts/qualification/native.sh` | Serialized invocation and artifact path checks |
| `docs/testing-sandboxed-native.md` | Single-host runbook and report interpretation |

All support modules are reached via `#[path = "qualification/mod.rs"] mod qualification;` in the one integration target, so Cargo does not discover them as independent test binaries. Sibling `_test.rs` modules follow repository conventions. No production source file is changed by E0. The future runtime driver is a qualification binary linked to B–D implementation, built separately from the shipped CLI; creating that adapter belongs to E1. E0 defines its exact wire protocol now and tests it with deterministic fixture observations. If no driver exists, the native report contains 16 blocked scenarios and exits unsuccessfully. E0 has no authenticated run-owned cgroup/process authority after supervisor death, so it must not perform PID/PGID-only automatic recovery or start destructive native scenarios. E1 adds a pinned run-cgroup/driver identity, an unprivileged watchdog and authenticated recovery before those scenarios can execute. Until then a durable unfinished marker blocks later native runs, even if a crash releases the advisory lock.

### Common types and testing commands

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ScenarioId { S01, S02, S03, S04, S05, S06, S07, S08,
    S09, S10, S11, S12, S13, S14, S15, S16 }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Wave { Cold, Warm, Failure, Cancel, Restart, NextTenant, Idle }
pub enum EvidenceMode { Fixture, NestedSmoke, NativeDebian }
pub enum Verdict { Passed, Failed, Blocked, Inconclusive }
pub enum Reason { BackendUnavailable, PlatformUnsupported, HostBusy, InvalidConfig,
    MissingEvidence, StaleEvidence, UnfinishedRun, BoundaryViolation, DeadlineExceeded,
    CleanupUnconfirmed, SloExceeded, ProtocolViolation }
pub struct CaseKey { pub scenario: ScenarioId, pub case: String,
    pub wave: Wave, pub concurrency: u16 }
pub enum CheckId {
    PreflightRejectedBeforePolling, RollbackConfirmed, HostFilesystemDenied,
    PeerFilesystemDenied, ProcessIsolated, NetworkPolicyEnforced,
    OutsideControlAvailable, PublicRegistryReachable, DockerApiCompatible,
    BuildxCompatible, ChangedHostSemanticsContained, ResourceLimitEnforced,
    ProductionReservePreserved, CancellationBounded, RestartReconciled,
    CapacityBounded, DistinctStateConfirmed, ExtraAdmissionBlocked,
    NextTenantClean, IdleZero, NativeMetricsComplete,
    CleanupConfirmed,
}
pub struct Check { pub id: CheckId, pub passed: bool }
pub struct EvidenceProvenance { pub identity: RunIdentity, pub key: CaseKey,
    pub driver_commit: String, pub driver_digest: String }
pub struct CaseResult { pub key: CaseKey, pub verdict: Verdict,
    pub reason: Option<Reason>, pub provenance: EvidenceProvenance,
    pub checks: Vec<Check>, pub duration_ms: u64 }
pub fn required_checks(key: &CaseKey) -> &'static [CheckId];
```

These are closed enums with serde spellings fixed to `S-01`…`S-16`, kebab-case waves/modes/reasons. Derive `Clone, Debug, Eq, PartialEq, Serialize, Deserialize` on every common type whose numeric fields permit `Eq`, and `Ord, PartialOrd` on `ScenarioId`, `Wave`, `CaseKey`, and `CheckId`; implement fixed `ScenarioId::ALL: [ScenarioId; 16]`. Task 1 defines an exact allowlisted `required_checks` set for every catalogue case. Tasks 4–7 decode scenario-specific typed facts and are the only producers of those checks; the driver never supplies checks or verdicts. No free-text subprocess output, tokens or command payloads are stored in these types.

Every task follows RED then GREEN with complete captured output. Setup on Linux:

```bash
mkdir -p "$PWD/target/chimera-tests"
export TMPDIR="$PWD/target/chimera-tests"
```

Portable command prefix is `cargo test --test sandboxed_qualification_test`. The native test is `#[ignore = "native Debian, exclusive host qualification and configured runtime driver required"]`; ordinary `cargo test` never runs it. Invoking an unavailable native test fails with a blocked report; it does not return early with an `Ok` result. Commit commands describe future plan execution, not this planning change.

### Task 1: Catalogue every release obligation explicitly

**Files:** Create integration target, `qualification/mod.rs`, `catalog.rs`, `catalog_test.rs`.

**Produces:** `pub fn required_cases() -> Vec<CaseKey>`, `pub fn required_checks(key: &CaseKey) -> &'static [CheckId]`, and `pub fn validate_coverage(results: &[CaseResult]) -> Result<(), Reason>`; common types above live in `catalog.rs` except report result types in `report.rs` created in this task with data definitions only.

The catalogue is an explicit table; each row enumerates its cases without discovery by test-name convention:

| ID | Case names and required dimensions |
|---|---|
| S-01 | `no-userns`, `no-cgroup-v2`, `no-ebpf`, `no-storage-bound`, `unsupported-container`, `unsupported-platform`; Cold/1 |
| S-02 | `after-journal`, `after-cgroup`, `after-namespaces`, `after-rootfs`, `after-pivot`, `after-init`, `after-dockerd`, `after-probes`; Failure/1 |
| S-03 | `host-files`, `peer-files`, `supervisor-credentials`, `bind-host`, `bind-peer`; Cold/2 |
| S-04 | `pid-visibility`, `signal-peer`, `ipc-peer`, `uts-private`, `init-control-fd`; Cold/2 |
| S-05 | `loopback`, `host-addresses`, `lan`, `production-cidrs`, `public-registry`, `scoped-capabilities`; Cold/2 |
| S-06 | `pull-push-login-logout`, `run-exec`, `images`, `volumes`, `networks`, `bind-own`, `job-container`, `service-container`, `docker-action`; Cold/1 |
| S-07 | `pinned-buildx-login-build-push`; Cold and Warm/1 |
| S-08 | `privileged`, `network-host`, `published-port`; Cold/2 |
| S-09 | `memory-oom`, `pids`, `cpu`, `io`; Cold/1, each with production-sentinel SLO sampling |
| S-10 | `step`, `post`, `buildkit`, `teardown`, `stale-cancel`, `lease-loss`, `post-failure`, `shutdown`; Cancel/1 |
| S-11 | `reserved`, `provisioning`, `ready`, `running`, `cleaning`, `destroying`; Restart/1 |
| S-12 | `symlink-root`, `symlink-command-file`, `inode-replacement`, `path-replacement`, `unknown-resource`; Failure/1 |
| S-13 | `capacity-and-distinct-state`; Cold/Warm/Failure/Cancel/Restart at both 20 and 40; also request one extra admission in each case |
| S-14 | `next-tenant-clean`; NextTenant at 20 and 40 after **each** S-13 wave (encode source wave in case name) |
| S-15 | `zero-domain-processes`; Idle at 20 and 40 after **each** S-13 + S-14 pair (encode source wave in case name) |
| S-16 | `native-storage`; Cold and Warm at 1, 20 and 40 |

The extra report-derived cases (`lease-loss`, `init-control-fd`, credentials/capabilities/command-file attacks) are scoped qualification observations, not implementations of issues #47–#53. If the relevant service is absent, the case blocks.

- [ ] **Step 1: Write failing tests.** Verify fixed 16 IDs, unique case keys, both 20/40 dimensions and each next-tenant/idle wave dependency. Delete one S-14 result, duplicate S-07, or replace 40 with 39: coverage fails. For every required case, `required_checks` is nonempty, sorted, duplicate-free, and contains `CleanupConfirmed` whenever the case creates an attempt. Pin representative exact sets for S-01, S-05 network, S-09 CPU/I/O, S-13, S-14, S-15 and S-16 so adding one arbitrary all-true check can never replace required evidence.

```rust
#[test]
fn catalogue_has_all_sixteen_ids_and_no_duplicate_keys() {
    let cases = required_cases();
    let ids: std::collections::BTreeSet<_> = cases.iter().map(|c| c.scenario).collect();
    assert_eq!(ids.into_iter().collect::<Vec<_>>(), ScenarioId::ALL);
    let keys: std::collections::BTreeSet<_> = cases.iter().map(|c|
        (c.scenario, c.case.clone(), c.wave, c.concurrency)).collect();
    assert_eq!(keys.len(), cases.len());
    assert!(cases.iter().any(|c| c.scenario == ScenarioId::S13 && c.concurrency == 40));
}
```

- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test catalog > /tmp/chimera-e0-catalog.log 2>&1` — absent catalogue/types fail.
- [ ] **Step 3: Implement exact catalogue expansion.** Use fixed arrays for named cases and explicit loops over `[20, 40]` and the five source waves. `validate_coverage` compares complete key sets and also rejects duplicate rows; do not treat a set conversion as sufficient. `required_checks` matches on the closed scenario/case/wave dimensions and returns the exact typed checklist; no fallback/default arm is allowed. Case names are allowlisted, never directly used as host paths.
- [ ] **Step 4: GREEN.** Repeat command; inspect `rg 'test result:|^failures:' /tmp/chimera-e0-catalog.log`.
- [ ] **Step 5: Commit.** `git add tests/sandboxed_qualification_test.rs tests/qualification && git commit -m "test: catalogue sandboxed release qualification cases"`

### Task 2: Versioned observations and reports distinguish harness success from release evidence

**Files:** Create `driver.rs`, `driver_test.rs`, `report_test.rs`, JSON fixture files `driver-hello.json`, `report-incomplete.json`; extend `report.rs` and module exports.

**Interfaces:**

```rust
pub struct RunIdentity { pub run_id: uuid::Uuid, pub commit: String,
    pub config_digest: String, pub host_boot_id: uuid::Uuid, pub mode: EvidenceMode }
pub struct DriverHello { pub schema_version: u32, pub commit: String,
    pub binary_digest: String, pub backend: String, pub supported: Vec<ScenarioId> }
pub struct DriverRequest { pub schema_version: u32, pub identity: RunIdentity,
    pub key: CaseKey, pub recipe: Recipe }
pub struct Recipe { pub operations: Vec<Operation>, pub deadline_ms: u64 }
pub enum Operation {
    Preflight { missing: String },
    Provision { attempt: uuid::Uuid, fail_after: Option<String> },
    RunFixture { attempt: uuid::Uuid, fixture: String },
    Cancel { attempt: uuid::Uuid, phase: String },
    CrashSupervisor { phase: String }, Reconcile,
    Destroy { attempt: uuid::Uuid }, Observe,
}
pub struct Observation { pub name: String, pub value: serde_json::Value }
pub struct DriverResponse { pub schema_version: u32, pub run_id: uuid::Uuid,
    pub commit: String, pub config_digest: String, pub host_boot_id: uuid::Uuid,
    pub driver_digest: String, pub key: CaseKey, pub observations: Vec<Observation> }
pub async fn run_driver(binary: &std::path::Path, request: &DriverRequest)
    -> Result<DriverResponse, Reason>;
pub struct QualificationReport { pub schema_version: u32, pub identity: RunIdentity,
    pub driver_digest: String, pub activation_available: bool, pub results: Vec<CaseResult>,
    pub cleanup_confirmed: bool }
pub fn qualifies(report: &QualificationReport) -> bool;
pub fn write_report(directory: &std::path::Path, report: &QualificationReport)
    -> std::io::Result<()>;
```

Protocol transport: pin/open the absolute driver with `O_NOFOLLOW`, verify regular-file ownership/mode and hash its bytes with SHA-256 before the first execution; execute that same `/proc/self/fd/<n>` identity with `--qualification-protocol=1`, one JSON request on stdin and one JSON response on stdout, never through a shell. Handshake uses the pinned identity with `--qualification-hello=1`; `DriverHello.binary_digest` must equal the independently computed digest. Recheck the opened file identity before every invocation and retain the FD for the run. `QualificationReport.driver_digest`, every `EvidenceProvenance.driver_digest`, hello, and response must equal that independently computed value. Each invocation has an enforced timeout and 1 MiB stdout/64 KiB stderr caps; stderr is not copied into the report. All unknown top-level fields are rejected. `Observation.value` is schema-checked by scenario-specific typed decoders before evaluation; no driver-provided `passed` or release verdict exists.

- [ ] **Step 1: Add tests.** All-fixture-Passed report does not qualify; all-native-Passed with one missing case does not qualify; Blocked/Inconclusive/Failed, duplicate observations, mismatched run ID/commit/config/boot/key/driver digest, nonzero exit, oversized/truncated response and unknown protocol version all fail. A native-labelled complete report made from caller-constructed all-true checks fails when one exact `required_checks(key)` member is absent, duplicated, unexpected, or its per-case provenance differs from the report identity. Test bounded timeout against a fixture subprocess that waits on stdin without replying. Fixture scripts exist only under temporary test directories with synthetic contents.

```rust
#[test]
fn fixture_success_is_not_native_release_qualification() {
    let results = required_cases().into_iter().map(|key| {
        let provenance = fixture_provenance(&key);
        CaseResult { key, verdict: Verdict::Passed, reason: None, provenance,
            checks: vec![Check { id: CheckId::CleanupConfirmed, passed: true }],
            duration_ms: 1 }
    }).collect();
    let report = QualificationReport { schema_version: 1,
        identity: RunIdentity { run_id: uuid::Uuid::new_v4(), commit: "a".repeat(40),
            config_digest: "b".repeat(64), host_boot_id: uuid::Uuid::new_v4(),
            mode: EvidenceMode::Fixture }, activation_available: false,
        driver_digest: fixture_driver_digest(), results, cleanup_confirmed: true };
    assert!(!qualifies(&report));
}
```

- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test report > /tmp/chimera-e0-report.log 2>&1` and `cargo test --test sandboxed_qualification_test driver > /tmp/chimera-e0-driver.log 2>&1`.
- [ ] **Step 3: Implement protocol and reporting.** `run_driver` receives the pinned driver handle plus independently computed digest and rejects any hello/response whose binary digest or run/commit/config/boot/key differs from it and the request. Scenario-specific typed decoders transform bounded `Observation` values into facts; trusted evaluators alone produce `CaseResult`, per-case `EvidenceProvenance`, and `CheckId`s. `qualifies` requires native identity, complete exact coverage, every case Passed, the exact sorted `required_checks(key)` set with every check true, a nonempty report driver digest, per-case provenance identical to the report identity/key and that independently authenticated digest, valid bounded typed metric summaries, and cleanup confirmed. It never accepts an arbitrary check name, a driver-provided verdict, or a report row whose provenance was synthesized after the driver response. `activation_available` stays false even for a qualifying report: activation is a separate reviewed change. Write `report.json` and `report.md` to create-new temporary files under the held run directory, sync files, rename and sync directory. Markdown contains 16 scenario summary rows plus per-case status and reasons, prominently `FIXTURE / NOT RELEASE EVIDENCE` or `NATIVE / INCOMPLETE` as applicable. Never serialize raw observation values containing stdout, environment, tokens or paths supplied by a workload; store only validated typed facts, typed check IDs, provenance and synthetic IDs. An interrupted run leaves a partial report whose `cleanup_confirmed` is false.
- [ ] **Step 4: GREEN.** Repeat both commands. Round-trip report fixtures and assert rendered Markdown includes all 16 scenario IDs.
- [ ] **Step 5: Commit.** `git add tests/qualification tests/fixtures/qualification && git commit -m "test: add strict sandbox qualification protocol and reports"`

### Task 3: Exclusive single-host ownership and conservative native preconditions

**Files:** Create `host.rs`, `host_test.rs`, `tests/fixtures/qualification/config.json`; extend protocol metadata and module exports.

**Interfaces:**

```rust
pub struct NativeConfig {
    pub root: std::path::PathBuf,
    pub driver: std::path::PathBuf,
    pub report_root: std::path::PathBuf,
    pub lock_file: std::path::PathBuf,
    pub active_marker: std::path::PathBuf,
    pub max_case_ms: u64,
    pub cleanup_deadline_ms: u64,
    pub production_sentinel: std::net::SocketAddr,
    pub negative_sentinels: Vec<NegativeSentinel>,
    pub public_registry_url: String,
    pub sentinel_p99_ms: u64,
    pub execution_resources: chimera::config::resources::ExecutionResources,
    pub minimum_production_memory_bytes: u64,
    pub maximum_chimera_memory_bytes: u64,
    pub maximum_chimera_pids: u64,
    pub max_parallel_builds: u16,
}
pub enum SentinelRole { Loopback, Host, Lan, Production }
pub struct NegativeSentinel { pub role: SentinelRole,
    pub address: std::net::SocketAddr, pub denied_prefix: String }
pub struct NativeLease { lock: std::fs::File, run_directory: std::path::PathBuf,
    marker: std::fs::File }
pub fn acquire_native(config: &NativeConfig, run_id: uuid::Uuid)
    -> Result<NativeLease, Reason>;
pub fn recover_unfinished(config: &NativeConfig) -> Result<(), Reason>;
impl NativeLease {
    pub fn run_directory(&self) -> &std::path::Path;
    pub fn publish_blocked_and_release(self, report: &QualificationReport)
        -> Result<(), Reason>;
}
pub struct HostSnapshot { pub boot_id: uuid::Uuid, pub kernel: String,
    pub systemd_version: String, pub cgroup_v2: bool, pub container: bool,
    pub service_uid: u32, pub service_name: String }
pub fn inspect_host() -> Result<HostSnapshot, Reason>;
```

Native config must be provided, not synthesized from these test fixture limits. Native config and its nested types derive serde with `deny_unknown_fields`. `execution_resources` uses B's production parser and validation and its canonical bytes are included in `RunIdentity.config_digest`; Task 7/E1 later compare them with live cgroup readback rather than trusting duplicate test-only limits. All durations/limits must be positive, cleanup deadline <= case deadline, `max_parallel_builds` between 1 and 40. `negative_sentinels` must cover all four roles; the public-registry URL must use HTTPS and contain no userinfo or query credentials. The production SLO listener and negative isolation listeners serve separate roles even when hosted on the same physical machine. Numeric resource limits in E0 are fixture inputs, not operator-approved benchmark provenance. E1 must add an authenticated operator manifest for actual production roots, CIDR inventory, bounded storage and approved reserve/SLO before any native case can qualify. `active_marker` is fixed to `/run/lock/chimera-qualification.active` and records only run UUID, boot ID, supervisor start identity, optional run-owned cgroup identity and report-directory identity; no command, secret or workload path is stored. E0 writes no cgroup identity and never invokes a native driver.

- [ ] **Step 1: Add tests.** Two processes using different run directories and the same test lock file: the second receives HostBusy. Reject symlink lock/root/report directory, unowned/shared writable root, `/`, `/tmp`, home directory, report root outside designated qualification storage, and driver under writable attempt storage. Refuse a preexisting run UUID directory. Spawn a portable fixture harness which fsyncs an active marker, kill only that harness, and assert a second invocation cannot start: the marker yields UnfinishedRun even though process exit released the advisory lock. `recover_unfinished` never deletes or heuristically clears a stale, changed-boot, or changed-process marker in E0. A clean blocked preflight with no driver/cgroup ever started writes and syncs a complete blocked report, removes only its own exact marker, and allows a subsequent run; a failed report write leaves the marker. No test touches `/run/lock` or real cgroups.

```rust
#[test]
fn exclusive_lock_cannot_be_bypassed_by_a_second_output_directory() {
    let temp = tempfile::tempdir().unwrap();
    let lock = temp.path().join("qualification.lock");
    // Test helper accepts a lock path only; production acquire_native fixes it below.
    let first = lock_exclusive(&lock).unwrap();
    assert!(matches!(lock_exclusive(&lock), Err(Reason::HostBusy)));
    drop(first);
    assert!(lock_exclusive(&lock).is_ok());
}
```

Define `fn lock_exclusive(path: &Path) -> Result<File, Reason>` in `host.rs` for portable fixture paths; it takes an owned non-shared-writable parent directory and opens the filename with `O_NOFOLLOW|O_CLOEXEC|O_CREAT` mode 0600, validates identity and uses `LOCK_EX|LOCK_NB`. Native acquisition uses the fixed `/run/lock/chimera-qualification.lock` without `O_CREAT`: the operator preprovisions a service-owned 0600 regular file with link count one. Accept a root-owned sticky `/run/lock` only when its descriptor proves directory identity, root ownership, sticky bit, no symlink and no group/other write except that protected sticky directory; reject all other writable parents. This rule does not change permissions on the global directory. The test-only custom path is not exposed as a native CLI override.
- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test host > /tmp/chimera-e0-host.log 2>&1`.
- [ ] **Step 3: Implement fail-closed ownership and observations.** Require native `lock_file` exactly `/run/lock/chimera-qualification.lock` and `active_marker` exactly `/run/lock/chimera-qualification.active`; do not create or chmod the native lock file. After taking the lock, reject any existing marker as UnfinishedRun, create+fsync a 0600 marker with run UUID, boot ID, supervisor PID/start identity, no cgroup, and pinned report-directory identity before any external driver activity. E0 never starts a native driver or destructive scenario. `NativeLease::Drop` leaves the marker in place. Only `publish_blocked_and_release` may write and sync an all-Blocked report and remove+sync the exact same marker while the original process still holds the lock and no driver/cgroup was started. A failed write or changed marker leaves it and returns CleanupUnconfirmed. `recover_unfinished` returns UnfinishedRun for any marker; E1 replaces this with authenticated exact-resource recovery and a watchdog once it owns real driver/cgroup identities. Verify Debian `/etc/os-release`, systemd PID 1, unified cgroup v2 and no container environment through mount/cgroup/runtime indicators; inability to establish bare-metal provenance is Inconclusive, not native success. Check configured root/report/driver paths for no-follow identity, normalization, ownership and disjointness, but do not infer actual production-root or bounded-storage approval from path checks. Use pinned directory handles and UUID ownership markers. These E0 checks cannot qualify a native release without the E1 operator manifest and runtime adapter.
- [ ] **Step 4: GREEN.** Repeat host command. Ensure the tests use temporary lock paths and cannot touch `/run/lock` in the portable run.
- [ ] **Step 5: Commit.** `git add tests/qualification tests/fixtures/qualification/config.json && git commit -m "test: serialize native sandbox qualification on one host"`

### Task 4: Isolation fixtures and validators for S-01/S-03/S-04/S-05/S-12

**Files:** Create `fixtures.rs`, `fixtures_test.rs`, `isolation.rs`, `isolation_test.rs`; extend exports.

**Interfaces:**

```rust
pub struct CanarySet { pub run_id: uuid::Uuid, pub host: String, pub peer: String,
    pub supervisor: String, pub credential: String }
pub fn make_canaries(run_id: uuid::Uuid) -> CanarySet;
pub fn isolation_recipe(key: &CaseKey, attempts: &[uuid::Uuid]) -> Result<Recipe, Reason>;
pub fn evaluate_isolation(key: &CaseKey, response: &DriverResponse)
    -> Result<Vec<Check>, Reason>;
pub struct QualificationNetworkFacts {
    pub expected: chimera::sandbox_policy::NetworkPolicy,
    pub applied: chimera::sandbox_policy::AppliedNetworkPolicy,
    pub probes: chimera::sandbox_policy::ProbeBatch,
}
pub enum IsolationTarget {
    HostFile, PeerFile, SupervisorCredential, HostBind, PeerBind,
    HostProcess, PeerSignal, PeerIpc, Hostname, InitControlFd,
}
pub enum IsolationOutcome { Denied, Absent, Visible, Modified, Signalled }
pub struct IsolationObservation { pub target: IsolationTarget,
    pub outcome: IsolationOutcome }
pub struct IsolationFacts {
    pub setup_confirmed: bool, pub outside_control_before: bool,
    pub outside_control_after: bool,
    pub network: Option<QualificationNetworkFacts>,
    pub observations: Vec<IsolationObservation>,
    pub peer_unchanged: bool, pub polling_started: bool,
    pub rollback_confirmed: bool, pub cleanup_confirmed: bool,
}
```

Observation name `isolation` contains only `IsolationFacts`. Each case uses relevant fields and rejects missing fields, inconsistent facts and unknown observations. `CanarySet` strings are synthetic (`chimera-qualification:<run>:<role>`), never copied from real host credentials. Host/peer canary files live under run-owned fixture roots outside the private rootfs; “supervisor credentials” are synthetic files at the same relative shape, not actual registrations.

- [ ] **Step 1: Add tests.** Every catalogue isolation case has a recipe and evaluator; known failing observations are rejected. For S-03/S-04, each case requires the exact typed `IsolationTarget`; `Visible`, `Modified`, or `Signalled` is BoundaryViolation, while a missing target observation is MissingEvidence. For S-05, reuse D0's typed `ConnectOutcome`: `Refused` and `Unreachable` remain Inconclusive, `Connected` is BoundaryViolation, and only `Denied` or bounded `TimedOut` can satisfy a negative endpoint when both outside controls and public-registry positive control pass. Mismatched expected/applied policy, sentinel address/role or policy generation is StaleEvidence. For S-12, require peer canary inode/content unchanged after symlink/inode replacement attempts. For S-01, require `polling_started=false` and clean rollback; a setup error after polling is failure.

```rust
#[test]
fn unavailable_sentinel_is_not_network_isolation() {
    let facts = IsolationFacts { setup_confirmed: true,
        outside_control_before: false, outside_control_after: false,
        network: Some(network_facts(ConnectOutcome::Refused)),
        observations: vec![],
        peer_unchanged: true, polling_started: false,
        rollback_confirmed: true, cleanup_confirmed: true };
    assert!(matches!(evaluate_network_facts(&facts), Err(Reason::MissingEvidence)));
}
```

Define `fn evaluate_network_facts(facts: &IsolationFacts) -> Result<Vec<Check>, Reason>` in `isolation.rs`, returning typed checks for both controls and negative connection result. Define `fn evaluate_boundary_observations(key: &CaseKey, observations: &[IsolationObservation]) -> Result<Vec<Check>, Reason>` with an exact required-target table for S-03/S-04; duplicate, unrelated or missing observations fail.
- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test isolation > /tmp/chimera-e0-isolation.log 2>&1` and `cargo test --test sandboxed_qualification_test fixtures > /tmp/chimera-e0-fixtures.log 2>&1`.
- [ ] **Step 3: Implement explicit recipes.** S-01 requests fault injection through driver capability inventory, never disables host userns/eBPF/cgroup. S-03 executes reads and bind attempts against known canary paths in A and records an exact typed outcome for each target; sentinel B verifies identity/content afterward. S-04 queries peer PID/signal/IPC, hostname isolation and control-FD absence through purpose-built fixture operations and records the matching target/outcome rather than a generic boolean. S-05 uses listeners outside the target service boundary on the same host, loopback/host/LAN/production addresses already configured by the operator, plus public registry positive connectivity. It never adds a production route or interface alias; absent reachable outside-control listener blocks that case. Preserve compiled expected `NetworkPolicy`, applied policy, every sentinel's `SocketAddr`, before/after controls and typed `ConnectOutcome`; never reduce these to a reached boolean. D0's public `sandbox_policy` facade re-exports `NetworkPolicy`, `AppliedNetworkPolicy`, `ProbeBatch`, `ConnectOutcome`, and `validate_network_evidence`; `evaluate_network_facts` first validates E0 run/key provenance, then calls `chimera::sandbox_policy::validate_network_evidence(&expected, &applied, &probes)`, mapping `ProbeInconclusive` to MissingEvidence and `ProbeAllowedForbidden` to BoundaryViolation. Scoped capability checks test cross-attempt grant rejection and post-revoke refusal, including known synthetic IDs/hashes. S-12 races only the run-owned test resource; unknown-resource case must remain quarantined and untouched. No arbitrary user-provided shell path or filesystem traversal is embedded in recipes.
- [ ] **Step 4: GREEN.** Repeat both commands; malformed observations must produce Failed/Inconclusive rather than panic. Fixtures exercise evaluator branches, not security claims.
- [ ] **Step 5: Commit.** `git add tests/qualification && git commit -m "test: add sandbox isolation and hostile path qualification fixtures"`

### Task 5: Exact Docker/action recipes and changed host semantics, S-06…S-08

**Files:** Create `docker.rs`, `docker_test.rs`, `actions.json`, `workflows/pinned-build.yml`, `workflows/Dockerfile`, `workflows/payload.txt`; extend `fixtures.rs` and exports. Read `tests/execution_domain_docker_test.rs` pinned acceptance test and `tests/common/pinned_action.rs` completely before implementation.

**Interfaces:**

```rust
pub struct ActionPin { pub owner: String, pub repository: String, pub commit: String }
pub fn action_pins() -> [ActionPin; 3];
pub fn docker_recipe(key: &CaseKey, attempt: uuid::Uuid) -> Result<Recipe, Reason>;
pub struct DockerFacts { pub operation_exit_codes: Vec<i32>,
    pub pushed_digest: Option<String>, pub pulled_digest: Option<String>,
    pub builder_driver: Option<String>, pub post_order: Vec<String>,
    pub host_canary_reached: bool, pub peer_canary_reached: bool,
    pub host_port_reached: bool, pub domain_port_reached: bool,
    pub remaining_owned_objects: u64, pub cleanup_confirmed: bool }
pub fn evaluate_docker(key: &CaseKey, facts: &DockerFacts) -> Result<Vec<Check>, Reason>;
```

Use these existing verified repository pins, unchanged:

```text
docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5
docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee
docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
```

- [ ] **Step 1: Add tests.** Pins must match exactly and be 40 hexadecimal characters; reject branch/tag pins. Validator requires all command exit codes zero, `docker-container` driver, identical pushed/pulled `sha256:<64hex>` digest, exact reverse post order and zero remaining owned builders/containers/volumes after explicit destroy. S-08 requires domain port reachable and host/peer sentinels unreachable; no `--network host` success is accepted as host network reachability.

```rust
#[test]
fn exact_action_pins_are_frozen() {
    let pins = action_pins();
    assert_eq!(pins[0].commit, "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5");
    assert_eq!(pins[1].commit, "650006c6eb7dba73a995cc03b0b2d7f5ca915bee");
    assert_eq!(pins[2].commit, "f9f3042f7e2789586610d6e8b85c8f03e5195baf");
}
```

- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test docker > /tmp/chimera-e0-docker.log 2>&1`.
- [ ] **Step 3: Implement recipes and fixture workload.** Use a registry running **inside the same attempt** with synthetic credentials, accessible to that attempt's Docker/BuildKit network. Do not expose a host registry through an egress allow override. The pinned workflow uses `driver: docker-container`, login, build-push and pull-by-digest verification. Supply context as fixture files; no checkout of production source is necessary for these three pins. Dockerfile content is `FROM scratch`, `COPY payload.txt /payload.txt`; payload is an ASCII synthetic canary. Exact checkout/hadolint runtime compatibility remains separately recorded under #49 and cannot be inferred from these three actions.

```yaml
name: synthetic-sandbox-qualification
on: workflow_dispatch
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5
        with:
          driver: docker-container
      - uses: docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee
        with:
          registry: ${{ env.QUALIFICATION_REGISTRY }}
          username: ${{ env.QUALIFICATION_USER }}
          password: ${{ secrets.QUALIFICATION_PASSWORD }}
      - uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          push: true
          tags: ${{ env.QUALIFICATION_REGISTRY }}/synthetic:qualification
```

The E1 driver maps this fixture through the actual job engine; E0 verifies the parsed fixture and intended observations only. Synthetic credentials are generated per run and redacted using existing masking semantics, never written to report. S-06 recipes explicitly cover every catalogue operation including job/service containers and Docker actions. S-08 tests `--privileged` against host/peer canaries, `--network host` against domain vs host listeners, and `-p` from domain vs outside host; outside listeners have positive controls.
- [ ] **Step 4: GREEN.** Repeat Task 5 command. Because Docker-related tests are added, later integration verification also runs `cargo test -- --ignored` in the documented environment; the new native target must be excluded from ordinary Docker smoke using its exact target selection and run separately on Debian. Amend the native test feature gating in Task 8 so unrelated ignored runs do not trigger it.
- [ ] **Step 5: Commit.** `git add tests/qualification tests/fixtures/qualification && git commit -m "test: define pinned sandbox Docker qualification workloads"`

### Task 6: Failure, cancellation, restart, concurrency and next-tenant evidence

**Files:** Create `lifecycle.rs`, `lifecycle_test.rs`; extend fixtures and exports.

**Interfaces:**

```rust
pub struct LifecycleFacts { pub provisioned: Vec<String>, pub rolled_back: Vec<String>,
    pub active_peak: u16, pub extra_admission_blocked: bool,
    pub attempt_ids: Vec<uuid::Uuid>, pub endpoint_ids: Vec<String>,
    pub revoked_before_destroy: bool, pub destroy_before_completion: bool,
    pub elapsed_ms: u64, pub deadline_ms: u64,
    pub remaining_processes: u64, pub remaining_mounts: u64,
    pub remaining_sockets: u64, pub remaining_writable_roots: u64,
    pub next_tenant_canaries: Vec<String>, pub peer_unchanged: bool,
    pub root_poisoned: bool, pub cleanup_confirmed: bool }
pub fn lifecycle_recipe(key: &CaseKey, attempts: &[uuid::Uuid],
    deadline_ms: u64) -> Result<Recipe, Reason>;
pub fn evaluate_lifecycle(key: &CaseKey, facts: &LifecycleFacts)
    -> Result<Vec<Check>, Reason>;
```

- [ ] **Step 1: Add tests.** Parameterize all eight provisioning fault sites, all cancellation sites and six SIGKILL phases. Reverse rollback order must equal reversed successfully-created resource sequence; journal intent alone cannot count as a resource. Duplicate attempts/endpoints, active peak 41 under capacity 40, or extra admission released before destroy fail. Stale cancel targets old UUID and leaves new peer unchanged. Any remaining process/mount/socket/writable root fails the clean result; ambiguous cleanup requires poison and stops subsequent cases.

```rust
#[test]
fn rollback_order_reverses_actual_side_effects() {
    let created = vec!["journal".to_string(), "cgroup".to_string(), "namespaces".to_string()];
    let reversed: Vec<_> = created.iter().rev().cloned().collect();
    assert!(rollback_matches(&created, &reversed));
    assert!(!rollback_matches(&created, &created));
}
```

Define `fn rollback_matches(created: &[String], removed: &[String]) -> bool` in `lifecycle.rs`; it also rejects duplicate/unknown stage names. Add fixtures for completion-before-destroy, missing capability revoke, elapsed timeout, a leftover reparented BuildKit process and stale credential canary in NextTenant.
- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test lifecycle > /tmp/chimera-e0-lifecycle.log 2>&1`.
- [ ] **Step 3: Implement deterministic sequences.** S-02 `Provision(fail_after)` → `Observe` → `Reconcile` → `Observe`; S-10 pauses at explicit driver barrier before cancel/lease-loss/post-failure/shutdown fixture → destroy → observe; S-11 waits for acknowledged phase, sends SIGKILL to exact supervisor identity through the driver, restarts same root and reconciles before any new work. PID reuse is guarded by boot ID/process start time; a saved PID alone is not authority. S-13 provisions N distinct attempts with a barrier proving simultaneous Ready/Running, requests N+1 and observes no Online/admission until confirmed destruction. Cold means empty **owned** immutable/runtime cache variant; Warm reuses approved immutable inputs only. No host drop-caches command. For every five-wave N run, S-14 starts a distinct identity wave and searches for known previous filesystem/process/env/Docker/cache/artifact/credential canaries; S-15 then enumerates exact owned process cgroups and requires zero dockerd/rootlesskit/containerd/BuildKit descendants plus no writable attempt state. Do not reuse UUIDs or writable stores. Driver must report cross-capability rejection; lack of artifact integration blocks that part of qualification.
- [ ] **Step 4: GREEN.** Repeat lifecycle command. Native failure handling records partial report, attempts exact owned reconciliation under the retained lease, and refuses subsequent cases when cleanup is unconfirmed. Test this orchestrator branch with fixture driver observations; no real daemon signals in portable tests.
- [ ] **Step 5: Commit.** `git add tests/qualification && git commit -m "test: cover sandbox teardown and successive tenant waves"`

### Task 7: Bounded resource stress and native PSS/storage measurements

**Files:** Create `resources.rs`, `resources_test.rs`; extend report with typed metric summaries.

**Interfaces:**

```rust
pub struct MetricSample { pub elapsed_ms: u64, pub pss_bytes: u64,
    pub cpu_usage_usec: u64, pub io_read_bytes: u64, pub io_write_bytes: u64,
    pub io_read_ops: u64, pub io_write_ops: u64, pub pids_current: u64,
    pub memory_current: u64, pub memory_events_oom_kill: u64,
    pub pids_events_max: u64, pub cpu_nr_periods: u64,
    pub cpu_nr_throttled: u64, pub cpu_throttled_usec: u64,
    pub host_mem_available_bytes: u64, pub sentinel_latency_us: u64 }
pub struct LimitReadback { pub cgroup: String,
    pub memory_high: u64, pub memory_max: u64, pub memory_swap_max: u64,
    pub pids_max: u64, pub cpu_quota_usec: u64, pub cpu_period_usec: u64,
    pub cpu_weight: u64, pub io_device_major: u32, pub io_device_minor: u32,
    pub io_read_bps: Option<u64>, pub io_write_bps: Option<u64>,
    pub io_read_iops: Option<u64>, pub io_write_iops: Option<u64> }
pub struct ResourceFacts { pub samples: Vec<MetricSample>, pub startup_ms: u64,
    pub global_limits: LimitReadback, pub attempt_limits: LimitReadback,
    pub cleanup_ms: u64, pub oom_contained: bool, pub pid_limit_hit: bool,
    pub cpu_saturation_completed: bool, pub io_saturation_completed: bool,
    pub expected_work_completed: bool, pub cleanup_confirmed: bool }
pub struct ResourceSummary { pub peak_pss_bytes: u64, pub peak_pids: u64,
    pub sentinel_p99_us: u64, pub read_iops: f64, pub write_iops: f64,
    pub minimum_host_mem_available_bytes: u64,
    pub cpu_throttled_periods: u64, pub cpu_throttled_usec: u64,
    pub startup_ms: u64, pub cleanup_ms: u64 }
pub struct CaseMetrics { pub key: CaseKey, pub summary: ResourceSummary }
pub fn summarize_resources(facts: &ResourceFacts) -> Result<ResourceSummary, Reason>;
pub fn evaluate_resources(key: &CaseKey, config: &NativeConfig,
    facts: &ResourceFacts) -> Result<Vec<Check>, Reason>;
```

Add `pub resource_summaries: Vec<CaseMetrics>` to `QualificationReport` in this task and update all earlier report literals with an empty vector. Native `qualifies` additionally requires one validated summary for each S-09/S-16 case, rejects duplicate/unexpected metric keys, and serializes their measurement units explicitly in JSON/Markdown. Fixture reports remain disqualified even with complete synthetic summaries.

- [ ] **Step 1: Add tests.** Empty, one-sample, nonmonotonic time, missing PSS, counter regression, NaN/nonfinite derived rates, no completed work and SLO violation all reject. PSS zero is valid only for a documented empty idle interval, never during active workload. Quantile uses nearest-rank `ceil(0.99*n)-1`, with checked indexing. Given three samples at 0, 1000, 2000 ms and write-op counters 10, 20, 30, write IOPS equals 10; a single aggregate RSS observation is not accepted by the schema. Reject a missing/mismatched global or attempt `LimitReadback`, zero CPU throttling during the saturated CPU fixture, observed CPU usage above configured quota tolerance, absent `io.max` for the configured device, saturated I/O throughput above its configured ceiling tolerance, and any sample whose host `MemAvailable` drops below `minimum_production_memory_bytes`. Each negative test keeps sentinel latency healthy so a fast machine cannot mask disabled enforcement.

```rust
#[test]
fn p99_uses_nearest_rank_without_hiding_tail_latency() {
    assert_eq!(nearest_rank_p99(&[100, 200, 9000]).unwrap(), 9000);
    assert!(nearest_rank_p99(&[]).is_err());
}
```

Define `fn nearest_rank_p99(values: &[u64]) -> Result<u64, Reason>` in `resources.rs`; sort a copied vector and use integer arithmetic for the rank.
- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test resources > /tmp/chimera-e0-resources.log 2>&1`.
- [ ] **Step 3: Implement metrics and recipes.** The harness, not the workload driver, reads both global and exact attempt cgroups. It compares `memory.high/max`, `memory.swap.max`, `pids.max`, `cpu.max`, `cpu.weight`, and device-qualified `io.max` with canonical `ValidatedLimits::writes()` produced from `NativeConfig.execution_resources`; a missing controller/file, `max` where a bound is required, wrong device, or changed value is MissingEvidence/Failed. The sampler sums process PSS from `/proc/<pid>/smaps_rollup` while guarding PID start time, reads `cpu.stat`, `io.stat`, memory/pids events, samples host `/proc/meminfo` `MemAvailable`, and samples production sentinel from outside Chimera cgroup on the same host. Sample at 250 ms with monotonic timestamps before/during/after each workload; require at least ten active samples for benchmark/stress intervals. Permission-denied/missing samples mark evidence incomplete. Stress fixture durations are capped by config and an independent outside watchdog; tests never remove configured global limits. Memory fixture allocates within the attempt until cgroup OOM event and requires host `MemAvailable` to remain at or above the configured production reserve; PID fixture uses a bounded child loop until pids.max denial, never an unbounded shell fork bomb. CPU fixture has finite worker count and deadline, must increase `nr_throttled/throttled_usec`, and verifies usage over at least ten periods does not exceed the configured quota by more than 10%. I/O fixture writes/fsyncs only owned bounded storage, stops before its configured byte budget, requires the configured `io.max` device counters to advance, and checks sustained BPS/IOPS do not exceed the applicable ceiling by more than 10% after warm-up. If the production device cannot expose the configured I/O controller evidence, the case is nonqualifying rather than silently skipped. Record production sentinel baseline for 10 s before each stress and compare in absolute configured SLO terms. S-16 records Cold/Warm startup, total CPU, PSS, IOPS, minimum host available memory and cleanup for 1/20/40 attempts; do not derive sizing from nested VFS measurements.
- [ ] **Step 4: GREEN.** Repeat resource command. Synthetic fixture thresholds are only parser/evaluator test data; native config has no default reserve or SLO.
- [ ] **Step 5: Commit.** `git add tests/qualification && git commit -m "test: measure sandbox resource limits with native evidence"`

### Task 8: Orchestrate reports, preserve activation, and document serialized native execution

**Files:** Extend `tests/sandboxed_qualification_test.rs`, `qualification/mod.rs`, report tests; create `scripts/qualification/native.sh`, `docs/testing-sandboxed-native.md`. No new Cargo feature: reuse the existing `acceptance-tests` feature to compile the one native orchestrator only when explicitly requested.

**Interfaces:** `pub async fn run_native(config: NativeConfig) -> Result<QualificationReport, Reason>`; `pub fn blocked_report(identity: RunIdentity, reason: Reason) -> QualificationReport`. `blocked_report` emits one result for every required case, all Blocked, with cleanup false when any target resource may exist. No external driver is consulted by portable fixture tests.

- [ ] **Step 1: Add orchestrator tests.** Missing driver emits a complete blocked report and nonzero outcome. Even a present fixture driver cannot be invoked in NativeDebian mode because E0 has no authenticated run-cgroup authority; all required cases remain Blocked/BackendUnavailable. A failed report write leaves the active marker and blocks another invocation. Kill the orchestrator after marker fsync and prove a second orchestrator cannot issue any driver request: it receives UnfinishedRun until E1's exact-resource recovery exists. A portable test invokes the built production `chimera start` with sandboxed profile and verifies its unchanged unavailable diagnostic; no feature/env setting used by the harness changes that result. Do not simulate a successful native cleanup or fabricate a passing report.

```rust
#[cfg(feature = "acceptance-tests")]
#[tokio::test]
#[ignore = "native Debian, exclusive host qualification and configured runtime driver required"]
async fn native_sandboxed_release_qualification() {
    let path = std::env::var_os("CHIMERA_QUALIFICATION_CONFIG")
        .expect("explicit native qualification config required");
    let bytes = std::fs::read(path).unwrap();
    let config: qualification::host::NativeConfig = serde_json::from_slice(&bytes).unwrap();
    let report = qualification::run_native(config).await.unwrap();
    assert!(qualification::report::qualifies(&report), "native qualification incomplete");
    assert!(!report.activation_available);
}
```

`run_native` always persists reports before returning a negative qualification result; parsing failures write a safe preflight report if the output directory can be safely opened, otherwise print only the safe error category.
- [ ] **Step 2: RED.** `cargo test --test sandboxed_qualification_test orchestrator > /tmp/chimera-e0-orchestrator.log 2>&1` — new orchestration tests fail. The production-gate regression must remain green throughout.
- [ ] **Step 3: Implement orchestration and script.** Native entrypoint requires exactly one absolute config path, verifies it is a regular no-follow file, sets TMPDIR inside checkout target, and invokes the single target serially:

```bash
#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 1
case "$1" in /*) ;; *) exit 2 ;; esac
test -f "$1"
test ! -L "$1"
mkdir -p "$PWD/target/chimera-tests"
export TMPDIR="$PWD/target/chimera-tests"
export CHIMERA_QUALIFICATION_CONFIG="$1"
cargo test --features acceptance-tests --test sandboxed_qualification_test \
  native_sandboxed_release_qualification -- --ignored --exact --test-threads=1 \
  > /tmp/chimera-sandboxed-native.log 2>&1
```

The Rust harness, not the Bash process, holds `/run/lock/chimera-qualification.lock` throughout. Script exit reflects cargo exit; review captured log and JSON report afterward. The runbook explains dedicated qualification roots on the single host, operator preprovisioning of the exact lock file, bounded filesystem, target service stop/restart sequencing, positive sentinel controls outside its cgroup, mandatory reserve/SLO config, synthetic credentials and no production deploy. It must state that E0 has no watchdog or automatic orphan recovery: a crash leaves an active marker and manual quarantine is required, never `rm` on guessed paths. E1 must add exact run-owned cgroup/driver identity, watchdog, authenticated cleanup and operator-approved storage/benchmark inventory before S-01…S-16 can run. E0's correct native result is a complete blocked report, even if a driver executable happens to exist.

Do not run native stress concurrently with any other native qualification or daemon migration. The shared machine lock, not an instruction to obtain separate VMs, serializes S-01…S-16. One scenario may create 20/40 concurrent attempts internally; this is the behavior under test, not parallel test scheduling.
- [ ] **Step 4: GREEN and completion checks.** Run:

```bash
cargo test --test sandboxed_qualification_test > /tmp/chimera-e0-harness.log 2>&1
cargo build > /tmp/chimera-e0-build.log 2>&1
cargo clippy --all-targets -- -D warnings > /tmp/chimera-e0-clippy.log 2>&1
cargo test > /tmp/chimera-e0-all.log 2>&1
cargo test -- --ignored > /tmp/chimera-e0-docker.log 2>&1
git diff --check
```

Run the ignored Docker command using the existing Linux/macOS Docker runbook as appropriate; the native test is absent unless `acceptance-tests` is explicitly enabled. Native script execution on the single Debian host is a separate serialized operation; during E0 its correct result, regardless of a driver path, is a complete blocked report, not a release pass. Check each exit code and captured failure section. Also compile native target with `cargo test --features acceptance-tests --test sandboxed_qualification_test --no-run > /tmp/chimera-e0-native-compile.log 2>&1` so feature-gated code cannot rot.
- [ ] **Step 5: Commit.** `git add tests/sandboxed_qualification_test.rs tests/qualification scripts/qualification/native.sh docs/testing-sandboxed-native.md && git commit -m "test: add serialized native sandbox qualification entrypoint"`

## E0 completion and E1 release boundary

E0 completion means all catalogue, fixture, protocol, report, lock and evaluator tests pass, native target compiles, and the production activation rejection remains unchanged. Its fixture reports are useful to review harness behavior but cannot satisfy S-01…S-16. The E0 native entrypoint is deliberately fail-closed and does not launch destructive scenarios or claim automatic crash recovery; an unfinished marker blocks subsequent native attempts.

E1 supplies the real driver using the stable B–D interfaces, the operator-approved production-root/CIDR/storage/benchmark manifest, pinned run-owned cgroup/process identity, unprivileged watchdog and authenticated crash recovery. Only then does it execute the exact native catalogue on the single Debian host with agreed reserve/SLO limits and publish commit/config-bound evidence for every case including cold/warm/failure/cancel/restart followed by next tenant and idle checks. External runtime/image/log/lease/artifact issue gaps remain blocked cases instead of being erased from the report. Only the final activation change can remove the unavailable gate after the complete native evidence is accepted; no task here grants that permission or makes that change.
