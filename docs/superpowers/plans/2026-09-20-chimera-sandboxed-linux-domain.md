# Sandboxed Linux Domain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze the contracts consumed by Plans C–E and implement the Linux process/filesystem/resource backend, with command execution, safe state transfer, cancellation, destruction, and crash recovery, while keeping `sandboxed` unavailable.

**Architecture:** One manager task owns an attempt's permit, journal, directory descriptors, cgroup, launcher, and control connection. The runner holds a request handle; a synchronous, unprivileged bootstrap starts before Tokio, enters RootlessKit namespaces, creates an inner PID namespace, pivots an allowlisted rootfs, and becomes `domain-init` PID 1. Production retains the existing activation gate; isolated native test fixtures can exercise the kernel backend without constructing a production-ready domain.

**Tech Stack:** Rust 2024, Tokio, existing libc/Serde/UUID dependencies, RootlessKit 2.3.5 as the first native qualification pin, Linux unified cgroup v2, `openat2`, pidfds, seccomp BPF, and Landlock ABI 3 or newer. No custom privileged binary, additional Rust dependency, private dockerd, or network policy is introduced by this plan.

**Spec:** [`docs/superpowers/specs/2026-09-20-chimera-sandboxed-execution-domain.md`](../specs/2026-09-20-chimera-sandboxed-execution-domain.md). Read [the roadmap](2026-09-20-chimera-sandboxed-execution-roadmap.md) and [implemented Plan A](2026-09-20-chimera-sandboxed-foundation.md) first. Source baseline for this plan is `origin/main@39585f1`, following foundation commit `b65da30`.

**Contract prerequisite:** Plan C Task C0 owns the opaque `DockerEndpoint` in `src/docker/endpoint.rs`, with `trusted_host()`, `unix_socket(&Path)`, and `socket_address()`. Execute C0 before Task 9 uses that type. This plan does not define a competing endpoint enum, inspect endpoint fields, or make endpoint construction depend on `DomainPath`; Plan C keeps dual host/domain socket metadata private to its runtime implementation.

## Global Constraints

- «один `chimera` service account и один systemd unit».
- «VM на каждый job отсутствуют».
- «нет пула из 20–40 системных пользователей, per-job systemd services или собственного privileged helper».
- «Профиль остаётся default для обратной совместимости существующих установок» applies to `trusted-host`.
- «macOS, запуск Chimera внутри контейнера и Linux без необходимых kernel features получают явный preflight error. Ослабленный fallback не выполняется».
- «Rootfs строится allowlist-ом, а не overlay всего `/`».
- «Обязательны отдельный mount namespace, `pivot_root` и отсоединение старого root».
- «Journal не содержит manifest, secrets, Docker credentials или command lines».
- «Сохранённый PID служит только диагностикой: после restart он мог быть повторно использован».
- «Неподтверждённый teardown переводит его в `Quarantined` и poison-ит общий `ExecutionDomainRoot`».
- «Новый production mode не включается частично». `validate_execution_profile` remains the first operation in `Daemon::run`; neither CLI nor environment gains an activation bypass.
- Plan B's disconnected test namespace uses `--net=none`; Plan D owns slirp/egress policy. Plan C owns private Docker. A successful kernel fixture does not constitute `Ready` for production.
- Existing trusted-host behavior, including host environment inheritance and private `/tmp`, remains covered during migration. Sandbox children alone receive cleared environment and hardening policy.

## Review Focus

- RootlessKit's target is not PID 1, and arbitrary extra descriptors do not survive its Go exec chain; Task 5 proves nested PID 1 and an inherited socket on stdin without a pathname endpoint.
- Workflow replacement of a state file by a FIFO, symlink, hard link, or inode swap must not block or cause supervisor filesystem reads; Tasks 3 and 8 test descriptor-bound state transfer and explicit size limits.
- A process can exit while its grandchild keeps stdout open, or can ignore TERM after `setsid`; Tasks 7 and 10 bound pipe drain and verify cgroup-wide teardown.
- A crash between deterministic resource creation and journal update must still be recoverable; Task 11 scans the union of UUID directories and owned cgroups, including cgroup-only orphans.
- Missing resource controllers, cgroup write rejection, readonly nested mounts, and architecture-mismatched seccomp must fail closed; Tasks 2, 4, 6, and 7 exercise each refusal.

---

## Delivery boundary and frozen interfaces

This is a contract-freeze plan followed by Plan B. `ExecutionDomain` remains the only lifecycle owner; private `DomainManager` and `KernelDomain` are its implementation, not independently usable public owners. No public method returns namespace PID, pidfd, mount FD, cgroup path, launcher child, or daemon process handle.

Freeze decisions relative to Plan A:

1. `DomainPermit::provision()` and `ExecutionDomain::destroy()` become async. The runner creates `AttemptIdentity` only after it receives a job; it passes that exact identity into provisioning. UUID directory spelling remains the existing 32 lowercase hexadecimal characters; cgroups use `attempt-` plus that spelling.
2. `DestroyReport` is evidence, not a permit owner. Successful destruction releases the permit before returning; completion publication waits for that return. This preserves implemented Plan A ordering. The spec's final two diagram arrows are refined here: no slot is released before confirmed destruction, but it need not wait for the remote completion HTTP call. On failure, poison is visible before any permit is released.
3. Existing trusted-host getters remain during C migration. `DomainPaths` holds domain-visible paths; host backing paths stay manager-private. `DomainPath` validates lexical absolute paths and cannot be implicitly converted into a supervisor `PathBuf`.
4. `run` is shared by shell, composite, and Node actions. Output events carry raw bytes; existing `OutputProcessor` remains responsible for line parsing and masking. Cancellation of a command is distinct from cancellation of the entire domain, so post actions can still execute after step cancellation.
5. Linux provisioning has internal `KernelReady`, distinct from journal `Ready`. Plan C supplies Docker readiness; Plan D supplies network/storage/capability readiness; Plan E alone authorizes production activation. Missing readiness is an error, never a trusted-host fallback.
6. B owns `ExecutionConfig.resources`; D owns `ExecutionConfig.network` and `ExecutionConfig.storage`. Resource quantities are parsed explicitly, without benchmark-derived production defaults.

The signatures below are normative; all return errors from the existing `ExecutionDomainError` enum extended in Task 1:

```rust
pub struct AttemptIdentity(Uuid);
impl AttemptIdentity {
    pub fn new() -> Self;
    pub fn from_uuid(id: Uuid) -> Result<Self, ExecutionDomainError>;
    pub fn uuid(&self) -> Uuid;
    pub(crate) fn component(&self) -> String;
}

pub struct DomainPath(String);
impl DomainPath {
    pub fn parse(value: &str) -> Result<Self, ExecutionDomainError>;
    pub fn as_str(&self) -> &str;
    pub fn join(&self, relative: &str) -> Result<Self, ExecutionDomainError>;
}

pub struct DomainPaths {
    pub work: DomainPath, pub tmp: DomainPath, pub home: DomainPath,
    pub run: DomainPath, pub docker_config: DomainPath,
    pub docker_data: DomainPath, pub docker_exec: DomainPath,
}
pub struct DomainEnvironment { values: HashMap<String, String> }
impl DomainEnvironment {
    pub fn merge(&self, supplied: &HashMap<String, String>, source: &'static str)
        -> Result<HashMap<String, String>, ExecutionDomainError>;
}
use crate::docker::endpoint::DockerEndpoint; // Opaque C0 contract.
pub enum CancelReason { User, Timeout, Shutdown, HandleDropped, ProtocolFailure }
pub enum CommandTarget {
    Trusted { program: std::ffi::OsString, args: Vec<std::ffi::OsString>,
              cwd: std::path::PathBuf },
    Sandboxed { program: DomainPath, args: Vec<String>, cwd: DomainPath },
}
pub struct CommandSpec {
    pub target: CommandTarget, pub env: HashMap<String, String>,
    pub timeout: Duration, pub state: Option<StepFilesId>,
}
pub enum CommandEvent { Stdout(Vec<u8>), Stderr(Vec<u8>) }
pub enum CommandOutcome { Exited(i32), Signalled(i32), Cancelled, TimedOut }
pub struct DestroyReport { pub attempt: AttemptIdentity, pub forced_kill: bool }
pub struct StepFilesId(Uuid);
pub struct StepStateSnapshot {
    pub env: String, pub path: String, pub output: String,
    pub state: String, pub summary: String,
}

impl DomainPermit {
    pub async fn provision(self, attempt: AttemptIdentity)
        -> Result<ExecutionDomain, ExecutionDomainError>;
}
impl ExecutionDomain {
    pub fn paths(&self) -> &DomainPaths;
    pub fn environment(&self) -> &DomainEnvironment;
    pub fn docker_endpoint(&self) -> &DockerEndpoint;
    pub async fn run(&self, spec: CommandSpec,
        output: tokio::sync::mpsc::Sender<CommandEvent>,
        cancelled: tokio_util::sync::CancellationToken)
        -> Result<CommandOutcome, ExecutionDomainError>;
    pub async fn cancel(&self, reason: CancelReason) -> Result<(), ExecutionDomainError>;
    pub async fn destroy(self) -> Result<DestroyReport, ExecutionDomainError>;
}
```

`AttemptIdentity`, `DomainPath`, IDs, and outcome enums derive `Clone`, `Debug`, `Eq`, `PartialEq`; identity additionally derives `Copy` and `Hash`. `CommandTarget`, `CommandSpec`, `DomainEnvironment`, protocol messages, state snapshots, and credentials do **not** derive payload-printing `Debug`. Their custom debug output names the type only. `Trusted` preserves native `OsString`/`PathBuf` values losslessly; only conversion of `Sandboxed` to the bounded wire protocol requires UTF-8. Existing trusted-host env/source error strings remain compatible; sandbox policy errors identify the reserved key but never its value.

## File structure

Create these cohesive files; add adjacent `_test.rs` modules as listed in each task:

| Path | Responsibility |
| --- | --- |
| `src/job/execution_domain/contracts.rs` | Public identity/path/command/report contracts; endpoint is imported from C0 |
| `src/config/resources.rs` | Resource parser and validated cgroup values |
| `src/job/execution_domain/manager.rs` | Resource ownership, mailbox, cancellation-safe async lifetime |
| `src/job/execution_domain/trusted.rs` | Existing host spawn and trusted filesystem implementation |
| `src/job/execution_domain/protocol.rs` | Bounded versioned control messages, framing and correlation |
| `src/job/execution_domain/state_bridge.rs` | Domain-local step files and returned snapshots |
| `src/job/execution_domain/workspace_reader.rs` | Opaque descriptor-bound workspace hashing capability |
| `src/job/execution_domain/linux/mod.rs` | Private kernel backend and capability checks |
| `src/job/execution_domain/linux/dirfd.rs` | Linux descriptor-relative filesystem operations |
| `src/job/execution_domain/linux/cgroup.rs` | Delegation, limits, descendant accounting and kill |
| `src/job/execution_domain/linux/launcher.rs` | RootlessKit child ownership and synchronous bootstrap |
| `src/job/execution_domain/linux/init.rs` | PID 1 control loop, spawning, reaping and service requests |
| `src/job/execution_domain/linux/rootfs.rs` | Typed mount plan, fresh proc/dev, pivot and mount proof |
| `src/job/execution_domain/linux/hardening.rs` | Child caps, seccomp, Landlock, descriptor closure |
| `src/job/execution_domain/linux/reconcile.rs` | Locked startup recovery of deterministic ownership |
| `src/job/execution_domain/linux/native_test.rs` | Ignored native kernel acceptance tests |
| `src/job/execution_domain/linux/native_fixture.rs` | Test-only configuration and resource assertions |
| `docs/testing/sandboxed-linux-domain.md` | Native fixture prerequisites, commands and evidence format |

Modify `src/main.rs`, `src/job/execution_domain/{mod.rs,admission.rs,error.rs,journal.rs,filesystem.rs}`, `src/config/{execution.rs,execution_test.rs}`, `src/job/{execute.rs,execute_test.rs,workspace.rs,workspace_test.rs,expression.rs,expression_test.rs}`, `src/job/expression/eval.rs`, `src/job/action/{node.rs,node_test.rs,composite_test.rs}`, `src/runner/{env.rs,env_test.rs,instance.rs,instance_test.rs}`, `src/daemon_test.rs`, and `tests/{common/mod.rs,execution_domain_test.rs,execution_domain_docker_test.rs}` only where their tasks say so. `Cargo.toml` does not need a new crate or feature. The existing `acceptance-tests` feature is used for native harness plumbing.

### Task 1: Freeze value contracts and test environment/path policy

**Files:** Create `src/job/execution_domain/contracts.rs`, `src/job/execution_domain/contracts_test.rs`; modify `src/job/execution_domain/mod.rs`, `src/job/execution_domain/error.rs`.

**Interfaces:** Consumes current `ExecutionDomainError` and UUID naming. Produces the value types above, plus `StepFilesId(Uuid)`, `Stage::{Preflight,Filesystem,Cgroup,Launch,Rootfs,Protocol,Command,State,Destroy,Reconcile}` and `FailureCategory::{Unsupported,InvalidInput,Unavailable,IdentityMismatch,Timeout,Io,Protocol,NotReady}`.

Declare `StepStateSnapshot` and its redacted Debug here so Task 5 can compile its transport; parsing and filesystem operations are implemented only in Task 8. `StepFilesId` owns a newly generated nonnil UUID and derives validated Serde like AttemptIdentity. The public async methods in the contract block are the destination API, introduced in Task 9; Task 1 adds value types without incomplete method bodies.

- [ ] **Step 1: Add failing contract tests, with no implementation aliases**

```rust
#[test]
fn contract_paths_and_identity_are_unambiguous() {
    use super::contracts::{AttemptIdentity, DomainPath};
    assert!(AttemptIdentity::from_uuid(uuid::Uuid::nil()).is_err());
    let id = AttemptIdentity::from_uuid(uuid::Uuid::from_u128(7)).unwrap();
    assert_eq!(id.component(), "00000000000000000000000000000007");
    for invalid in ["relative", "/work/../run", "/work//x", "/work/./x", "/x\0y"] {
        assert!(DomainPath::parse(invalid).is_err(), "{invalid:?}");
    }
    assert_eq!(DomainPath::parse("/work").unwrap().join("a/b").unwrap().as_str(), "/work/a/b");
    assert!(DomainPath::parse("/work").unwrap().join("/run").is_err());
}

#[test]
fn sandbox_environment_rejects_endpoint_replacement_without_printing_secrets() {
    use std::collections::HashMap;
    let environment = super::contracts::DomainEnvironment::sandboxed();
    for key in ["DOCKER_HOST", "DOCKER_CONFIG", "HOME", "XDG_RUNTIME_DIR"] {
        let supplied = HashMap::from([(key.to_owned(), "CANARY_SECRET".to_owned())]);
        let error = environment.merge(&supplied, "GITHUB_ENV").unwrap_err();
        assert!(!format!("{error:?} {error}").contains("CANARY_SECRET"));
    }
}
```

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::contracts_test -- --nocapture`. Require a missing-type error, not zero matching tests.

- [ ] **Step 3: Implement the value types and deterministic path table**

```rust
impl AttemptIdentity {
    pub fn new() -> Self { Self(Uuid::new_v4()) }
    pub fn from_uuid(id: Uuid) -> Result<Self, ExecutionDomainError> {
        if id.is_nil() { return Err(ExecutionDomainError::InvalidAttemptIdentity); }
        Ok(Self(id))
    }
    pub fn uuid(&self) -> Uuid { self.0 }
    pub(crate) fn component(&self) -> String { self.0.simple().to_string() }
}

impl DomainEnvironment {
    pub(crate) fn sandboxed() -> Self {
        Self { values: HashMap::from([
            ("HOME".into(), "/home/chimera".into()),
            ("XDG_RUNTIME_DIR".into(), "/run/chimera".into()),
            ("DOCKER_CONFIG".into(), "/home/chimera/.docker".into()),
            ("DOCKER_HOST".into(), "unix:///run/chimera/docker.sock".into()),
        ]) }
    }
    pub fn merge(&self, supplied: &HashMap<String, String>, source: &'static str)
        -> Result<HashMap<String, String>, ExecutionDomainError> {
        for (key, owned) in &self.values {
            if supplied.get(key).is_some_and(|value| value != owned) {
                return Err(ExecutionDomainError::ReservedDomainEnvironment {
                    key: key.clone(), source,
                });
            }
        }
        let mut result = supplied.clone();
        result.extend(self.values.clone());
        Ok(result)
    }
}
```

Implement `DomainPath::parse` by checking UTF-8 input starts with exactly one slash, contains no NUL, and each non-root component is nonempty and not `.` or `..`; reject a trailing slash except `/`. `join` validates a nonempty relative string using the same components before constructing and reparsing the result. Add `InvalidDomainPath` without the rejected payload. Implement private `DomainPaths::sandboxed()` with `/work`, `/tmp`, `/home/chimera`, `/run/chimera`, `/home/chimera/.docker`, `/var/lib/chimera/docker`, `/run/chimera/docker-exec`. The engine socket is a separate `DomainPath`, not the `run` directory.

Add `ExecutionDomainError::Backend { attempt: Option<Uuid>, stage: Stage, category: FailureCategory, errno: Option<i32> }`; its display prints only those fields. Do not wrap command/protocol payloads into `anyhow` contexts. Existing filesystem errors remain intact. Implement Serde for `DomainPath` through `parse`, not an unchecked derived deserializer.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain::contracts_test -- --nocapture` and `cargo test job::execution_domain -- --nocapture`; all contract and existing domain tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/contracts.rs src/job/execution_domain/contracts_test.rs src/job/execution_domain/mod.rs src/job/execution_domain/error.rs
git commit -m "refactor: freeze sandboxed domain value contracts"
```

### Task 2: Parse explicit global and attempt resource limits

**Files:** Create `src/config/resources.rs`, `src/config/resources_test.rs`; modify `src/config.rs`, `src/config/execution.rs`, `src/config/execution_test.rs`, `src/daemon_test.rs`.

**Interfaces:** Produces `ExecutionConfig.resources: Option<ExecutionResources>`, `ExecutionResources { global: ResourceLimits, attempt: ResourceLimits }`, and `ResourceLimits::validate() -> Result<ValidatedLimits, ResourceConfigError>`. `ValidatedLimits::writes() -> Vec<(&'static str, String)>` is the only input the cgroup writer accepts. None means unavailable for Linux; trusted-host ignores absent resources.

- [ ] **Step 1: Add failing parser tests**

```rust
const LIMITS: &str = r#"
memory_high = "256 MiB"
memory_max = "512 MiB"
memory_swap_max = "0"
cpu_quota = "150%"
cpu_weight = 100
pids_max = "256"
io_weight = 100
"#;

#[test]
fn limits_have_exact_kernel_units() {
    let parsed: super::ResourceLimits = toml::from_str(LIMITS).unwrap();
    let writes = parsed.validate().unwrap().writes();
    assert!(writes.contains(&("memory.max", "536870912".into())));
    assert!(writes.contains(&("cpu.max", "150000 100000".into())));
    assert!(writes.contains(&("memory.swap.max", "0".into())));
}

#[test]
fn malformed_or_unbounded_limits_are_rejected() {
    for changed in [
        LIMITS.replace("512 MiB", "128 MiB"),
        LIMITS.replace("512 MiB", "max"),
        LIMITS.replace("150%", "0%"),
        LIMITS.replace("150%", "1.5%"),
        LIMITS.replace("256\"", "0\""),
        LIMITS.replace("cpu_weight = 100", "cpu_weight = 10001"),
        LIMITS.replace("512 MiB", "18446744073709551615 GiB"),
    ] {
        assert!(toml::from_str::<super::ResourceLimits>(&changed)
            .and_then(|value| value.validate().map_err(serde::de::Error::custom)).is_err());
    }
}
```

- [ ] **Step 2: RED**

Run `cargo test config::resources_test -- --nocapture`; require missing resource module/type errors.

- [ ] **Step 3: Implement the resource schema and checked conversions**

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub memory_high: String,
    pub memory_max: String,
    pub memory_swap_max: String,
    pub cpu_quota: String,
    pub cpu_weight: u16,
    pub pids_max: String,
    pub io_weight: u16,
    #[serde(default)] pub io_max: Vec<IoMax>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoMax {
    pub device: String,
    pub read_bytes_per_second: String,
    pub write_bytes_per_second: String,
    pub read_iops: u64,
    pub write_iops: u64,
}
```

Use checked `u64` multiplication. Bytes accept a decimal integer with optional single-space suffix `B`, `KiB`, `MiB`, `GiB`, `TiB`; bare integer means bytes. Reject signs, fractional values, exponent syntax, arbitrary suffixes, and `max`. High/max must be positive and high ≤ max; swap may be zero. CPU is a positive integer percent, period fixed at 100000 μs, quota `percent.checked_mul(1000)`; reject zero/overflow. PIDs are positive decimal only. CPU and I/O weights are 1–10000. Device IDs are exactly two decimal `u32`s separated by `:`, unique per list; all configured I/O limits are positive. Render `io.max` as `major:minor rbps=N wbps=N riops=N wiops=N`, one line/device; `io.weight` as `default N`. Do not inject resource defaults into the generated trusted config.

Add positive tests for `io_max` rendering, zero swap, serde round-trip, and absence of resources preserving trusted-host parsing. Add explicit tests for duplicate device IDs and unknown fields. Keep `sandboxed` gate rejection earlier than Linux configuration validation; incomplete resource config cannot become a route around the gate.

- [ ] **Step 4: GREEN**

Run `cargo test config:: -- --nocapture` and `cargo test sandboxed_profile_is_rejected_before_runtime_start -- --nocapture`. Require at least one activation test executed.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/config/execution.rs src/config/execution_test.rs src/config/resources.rs src/config/resources_test.rs src/daemon_test.rs
git commit -m "feat: validate explicit sandbox resource limits"
```

### Task 3: Replace Linux cleanup and journal access with bound dirfds

**Files:** Create `src/job/execution_domain/linux/mod.rs`, `src/job/execution_domain/linux/dirfd.rs`, `src/job/execution_domain/linux/dirfd_test.rs`; modify `src/job/execution_domain/mod.rs`, `src/job/execution_domain/filesystem.rs`, `src/job/execution_domain/journal.rs`, `src/job/execution_domain/journal_test.rs`.

**Interfaces:** Produces private `BoundDir::open_root(&Path)`, `child(&CStr)`, `create_child(&CStr, u32)`, `read_regular(&CStr, usize)`, `write_atomic(&CStr, &[u8])`, `remove_tree(&CStr)`, `verify_binding()`, each returning `Result<_, ExecutionDomainError>`. `BoundDir` owns an `OwnedFd`, parent binding where present, and `(dev,ino,mount_id)`. Root opening is allowed only after the existing exclusive root lock.

- [ ] **Step 1: Write adversarial tests against the actual descriptors**

```rust
#[test]
fn dirfd_replacement_never_touches_outside_canary() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("owned")).unwrap();
    std::fs::create_dir(temp.path().join("outside")).unwrap();
    std::fs::write(temp.path().join("outside/canary"), b"keep").unwrap();
    let root = super::BoundDir::open_root(temp.path()).unwrap();
    let owned = root.child(c"owned").unwrap();
    std::fs::rename(temp.path().join("owned"), temp.path().join("moved")).unwrap();
    symlink(temp.path().join("outside"), temp.path().join("owned")).unwrap();
    assert!(owned.verify_binding().is_err());
    assert!(root.remove_tree(c"owned").is_err());
    assert_eq!(std::fs::read(temp.path().join("outside/canary")).unwrap(), b"keep");
}

#[test]
fn dirfd_regular_reader_refuses_fifo_without_waiting() {
    let temp = tempfile::tempdir().unwrap();
    let root = super::BoundDir::open_root(temp.path()).unwrap();
    let name = std::ffi::CString::new(temp.path().join("state").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let began = std::time::Instant::now();
    assert!(root.read_regular(c"state", 1024).is_err());
    assert!(began.elapsed() < std::time::Duration::from_secs(1));
}
```

- [ ] **Step 2: RED on Linux**

Run `cargo test job::execution_domain::linux::dirfd_test -- --nocapture`; require unresolved `BoundDir`. On macOS this module is correctly absent: do not record a zero-test invocation as a pass; use the native host gate for this task.

- [ ] **Step 3: Implement exact syscall rules**

```rust
const RESOLVE_POLICY: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS |
    libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV;

fn child_open_flags() -> i32 {
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
}
fn regular_read_flags() -> i32 {
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
}
```

Use `openat2` with `open_how`, `fstat`/`statx`, descriptor directory enumeration, `unlinkat`, and `renameat2(RENAME_NOREPLACE)` for initial ownership. If libc lacks a constant, define that Linux UAPI constant locally with a reference to its header; never substitute an unchecked path call. No `remove_dir_all` in the Linux sandbox backend. `read_regular` verifies regular file, `nlink == 1`, size ≤ limit before reading and after EOF; reads at most `limit + 1` bytes and rejects growth beyond limit. Atomic journal replace writes an exclusive `journal.json.next` mode 0600, fsyncs file, validates old/new and parent binding, renames within that dirfd, fsyncs directory. Unknown `.next`, symlink, version, or malformed record is refused. Keep macOS trusted implementation unchanged.

Removal starts only after Task 10 proves cgroup empty. Check mount IDs and refuse foreign/nested host mounts; unlink symlinks as leaf entries only within admitted writable subtrees, never follow them. At the attempt control root accept only the deterministic directory/file names from Tasks 6 and 11, refuse sockets except explicitly owned runtime socket names, and refuse devices everywhere. Revalidate parent/name binding before each destructive operation. A detected swap poisons the root and preserves evidence.

Add tests for hard-linked state file, oversized regular file, swapped parent inode, an unexpected mount (ignored native test), journal symlink, `.next` collision, and faulted file/directory fsync. Each asserts an outside canary remains byte-identical.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain -- --nocapture` on Linux, then the existing `cargo test --test execution_domain_test -- --nocapture`. Both must pass without relaxing old canary tests.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/linux src/job/execution_domain/mod.rs src/job/execution_domain/filesystem.rs src/job/execution_domain/journal.rs src/job/execution_domain/journal_test.rs
git commit -m "feat: bind sandbox filesystem operations to directory descriptors"
```

### Task 4: Create cgroups before children and enforce all configured limits

**Files:** Create `src/job/execution_domain/linux/cgroup.rs`, `src/job/execution_domain/linux/cgroup_test.rs`; modify `src/job/execution_domain/linux/mod.rs`.

**Interfaces:** Produces private `CgroupRoot::open_delegated(&Path) -> Result<CgroupRoot, ExecutionDomainError>`, `create_attempt(AttemptIdentity, &ValidatedLimits) -> Result<AttemptCgroup, ExecutionDomainError>`, and `AttemptCgroup::{launch_membership_fd,kill,wait_empty,remove,limits_match}`. `launch_membership_fd() -> BorrowedFd<'_>` is available only inside `linux`, never on `ExecutionDomain`. `wait_empty(Duration)` is async. `kill()` writes `1` to bound `cgroup.kill`.

- [ ] **Step 1: Add failing write-plan and refusal tests**

```rust
#[test]
fn cgroup_order_sets_limits_before_admitting_processes() {
    use super::{CgroupOperation, creation_operations};
    let writes = vec![("memory.max", "536870912".to_owned()),
                      ("pids.max", "256".to_owned())];
    let operations = creation_operations(&writes);
    assert_eq!(operations.last(), Some(&CgroupOperation::OpenMembership));
    assert!(operations.iter().position(|op| matches!(op, CgroupOperation::VerifyLimits)).unwrap()
        < operations.len() - 1);
}
#[test]
fn missing_controller_is_a_preflight_error() {
    assert!(super::validate_controllers("cpu memory pids").is_err());
    assert!(super::validate_controllers("cpu memory pids io").is_ok());
}
```

Define `CgroupOperation::{CreateAttempt,WriteLimit(String,String),VerifyLimits,CreateDomain,EnableControllers,OpenMembership}` and `creation_operations(&[(&str,String)]) -> Vec<CgroupOperation>` in `cgroup.rs`. The production driver interprets this tested sequence, not a second independent order.

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::linux::cgroup_test -- --nocapture`; require missing functions.

- [ ] **Step 3: Implement delegation layout and read-back validation**

```text
chimera.service/                       global limits supplied by operator/Plan D
  supervisor/                          all supervisor threads
  attempt-<simple-uuid>/                immutable-to-domain attempt limits
    domain/                            cgroup namespace root exposed to init
      init/                            RootlessKit evacuation leaf and runtime processes
```

Verify unified cgroup2 via `fstatfs`, controllers `cpu memory pids io`, writable delegation, `cgroup.kill`, memory swap support, and configured global limit read-back. Use service-root descriptor opened before any namespace exists; no search based on user-supplied PID. At daemon startup, before other children, move self to `supervisor/cgroup.procs`; require the service root has no remaining processes before enabling subtree controllers. Test harness supplies its dedicated predelegated service root; never moves unrelated host processes.

At attempt creation: mkdir deterministic attempt; write/read back all validated limits; enable controllers; mkdir `domain`; open `domain/cgroup.procs` for launcher membership. Launcher's synchronous entry writes `0\n` before executing RootlessKit. RootlessKit uses `--evacuate-cgroup2=init`; after evacuation the attempt `domain` has no internal processes, so enable its subtree controllers for later Plan C descendants. RootlessKit parent, slirp introduced in D, bootstrap, domain-init, commands, and later dockerd remain under the outer limited attempt. Expose only the `domain` cgroup subtree inside the namespace, so inner root cannot edit ancestor limits.

`wait_empty` requires `cgroup.events populated 0` and empty `cgroup.procs` across descendants; checking only the top cgroup is insufficient. `remove` recursively removes child cgroups bottom-up using bound descriptors and refuses unexpected controller filesystem type. Missing `cgroup.kill` is preflight failure. If its runtime write fails, perform pidfd-based best-effort kill of live members but still return a destroy error unless recursive emptiness is established within the deadline.

Add injection tests for each write/readback error and `EBUSY` removal; ensure failure never returns an admitted launcher FD. Native memory/PID/CPU/I/O enforcement belongs to Task 12, not regular-file emulation claims.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain::linux::cgroup_test -- --nocapture` and `cargo test config::resources_test -- --nocapture` on Linux.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/linux/cgroup.rs src/job/execution_domain/linux/cgroup_test.rs src/job/execution_domain/linux/mod.rs
git commit -m "feat: enforce attempt cgroup ownership and resource bounds"
```

### Task 5: Add a bounded control protocol and real PID 1 launcher

**Files:** Create `src/job/execution_domain/protocol.rs`, `src/job/execution_domain/protocol_test.rs`, `src/job/execution_domain/linux/launcher.rs`, `src/job/execution_domain/linux/launcher_test.rs`, `src/job/execution_domain/linux/init.rs`, `src/job/execution_domain/linux/rootfs.rs` (mount-plan records only); modify `src/main.rs`, `src/job/execution_domain/mod.rs`, `src/job/execution_domain/linux/mod.rs`.

**Interfaces:** `protocol::{encode,decode}` take/return `Frame`; `ControlConnection::request(Request) -> Result<Response, ExecutionDomainError>`. Private `launch(&AttemptCgroup, &LaunchSpec) -> Result<KernelDomain, ExecutionDomainError>`; `KernelDomain` owns control socket, launcher child/pidfd, and launch deadline. `LaunchSpec` contains attempt identity, bound rootfs location, canonical executable/RootlessKit paths, and `NetworkLaunch::{Disconnected,Slirp}`; B constructs only `Disconnected`. Synchronous `internal_entry() -> Option<i32>` is callable by `src/main.rs` and returns an exit code before Tokio starts.

`encode(&Frame) -> Result<Vec<u8>, ExecutionDomainError>` and `decode(&[u8]) -> Result<Frame, ExecutionDomainError>` handle a complete bounded frame; stream reader first calls `decode_header(version: u16, sequence: u64, length: u32) -> Result<(), ExecutionDomainError>` before allocating. `ControlConnection` is init/manager-private. Register every `_test.rs` explicitly so focused Cargo filters execute tests.

- [ ] **Step 1: Write protocol rejection tests**

```rust
#[test]
fn protocol_rejects_oversize_and_unknown_versions_without_allocating_payload() {
    use super::{decode_header, MAX_FRAME_BYTES};
    assert!(decode_header(2, 1, 16).is_err());
    assert!(decode_header(1, 1, MAX_FRAME_BYTES + 1).is_err());
    assert!(decode_header(1, 0, 16).is_err());
}
#[test]
fn launcher_never_selects_host_network_or_outer_ports() {
    let args = super::launcher_test_arguments();
    assert!(args.contains(&"--net=none".to_owned()));
    assert!(args.contains(&"--port-driver=none".to_owned()));
    assert!(args.contains(&"--evacuate-cgroup2=init".to_owned()));
    assert!(!args.iter().any(|arg| arg.starts_with("--publish")));
}
```

`launcher_test_arguments() -> Vec<String>` builds the real argument renderer with a fixed UUID and `/test/rootlesskit-state`; it is a test-local helper in `launcher_test.rs`. Add tests of truncated JSON, duplicate/out-of-order sequence, wrong attempt ID, unknown op, and EOF. None prints payloads.

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::protocol_test -- --nocapture` and `cargo test job::execution_domain::linux::launcher_test -- --nocapture` on Linux.

- [ ] **Step 3: Define exact frames and bounded queues**

```rust
pub(super) const MAX_FRAME_BYTES: u32 = 1024 * 1024;
pub(super) const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
pub(super) struct Frame {
    pub version: u16, pub sequence: u64, pub attempt: AttemptIdentity,
    pub message: Message,
}
pub(super) enum Request {
    Bootstrap { spec: BootstrapSpec },
    Hello,
    Run { command_id: u64, spec: CommandSpec },
    CancelCommand { command_id: u64, reason: CancelReason },
    PrepareStep { id: StepFilesId, event: Vec<u8> },
    ReadStep { id: StepFilesId },
    Shutdown { reason: CancelReason },
}
pub(super) enum Response {
    Bootstrapped,
    KernelReady,
    CommandStarted { command_id: u64 },
    Output { command_id: u64, event: CommandEvent },
    CommandFinished { command_id: u64, outcome: CommandOutcome },
    StepPrepared { id: StepFilesId },
    StepSnapshot { id: StepFilesId, snapshot: StepStateSnapshot },
    ShuttingDown,
    Rejected { category: FailureCategory },
}
pub(super) enum Message { Request(Request), Response(Response) }
```

Wire header is big-endian `u16 version + u64 sequence + u32 body_length`; body is typed Serde JSON, UTF-8, `deny_unknown_fields`, maximum 1 MiB. Serialize `Duration` as checked `timeout_ms: u64`; reject zero or overflow on decode. Sequence starts at one and increments per direction. Verify identity on every body. Bounded queues are 32 frames, output chunks at most 32 KiB before JSON encoding. Cancellation uses a separate control-priority queue so full log queues cannot block kill. `StepStateSnapshot` is declared in Task 1 and parsed in Task 8; transport chunks large snapshots into ≤32 KiB pieces with total-length validation instead of increasing frame limit.

`BootstrapSpec { attempt: AttemptIdentity, rootfs: RootfsPlan, hostname: String }` is the initial message on the already-inherited connected socket. Declare `RootfsPlan { inputs: Vec<MountInput>, staging_root: PathBuf }` and `MountInput { source: PathBuf, target: DomainPath, readonly: bool, expected_device: u64, expected_inode: u64 }` in rootfs.rs in this task; Task 6 implements validation and assembly. Send canonical mount sources and expected identities over this channel, never command-line/environment secrets or filesystem bootstrap files. The helper opens and verifies those identities before mounting; it rejects additional Bootstrap messages after entering setup. Before rootfs setup no workflow has run. RootlessKit target argv contains only the bootstrap mode and expected UUID. The socket proves supervisor authority by inheritance; no unauthenticated pathname listener can submit a bootstrap plan.

At the end of Task 5 the init loop acknowledges only Bootstrapped and Shutdown and rejects Hello/Run/state requests with NotReady; it cannot launch workflow commands or send KernelReady without Task 6's proof. This is a complete, testable transport/bootstrap deliverable. Task 6 wires assembly and enables KernelReady; Task 7 enables Run; Task 8 enables state requests. No future function is called before its implementation task.

- [ ] **Step 4: Implement synchronous bootstrap and socket inheritance**

```rust
fn main() -> anyhow::Result<()> {
    if let Some(code) = chimera::job::execution_domain::internal_entry() {
        std::process::exit(code);
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?
        .block_on(chimera::cli::run(<chimera::cli::Cli as clap::Parser>::parse()))
}
```

Supervisor opens anonymous `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)` and passes one end as RootlessKit stdin. Use stdout/stderr only for bounded redacted launcher diagnostics; never multiplex protocol on them. The synchronous `--internal-domain-launch` entry validates its inherited membership FD using `fstatfs`, writes its own PID with `0\n`, closes that FD, and `execve`s the canonical RootlessKit executable. It has no setuid bit/capabilities. Its argv contains only safe paths/identity, never env, shell body, or secrets. Use `Command::pre_exec` solely for prepared raw FD duplication/closure, with no allocation/logging/locks.

RootlessKit arguments are `--state-dir=<attempt>/rootlesskit`, `--net=none`, `--port-driver=none`, `--pidns`, `--cgroupns`, `--ipcns`, `--utsns`, `--propagation=rprivate`, `--evacuate-cgroup2=init`, followed by canonical Chimera executable and `--internal-domain-bootstrap`. Pin tests to RootlessKit 2.3.5. At bootstrap, validate FD0 is an AF_UNIX connected socket, duplicate it to an owned CLOEXEC control FD, redirect FD0 to `/dev/null`, call `unshare(CLONE_NEWPID | CLONE_NEWNS)`, and `fork` before starting threads. The child becomes PID 1 and performs Task 6 rootfs setup. The bootstrap parent waits/reaps its child; RootlessKit's own reaper remains outside the inner PID namespace. Signal handlers perform only safe notification; main loop executes shutdown/reap.

No pathname control socket is ever created. In init set `PR_SET_DUMPABLE=0`, install signal handling, reject `getpid()!=1`, close all old-root directory descriptors after pivot, and open the channel only after filesystem proofs. `KernelReady` acknowledges kernel setup only. Startup timeout is 30 seconds; any EOF/error/timeout uses Task 10 teardown. Every workflow child's FD0 is `/dev/null`, FD1/2 are its output pipes, and no control descriptor survives exec.

Source rationale: [RootlessKit parent FD and namespace setup](https://github.com/rootless-containers/rootlesskit/blob/v2.3.5/pkg/parent/parent.go) and [child target spawning](https://github.com/rootless-containers/rootlesskit/blob/v2.3.5/pkg/child/child.go) show why a target cannot be assumed PID 1 and why stdin is the selected FD carrier. Native assertions, not the version string alone, qualify this transport.

- [ ] **Step 5: GREEN**

Run both focused commands from Step 2 plus `cargo test --no-run`. The native PID/FD assertion is added in Task 12; do not claim isolation based on unit argument tests.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs src/job/execution_domain/mod.rs src/job/execution_domain/protocol.rs src/job/execution_domain/protocol_test.rs src/job/execution_domain/linux
git commit -m "feat: launch private domain init with bounded control protocol"
```

### Task 6: Assemble an allowlisted rootfs and detach every old-root reference

**Files:** Create `src/job/execution_domain/linux/rootfs_test.rs`; modify `src/job/execution_domain/linux/rootfs.rs`, `src/job/execution_domain/linux/init.rs`, `src/job/execution_domain/linux/mod.rs`.

**Interfaces:** `RootfsPlan::debian(&ImmutableInputs) -> Result<RootfsPlan, ExecutionDomainError>`, `RootfsPlan::validate()`, `assemble_and_pivot(&RootfsPlan) -> Result<RootfsProof, ExecutionDomainError>`. `ImmutableInputs { tool_cache: PathBuf, actions_cache: PathBuf, extra_tools: Vec<PathBuf> }` must be immutable to the mapped service identity independently of bind-mount flags. On a writable filesystem, B6 accepts operator/root-owned inputs only, with no group/other write; service-owned inodes remain unsafe even with modes 0444/0555. Alternatively the backing superblock must be readonly (a readonly bind is insufficient). The supervisor verifies this contract and captures a metadata fingerprint before launch. `RootfsProof` has a private constructor and lives only in `linux`.

- [ ] **Step 1: Add failing mount-plan tests**

```rust
#[test]
fn rootfs_rejects_broad_exports_and_writable_tools() {
    use super::{MountInput, validate_inputs};
    for source in ["/", "/usr", "/usr/local", "/home", "/root", "/run", "/var/run"] {
        assert!(validate_inputs(&[MountInput::readonly(source, source)]).is_err());
    }
    assert!(validate_inputs(&[MountInput::readonly("/usr/bin", "/usr/bin")]).is_ok());
    assert!(validate_inputs(&[MountInput::writable("/usr/bin", "/usr/bin")]).is_err());
}
#[test]
fn minimal_etc_contains_no_host_accounts_or_resolver_copy() {
    let files = super::generated_etc("attempt-test");
    assert_eq!(files["passwd"], b"root:x:0:0:root:/home/chimera:/bin/sh\n");
    assert!(!files.contains_key("shadow"));
    assert!(!files.contains_key("resolv.conf"));
}
```

`MountInput::{readonly,writable}` construct typed source/target records; `validate_inputs` validates those records. `generated_etc(&str) -> BTreeMap<String, Vec<u8>>` returns only generated assets.

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::linux::rootfs_test -- --nocapture`.

- [ ] **Step 3: Implement exact rootfs layout and mount policy**

```text
<active>/<uuid>/journal.json             supervisor-only metadata
<active>/<uuid>/rootlesskit/             supervisor-only RootlessKit state/API
<active>/<uuid>/rootfs/                  mount staging, never exported whole
<active>/<uuid>/work/       -> /work
<active>/<uuid>/tmp/        -> /tmp
<active>/<uuid>/home/       -> /home/chimera
<active>/<uuid>/run/        -> /run/chimera
<active>/<uuid>/docker/     -> /home/chimera/.docker
<active>/<uuid>/docker-data/ -> /var/lib/chimera/docker
<active>/<uuid>/docker-exec/ -> /run/chimera/docker-exec
```

Fresh root mount contains only allowlisted readonly executable/library roots `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/lib64` when present; resolve Debian `/bin`, `/sbin`, `/lib`, `/lib64` links into canonical allowed targets and recreate only those known aliases. Never recursively export `/usr`, `/usr/local`, `/dev`, or `/sys`. Extra tools are individual verified files/directories with explicit destinations below `/opt/chimera-tools`; canonical source must not overlap active root or contain writable-by-service executable files. Bind verified immutable caches at `/opt/hostedtoolcache` and `/opt/chimera-actions` readonly, without creating or chmod-ing the host caches from inside namespace.

**B6 review correction:** "Supervisor-owned" does not establish immutability: namespace root can remount a readonly bind writable and chmod a service-owned inode, or modify its outside hardlink alias. Writable-superblock trees therefore require unmapped operator ownership, conservatively root ownership in the current supervisor implementation; subordinate/mapped ownership is refused. The service must run non-root. Operators provision/update these shared caches outside active attempts; no automatic copying or host chmod/chown is performed during launch. A streaming descriptor-relative walk checks every inode with identity/ctime rechecks, at most 128 directory levels, 10 million entries and 30 seconds per input. Exhaustion fails closed. The launch plan carries a SHA256 metadata fingerprint, rechecked by the supervisor and on the child's pinned source FD before bind. These are generous refusal ceilings, not production sizing defaults.

Copy minimal CA bundle `/etc/ssl/certs/ca-certificates.crt` and allowlisted locale/timezone inputs `/usr/lib/locale`, `/usr/share/zoneinfo`, `/usr/share/locale` readonly. Generate `passwd`, `group`, `nsswitch.conf` (`passwd: files`, `group: files`, `hosts: files dns`), `hosts` with loopback and private hostname. B's disconnected fixture has no DNS config. D supplies generated resolver data, never host resolver content. No machine-id, host users, secrets, SSH directories, or service configs.

Mount new proc after entering inner PID namespace, `nosuid,nodev,noexec`; mask `/proc/sys`, `/proc/sysrq-trigger`, `/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/proc/acpi`, `/proc/scsi` as readonly or inaccessible when present. `/dev` is fresh tmpfs with only individually opened/bound null, zero, full, random, urandom; private `devpts` with `newinstance`, `/dev/ptmx` to its ptmx, private shm, and fd/stdin/stdout/stderr links to the new proc. No physical devices. `/sys` is empty readonly staging except the attempt's inner `domain` cgroup subtree mounted at `/sys/fs/cgroup`; ancestor limits and service cgroups remain absent.

Apply recursive readonly via `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV)` to each readonly input. Reject lack of `mount_setattr` or failed submount conversion; a remount of only the top level is not enough. Writable inputs are attempt-owned bind mounts with nosuid/nodev; `/tmp` mode 1777, home/run mode 0700. Require rprivate propagation before mounts.

```rust
// These calls execute in the single-threaded child; each failed return aborts setup.
checked_mount_private_recursive()?;
mount_plan_inputs(plan)?;
bind_mount_root_to_itself()?;
create_oldroot_directory()?;
checked_chdir_to_new_root()?;
checked_pivot_root(c".", c".oldroot")?;
checked_chdir(c"/")?;
checked_umount2(c"/.oldroot", libc::MNT_DETACH)?;
checked_rmdir(c"/.oldroot")?;
close_oldroot_descriptors()?;
verify_private_mountinfo()?;
```

Define each named function in `rootfs.rs` as a private `Result<(), ExecutionDomainError>` syscall wrapper; `mount_plan_inputs` consumes `&RootfsPlan`. `verify_private_mountinfo` rejects any host root path, shared propagation, writable readonly input, rootlesskit control state exposure, or namespace mismatch. Only then construct `RootfsProof`. Recheck that cwd and any inherited FD cannot reach old root; close all non-control, non-output, non-private-root descriptors before ready.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain::linux::rootfs_test -- --nocapture`; native sentinels, `/proc/1/root`, old-root FDs, and nested readonly mounts are required Task 12 cases.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/linux/rootfs.rs src/job/execution_domain/linux/rootfs_test.rs src/job/execution_domain/linux/init.rs src/job/execution_domain/linux/mod.rs
git commit -m "feat: pivot into an allowlisted per-attempt rootfs"
```

### Task 7: Harden children and run commands through the init reaper

**Files:** Create `src/job/execution_domain/linux/hardening.rs`, `src/job/execution_domain/linux/hardening_test.rs`, `src/job/execution_domain/linux/init_test.rs`; modify `src/job/execution_domain/linux/init.rs`, `src/job/execution_domain/linux/mod.rs`, `src/job/execution_domain/protocol.rs`.

**Interfaces:** `ChildPolicy::workflow(&RootfsProof) -> Result<ChildPolicy, ExecutionDomainError>`, `ChildPolicy::apply_before_exec() -> Result<(), ExecutionDomainError>`. Private `InitRuntime::run_command(id: u64, spec: CommandSpec)` and `cancel_command(id, CancelReason)` serve protocol requests. `InitRuntime::run(self) -> Result<(), ExecutionDomainError>` owns a poll loop plus `waitpid(-1, WNOHANG)`; it does not spawn a second async runtime before fork.

- [ ] **Step 1: Add failing architecture/policy and child-status tests**

```rust
#[test]
fn hardening_rejects_wrong_arch_and_dangerous_syscalls() {
    use super::{Decision, SeccompPolicy};
    let policy = SeccompPolicy::native().unwrap();
    assert_eq!(policy.decide(0, libc::SYS_read), Decision::Kill);
    for call in [libc::SYS_ptrace, libc::SYS_process_vm_readv,
                 libc::SYS_process_vm_writev, libc::SYS_bpf,
                 libc::SYS_mount, libc::SYS_setns, libc::SYS_unshare] {
        assert_eq!(policy.decide(policy.arch(), call), Decision::Errno(libc::EPERM));
    }
    assert_eq!(policy.decide(policy.arch(), libc::SYS_read), Decision::Allow);
}
#[test]
fn init_exit_status_preserves_signal_vs_exit_code() {
    assert_eq!(super::decode_wait_status(7 << 8), CommandOutcome::Exited(7));
    assert_eq!(super::decode_wait_status(libc::SIGTERM), CommandOutcome::Signalled(libc::SIGTERM));
}
```

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::linux::hardening_test -- --nocapture` and `cargo test job::execution_domain::linux::init_test -- --nocapture`.

- [ ] **Step 3: Implement hardening in the workflow child only**

```text
resolve checked program and cwd in private root
create stdout/stderr pipes; setpgid(0,0)
dup /dev/null to stdin; dup output pipes to stdout/stderr
close every FD >= 3, including control and mount/directory descriptors
clear supplementary groups
drop ambient and all capability bounding bits; capset effective/permitted/inheritable = 0
lock securebits NOROOT and NO_SETUID_FIXUP, including their LOCKED bits
prctl(PR_SET_NO_NEW_PRIVS, 1)
apply Landlock filesystem rules
install seccomp filter
execve with only CommandSpec env merged with DomainEnvironment
```

Set securebits while the child still has CAP_SETPCAP, before the final `capset`; execute no untrusted instruction before the sequence finishes. Landlock must support ABI ≥3 (including REFER and TRUNCATE). Grant read/execute only to readonly inputs and read/write/create/remove/refer/truncate to private writable mounts; restrict `/proc` to required reads and `/dev` to the named safe devices. Reject missing ABI/syscall/error; do not log a warning and continue. Init retains only the namespace capabilities needed for subsequent child setup; its code and control socket are never workflow executables/FDs.

Seccomp uses native audit architecture for x86_64 or aarch64; reject x32 syscall numbers on x86_64. Kill mismatched architecture. Deny ptrace, process_vm operations, pidfd_getfd, bpf, perf_event_open, keyctl/add_key/request_key, kexec variants, reboot, open_by_handle_at/name_to_handle_at, mount/umount/pivot_root/chroot, setns/unshare, and new mount API syscalls. Allow ordinary clone without CLONE_NEW flags and fork; return ENOSYS for clone3 so libc can use checked clone fallback. Return EPERM for clone requesting any CLONE_NEW bit. Do not deny Unix-socket Docker access. This policy applies to workflow commands; Plan C defines its separate managed daemon policy and must not launch a daemon through this workflow path.

On each command create a distinct process group, but retain the entire attempt cgroup as the final authority. Init keeps command child PIDs only during their live lifetime, tracks exit status, reaps every orphan, and translates signal/exit into the outcome enum. Cancellation sends TERM to the command group, then KILL after 5 seconds; `setsid` descendants remain for domain-wide kill at teardown. Timeout follows the same bounded path. After direct child exit, drain output for at most 2 seconds; lingering pipe holders cannot hang the step. Closing/broken output receiver cancels the command and drains/discards until bounded completion. Output EOF does not itself mean successful command exit. Concurrent Run during an active foreground command returns Busy/Unavailable rather than interleaving step state; managed services in C are a separate command class.

- [ ] **Step 4: GREEN**

Run both focused commands from Step 2. Native tests in Task 12 must prove empty effective/permitted/inheritable/bounding/ambient capabilities, `NoNewPrivs: 1`, descriptor closure, denied ptrace, and working shell/Node/fork/exec behavior.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/linux/hardening.rs src/job/execution_domain/linux/hardening_test.rs src/job/execution_domain/linux/init.rs src/job/execution_domain/linux/init_test.rs src/job/execution_domain/linux/mod.rs src/job/execution_domain/protocol.rs
git commit -m "feat: run hardened workflow commands through domain init"
```

### Task 8: Bridge workflow state through the private control channel

**Files:** Create `src/job/execution_domain/state_bridge.rs`, `src/job/execution_domain/state_bridge_test.rs`; modify `src/job/execution_domain/contracts.rs`, `src/job/execution_domain/protocol.rs`, `src/job/execution_domain/linux/init.rs`, `src/job/workspace.rs`, `src/job/workspace_test.rs`.

**Interfaces:** Implements `StepStateSnapshot::parse() -> Result<ParsedStepState, ExecutionDomainError>`, with `ParsedStepState { env: HashMap<String,String>, path: Vec<String>, output: HashMap<String,String>, state: HashMap<String,String>, summary: String }`, and private init `prepare_step/read_step` protocol handlers. `StepFilesId::new()` and snapshot records already exist from Task 1. Public `ExecutionDomain::prepare_step(event: &[u8]) async -> Result<StepFilesId, ExecutionDomainError>` and `read_step(StepFilesId) async -> Result<StepStateSnapshot, ExecutionDomainError>` are introduced with manager wiring in Task 9. ID→private file mapping stays in init. Export `Workspace` parsers crate-private and reuse their existing heredoc and case behavior.

- [ ] **Step 1: Add failing state and reserved-env tests**

```rust
#[test]
fn state_snapshot_preserves_multiline_and_case_rules() {
    let snapshot = StepStateSnapshot {
        env: "TOKEN<<E\na\nb\nE\n".into(), path: "/work/bin\n".into(),
        output: "Name=one\nname=two\n".into(), state: "saved=yes\n".into(),
        summary: "summary\n".into(),
    };
    let parsed = snapshot.parse().unwrap();
    assert_eq!(parsed.env["TOKEN"], "a\nb");
    assert_eq!(parsed.path, vec!["/work/bin"]);
    assert_eq!(parsed.output.len(), 1);
    assert_eq!(parsed.output.values().next().unwrap(), "two");
}
#[test]
fn state_snapshot_cannot_replace_private_docker_endpoint() {
    let snapshot = StepStateSnapshot {
        env: "DOCKER_HOST=unix:///production.sock\n".into(), path: String::new(),
        output: String::new(), state: String::new(), summary: String::new(),
    };
    let parsed = snapshot.parse().unwrap();
    assert!(DomainEnvironment::sandboxed().merge(&parsed.env, "GITHUB_ENV").is_err());
}
```

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::state_bridge_test -- --nocapture`.

- [ ] **Step 3: Implement private files and bounded snapshot transport**

```text
/run/chimera/steps/<step-files-uuid>/env
/run/chimera/steps/<step-files-uuid>/path
/run/chimera/steps/<step-files-uuid>/output
/run/chimera/steps/<step-files-uuid>/state
/run/chimera/steps/<step-files-uuid>/summary
/run/chimera/steps/<step-files-uuid>/event.json
```

Create fresh private directories/files mode 0700/0600 for every host/action step. Init overwrites corresponding `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`, `GITHUB_STEP_SUMMARY`, `GITHUB_EVENT_PATH` in the child env with those private paths; reject supplied mismatches. Event input limit is 4 MiB; each state file limit is 1 MiB, aggregate snapshot maximum 5 MiB. Use Task 3 regular-file checks within the domain. Opening symlink/FIFO/device/hardlink/replaced file yields a state failure; never follows into host/peer paths. Snapshot collection after foreground completion does not claim a coherent snapshot of intentionally background-written files; it provides bounded reads of descriptor-validated files. A file exceeding limits fails the step rather than silently truncating outputs. Parsing retains existing semantics.

Send chunks tagged with request ID, step ID, field name, total bytes, and chunk index; reject mismatch, repeat, gap, invalid UTF-8, or aggregate overflow. Supervisor never `fs::read`s a sandbox command-file path. Returned env is validated through `DomainEnvironment::merge` before affecting subsequent commands. Clear-step is achieved by a new ID, so an old step cannot redirect a new step's supervisor reads. The event and snapshot bytes are not journaled/logged/debug-printed.

For trusted-host `prepare_step/read_step` delegate to current Workspace behavior through the same typed snapshot; do not force sandbox paths into trusted workflows. Action state remains keyed by current action-instance key so pre/main/post transfer stays compatible. Plan C container commands must use this same domain-owned mapping when mounting workflow command files; they must not introduce supervisor path reads again.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain::state_bridge_test -- --nocapture` and `cargo test job::workspace_test -- --nocapture`. Add transport tests for chunk gap/duplicate/overflow and native FIFO/symlink cases in Task 12.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/state_bridge.rs src/job/execution_domain/state_bridge_test.rs src/job/execution_domain/contracts.rs src/job/execution_domain/protocol.rs src/job/execution_domain/linux/init.rs src/job/workspace.rs src/job/workspace_test.rs
git commit -m "feat: bridge workflow state without supervisor path access"
```

### Task 9: Make the manager the sole owner and migrate trusted execution

**Files:** Create `src/job/execution_domain/manager.rs`, `src/job/execution_domain/manager_test.rs`, `src/job/execution_domain/trusted.rs`, `src/job/execution_domain/workspace_reader.rs`, `src/job/execution_domain/workspace_reader_test.rs`; modify `src/job/execution_domain/mod.rs`, `src/job/execution_domain/admission.rs`, `src/job/execution_domain/admission_test.rs`, `src/job/execution_domain_test.rs`, `src/job/execute.rs`, `src/job/execute_test.rs`, `src/job/expression.rs`, `src/job/expression/eval.rs`, `src/job/expression_test.rs`, `src/job/action/node.rs`, `src/job/action/node_test.rs`, `src/job/action/composite_test.rs`, `src/runner/env.rs`, `src/runner/env_test.rs`, `src/runner/instance.rs`, `src/runner/instance_test.rs`, `tests/common/mod.rs`, `tests/execution_domain_test.rs`, `tests/execution_domain_docker_test.rs`.

**Interfaces:** Implements the frozen async domain methods. Private `Backend::{Trusted(TrustedBackend),Linux(KernelDomain)}`, `DomainManager::spawn(OwnedSemaphorePermit, AttemptIdentity, Backend) -> ExecutionDomain`; manager owns all mutable lifecycle state and permit. `ExecutionDomainRoot::prepare(&Path, NonZeroUsize)` remains trusted-compatible. Private Linux root construction exists only in module/tests until E.

- [ ] **Step 1: Add failing cancellation-safe ownership tests**

```rust
#[tokio::test]
async fn provisioning_future_drop_still_runs_manager_rollback() {
    let harness = ManagerHarness::blocked_provision().await;
    let task = harness.start_provision();
    harness.first_side_effect().await;
    task.abort();
    harness.allow_cleanup();
    harness.wait_clean().await;
    assert_eq!(harness.available_permits(), 1);
    assert!(!harness.has_live_resources());
}

#[tokio::test]
async fn dropped_domain_handle_stops_admission_then_cleans() {
    let harness = ManagerHarness::ready().await;
    let domain = harness.take_domain();
    drop(domain);
    assert!(harness.root().reserve().await.is_err());
    harness.wait_clean().await;
    assert!(!harness.has_live_resources());
}

#[tokio::test]
async fn manager_panic_poisons_before_a_waiter_can_take_its_permit() {
    let harness = ManagerHarness::ready().await;
    let waiter = harness.spawn_waiting_reserve();
    harness.panic_manager();
    assert!(matches!(waiter.await.unwrap(),
        Err(ExecutionDomainError::PoisonedRoot { .. })));
    assert!(!harness.waiter_observed_healthy_permit());
}
```

Define `ManagerHarness` in `manager_test.rs`: it owns a real capacity-one root plus fake `BackendOps` counters and barriers for `side_effect`, `cleanup`, and manager panic; `start_provision` returns `JoinHandle`, `first_side_effect/wait_clean` await barriers with one-second timeout, `allow_cleanup` sends the barrier, `available_permits/has_live_resources` inspect fake state, and `root/take_domain` expose test objects. `spawn_waiting_reserve` starts a reserve call after capacity is exhausted; `panic_manager` triggers a panic inside the manager task; `waiter_observed_healthy_permit` records any successful acquisition before poison. The fake implements the exact production private backend operations `provision`, `run`, `cancel`, `destroy` through boxed `Send` futures; no alternate lifecycle is tested.

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::manager_test -- --nocapture`; require missing async ownership APIs.

- [ ] **Step 3: Move resource state into the manager and expose async requests**

```rust
enum ManagerRequest {
    Run { spec: CommandSpec, output: mpsc::Sender<CommandEvent>,
          cancelled: CancellationToken,
          reply: oneshot::Sender<Result<CommandOutcome, ExecutionDomainError>> },
    PrepareStep { event: Vec<u8>, reply: oneshot::Sender<Result<StepFilesId, ExecutionDomainError>> },
    ReadStep { id: StepFilesId, reply: oneshot::Sender<Result<StepStateSnapshot, ExecutionDomainError>> },
    Cancel { reason: CancelReason, reply: oneshot::Sender<Result<(), ExecutionDomainError>> },
    Destroy { reply: oneshot::Sender<Result<DestroyReport, ExecutionDomainError>> },
}
```

The manager starts before first filesystem side effect and owns the permit immediately through `ManagerPermitGuard { root_state, permit: Option<OwnedSemaphorePermit>, clean_exit: bool }`. Its `Drop` implementation poisons `root_state` when `clean_exit` is false, before Rust drops the contained permit; normal confirmed destruction sets `clean_exit` and takes/releases the permit only after `Destroyed`. Thus an unwind cannot wake a healthy admission waiter before poison is observable. Provision response delivery failure triggers rollback; dropping/aborting a caller never aborts the manager. Root maintains manager join handles for shutdown draining. `ExecutionDomain::Drop` synchronously poisons the root and closes its request sender; manager observes channel closure and cancels/destroys. Preserve conservative Plan A dropped-handle poisoning even when background cleanup subsequently succeeds. Explicit destroy consumes the handle, marks the request sent to avoid false drop poison, and waits for its oneshot; if caller drops that wait, manager still finishes cleanup. `destroy` never relies on async Drop.

No mutex guard crosses await; the existing `operation_gate` protects only short metadata operations. The in-task `ManagerPermitGuard` is the ordering authority for panic poisoning; a join monitor subsequently starts the same idempotent cleanup using retained ownership records. If cleanup ownership cannot be recovered, quarantine and stop runners. The join monitor is never relied on to beat permit release.

Move the trusted `build_host_command`, credential-helper validation, Linux private-tmp `pre_exec`, spawn/output/wait logic from `execute.rs` into `trusted.rs`. Preserve current host env inheritance and private `/tmp` behavior, but execute through manager `run` with typed events. `run_process` builds `CommandTarget::Trusted` directly from the current `OsStr` arguments and native working directory without a UTF-8 round trip; sandbox callers build `CommandTarget::Sandboxed`, whose strings and logical paths are validated before protocol serialization. Dispatching a target to the wrong backend is `InvalidInput`, never an implicit conversion or fallback. Resolve sandbox executables using the step PATH and mapped runtime path (never supervisor inherited PATH), forward events to the existing `OutputProcessor`/stderr sender, and map outcomes to `StepConclusion`. Join event consumption and command completion concurrently; don't await command while blocking its bounded output receiver. Mask both stdout/stderr through existing logging behavior. Add a trusted regression test with a non-UTF-8 argument proving byte-for-byte delivery, and a sandbox test proving the same payload is rejected with a safe category before protocol output.

Replace `spawn_blocking(move || permit.provision())` in runner/tests with `permit.provision(AttemptIdentity::new()).await`; replace `spawn_blocking(move || domain.destroy())` with `domain.destroy().await.map(|_| ())`. Lifecycle `mark_running/mark_cleaning` become manager async requests with the same checked transition table. Update the three teardown paths (cache-registration failure, execution completion, lifecycle failure) consistently. Keep `finish_job_after_cache_revoke_and_destroy` generic future output `Result<(), ExecutionDomainError>`, preserving existing fatal cleanup classification.

Map Workspace data to domain paths for `build_base_env`, shell scripts, Node runtime/action entrypoints, `GITHUB_ACTION_PATH`, current working directory, and returned `GITHUB_PATH`; do not forward host action/tool-cache paths into the sandbox. Plan C uses the same logical workspace paths for binds.

Replace every direct `Workspace::read_env_file`, `read_path_file`, `read_output_file`, `read_state_file`, and `clear_step_files` consumer in shell, Node, composite, Docker-action main, and reverse-order post execution with one domain state transaction. The exact order for every phase is: `prepare_step(event)` returns only opaque `StepFilesId`; put that ID in `CommandSpec.state`; run the command; the selected backend resolves the ID and injects runner-owned command-file variables; `read_step(id)` even for a nonzero exit; validate the complete bounded snapshot; then apply output/env/path/action-state/summary mutations; only after that publish the step timeline completion. Linux init maps the ID to its private `/run/chimera/steps/<id>/...` files and never returns guest paths to the consumer. `TrustedBackend` maps the same ID to current bound `Workspace` files immediately before spawn and reads them through its backend state, preserving trusted-host paths without exposing them in `StepFilesId`. A missing/foreign ID is `IdentityMismatch`. A read, identity, size, UTF-8, parse, or reserved-environment failure changes the step conclusion to failure, applies none of that snapshot, and is returned rather than suppressed by `if let Ok`. Posts use a fresh `StepFilesId` while retaining typed action state from the corresponding main action. Add execution-level tests for each shell/Node/composite/post consumer showing malformed or replaced state fails before timeline completion, a valid snapshot is applied exactly once, and no consumer can construct or inspect a command-file pathname. The lower-level Task 8 snapshot tests do not substitute for these consumer tests.

C0's direct-reference endpoint contract remains unchanged: `ExecutionDomain::docker_endpoint() -> &DockerEndpoint`, `JobExecutionContext::{docker_endpoint,docker_client}` keep their C0 signatures, and runner/action callers continue to receive a domain-selected client. A kernel backend is private test-only in B and cannot produce a public `ExecutionDomain` until C1 installs its private endpoint before handle publication; therefore B introduces no `NotReady` result or trusted-host fallback at these accessors.

The expression evaluator is synchronous. Keep it synchronous and add an opaque, revocable `DomainWorkspaceReader` capability rather than evaluating host glob paths supplied by a workflow. `ExecutionDomain::workspace_reader() -> DomainWorkspaceReader` returns a cloneable wrapper with private backend state; `DomainWorkspaceReader::hash_files(&self, patterns: &[String]) -> Result<String, ExecutionDomainError>` uses descriptor-relative enumeration under the bound work directory, applies `glob::Pattern` to relative names, sorts/deduplicates, and streams regular file bytes into the existing SHA-256 algorithm. Reject absolute patterns, `..`, special files, symlinks, and mount crossings; hash no host path assembled from workflow text. Do not expose its dirfd. A read acquires a short manager-owned read lease; destroy revokes new reads and waits for active bounded reads before unlinking. Bound total bytes per call to 1 GiB and elapsed time to 30 seconds, returning a safe error rather than a partial digest. Trusted backend delegates to existing hashing behavior. `ExprContext` gains `workspace_reader: Option<DomainWorkspaceReader>` and the `hashfiles` branch uses it when present; existing `workspace_path` stays trusted-only.

Add `workspace_reader_test.rs` tests: two files return the existing concatenated-content digest, unmatched glob returns empty string, duplicate matches hash once, outside symlink and `../` pattern fail with canary untouched, and a revoked reader refuses access. Add expression tests that actually select the supplied reader and never call the host-path fallback in sandbox context.

- [ ] **Step 4: GREEN across current consumers**

```bash
cargo test job::execution_domain -- --nocapture
cargo test job::execute_test -- --nocapture
cargo test job::expression_test -- --nocapture
cargo test job::action -- --nocapture
cargo test runner:: -- --nocapture
cargo test --test execution_domain_test -- --nocapture
cargo test --no-run
```

Require nonzero tests in each filtered target. Add parity checks for stdout workflow commands, stderr masking, timeout, cancelled step followed by post-action, Node pre/main/post state, composite env, and trusted `/tmp` projection. Tests cover behavior; do not duplicate the implementation's private queue layout.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain src/job/execution_domain_test.rs src/job/execute.rs src/job/execute_test.rs src/job/expression.rs src/job/expression/eval.rs src/job/expression_test.rs src/job/action/node.rs src/job/action/node_test.rs src/job/action/composite_test.rs src/runner/env.rs src/runner/env_test.rs src/runner/instance.rs src/runner/instance_test.rs tests/common/mod.rs tests/execution_domain_test.rs tests/execution_domain_docker_test.rs
git commit -m "refactor: route attempt commands through the domain manager"
```

### Task 10: Implement bounded cancel, rollback, and destruction proofs

**Files:** Create `src/job/execution_domain/linux/destroy.rs`, `src/job/execution_domain/linux/destroy_test.rs`; modify `src/job/execution_domain/linux/mod.rs`, `src/job/execution_domain/manager.rs`, `src/job/execution_domain/manager_test.rs`, `src/job/execution_domain/journal.rs`, `src/runner/instance_test.rs`.

**Interfaces:** Private `destroy_kernel(&mut KernelDomain, &AttemptCgroup, &BoundDir, ShutdownBounds) async -> Result<DestroyReport, ExecutionDomainError>`. `ShutdownBounds { term: Duration, kill: Duration, drain: Duration }` defaults to 5s/10s/2s; deadline uses monotonic time. `cancel` closes new-command admission and initiates TERM; `destroy` is the only proof-producing terminal operation. Repeated cancellation and internal destroy calls are idempotent.

- [ ] **Step 1: Add failing operation-order and poison tests**

```rust
#[tokio::test]
async fn destroy_kills_before_removing_files_and_releases_only_after_proof() {
    let harness = DestroyHarness::term_ignoring_descendant().await;
    let result = harness.destroy().await.unwrap();
    assert!(result.forced_kill);
    assert_eq!(harness.events(), vec!["close-commands", "term", "kill",
        "empty", "close-handles", "no-mounts", "unlink-state", "remove-cgroup", "release"]);
}
#[tokio::test]
async fn failed_empty_proof_poison_is_visible_before_capacity_release() {
    let harness = DestroyHarness::permanently_populated().await;
    assert!(harness.destroy().await.is_err());
    assert!(harness.root().reserve().await.is_err());
    assert!(!harness.events().contains(&"unlink-state"));
}
```

Define `DestroyHarness` in `destroy_test.rs` with the real teardown driver and an injected private `DestroyOps` implementation. The implementation records stage names and supplies explicit `term_ignoring_descendant` or `permanently_populated` state. Methods shown return the real result, root, and recorded event vector. `DestroyOps` has `close_commands`, `term`, `kill`, `empty`, `close_handles`, `no_mounts`, `unlink_state`, `remove_cgroup`; futures are bounded by the driver's deadline. `release` is observed on real permit return.

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::linux::destroy_test -- --nocapture`.

- [ ] **Step 3: Implement the ordered teardown state machine**

```text
persist Destroying (or retain existing Destroying)
refuse Run/PrepareStep/new service requests
after capability revocation by runner/Plan D, signal init shutdown
TERM live members using pidfds opened from exact bound cgroup membership
wait at most term deadline; continue even if protocol is broken
write cgroup.kill=1; bound wait for recursively empty cgroup.events/procs
reap RootlessKit child; close control/pidfds/namespace/mount handles
prove no attempt mount remains in supervisor mountinfo and no retained namespace handle
remove only attempt-owned runtime sockets and filesystem via BoundDir
remove child/attempt cgroups bottom-up; fsync active root
mark in-memory Destroyed; release permit; return DestroyReport
```

When graceful shutdown already establishes emptiness, skip kill and set `forced_kill=false`; the test above deliberately retains a descendant. Never infer emptiness from RootlessKit exit or init ACK. TERM failure does not skip KILL. If kill timeout expires, cgroup read fails, a mount remains, inode changes, socket owner mismatches, or deletion/fsync fails: persist Quarantined if metadata is still safely bound, poison root, preserve remaining resources, return safe-stage error. Do not weaken an error because another stage succeeded.

Provisioning keeps an in-memory stage stack plus deterministic UUID resources. On error or cancelled response, use this same teardown state machine in reverse-resource order; only resources actually created are acted upon, but cgroup ownership is always checked because a launch may have forked before an ACK. Inject failures after directory creation, journal fsync, cgroup creation, each limit, launcher exec, namespace creation, rootfs binds, pivot, oldroot unmount, policy install, and KernelReady. Each succeeds in rollback or yields quarantine+poison. Never record Ready for this partial backend.

Add runner tests proving cache capability revoke happens before `destroy`, completion waits for destroy success/failure result, a destroy error downgrades success and stops all shared-root polling, and a lifecycle error remains fatal even if later destruction succeeds. Full capability broker revocation arrives in D through this same ordering seam.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain -- --nocapture` and `cargo test runner::instance_test -- --nocapture`. Native detached descendants and SIGKILL appear in Task 12.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/linux/destroy.rs src/job/execution_domain/linux/destroy_test.rs src/job/execution_domain/linux/mod.rs src/job/execution_domain/manager.rs src/job/execution_domain/manager_test.rs src/job/execution_domain/journal.rs src/runner/instance_test.rs
git commit -m "feat: prove bounded domain destruction and rollback"
```

### Task 11: Reconcile durable ownership under the exclusive root lock

**Files:** Create `src/job/execution_domain/linux/reconcile.rs`, `src/job/execution_domain/linux/reconcile_test.rs`; modify `src/job/execution_domain/linux/mod.rs`, `src/job/execution_domain/journal.rs`, `src/job/execution_domain/journal_test.rs`, `src/job/execution_domain/mod.rs`, `src/daemon_test.rs`.

**Interfaces:** `ExecutionDomainRoot::reconcile(&self) async -> Result<(), ExecutionDomainError>` delegates to private `reconcile_locked(&RootLockProof, &BoundDir, &CgroupRoot)`. `RootLockProof` is an unforgeable private token held by root construction and never serialized. Trusted-host startup continues refusing stale state; Linux recovery is invoked by native fixtures now and by production only after E.

- [ ] **Step 1: Add failing discovery tests**

```rust
#[test]
fn reconcile_union_finds_orphan_cgroup_without_journal() {
    let id = AttemptIdentity::from_uuid(Uuid::from_u128(9)).unwrap();
    let found = super::owned_attempts(&[], &[format!("attempt-{}", id.component())]).unwrap();
    assert_eq!(found, vec![id]);
}
#[test]
fn reconcile_refuses_noncanonical_identity() {
    for name in ["../outside", "0000000000000000000000000000000A", "not-an-attempt"] {
        assert!(super::owned_attempts(&[name.to_owned()], &[]).is_err());
    }
}
```

`owned_attempts(directory_names: &[String], cgroup_names: &[String]) -> Result<Vec<AttemptIdentity>, ExecutionDomainError>` sorts/deduplicates canonical simple-UUID names, excluding only the known `supervisor` cgroup. A nil UUID is invalid.

- [ ] **Step 2: RED**

Run `cargo test job::execution_domain::linux::reconcile_test -- --nocapture`.

- [ ] **Step 3: Implement provenance, journal versioning, and recovery order**

New sandbox journal version 2 adds only `backend: "linux"`, `attempt_id`, `state`, and fixed `layout_version: 1`; no host PID is authority and no paths/commands/env are serialized. Keep version 1 loading for trusted-host diagnostics; do not reinterpret a Plan A trusted directory as safe to clean with Linux cgroups. Read journals through BoundDir. All known states except `Destroyed` may require cleanup; `Destroyed` on disk is inconsistent and quarantined because successful destroy removes the journal. Version mismatch/truncated/symlinked metadata is preserved and blocks startup.

Scan the union of canonical active-root UUID directories and deterministic `attempt-<uuid>` cgroups while holding the exclusive daemon/root lock. Do a non-destructive inventory first; unknown/symlinked entries block all admission. For a known cgroup, kill and prove emptiness using Task 10 even if its journal is missing/corrupt; preserve malformed filesystem metadata after neutralizing processes and fail startup. For a cgroup-only orphan, verified service-root binding plus exact naming provides ownership. For a missing-journal directory, permit recovery only of the exact partially-created layout with no unknown top-level entry and valid ownership/modes/mount IDs; malformed present journals are never treated as missing. A directory-only valid Linux journal can be removed only after confirming its deterministic cgroup is absent and there are no attempt mounts/retained launcher resources.

Use bound descriptor removal and remove cgroups last. Recheck both inventory roots are empty of owned attempts. A recycled saved PID is ignored; add a test where diagnostic PID points at a separate live sentinel and prove it remains alive. Do not republish GitHub completion or manipulate broker leases; #48 is outside local recovery.

Add tests for each lifecycle state, journal-free partial creation, `.next` file preserved with failure, cgroup-only orphan, directory-only record, unknown entry, symlink journal, swapped inode, failed kill, residual nested cgroup, and corrupted JSON. Every failure preserves an outside canary and keeps startup admission closed. Add concurrent lock test: second recovery cannot scan/delete until first lock releases.

- [ ] **Step 4: GREEN**

Run `cargo test job::execution_domain::linux::reconcile_test -- --nocapture`, `cargo test job::execution_domain::journal_test -- --nocapture`, and `cargo test daemon_test -- --nocapture`. Assert sandboxed gate still rejects before root preparation/cache/sessions; do not call Linux reconcile in the rejected production branch.

- [ ] **Step 5: Commit**

```bash
git add src/job/execution_domain/linux/reconcile.rs src/job/execution_domain/linux/reconcile_test.rs src/job/execution_domain/linux/mod.rs src/job/execution_domain/journal.rs src/job/execution_domain/journal_test.rs src/job/execution_domain/mod.rs src/daemon_test.rs
git commit -m "feat: reconcile deterministic Linux attempt ownership"
```

### Task 12: Qualify the kernel backend on native Debian and hand off contracts

**Files:** Create `src/job/execution_domain/linux/native_fixture.rs`, `src/job/execution_domain/linux/native_test.rs`, `docs/testing/sandboxed-linux-domain.md`; modify `src/job/execution_domain/linux/mod.rs`, `docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md` only after evidence exists.

**Interfaces:** Test-only `NativeDomainFixture::prepare() async -> Result<Self, ExecutionDomainError>`, `kernel()`, `run(&str) async -> CommandOutcome`, `snapshot()`, `destroy()`, `assert_no_resources()`. Fixture constructs `KernelDomain` in Provisioning/KernelReady, never public sandbox Ready; it invokes exactly the production private implementation. `NativeDomainFixture::prepare` fails if prerequisites are absent; it never silently returns/marks pass.

Concrete fixture signatures: `kernel(&self) -> &KernelDomain`, `snapshot(&self) -> NativeSnapshot`, `destroy(&self) async -> Result<DestroyReport, ExecutionDomainError>`, `assert_no_resources(&self) async -> Result<(), ExecutionDomainError>`. The fixture retains only test inventory after taking its inner `Option<KernelDomain>` for destruction; repeated `destroy` returns the recorded proof. `NativeSnapshot { live_processes: usize, cgroups: usize, mounts: usize, entries: usize }` is test-only. It does not become a second production owner or expose kernel handles to runner code.

- [ ] **Step 1: Add ignored native tests before claiming a backend gate**

```rust
#[tokio::test]
#[ignore = "requires dedicated native Debian systemd delegation"]
async fn native_pid_one_private_root_and_control_fd() {
    let fixture = NativeDomainFixture::prepare().await.unwrap();
    let result = fixture.run("test $(cat /proc/1/comm) = chimera-domain; \
        test ! -e /.oldroot; test ! -e /run/docker.sock; \
        test ! -e /root/.ssh; test ! -e /proc/1/fd/3").await;
    assert_eq!(result, CommandOutcome::Exited(0));
    fixture.destroy().await.unwrap();
    fixture.assert_no_resources().await.unwrap();
}

#[tokio::test]
#[ignore = "requires dedicated native Debian systemd delegation"]
async fn native_detached_term_ignoring_descendant_is_destroyed() {
    let fixture = NativeDomainFixture::prepare().await.unwrap();
    fixture.run("setsid sh -c 'trap \"\" TERM; while :; do sleep 1; done' >/dev/null 2>&1 &").await;
    let report = fixture.destroy().await.unwrap();
    assert!(report.forced_kill);
    fixture.assert_no_resources().await.unwrap();
}
```

Set init process comm to `chimera-domain` via `PR_SET_NAME`. Use `set -eu` prefix in fixture `run`; a failed early assertion cannot be hidden by a later success. `assert_no_resources` inspects the bound attempt cgroup, recorded launcher lifetime, active root, and mount inventory; it never kills unrelated processes by name. Do not rely on FD3 alone: fixture additionally probes every `/proc/1/fd` entry and attempts `pidfd_getfd`/ptrace, expecting denial, and verifies the child has only stdin/stdout/stderr before its own executable opens files.

- [ ] **Step 2: RED on the native machine**

```bash
cargo test --features acceptance-tests job::execution_domain::linux::native_test -- --ignored --test-threads=1 --nocapture
```

Before implementation the fixture is unresolved or the assertions fail. After implementation the same command must execute the explicit nonzero case count. This command does not exist as a daemon CLI activation bypass.

- [ ] **Step 3: Complete fixtures and the acceptance matrix**

`prepare` reads only `CHIMERA_NATIVE_TEST_ROOT` and `CHIMERA_NATIVE_TEST_CGROUP` as fixture resource locations, plus `CHIMERA_NATIVE_TEST_BINARY` for the built Chimera binary. Require absolute canonical paths, a fresh private directory under the dedicated fixture root, exact delegated cgroup2, non-root dedicated service UID, no container marker, systemd parent, RootlessKit 2.3.5, one subordinate range ≥65536 in both subuid/subgid, `newuidmap/newgidmap`, and required kernel capabilities. These environment names are consumed only under `#[cfg(all(test,target_os="linux",feature="acceptance-tests"))]`; they cannot affect daemon startup. Reuse one dedicated test service and one service account; do not create per-test units or users.

Add the following named native tests to the same module, each using fresh IDs and confirmed fixture destruction:

| Name | Assertion |
| --- | --- |
| `native_namespace_identity_matrix` | user/mount/PID/IPC/UTS/cgroup/net differ from supervisor; init PID1; two attempts differ; host/peer sentinels absent |
| `native_old_root_is_unreachable` | `/proc/1/root`, cwd, inherited FDs, aliases and nested binds cannot reveal host or peer files |
| `native_readonly_nested_mounts` | writes under tool/cache and nested mount fail; private writable mounts work |
| `native_state_special_files_are_refused` | FIFO/symlink/hardlink/size overflow yields bounded failure and preserves outside canary |
| `native_policy_and_environment` | caps all zero, nnp=1, control FD inaccessible, host env canary absent, ptrace/unshare denied, shell/Node/fork/exec work |
| `native_output_drain_is_bounded` | grandchild retaining stdout cannot block step beyond configured drain deadline |
| `native_memory_and_pid_limits` | memory.events and pids.events increment under contained bounded probes; neighbor command stays responsive |
| `native_cpu_and_io_limits` | read-back matches configured quotas; cpu.stat throttles and device io.stat/io.max show enforcement on fixture device |
| `native_fault_after_each_provision_stage` | every injected stage yields no resources or explicit quarantine+poison |
| `native_cancel_in_each_phase` | step, post-action, provisioning and teardown cancellation converge within deadline |
| `native_kill_and_restart_each_phase` | supervisor SIGKILL at each lifecycle barrier; fresh locked recovery removes all known resources |
| `native_reconcile_ignores_recycled_pid` | diagnostic PID sentinel survives, cgroup members do not |
| `native_two_sequential_tenant_waves` | two waves of two attempts share no filesystem/process/state; idle count zero |

Resource tests use explicit fixture values from Task 2 (512 MiB/256 PIDs/150% CPU and a dedicated bounded I/O fixture device), not production defaults. Spawn bounded allocation/process workloads; terminate through cgroup and never run an unbounded host fork bomb. Native I/O test requires a configured fixture block device, fails preflight if absent, and performs file I/O only in the bounded fixture storage; it never writes a raw device. 20/40 Docker waves, production reserve/SLO, network denial, and full S-01…S-16 qualification remain C–E gates.

For crash tests, spawn a child supervisor process with a test-only barrier FD; send SIGKILL using its pidfd after each durable/in-memory phase notification. Parent test process survives outside the child attempt cgroup and runs recovery under a fresh lock. Injection is compiled into test code only, never an environment switch in production. Fault coverage includes failure during destroy after kill but before directory deletion and after directory deletion before cgroup removal.

- [ ] **Step 4: GREEN and operator evidence**

```bash
cargo build --bin chimera
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --features acceptance-tests job::execution_domain::linux::native_test -- --ignored --test-threads=1 --nocapture
git diff --check
```

Document exact kernel, Debian, systemd, RootlessKit versions, cgroup delegation/controllers, subordinate mapping, command outputs, executed case count, durations, and post-run zero-resource inventory in `docs/testing/sandboxed-linux-domain.md`. Record environment paths without secrets. macOS regular tests are portability evidence, not native security evidence. If native machine unavailable, leave Plan B gate pending and say so; do not mark it verified or make `sandboxed` available.

- [ ] **Step 5: Check activation and Plan C–E contract handoff**

Run `cargo test sandboxed_profile_is_rejected_before_runtime_start -- --nocapture`, `rg -n 'connect_docker\(None\)|validate_execution_profile|KernelReady' src/job/execution_domain src/daemon.rs`, and `git diff --check`. Review matches: no Linux path chooses a host Docker fallback; `KernelReady` cannot transition to production `Ready`; daemon gate remains first. Old trusted Docker paths are handled by C, not silently altered here.

Plan C owns `DockerEndpoint` from C0 and receives logical paths, manager ownership, a distinct service-request extension point in the control protocol, private cgroup subtree, and typed state bridge from B. Plan D receives parsed resources, cgroup delegation/readback, disconnected/Slirp launch enum, readiness barrier, and cancellation/revocation ordering. Plan E receives native evidence and the unchanged production activation gate. Changes to these frozen signatures require editing all dependent plans before implementation proceeds.

- [ ] **Step 6: Commit evidence and accurate roadmap status**

Only after the native command passes, update the roadmap's Plan B entry to “kernel backend implemented; native filesystem/process/cgroup gate verified”, include the actual tested commit from `git rev-parse HEAD`, and retain “production profile unavailable; C–E incomplete”. Otherwise record implementation-only status with native gate pending.

```bash
git add src/job/execution_domain/linux/native_fixture.rs src/job/execution_domain/linux/native_test.rs src/job/execution_domain/linux/mod.rs docs/testing/sandboxed-linux-domain.md docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md
git commit -m "test: qualify Linux execution domain isolation and recovery"
git status --short
```

## Self-review and scope coverage

Spec §§3–6, 9–14, and kernel portions of 15–16 map to Tasks 1–12. S-02/03/04/10/11/12 and the non-Docker portions of S-09/14/15 have native tests. S-01's eBPF/storage portions, S-05 network, S-06/07/08 Docker, S-13's 20/40 waves, and S-16 native production sizing belong explicitly to C–E. No B result substitutes for those gates.

The five Review Focus rows are covered by Tasks 5/12, 3/8/12, 7/10/12, 11/12, and 2/4/6/7/12 respectively. All API types used by later tasks are defined above or in an earlier named task; private syscall wrappers and test fixtures have explicit signatures/behavior at their owning task. Every task has a failing-test command, implementation content, green command, and scoped commit. Production code is not changed by writing this plan.
