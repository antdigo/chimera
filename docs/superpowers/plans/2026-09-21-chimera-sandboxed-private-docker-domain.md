# Sandboxed Private Docker Domain (C1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each sandboxed attempt one eagerly started, private rootless Docker Engine, shared by runner operations and workflow clients, with complete storage ownership and proven teardown; leave production sandbox activation blocked.

**Architecture:** Extend the existing `ExecutionDomain` manager, Linux bootstrap protocol, and `StrictCleanupRecord`. Fork dockerd inside the already pivoted attempt before init irreversibly drops its namespace capabilities; publish a domain handle only after private Docker readiness and identity checks. Use C0's typed endpoint seam, B's pinned filesystem/cgroup authority, and a revocable inode-pinned Unix client transport, with no extra daemon lifecycle owner or API authorization proxy.

**Tech Stack:** Rust 2024, Tokio, Bollard 0.18, Linux user/mount/PID/IPC/UTS/cgroup/network namespaces, RootlessKit 2.3.5 baseline, unified cgroup v2, rootless Docker with explicitly selected classic `overlay2` storage. Add direct dependencies on existing lockfile families `hyper` 1 (`client`, `http1`) and `hyper-util` 0.1 (`tokio`) only for Bollard's custom Unix transport.

**Spec:** [Approved sandboxed execution-domain design](../specs/2026-09-20-chimera-sandboxed-execution-domain.md), especially §§3–7 and 9–16. Read the [delivery roadmap](2026-09-20-chimera-sandboxed-execution-roadmap.md), [C0 endpoint plan](2026-09-20-chimera-sandboxed-docker-endpoint-plumbing.md), [B native status](../../testing/sandboxed-linux-domain.md), and [qualification harness plan](2026-09-20-chimera-sandboxed-qualification-harness.md).

## Global Constraints

- “один физический Debian/Linux server одновременно обслуживает Chimera и развернутые проекты” — preserve the production reserve on the shared host.
- “один `chimera` service account и один systemd unit”; “нет пула из 20–40 системных пользователей, per-job systemd services или собственного privileged helper”. Reuse B's short-lived unprivileged mapped cleanup worker; do not add a helper daemon, per-job user, unit, or VM.
- “Один lifecycle owner — `ExecutionDomain`.” Manager cancellation, retained cleanup authority, poison state, and admission permit remain authoritative.
- “Eager запускается private rootless dockerd.” Every admitted attempt starts its daemon before publication, including jobs whose manifest has no Docker operations.
- “Workflow получает прямой Docker Engine endpoint без authorization proxy или урезанного BuildKit-only protocol.” Rootless limitations remain explicit; arbitrary Engine endpoints and Buildx `docker-container` are supported within that boundary.
- “Shared/rootful Docker endpoint не используется как fallback.” No default socket, external containerd, host Docker context, or host daemon discovery in the Linux branch.
- “Новый production mode не включается частично.” Keep `validate_execution_profile` rejection before domain-root preparation, cache listeners, runners, sessions, and Online polling. C1 cannot activate production `sandboxed`.
- “Production changes выполняются test-first.” Each task starts with named failing tests and ends with its focused green cycle.
- “Cleanup имеет bounded TERM phase и обязательный kill fallback.” Permit release follows proven resource destruction and descriptor revocation.
- “Journal не содержит manifest, secrets, Docker credentials или command lines.” Errors/logs expose attempt ID, stage, category, and bounded safe counters only.
- “Exact action tests используют synthetic registry credentials и не выполняют production deploy.” No production account, registry credential, or deployment is used.
- “Security acceptance выполняется на native Debian/systemd host.” Linux compile, mocks, Docker Desktop, and nested Docker are not native qualification.
- This plan is a design artifact, not an implementation or release approval. Its commit checkpoints describe a later implementation run, after plan review; no new worktree is needed.
- No server command is authorized: no SSH, remote preflight, service inspection, install, restart, or contact with `flowwow.co` without separate explicit user consent. Prepare local artifacts and CI checks first.

## Review Focus

- A workflow replaces the visible socket with a symlink, another socket, or an inode from a previous attempt: runner traffic must remain pinned to the original private authority or fail; it must never connect to a host/peer socket. Task 2 owns replacement and stale-client tests.
- Docker 29 changes the image-store default or ignores an expected driver setting: readiness must reject the wrong store, and native pull/build/volume activity must leave no state under `/var/lib/containerd`, `/run/containerd`, or any external root. Tasks 1, 3, and 8 own these tests.
- Bootstrap fails or the caller disappears between daemon fork, socket creation, capture, ping, and handle publication: the one manager must perform bounded rollback, retain cleanup authority on uncertainty, and prevent capacity reuse. Tasks 3–5 own the fault matrix.
- Nested Docker consumers see different filesystem coordinates or environment layers: host steps, Node/composite actions, job/service containers, Docker actions, action posts, and Buildx must reach the same daemon and their correct command files. Tasks 6–8 own routing, bind, and transaction tests.
- A stopped attempt leaves BuildKit/containerd descendants, subordinate-owned layers, Unix sockets, locks, or cached image references across many attempts: teardown/reconciliation and two tenant waves must clear them without deleting peer resources or growing a daemon cache. Tasks 5, 7–9 own these checks.

---

## Baseline, boundaries, and evidence

Planning baseline is `origin/main@0664288`, branch `codex/sandboxed-private-docker-plan`. C0 endpoint propagation and B12a's first native fixture implementation are merged. B native qualification has **not passed**. The roadmap's older statement that the whole B harness consists of named failures is superseded by the merged B12a code and `docs/testing/sandboxed-linux-domain.md`: one native case is implemented, fourteen still fail explicitly when selected. Neither status is a native pass.

At this baseline:

- `DomainPaths::sandboxed` already specifies logical config/data/exec/socket paths; `DockerPaths` specifies their supervisor-side coordinates.
- `DomainEnvironment::sandboxed` owns four variables, but workflow state validation still checks only `DOCKER_CONFIG` in several paths.
- `StrictBackendBuilder::build` launches a kernel domain and retains teardown authority. `manager::build_handle` deliberately rejects `Backend::Linux` because it cannot yet publish a private endpoint.
- `init::serve` calls `retain_init_capabilities()` before `KernelReady`; it retains only SETGID and SETPCAP. Dockerd cannot be launched as an ordinary hardened workflow command after that drop.
- `RuntimeSocketRootKind` accepts only `RootlessKitState/api.sock`. `run/docker.sock` is deliberately refused without an explicit capability. Generic strict directory traversal also refuses sockets.
- RootlessKit uses `NetworkLaunch::Disconnected`; its test-only Slirp variant refuses startup. C1 keeps this default and does not bypass D's egress policy to make Docker tests pass.
- Docker action cache keys already include daemon ID. C1 must also prevent ephemeral-attempt entries/locks and reuse handles from persisting in the shared builder.

C1 delivers compiled runtime machinery plus daemon-free tests and explicitly selected native fixtures. Full S-05 network policy/capability service integration belongs to D; full B native qualification and S-01…S-16 release execution belong to B/D/E. Offline C1 fixtures may load verified local images and run a synthetic registry in the attempt. Registry Internet access and production-compatible capability endpoints wait for D.

The conceptually accepted no-downtime qualification topology is a future release dependency. Its written spec in draft PR [#71](https://github.com/antdigo/chimera/pull/71) is pending user review and is **not merged implementation authority**. Do not incorporate it by assuming its helpers, options, or deployment paths exist. Its eventual approved implementation must provide separate qualification resources and leave live production service/data untouched; no downtime or server access is authorized by this plan.

## Ownership and path contract

`A` below is the exact UUID attempt directory pinned under the locked resource root. B12a's fixture currently calls its active directory `active`; production root ownership uses `job-resources`. Pass a bound active directory capability; never infer ownership from the basename or rewrite production storage layout to match a test.

| Resource | Supervisor coordinate | In-domain coordinate | Owner/removal |
|---|---|---|---|
| Docker CLI config | `A/docker/config.json` | `/home/chimera/.docker/config.json` | Attempt; initial `{}` at `0600`; credentials erased with mapped cleanup |
| Engine listener | `A/run/docker.sock` | `/run/chimera/docker.sock` | Private dockerd; retained exact socket identity and O_PATH FD |
| Engine config | generated private rootfs `/etc/docker/daemon.json` | `/etc/docker/daemon.json` | Init-generated fixed config before daemon fork; no host config import |
| Data/images/volumes/BuildKit | `A/docker-data` | `/var/lib/chimera/docker` | Bound writable root; classic overlay2, managed containerd subdirectory |
| Exec/containerd runtime | `A/docker-exec` | `/run/chimera/docker-exec` | Bound writable root; managed containerd state below it |
| Daemon PID file | `A/run/dockerd.pid` | `/run/chimera/dockerd.pid` | Diagnostic only; never restart ownership/kill authority |
| Docker temporary files | `A/tmp/docker` | `/tmp/docker` | Attempt tmp; `DOCKER_TMPDIR` fixed for daemon |
| CLI home/Buildx metadata | `A/home` and `A/docker` | `/home/chimera` and `/home/chimera/.docker` | Attempt only; no shared writable plugin/config directory |
| RootlessKit state | `A/rootlesskit` | Not exported to workflows | Existing supervisor capability; never a Docker CLI mount |

Initial directories are service-owned `0700`; Docker-created subordinate ownership is expected only inside approved writable roots. Keep ancestor directories and mount source identities pinned. Domain namespace root maps to the service account; no host root privilege is introduced. Do not use `/proc/<pid>/root`, namespace PIDs, or mount handles as public APIs.

The supervisor endpoint uses an O_PATH descriptor of the **socket inode**, opened without following symlinks under the pinned run directory. Its transport connects through supervisor-local `/proc/self/fd/<fd>` while retaining that descriptor for the connect operation. This is a local fd reference, not a traversal through another process's root, and prevents socket-name replacement from redirecting authority. All Docker clients share a revocation token and tracked connections. They cannot retain reusable fd-number strings after teardown. Workflow clients use `/run/chimera/docker.sock` directly; both addresses refer to the same Engine listener. No forwarding or filtering daemon exists.

## Docker/storage decision

Select classic `overlay2` explicitly for C1. Do not auto-negotiate to VFS, fuse-overlayfs, a shared containerd, or a new default store. A host without working rootless overlay2 fails readiness and remains unqualified; adding a second driver is a separately reviewed measured extension.

Docker 29 fresh installations default to the containerd image store; setting `data-root` alone does not move that store. C1 disables that feature and verifies the actual store, managed containerd root/state, and negative default-path probes. [Docker containerd storage documentation](https://docs.docker.com/engine/storage/containerd/)

Use a complete generated configuration, with no host file merges:

```json
{
  "hosts": ["unix:///run/chimera/docker.sock"],
  "rootless": true,
  "data-root": "/var/lib/chimera/docker",
  "exec-root": "/run/chimera/docker-exec",
  "pidfile": "/run/chimera/dockerd.pid",
  "storage-driver": "overlay2",
  "features": {"containerd-snapshotter": false},
  "live-restore": false,
  "ipv6": false,
  "shutdown-timeout": 5,
  "max-concurrent-downloads": 1,
  "max-concurrent-uploads": 1,
  "log-driver": "local"
}
```

The proposed launch is the verified immutable `/usr/bin/dockerd` directly with `--config-file=/etc/docker/daemon.json`, inside B's existing RootlessKit namespace. This is a **hypothesis to prove before implementing the bootstrap path**: [Docker's rootless documentation](https://docs.docker.com/engine/security/rootless/tips/#without-systemd) prescribes `dockerd-rootless.sh` for direct operation without systemd, and the wrapper may set required state that B's namespace does not yet supply. Task 3 starts with a Linux CI feasibility fixture that enters B's actual isolated namespace and checks whether this direct invocation reaches rootless readiness with the generated configuration. If it fails, stop C1 implementation for a reviewed startup redesign; do not launch a second RootlessKit, use host Docker, or weaken the namespace boundary as an automatic fallback. Do not run `dockerd-rootless-setuptool.sh` or create a user service. `dockerd --validate` runs inside the same domain before the real fork. The explicit host, rootless, data-root, exec-root, config, PID, and shutdown options are documented by [dockerd reference](https://docs.docker.com/reference/cli/dockerd/).

The daemon environment is constructed from an empty map: fixed PATH, LANG, HOME, XDG_RUNTIME_DIR, DOCKER_CONFIG, and DOCKER_TMPDIR only. Never inherit DOCKER_DRIVER, DOCKER_RAMDISK, DOCKER_MIGRATE_SNAPSHOTTER_THRESHOLD, external containerd, proxy, TLS, socket activation, context, or rootlesskit port-driver variables. If the installed daemon requires a RootlessKit identity marker, admit only the exact verified marker from B's closed bootstrap contract; do not copy supervisor environment wholesale or expose the RootlessKit API path.

Do not require a nested systemd instance or promise per-container `--memory`/`--cpus` flags. Rootless Docker documents systemd/cgroup-v2 requirements for those flags; attempt-wide memory/CPU/PID/I/O enforcement remains B's outer cgroup and must include every descendant. Record Docker's actual cgroup mode and verify aggregate accounting independently. [Rootless resource limitations](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources)

Readiness requires: live daemon child; `_ping`; `info` with rootless security option, nonempty Engine ID, exact DockerRootDir, `Driver=overlay2`, and no containerd snapshotter driver marker; bound socket identity; verified generated managed-containerd configuration with root under Docker data and state under Docker exec; no `/var/lib/containerd`, `/run/containerd`, external socket or old-root access. A release inventory records exact Engine/containerd/runc versions and immutable executable identities. A future binary/default change must rerun these checks and native gates; version text alone is not a proof.

## File structure and interface map

New files:

- `src/job/execution_domain/private_docker.rs`, `private_docker_test.rs`: closed spec, generated configuration, sanitized observations, readiness validator; cross-platform pure code.
- `src/job/execution_domain/linux/docker.rs`, `docker_test.rs`: daemon child bootstrap, managed-containerd/default-path inspection, in-domain readiness probes; no independent cleanup manager.
- `src/docker/private_transport.rs`, `private_transport_test.rs`: Linux socket capability, custom Bollard HTTP transport, connection revocation.
- `src/job/execution_domain/docker_mounts.rs`, `docker_mounts_test.rs`: host/domain/container coordinate translation for runner-generated binds and environment.
- `src/job/execution_domain/linux/native_docker_fixture.rs`, `native_docker_test.rs`: test-only strict manager fixture and ignored offline native cases.
- `docs/testing/sandboxed-private-docker.md`: local build instructions, separately authorized native execution prerequisites, evidence table.

Extend existing `contracts.rs`, `protocol.rs`, `manager.rs`, `mod.rs`, `linux/{mod,init,launcher,rootfs_linux,cleanup,dirfd,reconcile}.rs`, their adjacent tests, Docker endpoint/client modules, job/action execution, runner setup, Docker action build/cache modules, and CI. Keep Linux-only production transport compiled on Linux, with pure config and reserved-environment tests available on macOS. Do not silently put production daemon code behind `cfg(test)` to satisfy lint.

The following signatures are C1 contracts. Types without `pub` remain inside the execution-domain module; neither workflow nor runner callers receive kernel/cleanup handles.

```rust
// private_docker.rs; derives Serialize/Deserialize with deny_unknown_fields as needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrivateStore { ClassicOverlay2 }
#[derive(Clone)]
pub(super) struct PrivateDockerSpec { pub store: PrivateStore }
pub(super) struct DockerObservation {
    pub engine_id: String, pub rootless: bool, pub driver: String,
    pub docker_root: String, pub snapshotter: bool,
    pub containerd_root: String, pub containerd_state: String,
    pub default_paths_absent: bool,
}
pub(super) fn daemon_config(spec: &PrivateDockerSpec) -> serde_json::Value;
pub(super) fn validate_observation(value: &DockerObservation)
    -> Result<(), ExecutionDomainError>;

// linux/docker.rs; init owns Child; StrictCleanupRecord owns all outer authority.
pub(super) struct DaemonChild { child: std::process::Child }
pub(super) fn spawn(spec: &PrivateDockerSpec) -> Result<DaemonChild, ExecutionDomainError>;
impl DaemonChild {
    pub(super) fn poll(&mut self) -> Result<bool, ExecutionDomainError>; // true = live
    pub(super) fn request_term(&mut self) -> Result<(), ExecutionDomainError>;
}

// docker/private_transport.rs; intentionally no Debug containing FDs or paths.
pub(crate) struct PrivateSocketAuthority { /* owned FD, identity, revocation, connections */ }
impl PrivateSocketAuthority {
    pub(crate) fn from_pinned_socket(fd: std::os::fd::OwnedFd) -> anyhow::Result<Self>;
    pub(crate) fn client(self: &std::sync::Arc<Self>) -> anyhow::Result<bollard::Docker>;
    pub(crate) async fn revoke(&self, deadline: tokio::time::Instant) -> anyhow::Result<()>;
}
// endpoint.rs: retain trusted_host(), unix_socket(), socket_address(), connect(&endpoint).
// Add a crate-private Linux constructor; endpoint clones share the authority.
impl DockerEndpoint {
    pub(crate) fn private_socket(authority: std::sync::Arc<PrivateSocketAuthority>) -> Self;
}

// docker_mounts.rs, consumed by runner setup, Docker actions, and container exec.
pub(crate) struct DockerBind { pub source: String, pub target: String, pub readonly: bool }
impl ExecutionDomain {
    pub(crate) fn docker_bind(&self, source: &std::path::Path, target: &str, readonly: bool)
        -> Result<DockerBind, ExecutionDomainError>;
    pub(crate) fn docker_environment(&self, supplied: &std::collections::HashMap<String, String>)
        -> Result<std::collections::HashMap<String, String>, ExecutionDomainError>;
    pub(crate) fn private_docker_binds(&self) -> Result<Vec<DockerBind>, ExecutionDomainError>;
    pub(crate) fn is_sandboxed(&self) -> bool;
}
```

`PrivateSocketAuthority`'s state is implemented in Task 2, not a public extensible backend. It owns one socket FD, `AtomicBool` revoked, a cancellation token, and a mutex-protected collection of spawned connection-task handles. Socket duplication and revocation serialize through the mutex. No public constructor takes a user-supplied private socket pathname. `socket_address()` remains a diagnostic/legacy accessor; private production connections dispatch through the private variant, never stringify then reconnect. For a private variant it returns the logical `unix:///run/chimera/docker.sock`; host consumers must call typed `connect`.

## Task 1: Pin the complete private daemon specification

**Files:** create `private_docker.rs`, `private_docker_test.rs` above; modify `src/job/execution_domain/mod.rs`, `contracts.rs`, `protocol.rs`, `protocol_test.rs`, and `linux/rootfs_linux.rs`.

**Interfaces:** consumes `DomainPaths::sandboxed`; produces `PrivateDockerSpec`, `PrivateStore`, `DockerObservation`, `daemon_config`, `validate_observation`; extends `BootstrapSpec` with `docker: Option<PrivateDockerSpec>`. `None` preserves B's kernel-only fixture. Add `Stage::Docker` and `Response::DockerReady { observation: DockerObservation }`; both observation and spec wire values reject unknown fields and redact Debug output.

- [ ] **Write the failing configuration and observation tests.** Register the module before running the filter. Construct `valid_observation()` in this test file with rootless=true, driver=`overlay2`, expected data root, snapshotter=false, managed root `/var/lib/chimera/docker/containerd/daemon`, state `/run/chimera/docker-exec/containerd/daemon`, nonempty synthetic Engine ID, and default_paths_absent=true.

```rust
#[test]
fn private_docker_config_pins_classic_storage_and_all_roots() {
    let spec = PrivateDockerSpec { store: PrivateStore::ClassicOverlay2 };
    let config = daemon_config(&spec);
    assert_eq!(config["features"]["containerd-snapshotter"], false);
    assert_eq!(config["storage-driver"], "overlay2");
    assert_eq!(config["data-root"], "/var/lib/chimera/docker");
    assert_eq!(config["exec-root"], "/run/chimera/docker-exec");
    assert_eq!(config["hosts"], serde_json::json!(["unix:///run/chimera/docker.sock"]));
    assert!(config.get("containerd").is_none());
    assert_eq!(config["live-restore"], false);
}
#[test]
fn private_docker_rejects_external_containerd_and_changed_store() {
    let mut observed = valid_observation();
    assert!(validate_observation(&observed).is_ok());
    observed.containerd_root = "/var/lib/containerd".into();
    assert!(validate_observation(&observed).is_err());
    observed = valid_observation();
    observed.snapshotter = true;
    assert!(validate_observation(&observed).is_err());
    observed = valid_observation();
    observed.driver = "vfs".into();
    assert!(validate_observation(&observed).is_err());
}
```

- [ ] **Run red:** `cargo test --lib private_docker`. Require actual selected tests/compile failure, not zero matches.
- [ ] **Implement the closed configuration and validator.** Return the literal JSON above. Accept managed-containerd root/state only as normalized descendants of the respective approved root, rejecting `..`, repeated separators, symlinks discovered by the Linux inspector, empty IDs, rootful mode, snapshotter markers, and default-path presence. Generate `/etc/docker/daemon.json` in private rootfs before mounting its generated `/etc` policy. Keep client `config.json` separate. Extend protocol roundtrips and oversized/unknown-field tests for the new payload; never put credentials or arbitrary config text in it.

```rust
let valid = value.rootless && !value.engine_id.is_empty()
    && value.driver == "overlay2" && !value.snapshotter
    && value.docker_root == "/var/lib/chimera/docker"
    && value.default_paths_absent;
if !valid { return Err(private_docker_failure(FailureCategory::IdentityMismatch)); }
```

Define `private_docker_failure(category: FailureCategory) -> ExecutionDomainError` in this module using `stage: Stage::Docker`, `attempt: None`, `errno: None`; the manager attaches the attempt when reporting the failure. Test all remaining invalid fields individually, with error text excluding supplied marker strings.
- [ ] **Run green:** `cargo test --lib private_docker`; `cargo test --lib job::execution_domain::protocol`; on Linux run rootfs tests proving no host `/etc/docker`, `/var/lib/docker`, `/var/lib/containerd`, or external socket was mounted.
- [ ] **Review/commit checkpoint:** config exactly describes one store and one Unix listener; no implicit backend or writable shared input. Future commit: `feat: define private Docker bootstrap and storage contract`.

## Task 2: Make the supervisor endpoint safe against socket replacement

**Files:** create `src/docker/private_transport.rs`, `private_transport_test.rs`; modify `Cargo.toml`, `Cargo.lock`, `src/docker.rs`, `endpoint.rs`, `endpoint_test.rs`, `client.rs`, and `src/job/execution_domain/linux/{cleanup,dirfd}.rs` plus adjacent tests.

**Interfaces:** consumes B `BoundDir` and socket metadata; produces `PrivateSocketAuthority` and `DockerEndpoint::private_socket(Arc<PrivateSocketAuthority>)`. Add `RuntimeSocketRootKind::DockerRun` admitting only `docker.sock`. Add `RuntimeSocketCapability::pin_connection_fd(&self) -> Result<OwnedFd, ExecutionDomainError>`; it performs an fd-relative `openat2`/O_PATH no-follow capture and verifies inode/device/type/mount/owner against the retained socket identity.

- [ ] **Write Linux red tests with two real local Unix HTTP listeners.** Reuse C0 `EngineProbe` response framing. Extend its fixture to expose only test-owned socket paths for rename/replacement. Pin socket A, replace its original name with a symlink to B, and use the typed private client; it must return A or connection failure, with B recording no request. Repeat with a different socket inode at the same name. Add `private_endpoint_revoke_closes_clients_and_prevents_fd_reuse`, checking a cloned Bollard client errors after revoke even if another fd gets the old number.

```rust
assert!(result.is_err() || result.as_ref().is_ok_and(|reply| reply == "engine-a"));
assert!(probe_b.requests().is_empty());
authority.revoke(tokio::time::Instant::now() + Duration::from_secs(2)).await.unwrap();
assert!(client.clone().ping().await.is_err());
```

The fixture owns `probe_a`, `probe_b`, `authority`, and `client`; declare them in the test using the existing `EngineProbe::start`/`endpoint` fixture and the new private capture API. Bound the test to two seconds per request. Add an HTTP upgrade test with a real bidirectional stream so Docker exec attach cannot accidentally regress.
- [ ] **Run red on Linux:** `cargo test --lib private_transport`; `cargo test --lib private_endpoint`. On macOS record these as unrun Linux cases and run pure endpoint tests.
- [ ] **Implement inode-pinned direct transport.** Use Bollard `connect_with_custom_transport`; each request duplicates the still-live O_PATH socket fd under the authority mutex, connects `tokio::net::UnixStream` to its `/proc/self/fd/<fd>` reference, performs `hyper::client::conn::http1::handshake(TokioIo::new(stream))`, and drives `connection.with_upgrades()` in a tracked task. Preserve method, query, headers, body, streaming, cancellation, and HTTP upgrades. No endpoint allowlist, response logging, or intermediate listener. Check revocation before connecting and before returning a response. Revocation marks closed, cancels connections, awaits/aborts tracked tasks within its deadline, then drops the socket FD. Each in-flight request holds its duplicated fd until connect completes; no fd string outlives the FD.

```rust
match endpoint.kind() {
    EndpointKind::Unix(address) => Docker::connect_with_unix(address, 120, API_DEFAULT_VERSION),
    #[cfg(target_os = "linux")]
    EndpointKind::Private(authority) => authority.client(),
}
```

Introduce private `EndpointKind` and `kind(&self)` inside the Docker module. Preserve trusted endpoint equality/string tests; private equality uses `Arc::ptr_eq`, not file descriptor numbers. Do not export the enum. Hyper errors become static safe connection failures through Bollard's error type.
- [ ] **Run green:** targeted Linux tests plus `cargo test --test docker_endpoint_test`. Verify listener upgrades, refused socket, long outer root paths, revoked in-flight requests, and descriptor count returns to baseline. Linux O_PATH socket connection behavior is an unverified design assumption and a separate first Linux CI spike/test before implementing the full transport: if unsupported, the fallback is a fail-closed C1 readiness error and a reviewed replacement transport design, never a pathname connection. This local/CI spike does not authorize a server test.
- [ ] **Review/commit checkpoint:** all cloned private clients retain/revoke the exact transport authority; C0 trusted behavior is unchanged. Future commit: `feat: pin private Docker clients to owned socket inodes`.

## Task 3: Start dockerd in the pivoted namespace before dropping capabilities

**Files:** create `src/job/execution_domain/linux/docker.rs`, `docker_test.rs`; modify `linux/{mod,init,launcher,hardening,rootfs_linux}.rs`, `protocol.rs`, adjacent init/launcher/hardening tests, and the B native fixture's `BootstrapSpec` construction.

**Interfaces:** consumes Task 1 bootstrap spec; produces `DaemonChild`, `spawn`, and a `DockerReady` response. `BootstrapSpec.docker=None` still yields B's `KernelReady` without a daemon. For `Some`, `KernelReady` means only namespace readiness; the supervisor also waits for `DockerReady`. Store `Option<DaemonChild>` directly in `InitRuntime`.

- [ ] **Prove the direct-launch assumption first in Linux CI.** Add a separately selected, bounded integration fixture that uses B's actual pivoted RootlessKit namespace and the Task 1 generated config, executes `dockerd --validate`, then starts the pinned daemon with a 30-second deadline and checks `_ping`, `docker info` rootless status, and exact data/exec/socket roots. It must report an explicit failure rather than skip if its pinned Docker/RootlessKit prerequisites are unavailable; the normal CI test job may compile it without executing it. Record the exact binary versions and environment keys used. If direct launch fails, stop before the implementation step below and revise the startup design through review; no server execution or alternate daemon authority is implied.

- [ ] **Write red state-machine tests.** Use existing init protocol fixture with a test-only injected spawn function to record the order below. Test validation failure, daemon early exit, duplicate Hello/bootstrap, workflow Run before DockerReady, control EOF, readiness timeout, and shutdown during readiness. A fake spawn reports observations without starting Docker; it cannot provide native evidence.

```rust
assert_eq!(events, ["pivot", "validate-daemon-config", "fork-dockerd",
    "drop-init-capabilities", "kernel-ready", "probe-private-docker", "docker-ready"]);
assert!(!events.contains(&"workflow-run"));
```

- [ ] **Run red:** Linux `cargo test --lib job::execution_domain::linux::docker`; existing init protocol tests must execute the new ordering case.
- [ ] **Implement startup before the irreversible init capability drop.** After pivot/rootfs proof, prepare daemon config and tmp directory using private paths; validate immutable dockerd/containerd/runc executable inputs through B rootfs ownership checks. Fork `/usr/bin/dockerd` using the closed environment and fixed argument. The daemon child closes every fd except stdin/stdout/stderr, resets inherited signal handlers/mask, keeps capabilities only inside the existing user namespace, and sets no-new-privileges. It must not inherit init's control fd or supervisor namespace descriptors. It cannot use workflow `ChildPolicy`, which denies the mounts/namespaces Docker needs. Parent immediately applies existing `retain_init_capabilities`; ordinary workflow children keep the current empty capability/seccomp/Landlock policy.

```rust
let daemon = match bootstrap_docker.as_ref() {
    Some(spec) => Some(docker::spawn(spec)?),
    None => None,
};
retain_init_capabilities()?;
// Move `daemon` into InitRuntime; never hand its process handle to runner code.
```

Drain daemon diagnostics to null or a bounded redacted diagnostic counter; raw daemon output may contain job/build/auth data and cannot become runner logs. `InitRuntime` includes the daemon in nonblocking child reaping. Unexpected exit invalidates the domain and triggers the existing control failure/manager cleanup path. Do not auto-restart it. During bootstrap, ping and collect bounded observations over its fixed local socket; parse managed-containerd config under the bound exec root with no-follow file access and a 64 KiB cap. Use a single 30-second readiness deadline with cancellation/shutdown polling, not repeated full-length timeouts.
- [ ] **Run green:** Linux unit tests, protocol tests, and existing hardening tests. Add FD inheritance/capability assertions to the ignored native fixture in Task 8. No need for a second RootlessKit, nested systemd, or new daemon thread per attempt in the supervisor.
- [ ] **Review/commit checkpoint:** daemon authority derives only from the already isolated namespace; parent/workflow hardening stays intact. Future commit: `feat: eagerly bootstrap rootless Docker inside execution domains`.

## Task 4: Publish Ready only after capturing and proving private Docker

**Files:** modify `src/job/execution_domain/{manager,manager_test,mod,journal,journal_test}.rs`, `linux/mod.rs`, `linux/launcher.rs`, and `linux/native_fixture.rs`.

**Interfaces:** add `docker: Option<PrivateDockerSpec>` to `StrictBackendBuilder`; return `private_endpoint: Option<DockerEndpoint>` and existing `path_mappings` in `StrictBackendParts`. `StrictCleanupRecord` owns socket and endpoint-revocation authority before either is published. Add private `DomainManager::spawn_sandboxed(root, permit, attempt, builder) -> Result<ExecutionDomain, ExecutionDomainError>` as an async method; only acceptance fixtures call it until E. Linux build_handle receives canonical paths/state from the existing root and strict parts, not a `TrustedBackend` allocated as a second owner.

- [ ] **Write red manager tests for the readiness sequence.** Extend current manager fixtures with a strict-backend adapter returning deterministic observed stages; cover rootful/wrong-store observation, socket capture mismatch, failed supervisor ping, cancelled ready receiver, and unexpected daemon exit. A manager handle cannot escape before endpoint capture, both in-domain and supervisor pings, all observations, and durable Ready.

```rust
assert_eq!(events, ["journal-provisioning", "kernel-ready", "docker-ready",
    "capture-socket", "supervisor-ping", "journal-ready", "publish-handle"]);
assert_eq!(domain.environment().merge(&HashMap::new(), "test").unwrap()["DOCKER_HOST"],
    "unix:///run/chimera/docker.sock");
```

- [ ] **Run red:** `cargo test --lib job::execution_domain::manager_test`; `cargo test --lib job::execution_domain::journal`.
- [ ] **Implement strict publication transaction.** Receive `DockerReady`, validate Task 1 observations, capture `DockerRun/docker.sock` from the retained `run` bound directory, build Task 2 authority, ping it, and persist Ready before creating `ExecutionDomain`. Add each created capability immediately to the existing cleanup record. Capture/fork/socket/journal gaps all return through `StrictCleanupRecord::rollback`; its failure preserves `StrictPartialCleanup` and poisons the shared root. Extend created-stage ordering for Docker socket/transport without allowing reverse-order teardown to unlink a live listener.

```rust
// The actual manager operation uses the existing retained backend slot.
validate_observation(&observation)?;
record.capture_private_docker()?;
record.verify_private_docker_endpoint().await?;
record.mark_ready()?;
```

Define `capture_private_docker(&mut self) -> Result<(), ExecutionDomainError>`, async `verify_private_docker_endpoint(&self) -> Result<(), ExecutionDomainError>`, and `mark_ready(&mut self) -> Result<(), ExecutionDomainError>` on `StrictCleanupRecord`. Perform blocking kernel/socket work in the existing blocking worker; the async ping executes before handle publication with a remaining bootstrap budget. Store every resource before awaiting. Reuse `DomainManager`'s detached provisioning and dropped-ready-receiver cleanup. Keep production `DomainPermit::provision` profile rejection and daemon startup rejection intact; there is no operator flag to select this unfinished backend.
- [ ] **Run green:** focused manager/journal tests and `cargo test --lib daemon_test::sandboxed`. Assert trusted host-only provisioning creates no private daemon/run/data/exec roots. Inspect failure categories for credential/config/body redaction.
- [ ] **Review/commit checkpoint:** Ready has one definition for C1 private fixtures; kernel-only B fixtures do not get public Ready. Future commit: `feat: publish private Docker domains after eager readiness`.

## Task 5: Complete daemon-aware teardown and restart reconciliation

**Files:** modify `linux/{mod,destroy,cleanup,dirfd,reconcile}.rs`, their adjacent tests, `manager.rs`, `manager_test.rs`, and `journal.rs` tests.

**Interfaces:** consumes Task 2 authority and Task 4 stage stack; extends existing `DestroyOps` with bounded transport revocation before kernel shutdown. Promote the existing reconcile module's necessary production code out of its current module-level `cfg(test)`; its public activation remains blocked. Preserve `LinuxReconcileContext` root-lock proof and typed deterministic attempt identity.

- [ ] **Write red teardown/fault matrix tests.** Fail after each side effect: config creation, fork, listener bind, socket capture, readiness, Ready journal, publication, daemon TERM, forced kill, transport close, mapped cleanup, cgroup removal, fsync. At every point assert either empty resources plus released permit or retained authority plus poisoned root. Add mapped-UID directories, nested containerd/shim sockets, workflow-created sockets, FIFOs/symlinks, and peer sentinels.

```rust
assert!(report.destroyed || (report.poisoned && report.permit_held));
assert_eq!(peer_before, peer_after);
assert!(!events.iter().position(|e| e == "unlink-socket")
    .zip(events.iter().position(|e| e == "cgroup-empty"))
    .is_some_and(|(unlink, empty)| unlink < empty));
```

Here `report` is a test-only `FaultReport { destroyed: bool, poisoned: bool, permit_held: bool }` added to `destroy_test.rs`'s existing fake operations; `events` and peer snapshots come from the same fixture. Do not add test-report booleans to production success APIs.
- [ ] **Run red:** Linux `cargo test --lib job::execution_domain::linux::destroy`; `cargo test --lib job::execution_domain::linux::cleanup`; `cargo test --lib job::execution_domain::linux::reconcile`.
- [ ] **Implement exact owned cleanup.** After post-actions and external capability revocation, close command admission and revoke all private transports; TERM init/domain with existing bound grace, then cgroup.kill fallback. Prove recursive cgroup emptiness, reap launcher, release namespace/connection handles, and prove no mounts before unlinking sockets and removing stores. Normal stop may remove the captured socket itself; proven absence is idempotent success. Replacement of a captured top-level socket is identity mismatch and quarantine, never an excuse to unlink a different inode.

```rust
// Integrate with DestroyOps ordering, not a second teardown function.
close_admission()?;
revoke_private_transport(deadline).await?;
// Existing destroy_kernel performs TERM, kill fallback, emptiness and mount proofs.
```

Define async `revoke_private_transport(&self, deadline: tokio::time::Instant) -> Result<(), ExecutionDomainError>` on `StrictCleanupRecord` and call it from the manager before the existing blocking `destroy`. If revocation fails, still neutralize the cgroup while retaining transport/cleanup authority and poison; do not leave live descendants because an earlier cleanup phase errored.

For restart, inventory exact UUID attempt and cleanup cgroups even if journal recording was interrupted. Kill them before inspecting/removing writable trees; never kill saved PIDs. After neutralization, capture an existing expected top-level Docker socket with the same no-follow root/type/owner/mount rules. A missing socket is fine. Invalid/symlinked/unknown supervisor structure quarantines. Within pinned writable roots, extend mapped cleanup to unlink socket leaves only after neutralization and identity checks; Docker/containerd create socket names beyond `docker.sock`, so a filename-only list is insufficient. Symlink leaves may be unlinked without following them, while devices and mount crossings still fail closed. Never allow socket leaves in immutable caches or supervisor metadata. Recovery validates subordinate mappings and reuses B's mapped cleanup authority; it must clean image/layer ownership beyond the service UID.
- [ ] **Run green:** fault matrix plus manager poisoning/cancel tests. Require a journal-missing socket-created crash case to clean the owned attempt, or to quarantine if durable root identity is insufficient; report the distinction explicitly. Task 9 supplies native crash evidence, not these mocks.
- [ ] **Review/commit checkpoint:** no `remove_dir_all`, pathname PID kill, process-name kill, prune of a foreign daemon, or release-on-cleanup-error. Future commit: `feat: reconcile and destroy private Docker attempt resources`.

## Task 6: Route binds and reserved environment through the same domain

**Files:** create `docker_mounts.rs`, `docker_mounts_test.rs`; modify `execution_domain/{mod,contracts}.rs`, `src/job/{execute,execute_test}.rs`, `src/job/action/{docker,docker_test,node}.rs`, `src/docker/{resources,resources_test}.rs`, `src/runner/{instance,instance_test}.rs`.

**Interfaces:** produces the three Docker mapping methods in the interface map. `SetupParams` gains `domain: &ExecutionDomain`; existing host source fields stay host coordinates for remapping, while Engine mount sources are translated through `docker_bind`. `RunDockerParams` gains the same borrowed domain. Represent runner-generated mounts with Bollard structured `Mount` objects rather than colon-concatenated strings.

- [ ] **Write red mapping and environment tests.** Test workspace, nested command-file directories, runner tmp, immutable action/tool/Node locations, paths containing spaces/colons, unmapped peer paths, `..`, and read-only cache enforcement. A logical mount source resolves in the daemon rootfs, never the supervisor rootfs. Add job/step/action-input/image-env/GITHUB_ENV/workflow-command override cases for HOME, XDG_RUNTIME_DIR, DOCKER_HOST, DOCKER_CONFIG, DOCKER_CONTEXT, DOCKER_TLS_VERIFY, and DOCKER_CERT_PATH; errors are atomic and redact values.

```rust
assert_eq!(domain.docker_bind(&host_work.join("repo"), "/github/workspace", false)
    .unwrap().source, "/work/repo");
assert!(domain.docker_bind(Path::new("/peer/private"), "/escape", false).is_err());
let supplied = HashMap::from([("DOCKER_CONTEXT".into(), "host-authority".into())]);
assert!(domain.docker_environment(&supplied).is_err());
```

Use a test-only mapping fixture constructed from the current `DomainCommandMapping::Sandboxed` contract, without publishing a fabricated live domain. Trusted tests must preserve the existing C0 environment behavior.
- [ ] **Run red:** `cargo test --lib docker_mounts`; `cargo test --lib job::execute_test`; `cargo test --lib job::action::docker`.
- [ ] **Implement one explicit Docker coordinate conversion.** Factor the pure mapping calculation out of `DomainCommandMapping` for reuse, preserving longest matching input and normalized logical paths. Do not call `canonicalize` through workflow symlinks or use `/proc/<pid>/fd` as a Docker bind source. Translate runner-owned binds; user-provided Docker volume/bind sources remain logical private-rootfs paths. Engine rejects absent sources rather than receiving supervisor coordinates. Set immutable mounts readonly in job containers as well as action containers.

```rust
let bind = domain.docker_bind(source, target, readonly)?;
let mount = bollard::models::Mount {
    typ: Some(bollard::models::MountTypeEnum::BIND),
    source: Some(bind.source), target: Some(bind.target), read_only: Some(bind.readonly),
    ..Default::default()
};
```

For sandboxed Docker job/action containers, bind the attempt socket at `/run/chimera/docker.sock`, config at `/home/chimera/.docker`, private home at `/home/chimera`, and the needed runtime directory at `/run/chimera` with nested mounts ordered consistently. All sources are private logical paths. This gives Docker-capable steps in those containers the same direct Engine authority; service creation is performed by that Engine as well. Do not expose RootlessKit state, cgroup parent, or host `/run`. Preserve container image PATH; project-owned reserved environment wins after image/action/job merging. `private_docker_binds()` returns empty in trusted mode.

Extend `DomainEnvironment` with `validate_entry(key, value, source) -> Result<(), ExecutionDomainError>` and call it from `insert_checked`, `validate_step_environment`, and final host/container environment construction. Equal owned values are allowed; different owned values and nonempty context/TLS selectors are rejected in sandboxed mode. Check base env before insertion too. Do not turn this into a shell sandbox: workflow code can explicitly select another address, whose host/peer reachability remains the namespace/network boundary. The invariant is runner-supplied authority and protected workflow env layers.
- [ ] **Run green:** focused suites, `cargo test --test workflow_commands_test`, `cargo test --test docker_endpoint_test`. Audit every `SetupParams`, Docker action build/exec/post, login path, and service cleanup call for the retained client. Unsupported unmapped writable caches/externals fail setup; C1 must not copy or chmod immutable inputs automatically.
- [ ] **Review/commit checkpoint:** command-file state is still read/applied once per transaction and no host-only path leaks into private Engine binds. Future commit: `feat: align sandbox Docker mounts and workflow authority`.

## Task 7: Keep Docker action image reuse scoped and bounded

**Files:** modify `src/docker/{build,build_test,build_cache,build_cache_test}.rs`, `src/job/execute.rs`, `execute_test.rs`, and `src/job/action/docker.rs` tests.

**Interfaces:** retain shared `DockerActionBuilder` for trusted jobs. Add `DockerBuildScope::for_attempt(runner_identity, github_scope, attempt: uuid::Uuid) -> Self` and an optional attempt UUID to `BuiltDockerImage`; include it in reuse validation and cache keys. For sandboxed execution allocate a local `DockerActionBuilder` for the duration of `execute_job_steps` and its post-action phases, then drop it before domain destroy. This builder owns only in-memory cache metadata, not daemon lifecycle.

- [ ] **Write red tests for daemon identity collisions and many ephemeral attempts.** Same Engine ID and context but two attempt UUIDs must differ; reuse from A in B must rebuild; pre/main/post in A must reuse; dropping an attempt builder releases entries and per-key locks.

```rust
let a = DockerBuildScope::for_attempt("runner", "repo", Uuid::from_u128(1));
let b = DockerBuildScope::for_attempt("runner", "repo", Uuid::from_u128(2));
assert_ne!(BuildCacheKey::new("same-engine-id", &a, "linux/amd64", "Dockerfile", [0; 32]),
           BuildCacheKey::new("same-engine-id", &b, "linux/amd64", "Dockerfile", [0; 32]));
```

- [ ] **Run red:** `cargo test --lib docker::build_cache`; `cargo test --lib docker::build_test`.
- [ ] **Implement optional attempt scope and local builder selection.** Include attempt identity in fingerprint schema v2 and `BuiltDockerImage` reuse checks; trusted constructors use `None`. The engine ID and image-exists check remain required, since a private daemon exit cannot be hidden by cached images. Choose the local builder once outside the whole step/post lifecycle, not once per phase.

```rust
let local_builder = execution.docker_config().is_sandboxed().then(DockerActionBuilder::new);
let selected_builder = local_builder.as_ref().unwrap_or(docker_action_builder);
```

Update build request call sites to use `selected_builder` and the matching scope; preserve existing deadlines, cancelled-build retry, and Dockerfile/context pinning. No cross-attempt disk/image cache or shared daemon pool is introduced.
- [ ] **Run green:** build/cache/action suites including timeout and cancellation tests. Confirm trusted cache reuse behavior remains unchanged and 100 synthetic attempt builders leave shared cache counts unchanged.
- [ ] **Review/commit checkpoint:** memory does not grow per completed sandbox; action posts reuse only their own image and Engine. Future commit: `fix: scope sandbox action image caches to attempts`.

## Task 8: Add exact offline native Docker and Buildx acceptance fixtures

**Files:** create `linux/native_docker_fixture.rs`, `native_docker_test.rs`; modify `linux/mod.rs`, `native_fixture.rs` for shared prerequisite construction only, `tests/qualification/{docker,fixtures}.rs` when sharing pure constants, and create `docs/testing/sandboxed-private-docker.md`.

**Interfaces:** test-only `NativeDockerFixture::prepare() -> Result<Self, ExecutionDomainError>` (async), `domain(&self) -> &ExecutionDomain`, `run(&self, script: &str) -> Result<CommandOutcome, ExecutionDomainError>` (async), `destroy(&mut self) -> Result<DestroyReport, ExecutionDomainError>` (async), `assert_no_resources(&self) -> Result<(), ExecutionDomainError>` (async). It borrows the real manager-backed domain; no duplicate `StrictCleanupRecord` owner. Prerequisites add `CHIMERA_NATIVE_DOCKER_ASSETS`, an explicit immutable local asset directory, and validated resource settings separate from B12a's intentionally small shell-only limits.

- [ ] **Write failing pure preflight/catalog tests and ignored native cases.** Selected native cases must fail missing prerequisites; never `return Ok(())` or skip inside a selected case. Register these exact names:

```rust
#[tokio::test]
#[ignore = "requires separately authorized native Debian qualification"]
async fn native_private_docker_eager_api_and_complete_storage() {
    let mut f = NativeDockerFixture::prepare().await.unwrap();
    let result = f.run("set -eu\ndocker version\ndocker info\n").await;
    f.destroy().await.unwrap();
    f.assert_no_resources().await.unwrap();
    assert_eq!(result.unwrap(), CommandOutcome::Exited(0));
}
```

Also register `native_private_docker_runner_consumers`, `native_private_docker_pinned_buildx`, and `native_private_docker_no_host_peer_escape`. Expand their assertions below before treating implementation as complete; the short bootstrap test alone is insufficient.
- [ ] **Run red/pure:** `cargo test --lib --features acceptance-tests native_docker -- --nocapture`. Compile ignored cases on Linux; require missing/incomplete fixture errors in selected local pure tests. Do not execute native cases here.
- [ ] **Implement fixture against the real manager and Engine.** Reuse B's dedicated native prerequisites and exact RootlessKit check; validate immutable Chimera/Docker/containerd/runc/CLI/Buildx/Node/action inputs and local archive SHA-256 manifest before side effects. Asset manifest stores exact image digests, three exact action commits, binary versions, and archive hashes; no mutable `latest` acceptance assets. Assets are operator-prepared, never silently downloaded during native preflight. Preload registry/base/BuildKit images through the domain-selected Engine; run the synthetic authenticated registry inside that attempt. All CLI invocations execute through `ExecutionDomain::run` or explicitly typed runner clients; no supervisor `docker` using ambient environment.

The fixture uses disconnected outer networking. Set the synthetic registry on the domain loopback/published port and a domain-private Docker network reachable by its BuildKit container; the pinned workflow already takes `QUALIFICATION_NETWORK` and `QUALIFICATION_REGISTRY`. Use only synthetic credentials. Buildx plugin and pinned Node action sources are immutable allowlisted inputs; give Buildx the preloaded digest-pinned BuildKit image through fixture input without modifying the upstream action source. No host published port or Internet exemption.

Implement the full assertion matrix:

| Native case | Required observed behavior |
|---|---|
| `native_private_docker_eager_api_and_complete_storage` | Daemon already healthy before first command; pull/push/login/logout; create/start/stop/run/exec; images; named volumes; networks; own bind write/read. Capture rootless/store info, managed-containerd config, cgroup membership and no default/external storage before and after operations. |
| `native_private_docker_runner_consumers` | Real job container plus service readiness/addressing, inline Docker action, Dockerfile action pre/main/post, host shell, Node and composite steps; each reports the same Engine ID and writes an attempt marker. Command-file env/output/state survive exactly once. |
| `native_private_docker_pinned_buildx` | `docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5`, `docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee`, `docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf`; docker-container driver; build/push and pull-by-digest; exact posts remove builder/config credentials; no workflow API emulation. |
| `native_private_docker_no_host_peer_escape` | Host/peer filesystem canaries absent, own bind succeeds, host/peer bind fails, `--privileged` remains inside user namespace, `--network host` reaches only attempt listener, `-p` reachable from attempt but not host/peer; before/after positive controls prove external sentinels were live. FD probe shows no init/control/outer descriptors in daemon's workflow descendants. |

The fixture must assert storage coverage across daemon process cmdline/config/root/cwd/fds and cgroup-owned containerd/BuildKit processes, with positive controls for its own paths. Capture sanitized facts only, never full process environments or Docker info/auth response bodies. Both default containerd paths must remain absent from the generated rootfs as well as untouched on the host. Every case stores its result, destroys the fixture, checks inventory, then asserts success so ordinary assertion failures do not bypass cleanup.
- [ ] **Run green/pure and compile:** `cargo test --lib --features acceptance-tests native_docker -- --nocapture`; `cargo test --lib --features acceptance-tests --no-run`. Exact native execution remains “not run: requires consent, native host, and prerequisites” unless separately authorized. Native fixture implementation is not acceptance passed.
- [ ] **Review/commit checkpoint:** no legacy trusted-host fixture is presented as sandbox evidence; all operation and cleanup authority belongs to the attempt. Future commit: `test: add native private Docker and pinned Buildx fixtures`.

## Task 9: Exercise cancellation, crash gaps, tenant waves, and capacity

**Files:** extend `linux/native_docker_fixture.rs`, `native_docker_test.rs`, adjacent manager/cleanup/reconcile tests, `docs/testing/sandboxed-private-docker.md`; keep E0 catalog/evidence meaning unchanged.

**Interfaces:** extend fixture with test-only `FaultPoint` enum (`AfterFork`, `AfterSocketBind`, `AfterSocketCapture`, `AfterDockerReady`, `AfterReadyJournal`, `Running`, `PostActions`, `Destroying`), controlled forked fixture process, exact owned root/cgroup inventory, and serial wave runner. Failure injection only exists under `cfg(all(test, feature = "acceptance-tests"))` and never via a production environment variable.

- [ ] **Write red native-fixture unit tests for scenario selection and evidence completeness.** Nonzero case count, each failure phase, two waves, and exact 20/40 concurrency values are mandatory. Add ignored `native_private_docker_cancel_and_restart`, `native_private_docker_two_tenant_waves`, `native_private_docker_twenty_and_forty` cases. Their helper asserts teardown truth from inventories, not successful Docker CLI exit.

```rust
assert_eq!(wave_sizes, vec![20, 40]);
assert_eq!(after.live_daemons, 0);
assert_eq!(after.active_attempts, 0);
assert_eq!(after.owned_sockets, 0);
assert_eq!(after.owned_cgroups, 0);
```

Define `DockerInventory { live_daemons: usize, active_attempts: usize, owned_sockets: usize, owned_cgroups: usize }` in the fixture, filled from bound root/cgroup/pidfd observations; daemon count includes dockerd, RootlessKit, containerd, shims, and BuildKit descendants. Do not count/kill unrelated host processes by name.
- [ ] **Run red/pure:** Linux `cargo test --lib --features acceptance-tests native_docker`.
- [ ] **Implement cancellation and recovery scenarios.** Cancel during host step, action post, BuildKit build, readiness, and destroy; kill the fixture supervisor process at every fault point using its retained pidfd and then run the production `LinuxReconcileContext` with exclusive root-lock proof. Compare pre/post host/peer sentinels and prove empty owned cgroups/mounts/socket/stores. Cancellation must close active Engine HTTP upgrades too. Replacement socket/ancestor cases quarantine safely and prevent another attempt; they are not counted as a clean usable root until manual fixture recovery under explicit ownership succeeds.

Two sequential tenant waves reuse the same service account and subordinate mapping: tenant B cannot observe A's images, containers, volumes, networks, build cache, credentials, files, or processes. The 20/40 cases exercise the existing admission semaphore, measure admitted peak, and include idle-after-wave zero-resource assertions. Record wall-clock startup/ping/destroy latency, PSS from exact owned processes, CPU/cgroup memory/PID/I/O counters, storage peak, and configured production reserve/SLO sentinel observations. Do not assign production resource limits from nested VFS or aggregate RSS. The fixture must refuse missing operator resource budgets before allocating a wave.
- [ ] **Run green/pure and compile; leave native results explicit.** Full cold/warm/failure/cancel/restart waves, resource stress, and production SLO measurement remain E release execution and require the reviewed no-downtime qualification facility plus separate server consent. Record which C1 cases are implemented and which are actually executed; never mark S-09/S-13/S-16 green from scenario construction.
- [ ] **Review/commit checkpoint:** stale resources cannot disappear from inventory due to a missing journal; no host daemon/user/unit/process is modified. Future commit: `test: cover private Docker rollback and tenant waves`.

## Task 10: Compile Linux branches in CI and document the release boundary

**Files:** modify `.github/workflows/ci.yml`, `docs/job-docker-config.md`, `docs/testing/sandboxed-private-docker.md`, and `docs/superpowers/plans/2026-09-20-chimera-sandboxed-execution-roadmap.md` status prose only in the implementation run.

**Interfaces:** CI reports pure/unit/integration success and native-fixture compilation separately. Preserve existing rootless Docker smoke shards and their `--skip job::execution_domain::linux::` native exclusion. No CI job deploys qualification resources or connects to a server.

- [ ] **Add a regression assertion before documentation changes:** keep `daemon_test::sandboxed` proving rejection before root/listener/session effects. Add a test that acceptance-test compilation does not change the ordinary `profile = "sandboxed"` startup result. Run it red if any proposed private fixture wiring has opened the production gate; fix that before continuing.
- [ ] **Add explicit Linux CI compilation in the existing unit job:** compile all acceptance targets; run nonignored native fixture preflight tests without `--ignored`.

```yaml
- name: Compile Linux acceptance targets without native execution
  run: cargo test --all-targets --features acceptance-tests --no-run
- name: Run private Docker contract and fixture preflight tests
  run: cargo test --lib --features acceptance-tests native_docker -- --nocapture
```

Keep build.rs's static FD-probe prerequisites and native Linux compiler handling. Do not use macOS cargo success as evidence that Linux cfg branches compile.
- [ ] **Document exact behavior and limitations.** Explain shared-kernel risk, eager cost, direct API/rootless semantics, complete private classic store, no persistent daemon pool, protected env, container socket availability, mapped binds, Docker resource-flag limitations, cleanup/quarantine, and native prerequisites. Mark C1 “implementation/tests compiled; native acceptance pending” until actual evidence exists. Update B's stale roadmap wording to B12a implemented/native not qualified without implying C1 passed B.
- [ ] **Run final local and CI verification once after implementation:**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --all-targets --features acceptance-tests --no-run
git diff --check
rg -n 'connect\(None|connect_with_(local_defaults|unix_defaults|socket_defaults)' src tests
rg -n 'DockerEndpoint::trusted_host|connect_with_unix|client::connect|docker_client' src
rg -n 'validate_execution_profile|SandboxedUnavailable' src/daemon.rs src/config src/job/execution_domain
```

Inspect search matches, not just exit status. Trusted resolution remains only in trusted provisioning/explicit legacy fixtures. Private connections only use the retained transport. Every native case remains ignored in the default run; all-target test success means those cases compiled, not ran. If local platform cannot run Linux-specific tests, retain CI's Linux compile/unit result and list local omissions accurately.
- [ ] **Review/commit checkpoint:** request whole-branch security/lifecycle/compatibility review in the selected implementation workflow. Future commit: `docs: document private Docker implementation and pending native gates`. Do not merge, deploy, or remove startup rejection solely because C1 local/CI tests pass.

## Acceptance and release handoff

The implementation handoff records commit/tree, exact commands and selected test counts, Linux CI result, changed files/interfaces, every native case's `not run`/pass/fail status, residual quarantined resources if any, and all remaining release prerequisites. A pure/mocked result must carry that label.

| Gate | C1 contribution | Required evidence before production activation |
|---|---|---|
| B / S-03, S-04, S-09, S-12 | Reuses kernel/cgroup/rootfs and extends adversarial cleanup fixtures | Full B native qualification, not only merged B12a |
| S-02, S-10, S-11 | Docker fault points, cancellation, transport revocation, restart reconciliation | Native faults at all phases with exact zero-resource or quarantine proof |
| S-06, S-07, S-08 | Real Engine APIs, all runner consumers, exact Buildx/action pins, boundary canaries | Native Debian runs against owned private Engines |
| D / S-01, S-05 | Keeps disconnected fixture mode and rejects unproved storage/network preconditions | eBPF denial, capacity-bounded storage, scoped capability services, negative host/LAN probes |
| S-13, S-14, S-15, S-16 | 20/40 and two-wave fixture implementation, PSS/storage accounting fields | Authorized native cold/warm/failure/cancel/restart waves and production reserve/SLO measurements |
| E activation | Preserves unavailable gate throughout C1 | Reviewed no-downtime qualification facility, complete S-01…S-16 evidence, atomic activation change |

Native execution is deferred honestly. Build the test executable outside its dedicated delegated unit; later, after separate consent and operator provisioning, the qualification facility runs the already-built binary directly with a named ignored test filter, because a parent Cargo process in the delegated cgroup violates B's preflight. Example **arguments only**, not a server command to execute now:

```text
job::execution_domain::linux::native_docker_test::native_private_docker_pinned_buildx
--exact --ignored --test-threads=1 --nocapture
```

No release claim follows from C1 completion alone. Remaining measured decisions are the native Docker/containerd/runc binary inventory, rootless overlay2 compatibility on the bounded filesystem, resource budgets/PSS at 20 and 40 attempts, and the reviewed qualification facility. Each is a fail-closed qualification prerequisite, not permission to choose a shared daemon or weaken isolation.

## Plan self-review record

- Spec §§3–5: Tasks 3–4 preserve one owner, eager readiness, and reverse rollback; Task 5 retains permit/poison behavior.
- Spec §§6–7: Tasks 1–2 and 6 constrain complete stores, socket identity, mapping, direct Engine authority and env; Tasks 7–8 cover action cache and exact compatibility.
- Spec §§9–12: Tasks 5 and 9 cover cgroup descendants, sockets, mapped ownership, durable crash gaps and two tenant waves; D's quota and E's native sizing remain explicit prerequisites.
- Spec §§14–16: Task 10 preserves production rejection and separates compiled fixtures from native acceptance; the table above assigns every remaining release gate.
- Review Focus entries each have owning negative tests; no unknown daemon/storage fallback or server command is authorized.
