# Sandboxed Docker Endpoint Plumbing (C0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make runner Docker authority explicit and attempt-owned, preserve current `trusted-host` behavior, and prepare deterministic Docker storage coordinates and daemon-free acceptance fixtures independently of the Linux backend.

**Architecture:** A typed `DockerEndpoint` records the existing trusted-host Unix endpoint selection once at domain provisioning; every runner-side Docker connection consumes that value. `ExecutionDomain` remains the lifecycle owner and exposes a pure Docker path description without creating Docker runtime directories or starting a daemon. A small Unix HTTP probe verifies endpoint routing without Docker; the existing rootless/Buildx suite remains a trusted-host compatibility suite.

**Tech Stack:** Rust 2024, existing Bollard 0.18, Tokio Unix sockets, UUID, tempfile, existing Cargo unit/integration harness; no new dependency.

**Spec:** [Sandboxed execution domain](../specs/2026-09-20-chimera-sandboxed-execution-domain.md), especially §§2, 3, 7, 10, 14–15. Read [delivery roadmap](2026-09-20-chimera-sandboxed-execution-roadmap.md) and [implemented foundation plan](2026-09-20-chimera-sandboxed-foundation.md) first. This document refines only C0 from roadmap Plan C; C1 is a separate plan after B.

## Global Constraints

- “Профиль остаётся default для обратной совместимости существующих установок.” — `trusted-host` stays the default.
- “Local defaults допустимы только в `trusted-host`” is implemented as a named trusted-host resolver; connection code never selects defaults.
- “Один lifecycle owner — `ExecutionDomain`.” No second lifecycle manager or daemon owner is introduced.
- “Production changes выполняются test-first.” Every implementation task below has a red/green test cycle.
- “Новый production mode не включается частично.” Preserve `validate_execution_profile` and its existing rejection before all daemon-owned side effects.
- “Ошибки содержат attempt ID, stage и безопасную категорию. Environment, command payloads, registry auth, Docker config и response bodies не логируются.” New validation errors use static categories and do not echo rejected values.
- “Exact action tests используют synthetic registry credentials и не выполняют production deploy.” Existing fixture credentials and exact pinned SHAs remain intact.
- This planning change writes this document only; it does not implement production code or make a git commit. Commit steps below apply only to a separately authorized implementation run.
- C0 does not start dockerd, RootlessKit, containerd, or BuildKit; does not provision/destroy runtime sockets; does not change mounts, namespaces, cgroups, network policy, reconciliation, Docker cleanup guarantees, or shell environment policy.

## Review Focus

- Missing, empty, non-Unix, or non-UTF-8 `DOCKER_HOST` must preserve the actual legacy Unix default selection, not accidentally enable TCP/TLS/context support; Task 1 pins the selection table and Task 2 snapshots it.
- A selected endpoint that disappears or refuses connections must fail at that endpoint, even when another reachable socket exists; Task 1 adds the missing-socket check and Task 3 adds the two-socket/refused-connection checks.
- Docker actions with no job/service resources, actions with resources, and Dockerfile builds must all use the domain-selected client; Task 4 tests the context's owned/borrowed selection and migrates both action entry points.
- UUID-derived config/run/data/exec/socket paths must be stable, disjoint between attempts, and computation must have no filesystem side effects; Task 2 tests exact paths, absent runtime directories, and unchanged destruction.
- An explicitly requested native acceptance run must fail when prerequisites are missing; default tests must neither start a daemon nor pretend native isolation was verified; Task 3 separates and tests the explicit fixture contract.

---

## Scope and evidence at the baseline

Planning baseline: `origin/main@39585f1`; target branch: `codex/sandboxed-contracts`. Plan A is implemented. Read current code rather than copying older illustrative signatures from Plan A.

There are exactly three production `connect(None)` sites at this baseline:

| Consumer | Current site | C0 replacement |
|---|---|---|
| Runner job/service setup | `src/runner/instance.rs`, `run_job_body` | `connect(domain.docker_endpoint())` |
| Inline Docker action | `src/job/action/docker.rs`, `run_docker_image_action` | `execution.docker_client()?` |
| Metadata Docker action and Dockerfile build | `src/job/action/docker.rs`, `run_docker_metadata_action` | `execution.docker_client()?` |

`src/docker/resources.rs` already retains one `Docker` for setup, exec, and cleanup. `DockerBuildRequest` already borrows a client. Do not redesign these lifecycles or the global Docker action build cache in C0; future cross-daemon cache isolation is a C1 concern.

Bollard 0.18 `connect_with_local_defaults()` on Unix calls `connect_with_unix_defaults()`: a UTF-8 `DOCKER_HOST` beginning with `unix://` is used verbatim; every other value chooses `unix:///var/run/docker.sock`. It does not honor Docker contexts, TCP/SSH, or TLS variables. `connect_with_unix` checks socket-path existence synchronously but performs API traffic later. Preserve that split: endpoint resolution and domain provisioning cannot require a live socket, and the first Docker operation retains its current failure timing. Inspect the lockfile-resolved Bollard implementation again if the dependency changes during execution.

Host shell/Node/Buildx commands retain existing environment behavior, including `DOCKER_HOST`, `DOCKER_CONTEXT`, `HOME`, `XDG_RUNTIME_DIR`, `PATH`, and the already reserved `DOCKER_CONFIG`. C0 does not make `DOCKER_HOST` a reserved workflow variable or override shell Docker contexts. Thus C0 establishes explicit runner-side authority; it does not claim runner/shell endpoint equality for arbitrary trusted-host workflow overrides.

## File structure and contracts

- Create `src/docker/endpoint.rs`: endpoint value, explicit Unix validation, trusted-host legacy resolver, endpoint tests.
- Modify `src/docker.rs`: export `endpoint`.
- Modify `src/docker/client.rs`: typed-only `connect`, transport routing tests.
- Create `src/job/execution_domain/docker_paths.rs`: pure deterministic supervisor-side path value; unit tests in the same file.
- Modify `src/job/execution_domain/mod.rs`: retain endpoint and path value, delegate existing Docker config getters.
- Modify `src/job/execution_domain_test.rs`: provisioning/destruction regression tests.
- Modify `src/job/execute.rs` and `src/job/execute_test.rs`: expose typed endpoint and one client selection method.
- Modify `src/job/action/docker.rs`, `src/runner/instance.rs`: remove implicit connections.
- Modify existing Docker-dependent tests in `src/docker/{build,exec,resources}_test.rs`, `src/job/action/docker_test.rs`, `tests/common/mod.rs`, and `tests/dockerfile_actions_test.rs` for the typed signature.
- Create `tests/common/docker_endpoint.rs`: bounded test-only Unix HTTP probe and explicit acceptance endpoint fixture.
- Create `tests/docker_endpoint_test.rs`: daemon-free routing and harness tests.
- Modify `tests/execution_domain_docker_test.rs`: connect the existing rootless preflight's parsed endpoint to the typed value; retain the existing ignored compatibility tests and pinned action SHAs.
- Modify `docs/job-docker-config.md`: document exact trusted-host selection and C0/C1 boundary.

Public signatures introduced by C0:

```rust
// src/docker/endpoint.rs
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerEndpoint { socket_address: String }
impl DockerEndpoint {
    pub fn trusted_host() -> Self;
    pub fn unix_socket(path: &std::path::Path) -> anyhow::Result<Self>;
    pub fn socket_address(&self) -> &str;
}
// src/docker/client.rs
pub fn connect(endpoint: &DockerEndpoint) -> anyhow::Result<bollard::Docker>;
// src/job/execution_domain/mod.rs
pub fn docker_endpoint(&self) -> &DockerEndpoint; // on ExecutionDomain
pub fn docker_paths(&self) -> &DockerPaths;       // on ExecutionDomain
// src/job/execute.rs, on JobExecutionContext<'a>
pub fn docker_endpoint(&self) -> &'a DockerEndpoint;
pub fn docker_client(&self) -> anyhow::Result<bollard::Docker>;
```

`DockerPaths` exposes `config_dir()`, `run_dir()`, `data_root()`, `exec_root()`, and `socket_path()`, each returning `&Path`. Construction is `pub(super) fn for_attempt(attempt_dir: &Path) -> Self`; no public constructor accepts user strings or an arbitrary UUID/path pair.

## Task 1: Pin legacy resolution and introduce typed-only connections

**Files:** create `src/docker/endpoint.rs`; modify `src/docker.rs`, `src/docker/client.rs`; migrate all `connect` callers listed above, initially using `&DockerEndpoint::trusted_host()` until Task 4 threads the domain value.

**Interfaces:** consumes Bollard's current Unix semantics; produces `DockerEndpoint` and `connect(&DockerEndpoint)`. The temporary production resolver calls introduced by this task must be removed in Task 4.

- [ ] **Step 1: Write pure endpoint characterization tests.**

Put these in the new endpoint module. Define the private helper `trusted_host_from_docker_host(Option<&str>) -> DockerEndpoint` in Step 3, not in this red step.

```rust
#[test]
fn trusted_host_resolution_preserves_legacy_selection() {
    for value in [None, Some(""), Some("tcp://127.0.0.1:2375"),
                  Some("ssh://host"), Some("/tmp/docker.sock")] {
        assert_eq!(trusted_host_from_docker_host(value).socket_address(),
                   "unix:///var/run/docker.sock");
    }
    for value in ["unix:///tmp/custom.sock", "unix://relative.sock", "unix://"] {
        assert_eq!(trusted_host_from_docker_host(Some(value)).socket_address(), value);
    }
}

#[test]
fn explicit_unix_endpoint_is_validated_without_touching_disk() {
    let path = std::path::Path::new("/not-created-by-chimera/run/docker.sock");
    let endpoint = DockerEndpoint::unix_socket(path).unwrap();
    assert_eq!(endpoint.socket_address(), "unix:///not-created-by-chimera/run/docker.sock");
    for invalid in ["", "relative.sock", "/run/../docker.sock", "/run/./docker.sock",
                    "/run//docker.sock", "/run/docker.sock/", "/", "/run/a\0b"] {
        assert!(DockerEndpoint::unix_socket(std::path::Path::new(invalid)).is_err());
    }
}

#[test]
fn explicit_unix_endpoint_rejects_non_utf8_without_echoing_input() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"/run/\xff.sock".to_vec()));
    let error = DockerEndpoint::unix_socket(&path).unwrap_err();
    assert_eq!(error.to_string(), "Docker socket path must be UTF-8");
}
```

Legacy resolution intentionally accepts malformed `unix://` strings so they fail at the same connection boundary as before; explicit socket construction validates inputs. The legacy compatibility constructor is named for its trust model, not usable as a sandbox fallback.

- [ ] **Step 2: Run `cargo test --lib docker::endpoint -- --nocapture`.** Expected: compilation fails because the new methods/helper are absent. Register the module before running so a zero-test success is not mistaken for red.

- [ ] **Step 3: Implement the value and exact resolver.**

```rust
fn trusted_host_from_docker_host(value: Option<&str>) -> DockerEndpoint {
    DockerEndpoint {
        socket_address: value.filter(|v| v.starts_with("unix://"))
            .unwrap_or("unix:///var/run/docker.sock").to_owned(),
    }
}

impl DockerEndpoint {
    pub fn trusted_host() -> Self {
        trusted_host_from_docker_host(std::env::var("DOCKER_HOST").ok().as_deref())
    }

    pub fn unix_socket(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = path.to_str().ok_or_else(|| anyhow::anyhow!("Docker socket path must be UTF-8"))?;
        anyhow::ensure!(path.is_absolute() && text != "/" && !text.contains('\0')
            && !text[1..].split('/').any(|part| part.is_empty() || part == "." || part == ".."),
            "Docker socket path must be absolute and normalized");
        Ok(Self { socket_address: format!("unix://{text}") })
    }

    pub fn socket_address(&self) -> &str { &self.socket_address }
}
```

Do not derive `Default`, `Deserialize`, or `Deref<Target=str>`; callers choose a trust model deliberately. The type carries a selected address, not proof of a live/rootless/private daemon. Do not use its `Debug` output for diagnostics.

- [ ] **Step 4: Add a missing-socket transport test, run it red, and replace the client signature.**

```rust
#[tokio::test]
async fn selected_missing_endpoint_fails_without_default_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = DockerEndpoint::unix_socket(&temp.path().join("absent.sock")).unwrap();
    assert!(connect(&endpoint).is_err());
}
```

Implementation:

```rust
pub fn connect(endpoint: &DockerEndpoint) -> Result<Docker> {
    Docker::connect_with_unix(endpoint.socket_address(), 120, bollard::API_DEFAULT_VERSION)
        .context("connecting to selected Docker Unix endpoint")
}
```

Use `connect_with_unix`, not a new protocol auto-detector. This repository already imports Unix-only execution-domain primitives; C0 adds no new Windows support promise.

Migrate every current `connect(None)` to `connect(&DockerEndpoint::trusted_host())`, adding imports or fully qualified names. No compatibility overload accepting `Option<&str>` remains. This mechanical intermediate compiles; Task 4 replaces production temporary resolver calls with domain references. Existing `JobDockerResources::new(Docker)` stays unchanged.

- [ ] **Step 5: Run `cargo test --lib docker::endpoint`, `cargo test --lib selected_missing_endpoint`, and `cargo test --no-run`.** Expected: green and every ignored Docker target compiles. No daemon is required.
- [ ] **Step 6: Commit the complete typed signature migration.**

```bash
git add src/docker.rs src/docker src/job/action/docker.rs src/job/action/docker_test.rs src/runner/instance.rs tests/common/mod.rs tests/dockerfile_actions_test.rs
git commit -m "refactor: make Docker endpoint selection explicit"
```

## Task 2: Bind endpoints and deterministic path metadata to the attempt

**Files:** create `src/job/execution_domain/docker_paths.rs`; modify `src/job/execution_domain/mod.rs`, `src/job/execution_domain_test.rs`.

**Interfaces:** consumes `DockerEndpoint::trusted_host` and the existing canonical UUID attempt directory; produces the domain endpoint and Docker path getters. Existing `prepare`, `reserve`, `provision`, `destroy`, and config getters retain signatures and semantics.

- [ ] **Step 1: Add failing exact-path and no-runtime-side-effect tests.**

```rust
#[test]
fn docker_paths_are_deterministic_and_disjoint() {
    let left = DockerPaths::for_attempt(std::path::Path::new("/attempts/00000000000000000000000000000001"));
    let right = DockerPaths::for_attempt(std::path::Path::new("/attempts/00000000000000000000000000000002"));
    let base = std::path::Path::new("/attempts/00000000000000000000000000000001");
    assert_eq!(left.config_dir(), base.join("docker"));
    assert_eq!(left.run_dir(), base.join("run"));
    assert_eq!(left.socket_path(), base.join("run/docker.sock"));
    assert_eq!(left.data_root(), base.join("docker-data"));
    assert_eq!(left.exec_root(), base.join("docker-exec"));
    assert_ne!(left.socket_path(), right.socket_path());
    assert_ne!(left.config_dir(), right.config_dir());
    assert_ne!(left.data_root(), right.data_root());
    assert_ne!(left.exec_root(), right.exec_root());
    assert_eq!(left, DockerPaths::for_attempt(base));
}

// Add to the existing execution_domain_test module.
#[test]
fn docker_runtime_paths_are_metadata_only_in_trusted_host() {
    let (_temp, root) = prepared_root();
    let domain = admitted_domain(&root).unwrap();
    let paths = domain.docker_paths();
    assert_eq!(paths.config_dir(), domain.docker_config_dir());
    assert!(domain.config_file().is_file());
    assert!(!paths.run_dir().exists());
    assert!(!paths.socket_path().exists());
    assert!(!paths.data_root().exists());
    assert!(!paths.exec_root().exists());
    let attempt = domain.attempt_dir().to_path_buf();
    domain.destroy().unwrap();
    assert!(!attempt.exists());
}
```

- [ ] **Step 2: Run `cargo test --lib docker_paths` and `cargo test --lib docker_runtime_paths`.** Expected: missing type/accessor errors.

- [ ] **Step 3: Implement the pure path description and delegate existing config storage.**

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerPaths {
    config_dir: std::path::PathBuf,
    run_dir: std::path::PathBuf,
    data_root: std::path::PathBuf,
    exec_root: std::path::PathBuf,
    socket_path: std::path::PathBuf,
}
impl DockerPaths {
    pub(super) fn for_attempt(attempt_dir: &std::path::Path) -> Self {
        Self {
            config_dir: attempt_dir.join("docker"),
            run_dir: attempt_dir.join("run"),
            data_root: attempt_dir.join("docker-data"),
            exec_root: attempt_dir.join("docker-exec"),
            socket_path: attempt_dir.join("run/docker.sock"),
        }
    }
    pub fn config_dir(&self) -> &std::path::Path { &self.config_dir }
    pub fn run_dir(&self) -> &std::path::Path { &self.run_dir }
    pub fn data_root(&self) -> &std::path::Path { &self.data_root }
    pub fn exec_root(&self) -> &std::path::Path { &self.exec_root }
    pub fn socket_path(&self) -> &std::path::Path { &self.socket_path }
}
```

In `mod.rs`, declare `mod docker_paths; pub use docker_paths::DockerPaths;`. Replace the stored `docker_config_dir: PathBuf` with `docker_paths: DockerPaths`; derive the same local config directory from the value during provisioning and keep `docker_config_dir_env` and `docker_config_file`. Add `docker_endpoint: DockerEndpoint` to `ExecutionDomain`, set it from `DockerEndpoint::trusted_host()` before attempt directory creation, and expose both getters. Existing `docker_config_dir()` delegates to `self.docker_paths.config_dir()`.

No filesystem validation/removal allowlist changes are necessary: only `docker`, `tmp`, `work`, and the existing journal are created. Do not make a trusted-host domain's endpoint point to its prospective private socket.

The Docker endpoint module must not import `ExecutionDomain`, `DockerPaths`, or B's `DomainPath`; dependencies point from execution_domain to docker only. Do not publish a second incompatible endpoint enum in Plan B. The opaque representation may later acquire a private variant in C1 without changing C0's consumer signatures; no private runtime construction or fallback exists in C0.

These are supervisor-side storage coordinates, not paths inside a future mount namespace. C1 must bind them to B's agreed rootfs mapping and decide how the supervisor reaches the socket. C0 must not create `rootfs`, invent `domain-init` methods, derive paths through `/proc/<pid>/root`, or assume the workflow sees these host paths.

- [ ] **Step 4: Pin environment snapshot behavior using the existing child-process test pattern.**

Add an isolated child test which receives `DOCKER_HOST=unix:///absent/first.sock`, provisions a domain, and asserts the retained endpoint equals that exact address; destroy successfully without connecting. Run another isolated child with `unix:///absent/second.sock` and verify its independent selection. Also run the child with a non-UTF-8 `DOCKER_HOST` via `Command::env` and assert the default endpoint. Never call unsafe `std::env::set_var` in the parallel test process.

The core assertions in each child are:

```rust
let (_temp, root) = prepared_root();
let domain = admitted_domain(&root).unwrap();
assert_eq!(domain.docker_endpoint().socket_address(), expected);
assert_eq!(domain.docker_config_dir(), domain.attempt_dir().join("docker"));
domain.destroy().unwrap();
```

Use a marker such as `CHIMERA_ENDPOINT_CHILD_CASE` and invoke the exact test by fully qualified name through `std::env::current_exe()`, following the existing restrictive-umask child test pattern. Parent checks child status and stdout/stderr only on failure. This tests environment reading without globally mutating the test process.

- [ ] **Step 5: Run `cargo test --lib job::execution_domain` and `cargo test --test execution_domain_test`.** Expected: config permissions, stale-root handling, journal integrity, collision, admission, symlink/replacement, poisoning, and destroy-order tests remain green.
- [ ] **Step 6: Commit the attempt metadata contract.**

```bash
git add src/job/execution_domain/mod.rs src/job/execution_domain/docker_paths.rs src/job/execution_domain_test.rs
git commit -m "refactor: bind Docker endpoint and paths to execution domains"
```

## Task 3: Finish daemon-free acceptance scaffolding and preserve native gates

**Files:** create `tests/common/docker_endpoint.rs`, `tests/docker_endpoint_test.rs`; modify `tests/execution_domain_docker_test.rs`, `docs/job-docker-config.md`. The shared probe is completed here before Task 4 consumes it.

**Interfaces:** `EngineProbe::start(marker: &'static str) -> impl Future<Output = anyhow::Result<Self>>`, `EngineProbe::start_failing_images() -> impl Future<Output = anyhow::Result<Self>>`, `endpoint(&self) -> &DockerEndpoint`, `requests(&self) -> Vec<String>`; test-only `AcceptanceDockerTarget::from_values(docker_host: Option<&str>, runtime_dir: Option<&str>) -> anyhow::Result<Self>` with `endpoint() -> &DockerEndpoint` and `runtime_dir() -> &Path` getters. Implement the two probe constructors as `async fn`. No production API is added for daemon provisioning or socket injection.

- [ ] **Step 1: Write a failing two-socket transport test.**

```rust
#[tokio::test]
async fn explicit_clients_route_to_distinct_unix_endpoints() {
    let a = EngineProbe::start("engine-a").await.unwrap();
    let b = EngineProbe::start("engine-b").await.unwrap();
    let client_a = chimera::docker::client::connect(a.endpoint()).unwrap();
    let client_b = chimera::docker::client::connect(b.endpoint()).unwrap();
    assert_eq!(client_a.ping().await.unwrap(), "engine-a");
    assert_eq!(client_b.ping().await.unwrap(), "engine-b");
    assert_eq!(a.requests().len(), 1);
    assert_eq!(b.requests().len(), 1);
}
```

Register it with `#[path = "common/docker_endpoint.rs"] mod docker_endpoint;` so this narrow integration target does not import the entire large `common` module. The support module imports the type with `use super::DockerEndpoint;`; its integration-test parent imports `chimera::docker::endpoint::DockerEndpoint`, and its unit-test parents import `crate::docker::endpoint::DockerEndpoint`. This allows reusing the probe without importing the library as an external crate inside its own unit tests. Run `cargo test --test docker_endpoint_test`; expected missing probe/API errors, not ignored tests.

- [ ] **Step 2: Implement the bounded probe.**

Store a short `tempfile::Builder::new().prefix("ch-ep-").tempdir_in("/tmp")?`, endpoint, `Arc<Mutex<Vec<String>>>`, and Tokio task. Bind `tokio::net::UnixListener` before returning. For each accepted stream, read only to `\r\n\r\n`, cap headers at 8192 bytes, wrap reading in a two-second timeout, record only the request line, and respond with `Connection: close` and exact `Content-Length`. A ping response is:

```rust
let response = format!(
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
    marker.len(), marker,
);
```

For the image-routing fixture use the fixed response below and record the request line before writing it; never record Authorization, bodies, or full headers:

```rust
let body = r#"{"message":"synthetic endpoint probe failure"}"#;
let response = format!(
    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
    body.len(), body,
);
```

Offer `start_failing_images()` using that response in addition to `start(marker)`. Abort the listener task in `Drop`; it owns no daemon or external resources. The temp directory removes only the fixture's socket. For a connection-refused case bind then drop a listener without unlinking its socket, call `connect` then `ping` under a two-second timeout, assert error, and assert the second live probe received no request. This distinguishes address selection failure from daemon readiness.

- [ ] **Step 3: Write and run failing explicit acceptance-target tests.**

```rust
#[test]
fn acceptance_target_requires_explicit_coherent_unix_runtime() {
    for (host, runtime) in [
        (None, Some("/run/user/1501")),
        (Some("unix:///run/user/1501/docker.sock"), None),
        (Some("tcp://127.0.0.1:2375"), Some("/run/user/1501")),
        (Some("unix:///var/run/docker.sock"), Some("/run/user/1501")),
        (Some("unix:///run/user/1501/docker.sock"), Some("/run/user/1501/../1501")),
    ] {
        assert!(AcceptanceDockerTarget::from_values(host, runtime).is_err());
    }
    let target = AcceptanceDockerTarget::from_values(
        Some("unix:///run/user/1501/docker.sock"), Some("/run/user/1501")
    ).unwrap();
    assert_eq!(target.endpoint().socket_address(), "unix:///run/user/1501/docker.sock");
}
```

Implement by extracting the current `validate_rootless_environment` contract into this test module, validating both strings without environment mutation, using `DockerEndpoint::unix_socket`, and requiring `socket == runtime_dir.join("docker.sock")`. Retain `validate_rootless_security_options` and native `docker info` preflight: address coherence never proves rootless mode. The typed fixture holds data only; validation does not connect, create directories, or set environment variables.

In `tests/execution_domain_docker_test.rs`, construct the typed target from the already parsed explicit values and use its address for endpoint assertions; retain the existing wrapper's string fields if that avoids unrelated churn. Preserve its missing-prerequisite failures, original ignored test name, exact SHAs, synthetic authenticated registry, helper-free Docker config, exact owned container/volume cleanup, post-action assertions, and immutable BuildKit image requirement.

Existing `tests/common/docker_registry.rs` CLI helpers continue their trusted-host environment behavior. Do not reuse them as sandbox acceptance evidence: C1 must make registry, Buildx, fixture cleanup, and workflow commands use its owned domain endpoint and domain-local network together.

- [ ] **Step 4: Run all daemon-free tests and compile native tests.**

```bash
cargo test --test docker_endpoint_test
cargo test --test execution_domain_docker_test
cargo test --test execution_domain_docker_test --no-run
cargo test --lib daemon_test::sandboxed
```

Expected: ordinary tests pass; existing Docker/Buildx tests remain ignored. Existing sandboxed-startup tests still prove rejection before root creation, cache listeners, or sessions. Do not turn ignored native tests into `if unavailable { return; }` successes.

- [ ] **Step 5: Document exactly what C0 verifies.**

Add this paragraph to `docs/job-docker-config.md`:

```text
Runner Docker API calls resolve the trusted-host Unix endpoint once for each
attempt and pass that endpoint explicitly to job/service containers and Docker
actions. Selection preserves the existing Unix DOCKER_HOST behavior; Docker
contexts and TCP/TLS support are unchanged. Host shell and Node actions keep
their existing Docker environment behavior. The domain also records deterministic
Docker storage paths, but trusted-host does not create a private daemon, socket,
data root, or exec root. The sandboxed profile remains unavailable. Daemon-free
endpoint tests and the existing trusted-host rootless Buildx test do not establish
sandbox isolation or satisfy the native sandbox release gate.
```

No roadmap item C is marked complete by C0; its daemon ownership and native acceptance remain C1/E work.

- [ ] **Step 6: Commit the acceptance scaffolding and documentation.**

```bash
git add tests/common/docker_endpoint.rs tests/docker_endpoint_test.rs tests/execution_domain_docker_test.rs docs/job-docker-config.md
git commit -m "test: scaffold explicit Docker endpoint acceptance"
```

## Task 4: Route every runner Docker path through the selected domain

**Files:** modify `src/job/execute.rs`, `src/job/execute_test.rs`, `src/job/action/docker.rs`, `src/job/action/docker_test.rs`, `src/runner/instance.rs`. Consume the shared probe completed by Task 3; include it in crate unit tests with a test-only relative `#[path]` module declaration if necessary.

**Interfaces:** consumes `ExecutionDomain::docker_endpoint`; produces `JobExecutionContext::docker_client`. Existing resources own their client; a `Docker` clone shares Bollard's transport rather than selecting a new endpoint.

- [ ] **Step 1: Add a failing context test using a nonexistent explicit endpoint in a child process.**

With the child environment `DOCKER_HOST=unix:///absent/context.sock`, provision a domain and construct the existing `JobExecutionContext::new(&domain, None, &node_runtimes)` after constructing `let node_runtimes = crate::node::NodeRuntimes::single("node".into());`. Assert the exposed endpoint equals the domain endpoint and `docker_client()` fails without any Docker installation.

```rust
assert_eq!(execution.docker_endpoint(), domain.docker_endpoint());
assert!(execution.docker_client().is_err());
```

Run `cargo test --lib docker_context -- --nocapture`; expected red is absent methods. Name the test with the `docker_context` prefix so the filter executes it.

- [ ] **Step 2: Implement the one client-selection method.**

```rust
pub fn docker_endpoint(&self) -> &'a crate::docker::endpoint::DockerEndpoint {
    self.domain.docker_endpoint()
}

pub fn docker_client(&self) -> anyhow::Result<bollard::Docker> {
    match self.docker_resources {
        Some(resources) => Ok(resources.docker().clone()),
        None => crate::docker::client::connect(self.docker_endpoint()),
    }
}
```

Both Docker action entry points replace their `owned_docker`/`match` blocks with:

```rust
let docker = execution.docker_client()?;
```

Pass `&docker` to `RunDockerParams` and `DockerBuildRequest`. The build, pre/main/post phases, timeout budgets, cancellation and cleanup continue to use that selected client. `run_job_body` replaces its temporary trusted-host resolver with:

```rust
let docker = crate::docker::client::connect(domain.docker_endpoint())?;
crate::docker::client::ping(&docker).await?;
let mut resources = JobDockerResources::new(docker);
```

Do not reconnect inside `JobDockerResources::setup`, `exec`, cleanup, or Docker builds. Keep existing `SetupParams` host path semantics: translating bind mounts is C1 on top of B.

- [ ] **Step 3: Add routing coverage with the daemon-free probe in Task 3.**

Use its `EngineProbe` to create two listeners A/B. The no-resource context is provisioned in an isolated child with `DOCKER_HOST=A`; `execution.docker_client()?.ping().await` must return A's marker. The with-resources context uses `JobDockerResources::new(connect(B)?)`; the same method must return B's marker even if the domain endpoint is absent. This deliberately mismatched fixture pins existing reuse semantics; production constructs resources from the domain in the runner. Start the child with `tokio::process::Command` and await its output under a bounded timeout so the parent Tokio runtime can service the listeners; do not block that runtime with `std::process::Command::output`.

Check both public action entry points with an A probe returning a deliberate Engine 500 JSON response for image inspection/pull: the request log must contain an image operation on A and the returned action error must be expected. Reuse the existing `docker_action_step`, `make_docker_metadata`, `test_docker_config`, workspace/log fixtures in `docker_test.rs`, parameterized with a child-supplied endpoint. Keep post/build client sharing covered by the existing `DockerBuildRequest`/lifecycle tests and the typed call-site review; do not implement a mock Docker build server.

Write these routing tests alongside Step 1 and run them red before Step 2's production replacements; then rerun green. The Task 3 probe is already available. These tasks form one sequential implementation stream, not parallel file edits.

- [ ] **Step 4: Run focused suites and audit every connection constructor.**

```bash
cargo test --lib job::execute_test
cargo test --lib job::action::docker
cargo test --lib runner::instance_test
cargo test --lib docker::resources_test
rg -n 'connect\(None|connect_with_(local_defaults|unix_defaults|socket_defaults)' src tests
rg -n 'DockerEndpoint::trusted_host|client::connect|docker_client::connect' src tests
```

Expected: first search has no matches. Resolver calls in production occur only in domain provisioning; all connection sites use a typed endpoint or the context-selected existing client. Explicit trusted-host resolution in ignored legacy Docker fixtures is permitted. Inspect results, not only search exit codes. Tests that intentionally use Bollard directly with a fake HTTP server may retain their explicit transport constructor.

- [ ] **Step 5: Commit endpoint propagation and its routing tests.**

```bash
git add src/job/execute.rs src/job/execute_test.rs src/job/action/docker.rs src/job/action/docker_test.rs src/runner/instance.rs tests/common/docker_endpoint.rs tests/docker_endpoint_test.rs
git commit -m "refactor: route runner Docker operations through attempt endpoints"
```

## Final verification and handoff

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Run `cargo test --all-targets --all-features` once after the final implementation change.
- [ ] Run `git diff --check` and inspect all connection constructor search results from Task 4.
- [ ] Review `git diff origin/main -- src/daemon.rs src/config/execution.rs src/job/execution_domain/filesystem.rs`: no activation-gate removal, sandbox fallback, or cleanup-allowlist expansion belongs to this plan.
- [ ] If a native trusted-host rootless environment is available, run the existing `pinned_buildx_flow_uses_job_config_and_original_socket` ignored test explicitly with its documented pinned local assets. Record pass/fail or “not run: native prerequisites unavailable”; the latter is not a sandbox acceptance pass. C0's required routing coverage is daemon-free.

The implementation handoff must report the typed API, preserved selection behavior, test commands/results, and any unrun native compatibility check. C0 is complete only when all production connections use domain-selected clients, no `connect(None)` remains, normal host-only jobs still need no Docker daemon, and the startup rejection remains intact.

## C1 dependency boundary

C1 requires B's actual launcher/rootfs/cgroup interfaces and gets its own detailed plan. It must provide eager private dockerd startup/readiness, the supervisor/domain socket mapping, private runtime/data/exec creation and destruction, endpoint-bound runner and shell authority, reserved sandbox environment enforcement, daemon-aware Docker action build-cache scoping, job/services/actions/Buildx acceptance, rollback/cancellation/restart cleanup, and 20/40 concurrency tests. C0 supplies values and routing seams only. It does not grant Ready for a sandbox, satisfy S-02/S-03/S-06–S-16, or authorize activation.
