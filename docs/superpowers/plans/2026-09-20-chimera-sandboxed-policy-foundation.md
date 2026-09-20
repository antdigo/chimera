# Sandboxed Policy Foundation (D0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build independently testable network/storage policy, capability and doctor/install contracts without enabling sandboxed execution or connecting a launcher.

**Architecture:** Extend `ExecutionConfig` with optional policy inputs and expose a small `sandbox_policy` module that converts configuration plus fresh observations into validated policy and diagnostic reports. Keep policy rendering, live read-only collection, and evidence evaluation separate: a rendered unit, a quota number in TOML, or a failed TCP connection alone is never proof of enforcement. The existing `Daemon::run` activation rejection remains the first runtime action.

**Tech Stack:** Rust 2024, existing serde/toml/serde_json, thiserror/anyhow, tokio, libc and blake3; native Debian/systemd observations. No new crate.

**Spec:** [CHM-08 sandboxed execution domain](../specs/2026-09-20-chimera-sandboxed-execution-domain.md), especially §§8–9, 13–17. Also read the [roadmap](2026-09-20-chimera-sandboxed-execution-roadmap.md) and [related-issues report](../reports/2026-09-20-chimera-attempt-isolation-related-issues.md). Current implementation base is `origin/main@39585f17dc58bf108aefaf6efc0067d3371df166`; historic source observations in the report are not the current interfaces.

## Global Constraints

- `trusted-host` remains the default; existing TOML without policy tables retains its current meaning.
- «один `chimera` service account и один systemd unit»; «VM на каждый job отсутствуют».
- «нет пула из 20–40 системных пользователей, per-job systemd services или собственного privileged helper».
- «один диапазон минимум 65 536 subordinate UID/GID».
- «macOS, запуск Chimera внутри контейнера и Linux без необходимых kernel features получают явный preflight error. Ослабленный fallback не выполняется.»
- «Production Docker API не может быть таким endpoint: deploy использует отдельный узкий protocol.»
- «Без доказанного global storage bound strong profile не стартует.»
- «До прохождения Plans B–E и полного release gate S-01…S-16 этот профиль не активируется и не запускает job.»
- Native tests run serialized and with an exclusive machine-wide qualification lock on the single Debian host. No extra VM or second host is required.
- This slice never installs a unit, alters network policy, starts/stops a service, mounts storage, changes quota, creates a namespace, issues a runtime capability, or opens a job listener. CLI commands inspect or render only.
- Resource parser/controller types belong to Plan B; D0 owns `ExecutionConfig.network` and `.storage` only. No duplication of `ExecutionDomain` ownership, `CacheAuthority`, or resource-limit parsers.

## Review Focus

- CIDRs with host bits, IPv4-mapped IPv6, duplicate addresses and newline injection must not weaken a deny policy (Task 1 and Task 2).
- A missing sentinel, connection refusal, or a stale service generation must not be classified as enforced filtering (Task 3).
- A bind mount of ordinary host storage, nested writable mount, changed inode or mere free-space measurement must not prove an independent capacity bound (Task 4).
- Old capability handles and artifact/deploy descriptors must not grant production Docker access or revoke a new attempt (Task 5).
- A plausible doctor report or rendered systemd drop-in must not imply runtime availability; malformed policy and all successful diagnostics still leave the activation gate intact (Task 6).

---

## Scope and file map

Existing seams: `src/config/execution.rs` currently holds only profile and capacity; `src/daemon.rs::validate_execution_profile` rejects sandboxed before `prepare_daemon_root`, cache server startup, runner construction and sessions. `src/cache/auth.rs` already has opaque epochs, operation gates and immediate/async revocation; `src/cache/server.rs::start` binds `0.0.0.0`. D0 does not change those cache listening or authorization behaviors.

| Files | Responsibility |
|---|---|
| `src/config/network.rs`, `network_test.rs` | CIDR syntax and serialized operator network policy |
| `src/config/storage.rs`, `storage_test.rs` | Storage-bound request and strict byte-limit syntax |
| `src/config/execution.rs`, `execution_test.rs`, `src/config.rs` | Optional table integration and backward compatibility |
| `src/sandbox_policy.rs`, `src/sandbox_policy/error.rs` | Public facade and safe typed errors |
| `src/sandbox_policy/network.rs`, `network_test.rs` | Canonical deny-set and effective-policy evaluation |
| `src/sandbox_policy/probe.rs`, `probe_test.rs` | Bounded live connect probe and evidence evaluator |
| `src/sandbox_policy/storage.rs`, `storage_test.rs` | Pinned-directory storage observations and bound validation |
| `src/sandbox_policy/capability.rs`, `capability_test.rs` | Attempt-scoped descriptors and cache binding contract |
| `src/sandbox_policy/doctor.rs`, `doctor_test.rs` | Read-only observation collection and diagnostic report |
| `src/sandbox_policy/install.rs`, `install_test.rs` | Deterministic install-plan rendering, no application |
| `src/cli.rs`, `cli_test.rs`, `src/lib.rs` | Public doctor/render consumers |
| `src/daemon_test.rs`, `tests/sandboxed_policy_test.rs` | Activation regression and CLI behavior |
| `docs/sandboxed-policy.md` | Operator contract, limitations, handoff to runtime integration |

Use sibling `*_test.rs` with `#[path]`, as required by `CLAUDE.md`. Keep each module focused; do not enlarge `config.rs` with policy algorithms. All displayed examples are synthetic test values, not rollout sizing.

### Shared validation and command conventions

Use `PolicyError` with these fixed variants: `InvalidCidr`, `InvalidStorageLimit`, `MissingPolicy(&'static str)`, `InvalidService`, `InvalidObservation(&'static str)`, `PolicyMismatch`, `ProbeInconclusive`, `ProbeAllowedForbidden`, `StorageUnbounded`, `StorageIdentityChanged`, `UnsupportedStorageProbe`, `CapabilityMismatch`, `UnsupportedCapability`, `UnsupportedPlatform`, and `Io(std::io::Error)`. Error text includes the category and safe field name, never raw TOML, environment, tokens or subprocess stderr. `PolicyError` lives in `src/sandbox_policy/error.rs`; config parser errors use the appropriate category's constant Display string through `serde::de::Error::custom`.

Every RED command below must fail at the named new test or missing new symbol; every GREEN repeats exactly that command and must pass. Redirect complete output to the named file, then inspect it with `rg`, preserving the cargo exit status in the terminal. On Linux first run:

```bash
mkdir -p "$PWD/target/chimera-tests"
export TMPDIR="$PWD/target/chimera-tests"
```

No implementation commit is made while reviewing this plan. Commit commands below belong to its later execution.

### Task 1: Strict policy configuration without changing trusted-host defaults

**Files:** Create `src/config/network.rs`, `src/config/network_test.rs`, `src/config/storage.rs`, `src/config/storage_test.rs`, `src/sandbox_policy.rs`, `src/sandbox_policy/error.rs`; modify `src/config.rs`, `src/config/execution.rs`, `src/config/execution_test.rs`, `src/config_test.rs`, `src/daemon_test.rs`, `src/lib.rs`.

**Interfaces:**

```rust
// All listed config types derive Clone, Debug, PartialEq, Eq, Serialize, Deserialize.
pub struct IpCidr { address: std::net::IpAddr, prefix: u8 }
impl std::str::FromStr for IpCidr { type Err = crate::sandbox_policy::PolicyError; }
// Also implement Display and serde as a single string, not an object.
impl IpCidr {
    pub fn contains(&self, address: std::net::IpAddr) -> bool;
    pub fn address(&self) -> std::net::IpAddr;
    pub fn prefix(&self) -> u8;
}
pub struct NetworkPolicyConfig {
    pub production_cidrs: Vec<IpCidr>,
}
pub struct StorageBoundConfig {
    pub mechanism: StorageMechanism,
    pub max_bytes: StorageBytes,
}
#[serde(rename_all = "kebab-case")]
pub enum StorageMechanism { DedicatedFilesystem, ProjectQuota, BtrfsQuota }
pub struct StorageBytes(std::num::NonZeroU64);
impl StorageBytes { pub fn get(self) -> u64; }
impl std::str::FromStr for StorageBytes { type Err = crate::sandbox_policy::PolicyError; }
// ExecutionConfig gains these exact fields, each #[serde(default)]:
// pub network: Option<NetworkPolicyConfig>, pub storage: Option<StorageBoundConfig>
```

`NetworkPolicyConfig` and `StorageBoundConfig` reject unknown fields. `production_cidrs` is required when the network table is present: explicit `[]` is meaningful operator policy. Empty optional tables are errors. Do not add `deny_unknown_fields` globally to `ChimeraConfig` in this slice.

- [ ] **Step 1: Add parser tests.** Pin normal values and invalid input classes with actual assertions:

```rust
#[test]
fn cidr_is_strict_and_family_aware() {
    let cidr: IpCidr = "10.2.0.0/16".parse().unwrap();
    assert!(cidr.contains("10.2.9.3".parse().unwrap()));
    assert!(!cidr.contains("10.3.9.3".parse().unwrap()));
    for bad in ["10.2.1.1/16", "::ffff:127.0.0.1/128", "0.0.0.0/33",
                "::/129", "10.0.0.0/8\nIPAddressAllow=any", " 10.0.0.0/8"] {
        assert!(bad.parse::<IpCidr>().is_err(), "accepted {bad:?}");
    }
}
#[test]
fn storage_limit_has_exact_units_and_checked_arithmetic() {
    assert_eq!("64GiB".parse::<StorageBytes>().unwrap().get(), 68_719_476_736);
    assert_eq!("1B".parse::<StorageBytes>().unwrap().get(), 1);
    for bad in ["0", "0B", "1GB", "1.5GiB", "max", "-1B", "18446744073709551615TiB"] {
        assert!(bad.parse::<StorageBytes>().is_err());
    }
}
```

Add `optional_policy_preserves_trusted_defaults`, `sandboxed_without_policy_still_parses`, `policy_tables_round_trip`, and `unknown_policy_fields_fail`. Existing `parses_sandboxed_capacity` must still pass. Config parsing and qualification validation are separate.

- [ ] **Step 2: RED.** `cargo test --lib config:: > /tmp/chimera-d0-config.log 2>&1` — fail on missing config types/fields.
- [ ] **Step 3: Implement the types.** Use `IpAddr::from_str`, exactly one `/`, checked `u8` prefix, and bit masks with explicit `/0` handling. Reject host bits rather than silently normalizing user intent; reject IPv4-mapped IPv6 so address-family comparison cannot bypass rules. Accept only integer `B`, `KiB`, `MiB`, `GiB`, `TiB` suffixes with checked multiplication and nonzero output. Serialize limits canonically as decimal bytes followed by `B`. `Default for ExecutionConfig` sets both fields to `None`. Update existing exhaustive `ExecutionConfig` literals in `src/config_test.rs` (current line 100) and `src/daemon_test.rs` (current lines 19, 42, 538) using `..ExecutionConfig::default()`; preserve each explicit profile/capacity value and any Plan B resource fields already integrated.

```rust
fn checked_bytes(value: u64, multiplier: u64) -> Result<StorageBytes, PolicyError> {
    let bytes = value.checked_mul(multiplier)
        .and_then(std::num::NonZeroU64::new)
        .ok_or(PolicyError::InvalidStorageLimit)?;
    Ok(StorageBytes(bytes))
}
```

- [ ] **Step 4: GREEN.** Repeat the Task 1 command; inspect `rg 'test result:|^failures:' /tmp/chimera-d0-config.log`.
- [ ] **Step 5: Commit.** `git add src/config.rs src/config src/config_test.rs src/daemon_test.rs src/lib.rs src/sandbox_policy.rs src/sandbox_policy/error.rs && git commit -m "feat: define sandbox network and storage policy configuration"`

### Task 2: Canonical deny policy and deterministic install rendering

**Files:** Create `src/sandbox_policy/network.rs`, `network_test.rs`, `install.rs`, `install_test.rs`; modify facade.

**Consumes:** `NetworkPolicyConfig`, `IpCidr`, `PolicyError`.

**Produces:**

```rust
pub struct HostAddresses { pub addresses: Vec<std::net::IpAddr> }
pub struct NetworkPolicy {
    denied: Vec<IpCidr>, required_probe_prefixes: Vec<IpCidr>, digest: String,
}
pub fn compile_network(config: &NetworkPolicyConfig, host: &HostAddresses)
    -> Result<NetworkPolicy, PolicyError>;
impl NetworkPolicy {
    pub fn denied(&self) -> &[IpCidr];
    pub fn digest(&self) -> &str;
    pub fn permits(&self, address: std::net::IpAddr) -> bool;
    pub fn required_probe_prefixes(&self) -> &[IpCidr];
}
pub struct InstallPlan {
    pub schema_version: u32,
    pub relative_destination: String,
    pub drop_in: String,
    pub policy_digest: String,
    pub requires_restart: bool,
    pub activation_available: bool,
}
pub fn render_install_plan(policy: &NetworkPolicy) -> InstallPlan;
```

- [ ] **Step 1: Add tests.** `canonical_policy_blocks_host_and_special_networks` checks 127/8, 169.254/16, 10/8, 172.16/12, 192.168/16, 224/4, IPv6 `::1/128`, `fe80::/10`, `ff00::/8`, `fc00::/7`, observed public host address `203.0.113.9`, and operator production `198.51.100.0/24`. Additional unspecified `0.0.0.0/8`, `::/128` and IPv4 broadcast `255.255.255.255/32` are denied. IPv6 is fully denied (`::/0`) because v1 disables IPv6; do not claim public IPv6 compatibility. Public IPv4 `1.1.1.1` remains eligible. Duplicate/reordered host and operator inputs yield byte-identical output and digest.

```rust
#[test]
fn render_does_not_claim_installation_or_activation() {
    let config = NetworkPolicyConfig { production_cidrs: vec![] };
    let policy = compile_network(&config, &HostAddresses {
        addresses: vec!["203.0.113.9".parse().unwrap()],
    }).unwrap();
    let plan = render_install_plan(&policy);
    assert_eq!(plan.relative_destination, "chimera.service.d/50-sandbox-network.conf");
    assert!(plan.requires_restart);
    assert!(!plan.activation_available);
    assert!(plan.drop_in.contains("IPAddressDeny=203.0.113.9/32"));
    assert!(!plan.drop_in.contains("IPAddressAllow=any"));
}
```

- [ ] **Step 2: RED.** `cargo test --lib sandbox_policy:: > /tmp/chimera-d0-policy.log 2>&1` — new module/symbol failure.
- [ ] **Step 3: Implement sorted/deduplicated set compilation.** Add discovered addresses as `/32` or `/128`; reject an empty host inventory. Preserve `required_probe_prefixes` as sorted/deduplicated IPv4 loopback plus each discovered host address and every operator production prefix; this metadata lets the evaluator detect omitted sentinels without guessing which CIDRs came from configuration. IPv6 host addresses require outside positive controls even though v1 denies all IPv6. Canonical digest is BLAKE3 of `chimera-network-policy-v1\n` plus sorted CIDR lines and a separate `required-probes\n` section, never an unstable Debug rendering. `permits` treats mapped IPv6 as denied. Render the complete deterministic fragment below, with one canonical denial per line:

```ini
# Generated by chimera install-policy --render; policy-sha=<digest>
[Service]
IPAddressAllow=
IPAddressDeny=
IPAddressDeny=127.0.0.0/8
```

The example's last line represents the first generated denial; the implementation iterates every entry in `policy.denied()`. No allow exceptions are emitted: systemd allow precedence could reopen denied CIDRs. The installation model is specific to `chimera.service`; it does not accept arbitrary unit names or paths. It specifies re-render/reapply/restart on address/CIDR change. Other unit drop-ins can override it; Task 3 checks effective state, not file presence. Global resource/delegation directives remain Plan B's responsibility.
- [ ] **Step 4: GREEN.** Repeat Task 2 command and inspect log. Add golden-string assertion with every expected line, not only substring assertions.
- [ ] **Step 5: Commit.** `git add src/sandbox_policy.rs src/sandbox_policy/network* src/sandbox_policy/install* && git commit -m "feat: compile sandbox deny policy and render install plans"`

### Task 3: Network evidence cannot confuse broken connectivity with denial

**Files:** Create `src/sandbox_policy/probe.rs`, `probe_test.rs`; extend `network.rs`, `network_test.rs` and facade.

**Interfaces:**

```rust
pub struct ServiceGeneration {
    pub boot_id: uuid::Uuid,
    pub invocation_id: String, // exactly 32 lowercase hex characters
    pub control_group: String, // exactly /system.slice/chimera.service
}
pub struct AppliedNetworkPolicy {
    pub generation: ServiceGeneration,
    pub denied: Vec<IpCidr>,
    pub allowed: Vec<IpCidr>,
    pub bpf_attached: bool,
}
pub enum ConnectOutcome { Connected, Refused, TimedOut, Denied, Unreachable }
pub struct SentinelObservation {
    pub address: std::net::SocketAddr,
    pub control_before: bool,
    pub control_after: bool,
    pub observed: ConnectOutcome,
}
pub struct ProbeBatch {
    pub generation: ServiceGeneration,
    pub negative: Vec<SentinelObservation>,
    pub public_registry_ok: bool,
}
pub fn validate_network_evidence(expected: &NetworkPolicy,
    applied: &AppliedNetworkPolicy, probes: &ProbeBatch) -> Result<(), PolicyError>;
pub async fn probe_connect(address: std::net::SocketAddr,
    deadline: std::time::Duration) -> Result<ConnectOutcome, PolicyError>;
```

The public `sandbox_policy` facade re-exports `NetworkPolicy`, `AppliedNetworkPolicy`, `ProbeBatch`, `ConnectOutcome`, and `validate_network_evidence` for E0/E1 qualification. Internal collectors remain private; consumers cannot construct an applied-policy success without supplying all typed evidence to the validator.

`ServiceGeneration`, evidence and report types derive serde for reports; validators do not trust deserialization as live provenance. The collector owns the generation before/after check. Read-only doctor does not create an outside-service sentinel; E0/E1 native harness provides independently observed readiness.

- [ ] **Step 1: Add evaluator tests.** Build a complete valid fixture directly using the declared structs; use loopback, discovered public host IP and operator production sentinel addresses. Assert the following mutation table:

| Mutation of a valid fixture | Expected error |
|---|---|
| `control_before = false` or `control_after = false` | `ProbeInconclusive` |
| `observed = Connected` | `ProbeAllowedForbidden` |
| `observed = Refused` or `Unreachable` | `ProbeInconclusive` |
| `public_registry_ok = false` | `ProbeInconclusive` |
| changed boot/invocation/cgroup generation | `PolicyMismatch` |
| `allowed = ["0.0.0.0/0"]` or `bpf_attached = false` | `PolicyMismatch` |
| missing required sentinel address class | `ProbeInconclusive` |

```rust
#[tokio::test]
async fn connect_probe_identifies_a_live_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let result = probe_connect(listener.local_addr().unwrap(),
        std::time::Duration::from_secs(1)).await.unwrap();
    assert!(matches!(result, ConnectOutcome::Connected));
}
```

- [ ] **Step 2: RED.** `cargo test --lib sandbox_policy::probe > /tmp/chimera-d0-probe.log 2>&1` and `cargo test --lib sandbox_policy::network > /tmp/chimera-d0-evidence.log 2>&1` — fail on absent evidence implementation.
- [ ] **Step 3: Implement bounded connect and strict evaluation.** `tokio::time::timeout` bounds `TcpStream::connect`; classify `PermissionDenied` as Denied, `ConnectionRefused` as Refused, OS unreachable as Unreachable; unexpected errors return safe `Io`. Only Denied or TimedOut with positive outside-control checks before and after are acceptable negatives. Enforce nonempty negative set covering loopback, every detected host address and every configured production CIDR for which a sentinel is declared; require one sentinel per distinct production prefix. An unreachable configured sentinel leaves the check inconclusive. Check effective policy contains every required deny and zero allows; stronger denies are permitted only if public-registry positive probe succeeds. Require matching generation and attached ingress/egress cgroup policy evidence. `bpf_attached` is an observation supplied by trusted collection, not inferred from `IPAddressDeny` text.
- [ ] **Step 4: GREEN.** Repeat both commands, inspect logs. Run no host network mutation as part of portable tests.
- [ ] **Step 5: Commit.** `git add src/sandbox_policy.rs src/sandbox_policy/network* src/sandbox_policy/probe* && git commit -m "feat: distinguish sandbox policy evidence from failed connectivity"`

### Task 4: Bind storage evidence to the complete writable Chimera root

**Files:** Create `src/sandbox_policy/storage.rs`, `storage_test.rs`; modify facade. Reuse `src/storage.rs::open_existing_root` inside this crate, without changing its ownership checks.

**Interfaces:**

```rust
pub struct StorageIdentity {
    pub device: u64, pub inode: u64, pub mount_id: u64,
}
pub struct StorageObservation {
    pub root: StorageIdentity,
    pub mount_point: std::path::PathBuf,
    pub filesystem_root: std::path::PathBuf,
    pub filesystem_type: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub parent_device: u64,
    pub writable_nested_mounts: Vec<std::path::PathBuf>,
    pub aliases_outside_root: Vec<std::path::PathBuf>,
}
pub struct StorageBoundEvidence {
    identity: StorageIdentity,
    hard_limit_bytes: u64,
}
impl StorageBoundEvidence {
    pub fn hard_limit_bytes(&self) -> u64;
    pub fn identity(&self) -> &StorageIdentity;
}
pub fn probe_storage(root: &std::path::Path) -> Result<StorageObservation, PolicyError>;
pub fn validate_storage_bound(config: &StorageBoundConfig,
    observation: &StorageObservation) -> Result<StorageBoundEvidence, PolicyError>;
pub fn revalidate_storage_identity(root: &std::path::Path,
    evidence: &StorageBoundEvidence) -> Result<(), PolicyError>;
```

D0 supports live proof for an already provisioned, dedicated ext4/XFS filesystem/LV mounted exactly at Chimera root. Project-quota and btrfs-quota configuration are represented explicitly but return `UnsupportedStorageProbe`; D1 must add verified quota collectors before those mechanisms can pass. This is a deliberate bounded implementation slice, not an inferred hard limit from `max_bytes`. The final spec permits any one proven mechanism, so a dedicated filesystem is a complete usable strategy.

- [ ] **Step 1: Add tests.** Construct a `StorageObservation` for a 64 GiB dedicated ext4 root on device 8:2, parent 8:1, filesystem root `/`, no aliases or writable nested mounts. Validate against `64GiB`, then vary total bytes to 65 GiB, filesystem root to `/subdir`, parent device to the root device, nested writable cache mount, and an outside bind alias; all variations fail. A 64 GiB filesystem with 1 GiB free remains capacity-bounded, while a 1 TiB filesystem with 1 GiB free fails: free space is not capacity.

```rust
#[test]
fn unsupported_quota_collectors_do_not_accept_operator_assertions() {
    for mechanism in [StorageMechanism::ProjectQuota, StorageMechanism::BtrfsQuota] {
        let config = StorageBoundConfig { mechanism, max_bytes: "64GiB".parse().unwrap() };
        // root identity is synthetic; unsupported mechanism must be rejected first.
        let observation = StorageObservation {
            root: StorageIdentity { device: 2, inode: 7, mount_id: 9 },
            mount_point: "/srv/chimera".into(), filesystem_root: "/".into(),
            filesystem_type: "ext4".into(), total_bytes: 64 << 30,
            available_bytes: 1 << 30, parent_device: 1,
            writable_nested_mounts: vec![], aliases_outside_root: vec![],
        };
        assert!(matches!(validate_storage_bound(&config, &observation),
            Err(PolicyError::UnsupportedStorageProbe)));
    }
}
```

Add identity-replacement and symlink-root tests using real temporary directories. Test mountinfo escaping (`\040`, `\011`, `\134`), oversized input, malformed numeric IDs and checked multiplication overflow.
- [ ] **Step 2: RED.** `cargo test --lib sandbox_policy::storage > /tmp/chimera-d0-storage.log 2>&1` — missing storage functions/tests fail.
- [ ] **Step 3: Implement read-only Linux collection.** Pin existing root using `open_existing_root`; `fstat`, `fstatvfs`, and `/proc/self/mountinfo` establish device/inode/mount identity and total blocks × fragment size using checked arithmetic. Open/read mountinfo with a 4 MiB bound; require a unique exact mount-point match, device consistency and filesystem-root `/`. Collect nested mounts and every other mount of the same backing filesystem; reject writable nested mounts and aliases outside the bound root. Compare root `fstat` and path identity again after collection. Validate ext4/XFS only, total bytes nonzero and `<= max_bytes`, and parent on another device. The root must enclose work/tmp/job-resources/cache/actions/externals/tool-cache: no separate exempt cache path is accepted. Non-Linux returns `UnsupportedPlatform`. Do not allocate disk to exhaustion or run quota-changing commands.
- [ ] **Step 4: GREEN.** Repeat Task 4 command. The live dedicated-filesystem check is an ignored native test `native_dedicated_storage_bound`, compiled only under `#[cfg(all(target_os = "linux", feature = "acceptance-tests"))]`, reading `CHIMERA_QUALIFICATION_ROOT`. It directly holds an exclusive no-follow `flock` lock at `/run/lock/chimera-qualification.lock`, the same lock E0 uses, without importing E0 test-support code into the library. Missing provisioned dedicated storage produces a failed/inconclusive diagnostic, never success. Run only in the serialized native qualification session; ordinary ignored Docker runs do not compile this test.
- [ ] **Step 5: Commit.** `git add src/sandbox_policy.rs src/sandbox_policy/storage* && git commit -m "feat: prove dedicated sandbox storage bounds from live identity"`

### Task 5: Capability descriptors carry attempt identity, never host authority

**Files:** Create `src/sandbox_policy/capability.rs`, `capability_test.rs`; modify facade. Read but do not rewrite `src/cache/auth.rs`, `server.rs`, `manager.rs`, `upload.rs`.

**Interfaces:**

```rust
pub enum CapabilityService { Cache, Artifact, Deploy }
pub struct CapabilityDescriptor {
    pub attempt_id: uuid::Uuid,
    pub service: CapabilityService,
    pub grant_id: uuid::Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub local_path: String,
}
pub fn validate_descriptor(descriptor: &CapabilityDescriptor,
    attempt: uuid::Uuid, now: chrono::DateTime<chrono::Utc>) -> Result<(), PolicyError>;
pub struct CacheCapabilityBinding {
    attempt_id: uuid::Uuid,
    handle: crate::cache::auth::CapabilityHandle,
}
impl CacheCapabilityBinding {
    pub fn new(attempt_id: uuid::Uuid,
        handle: crate::cache::auth::CapabilityHandle) -> Result<Self, PolicyError>;
    pub fn attempt_id(&self) -> uuid::Uuid;
    pub async fn revoke(self, authority: &crate::cache::auth::CacheAuthority);
}
```

Descriptors are non-secret metadata, not authorization proofs. No Deserialize for an authority-bearing binding, no raw bearer token getter or serialization, and Debug redacts the binding. The existing cache epoch and registration checks remain authoritative. Artifact/deploy descriptor validation succeeds only structurally; doctor marks their runtime bridge as unavailable. There is no generic upstream URL, socket, host path, Docker service variant or user-controlled HTTP proxy target.

- [ ] **Step 1: Add tests.** Paths must exactly equal `/run/chimera/capabilities/<grant-uuid>.sock`; reject path traversal, NUL, percent encoding, `/var/run/docker.sock`, production socket and UUID mismatch. Reject nil attempt/grant UUID and `expires_at <= now`. Assert wrong attempt fails even with a valid grant.

```rust
#[tokio::test]
async fn binding_revokes_only_its_existing_cache_epoch() {
    use crate::cache::auth::{CacheAuthority, CacheScope, JobCapabilityClaims};
    let authority = CacheAuthority::new();
    let claims = JobCapabilityClaims {
        scope: CacheScope { repo: "synthetic/repo".into(), git_ref: "refs/heads/main".into(),
            default_ref: "refs/heads/main".into() }, job_id: "synthetic-job".into(),
    };
    let handle = authority.register_job("synthetic-old", claims.clone(), chrono::Utc::now())
        .await.unwrap();
    let old = CacheCapabilityBinding::new(uuid::Uuid::new_v4(), handle).unwrap();
    authority.register_job("synthetic-new", claims, chrono::Utc::now()).await.unwrap();
    old.revoke(&authority).await;
    assert!(authority.authenticate("synthetic-old").await.is_err());
    assert!(authority.authenticate("synthetic-new").await.is_ok());
}
```

Add the existing handle-reuse regression: clone old handle, revoke, register the same token in a new epoch, and revoke the old clone again; new registration remains valid. Use real `CacheAuthority`, not an internal mock.
- [ ] **Step 2: RED.** `cargo test --lib sandbox_policy::capability > /tmp/chimera-d0-capability.log 2>&1` — missing bindings fail.
- [ ] **Step 3: Implement structural validation and a thin cache adapter.** `CacheCapabilityBinding::revoke` delegates to `CacheAuthority::revoke(&handle).await`; immediate revoke remains the existing runner guard's responsibility until lifecycle integration. Do not create a competing RAII/async Drop owner. Match exact generated local path, supported enum and nonnil IDs; compare UTC expiry to supplied trusted time. Do not modify cache scope rules, upload ownership, grant lifetime or listener binding.
- [ ] **Step 4: GREEN.** Repeat Task 5 command; run `cargo test --lib cache::auth > /tmp/chimera-d0-cache.log 2>&1` to preserve current capability behavior.
- [ ] **Step 5: Commit.** `git add src/sandbox_policy.rs src/sandbox_policy/capability* && git commit -m "feat: define attempt-scoped capability bridge contracts"`

### Task 6: Read-only doctor, render-only install command, and activation regression

**Files:** Create `src/sandbox_policy/doctor.rs`, `doctor_test.rs`, `tests/sandboxed_policy_test.rs`, `docs/sandboxed-policy.md`; modify `src/sandbox_policy.rs`, `src/cli.rs`, `src/cli_test.rs`, `src/daemon_test.rs`.

**Interfaces:**

```rust
pub enum CheckStatus { Satisfied, Failed, Unverified }
pub struct DoctorCheck { pub id: String, pub status: CheckStatus, pub category: String }
pub struct DoctorReport {
    pub schema_version: u32, pub activation_available: bool,
    pub checks: Vec<DoctorCheck>, pub policy_digest: Option<String>,
}
pub fn inspect_policy(root: &std::path::Path) -> Result<DoctorReport, PolicyError>;
pub fn inspect_install_plan(root: &std::path::Path) -> Result<InstallPlan, PolicyError>;
// CLI additions:
// Doctor { root: PathBuf, json: bool }
// InstallPolicy { root: PathBuf, render: bool } // --render is required by clap
```

`CheckStatus`, `DoctorCheck` and `DoctorReport` derive Serialize; stable IDs are `platform`, `network_config`, `network_effective`, `network_negative_probes`, `storage_bound`, `capability_bridge`, `activation`. `Satisfied` describes a single observed check, never overall support. `activation_available` is always false in D0; `activation` is always Failed/category `sandboxed_unavailable`.

- [ ] **Step 1: Add CLI and gate tests.** Test `doctor --root <existing> --json`, reject `install-policy` without `--render`, accept `install-policy --render --root <existing>`, and reject `--apply`. Subprocess tests use `env!("CARGO_BIN_EXE_chimera")`, a temporary root and `std::process::Command`. Assert missing config is an error and is not created; tree contents/inodes before and after inspection are unchanged. Add daemon regression with valid network/storage configuration: it still reports `sandboxed execution profile is not available in this build` and creates no job resources, cache state or runner session.

```rust
#[test]
fn report_cannot_turn_diagnostics_into_activation() {
    let report = DoctorReport {
        schema_version: 1, activation_available: false,
        policy_digest: None,
        checks: vec![DoctorCheck { id: "activation".into(),
            status: CheckStatus::Failed, category: "sandboxed_unavailable".into() }],
    };
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["activation_available"], false);
    assert_eq!(json["schema_version"], 1);
}
```

Add malicious config with a synthetic secret in an invalid field; output includes field/category only. Test `doctor` on non-Linux emits platform Failed and does not panic.
- [ ] **Step 2: RED.** `cargo test --lib cli_test > /tmp/chimera-d0-cli.log 2>&1` and `cargo test --test sandboxed_policy_test > /tmp/chimera-d0-command.log 2>&1` — new commands/reports fail.
- [ ] **Step 3: Implement CLI consumers and collection.** Use `load_config_if_exists`, not `load_config` or `Daemon::load`, so diagnostics do not create files or acquire the runtime root lock. Require existing root. Collect interface addresses with libc `getifaddrs` and guard/free the returned allocation. Read boot ID, self cgroup, `/run/systemd/system` presence, container indicators and relevant platform prerequisites; failures are checks, not silent defaults. If outside the exact service cgroup, `network_effective` and `network_negative_probes` are Unverified. Do not attach eBPF or infer enforcement from unit text. D0 doctor may inspect static systemd properties via bounded read-only `systemctl show chimera.service` invocation with a fixed argument vector, cleared environment except PATH, 5 s timeout and 64 KiB output cap; it still marks live BPF/sentinel proof Unverified until runtime collection is integrated. `inspect_install_plan` needs valid policy plus complete live host addresses, but no affirmative activation result. Emit JSON/text to stdout only; exit nonzero whenever doctor has Failed/Unverified checks. Render command exits zero after producing a plan and explicitly prints `activation_available: false`.

Document the dedicated-filesystem requirement, quota probe limitations, service-wide egress scope (including supervisor/slirp), DNS through public reachable resolver/capability integration, policy re-render/restart on host address changes, exact S-01/S-05 native evidence still required, and shared-kernel residual risk. The operator installation model describes copying the reviewed fragment and restarting as later authorized operations; this command does neither.
- [ ] **Step 4: GREEN and final regression.** Run the two Task 6 commands, then:

```bash
cargo build > /tmp/chimera-d0-build.log 2>&1
cargo clippy -- -D warnings > /tmp/chimera-d0-clippy.log 2>&1
cargo test > /tmp/chimera-d0-all.log 2>&1
git diff --check
```

Inspect each exit status and `rg 'test result:|^failures:' /tmp/chimera-d0-all.log`. No `allow(dead_code)` or broad unused allowances; public contracts have CLI/test consumers. Since this slice changes no Docker implementation or Docker test, the ignored Docker suite is not an additional D0 requirement. Any later scope expansion into those files restores `CLAUDE.md`'s ignored-suite requirement.
- [ ] **Step 5: Commit.** `git add src/sandbox_policy.rs src/sandbox_policy/doctor* src/cli.rs src/cli_test.rs src/daemon_test.rs tests/sandboxed_policy_test.rs docs/sandboxed-policy.md && git commit -m "feat: expose sandbox policy diagnostics without activation"`

## Completion evidence and D1 handoff

D0 is complete when configuration round trips, policy/evidence/capability tests and CLI tests pass, dedicated storage observations are honest about provenance, and the unchanged daemon gate rejects every sandboxed configuration before runtime side effects. No native security claim is made from portable tests or doctor rendering.

D1 consumes these contracts to apply the reviewed unit policy, collect actual eBPF/sentinel evidence in the service generation, enforce RootlessKit/slirp flags, and establish domain-local bridges with lifecycle revocation. Project-quota/btrfs collectors are needed only if the operator selects those storage mechanisms; neither receives a false pass in D0. E0 records incomplete checks as blocked. Actual activation belongs to final Plan E after B–D runtime integration and all S-01…S-16 evidence, and is not a task in this document.
