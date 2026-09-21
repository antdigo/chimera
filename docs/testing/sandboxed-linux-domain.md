# Sandboxed Linux domain: native qualification

Status: **implementation-only; native gate NOT QUALIFIED**. The public
`sandboxed` profile remains fail-closed. This document is a handoff for the
dedicated Debian test host, not an assertion that isolation passed.

## What the current harness proves

The acceptance-feature-only `NativePrerequisites` checks three explicit paths:
`CHIMERA_NATIVE_TEST_ROOT`, `CHIMERA_NATIVE_TEST_CGROUP`, and
`CHIMERA_NATIVE_TEST_BINARY`. Each must be absolute and already canonical. It
rejects root UID, common container markers, non-Debian or non-systemd PID 1,
a non-private/non-empty fixture root, a non-executable binary, non-cgroup2 or
non-writable cgroup controls, absent helpers, absent kernel syscalls, multiple
or too-small subordinate ranges, and Debian package metadata not reporting
RootlessKit 2.3.5. The metadata check is not a runtime binary identity proof;
the real native fixture must pin and authenticate the executable before use.
It does not create or delete fixture resources. Only test code reads these
environment variables; daemon startup does not.

The 15 Task 12 native cases are present by name and `#[ignore]` solely to
avoid accidental execution without a dedicated host. Explicit selection is
**expected to fail**, including after a complete preflight: the cases have no
qualified production-path assertion yet. They are not acceptance passes.

## Blocking production-private seam

`StrictBackendBuilder` requires a `CleanupWorkerConfig` when subordinate-owned
files must be removed. Its pinned executable and `newuidmap`/`newgidmap`
capabilities have no safe constructor for the native fixture. Starting a
domain without that retained teardown authority would make an apparent test
success unsafe and could strand a live cgroup or writable tree. The next
implementation must add a narrowly scoped constructor that pins and validates
those three executable descriptors, carries them through rollback/recovery,
and then wire the fixture to the existing private builder, command protocol,
destroy, and locked reconcile paths. No separate deletion implementation is
authorized. Each named case then needs its specific real assertion and
zero-resource inventory, including crash barriers and the dedicated bounded
I/O fixture device. Until this is done, do not remove `#[ignore]` or claim the
matrix passes.

## Native operator gate (pending)

Use one dedicated non-root service account and systemd-delegated cgroup v2 on
native Debian. The fixture root must be an empty `0700` directory owned by
that account. The cgroup path must be a canonical delegated descendant of
`/sys/fs/cgroup`. The binary path must identify the built Chimera executable.
No per-job VM, user, helper daemon, or unit is required. The I/O case also
requires a separately configured, dedicated fixture filesystem/block device;
raw device writes are forbidden.

```bash
export CHIMERA_NATIVE_TEST_ROOT=/absolute/private/fixture
export CHIMERA_NATIVE_TEST_CGROUP=/sys/fs/cgroup/absolute/delegated/fixture
export CHIMERA_NATIVE_TEST_BINARY=/absolute/path/to/chimera
cargo test --features acceptance-tests job::execution_domain::linux::native_test -- --ignored --test-threads=1 --nocapture
```

Before marking this gate qualified, retain the exact Debian/kernel/systemd/
RootlessKit versions, delegated controllers, subordinate mappings, nonzero
executed case count, case durations, and a final zero-resource inventory.
Docker Desktop or containerized Linux compile is portability evidence only.

## Contract handoff

Plan C owns the distinct `DockerEndpoint`, logical path translation, private
daemon cgroup and socket lifetime. Plan D owns disconnected/slirp policy,
network denial, scoped service capabilities, and cancellation/revocation
ordering. Plan E owns atomic production activation and S-01…S-16 release
qualification. None may infer a native Plan B security pass from this harness.
