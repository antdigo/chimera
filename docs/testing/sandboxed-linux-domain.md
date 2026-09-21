# Sandboxed Linux domain: native qualification

Status: **implementation-only; native gate NOT QUALIFIED**. The public
`sandboxed` profile remains fail-closed. This document is a handoff for the
dedicated Debian test host, not an assertion that isolation passed.

## What the current harness proves

The acceptance-feature-only `NativePrerequisites` checks three explicit paths:
`CHIMERA_NATIVE_TEST_ROOT`, `CHIMERA_NATIVE_TEST_CGROUP`, and
`CHIMERA_NATIVE_TEST_BINARY`. Each must be absolute and already canonical. It
rejects root UID, common container markers, non-Debian or non-systemd PID 1,
a non-private fixture root with stale entries, a non-executable binary, non-cgroup2 or
non-writable cgroup controls, absent helpers, absent kernel syscalls, multiple
or too-small subordinate ranges, and Debian package metadata not reporting
RootlessKit 2.3.5. The package check is not native execution evidence.
Only test code reads these environment variables; daemon startup does not.

The 15 Task 12 native cases remain `#[ignore]` to prevent accidental execution
without a dedicated host. B12a implements only
`native_pid_one_private_root_and_control_fd`. The other 14 cases explicitly
fail when selected, before allocating a fixture. The full matrix is not green.

## B12a fixture implementation (native execution pending)

`CleanupWorkerConfig::verified` now pins the Chimera ELF and the two setuid
mapping helpers. Each must be root-owned, have no group/other write permission,
have exactly one link, and reside under root-owned directories without
group/other write permission. Symlinks and scripts are refused. Mode, owner,
inode, device, mount, size, link count and change timestamp are checked again
before execution through the retained descriptor. Chimera must not be setuid;
the mapping helpers must be setuid root.

The fixture holds the exclusive resource-root lock and constructs one
`KernelDomain` through `StrictBackendBuilder`, with the production rootfs,
hardening, command protocol and retained teardown authority. It never publishes
public `Ready`. `run(&mut self)` prefixes scripts with `set -eu`;
`destroy(&mut self)` uses the sole `StrictCleanupRecord` and records the report
for repeated calls. These mutable test-only signatures preserve the production
owner; `kernel(&self)` remains a borrowed view. After destruction only test
inventory remains. An unwinding test also attempts production teardown. Failed
construction or unproved teardown retains the root lock and available cleanup
record in process-local quarantine; stale durable resources refuse reuse after
process exit. Crash recovery qualification is still a separate unfinished case.

The first case checks PID1 comm, absent old root and host paths, early shell
failure, and control isolation. A test-only C probe checks inherited descriptors
before it opens files, then checks every visible `/proc/1/fd` entry (or, when
listing is denied, probes every descriptor pathname below the inherited hard
FD limit), `pidfd_getfd`, and ptrace denial. The FD limit must be finite and no
greater than 1,048,576; the command still has a 30-second deadline. Linux builds
with `acceptance-tests` compile a static probe with `cc` and embed it into the
test binary; preparation installs those bytes into the fresh bound work
directory. The build requires C headers and static libc, and refuses cross
compilation. Normal production builds and the native runtime need no probe
compiler. No compiler paths are added to the sandbox mount allowlist.
`/usr/share/zoneinfo/Etc` supplies the fixed immutable
inputs for both otherwise-unused cache targets and must pass the existing
strict rootfs checks.

Zero-resource assertions require the recorded launcher pidfd to report exit,
both exact attempt and cleanup cgroups to be absent, the active root to be
empty, and no supervisor mount below the recorded attempt path. Production
destroy additionally proves empty cgroups, reaps the launcher and releases
namespace handles before filesystem deletion. No process-name kills are used.

## Native operator gate (pending)

Use one dedicated non-root service account and systemd-delegated cgroup v2 on
native Debian. The fixture root must be an empty `0700` directory owned by
that account. Successful cases retain only `.chimera.lock` and an empty `active`
directory as reusable scaffolding. The cgroup path must be a canonical delegated
descendant of `/sys/fs/cgroup`. The binary path must identify the built Chimera
executable installed with the root-owned policy above.
No per-job VM, user, helper daemon, or unit is required. The I/O case also
requires a separately configured, dedicated fixture filesystem/block device;
raw device writes are forbidden.

For B12a, unit-level limits must already read back `memory.high=268435456`,
`memory.max=536870912`, `memory.swap.max=0`, `cpu.max="150000 100000"`,
`cpu.weight=100`, `pids.max=256`, and `io.weight="default 100"`. The same
explicit limits are applied to the attempt. No device-specific I/O qualification
is claimed by this first case. The test requires no supplementary groups and
must be the only process in the delegated root when it prepares the supervisor
subgroup. Build outside the qualification unit, then have the dedicated unit
execute the built library test binary directly: leaving a parent `cargo` process
in that delegated root correctly fails production preflight.

Do not stop or alter the live production `chimera.service` to run this fixture.
The separate no-downtime qualification design governs deployment; these commands
are a build/filter reference, not authorization to modify a production unit.

```bash
export CHIMERA_NATIVE_TEST_ROOT=/absolute/private/fixture
export CHIMERA_NATIVE_TEST_CGROUP=/sys/fs/cgroup/absolute/delegated/fixture
export CHIMERA_NATIVE_TEST_BINARY=/absolute/path/to/chimera
cargo test --features acceptance-tests job::execution_domain::linux::native_test -- --ignored --test-threads=1 --nocapture
```

For the B12a slice, pass the already-built test executable this exact filter:
`job::execution_domain::linux::native_test::native_pid_one_private_root_and_control_fd --exact --ignored --test-threads=1 --nocapture`.
The full command above intentionally still fails the 14 unfinished cases.

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
