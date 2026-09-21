# Sandboxed qualification on one Debian host

E0 checks the qualification harness. Its native entrypoint always exits nonzero
and, after successful preflight and lease acquisition, writes a complete
S-01…S-16 **Blocked / BackendUnavailable** report. It never invokes a runtime
driver, starts attempts, runs Docker, sends lifecycle signals or launches stress,
even when the configured driver executable exists. `activation_available` stays
false. The shipped `chimera start` still rejects `profile = "sandboxed"` with
`sandboxed execution profile is not available in this build`.

Fixture and nested Docker reports cannot qualify a release. E0's reported
`cleanup_confirmed: true` means this completed preflight-only invocation launched
no workload; it does not claim successful native teardown. A generic blocked
report defaults to cleanup unconfirmed. No missing measurements are synthesized
as zero-cost successes.

## Operator preprovisioning

Use the existing single bare-metal Debian/systemd host, existing non-root Chimera
service account and existing service unit. No second machine or VM is required.
The harness rejects non-Linux, root, containers, detected virtualization and hosts
without unified cgroup v2. Run it inside that service unit's cgroup, not an
interactive login shell: preflight records the service identity. Do not run it
alongside a daemon migration or another qualification invocation.

Before scheduling the maintenance window:

1. Review the exact checkout/commit and prepare its Rust toolchain and dependencies
   under the service account, including `/usr/bin/git`. Give the service an explicit
   PATH containing Bash and Cargo; systemd does not load the login shell's setup.
   The harness reads HEAD from that checkout; keep it
   unchanged during the run. E0 reports do not establish build provenance for E1.
2. Provision a dedicated qualification filesystem with an operator-approved byte
   bound. Create `/var/lib/chimera-qualification` and its `reports` child owned by
   the service UID, mode `0700`. They must be distinct from production roots and
   Docker stores. All path components must be actual directories, with no symlink
   aliases. Ancestry must be root/service-owned and not group/world-writable,
   except root-owned sticky directories. Do not use `/`, a home directory or a
   shared temporary root. The harness creates only UUID-owned child directories.
3. Have the operator precreate the exact
   `/run/lock/chimera-qualification.lock` as a service-owned `0600` regular file
   with one link. `/run/lock` must already be root-owned and sticky; do not change
   its permissions to make preflight pass. There must be no active marker or
   `.claim` directory from a prior run. Do not replace an existing lock inode.
   Provision the file again through the site's normal boot provisioning because
   `/run` is volatile; a reboot is never a recovery procedure for an unfinished run.
4. Create an absolute regular JSON config, e.g.
   `/etc/chimera/qualification.json`, readable by the service account and writable
   only by the operator. It must not be a symlink. The Rust reader opens the final
   file no-follow/nonblocking, checks regular-file metadata and caps input at
   1 MiB. Keep config and ancestry unchanged during execution.

Use [the synthetic schema example](../tests/fixtures/qualification/config.json)
to see field names, **not sizing recommendations**. Replace its documentation
addresses and tiny synthetic thresholds with reviewed local values. Unknown
fields, zero required bounds and invalid limits are rejected. Required inputs:

| Input | Operator decision |
| --- | --- |
| `root`, `report_root` | Dedicated bounded qualification filesystem and strict descendant report directory |
| `lock_file`, `active_marker` | Exactly `/run/lock/chimera-qualification.lock` and `/run/lock/chimera-qualification.active`; no overrides |
| `driver` | Absolute path outside the qualification root, under a protected parent; may be absent in E0. An existing file must be regular, executable, root/service-owned, not shared-writable or set-ID |
| `max_case_ms`, `cleanup_deadline_ms`, `max_parallel_builds` | Explicit deadlines (cleanup no greater than case) and 1–40 concurrency bound |
| `execution_resources.global`, `.attempt` | Validated finite memory/swap/PID/CPU/I/O limits; E1 also requires device-qualified I/O bounds and actual readbacks |
| `minimum_production_memory_bytes`, `maximum_chimera_memory_bytes`, `maximum_chimera_pids` | Agreed reserve and Chimera budgets; no native defaults |
| `production_sentinel`, `sentinel_p99_ms` | Positive production-SLO control outside Chimera's cgroup and explicit absolute p99 ceiling |
| `negative_sentinels` | Distinct, listening loopback, host, LAN and production controls with exact containing denied CIDRs, separate from the SLO endpoint |
| `public_registry_url` | HTTPS positive endpoint without userinfo, query or fragment |

The controls can live on the same host using its assigned interfaces. Verify
positive connectivity outside the sandbox before considering any negative probe;
an endpoint that never listened proves nothing. E0 validates configuration only
and does not collect live sentinel evidence. E1 must provide independently owned
live controls and measurements, including a 10 s SLO baseline.

## Serialized invocation and service sequencing

Stop the target Chimera unit after its jobs have drained, and verify it is stopped.
Keep unrelated production services running. As the operator, inspect
`systemctl cat chimera.service` (substitute the actual existing unit name) and
prepare a temporary drop-in for this same unit and service account. Preserve the
site's approved resource and delegation settings, set `Type=oneshot` and
`Restart=no`, and replace `ExecStart` with the absolute checkout path to
`scripts/qualification/native.sh /etc/chimera/qualification.json`. Clear inherited
start/stop hooks that would launch or operate the production daemon. Do not create
a second concurrent service or relax resource limits for the harness. Check the
effective unit before starting it; normal systemd reload/start operations require
the operator's existing privileges, not root execution of the harness.

The command executed by that unit is:

```bash
/absolute/checkout/scripts/qualification/native.sh /etc/chimera/qualification.json
```

The script accepts exactly one absolute regular non-symlink config path, changes
to its own checkout, sets `TMPDIR` to `target/chimera-tests`, and invokes:

```bash
cargo test --features acceptance-tests --test sandboxed_qualification_test \
  native_sandboxed_release_qualification -- --ignored --exact --test-threads=1
```

It records output in a unique `0600` log beneath that TMPDIR and prints its path
to the service journal. Its exit status is Cargo's exit status. There is no
environment or feature override for activation, platform checks, machine lock,
report coverage or missing driver authority. `CHIMERA_QUALIFICATION_CONFIG` only
selects the config input. The feature compiles the ignored test; it changes no
production behavior. Ordinary `cargo test -- --ignored` does not include this
native test unless the feature is explicitly enabled.

The Rust `NativeLease`, not Bash, holds the fixed machine-wide advisory lock
through publication. Different checkout/output paths cannot evade it. Native
scenarios must eventually execute one at a time; 20/40 attempts inside an
explicitly requested wave are semantic concurrency, not parallel test scheduling.

After E0 exits, inspect the captured log and
`<report_root>/<run UUID>/report.json` plus `report.md`. Every required case must
be Blocked/BackendUnavailable, with no metrics, driver digest or Passed checks.
The Markdown report says `NATIVE / INCOMPLETE`. A normal completed publication
fsyncs the reports and moves the active marker into a retained
`chimera-qualification.active.completed.<UUID>` audit directory. It leaves the
UUID-owned report and root directories as evidence.

Malformed config, unsupported host, busy lock or unfinished marker exits with
only a closed error category. Without validated config and a held lease there is
no trusted report destination, so these errors do not write an ad hoc report.
A report-write error also exits nonzero, retaining the active marker; partial
artifacts are forensic evidence and must not be interpreted as completion.

After reviewing a clean E0 completion, restore the original unit definition,
reload systemd and restart the existing service in its previously supported
profile. Verify its normal health. Do not switch production to `sandboxed`.
The CLI already acquires its root storage lock before profile validation; portable
activation regression tests preprovision that lock and verify no further changes.

## Interrupted runs and E1 obligations

E0 has no outside watchdog or authenticated automatic orphan recovery. Killing
the harness releases the advisory lock but leaves the fsynced unfinished marker;
the next invocation fails with `UnfinishedRun`. Manual quarantine is required.
Preserve the marker, claim/completed records, UUID-owned directories and logs;
leave qualification disabled pending operator investigation. Never remove guessed
paths, kill processes by saved PID/PGID, clear markers to retry, reboot to clear
`/run`, prune Docker globally, flush host caches, remount filesystems or change
sysctls. E0 supplies no recovery command. Inspect exact retained ownership records
before any separately approved recovery; E1 must define its authenticated method.

Before S-01…S-16 can actually execute, E1 must supply:

- The real B–D runtime driver and pinned run-owned cgroup/process identities,
  including boot ID/start-time validation and authenticated post-crash cleanup.
- An independent unprivileged watchdog outside the workload cgroup, bounded
  deadlines/storage, and operator-approved production-root/CIDR/storage/benchmark
  inventory. E0 does not verify the live filesystem byte bound.
- Independent native cgroup limit readback for global and every attempt/device,
  PID-guarded PSS and CPU/I/O/event sampling, production reserve and sentinel SLO
  measurements before/during/after the workload. Missing or inaccessible samples
  remain incomplete; nested VFS RSS cannot establish sizing.
- Complete cold, warm, failure, cancel and restart waves, followed by next-tenant
  and idle checks, with exact runtime/image/log/lease/artifact integration gaps
  retained as blocked. Bounded completed-record retention must also be defined.

Pinned action workloads use synthetic registry credentials and an owned test
registry/network only, never production deployment credentials or Docker sockets.
Use [the macOS Docker runbook](testing-macos-docker.md) solely for existing nested
smoke tests. Neither those tests nor E0 completion authorizes removing the
production activation gate; that requires accepted native E1 evidence.
