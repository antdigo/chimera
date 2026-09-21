# Plan B Task 11 — deterministic Linux ownership reconciliation

## Delivered

- Added one locked reconciliation transaction over the descriptor-bound active and service-cgroup roots. `RootLockProof` is created only from a live exclusive `RootLock`, retains the flock and pinned root descriptor, and carries an in-process single-flight gate so two recovery calls cannot inventory or mutate concurrently.
- Admission stays closed until reconciliation succeeds. Any inventory, provenance, neutralization, removal, fsync, or final re-inventory failure poisons the execution-domain root and leaves admission closed. The production `sandboxed` profile remains rejected before resource-root, cache, or session preparation; daemon startup does not call Linux reconciliation before Plan E.
- Inventory retains exact directory and cgroup descriptors while building a sorted union of canonical UUID attempts, `attempt-<uuid>` cgroups, and short-lived `cleanup-<uuid>` bootstrap/cgroup artifacts. Nil/noncanonical names, unknown active-root entries, symlink/special cgroup entries, binding changes, unsafe modes, and unreadable inventory preserve evidence and block filesystem mutation.
- Recovery neutralizes every retained cleanup and attempt cgroup before any filesystem mutation. It preserves the first read/kill/proof error while still attempting the bounded cgroup-wide KILL and final empty proof, removes cleanup cgroups before bootstrap directories, reuses Task 10 descriptor-bound tree/cgroup removal, removes attempt cgroups last, fsyncs the active root, and requires a fresh empty union inventory.
- Added the separate minimal Linux journal v2 (`backend`, canonical `attempt_id`, lifecycle `state`, fixed `layout_version`). Trusted-host v1 remains unchanged and diagnostic-only for Linux recovery. Every v2 state except persisted `Destroyed` is recoverable; malformed, truncated, mismatched, symlinked, or `.next` evidence is preserved and blocks startup.
- Journal-free recovery is deliberately limited to the exact empty creation-prefix directory. A valid v2 directory uses the existing complete Task 10 removal-tree, ownership, device/mount, and no-mount proofs. Subordinate-owned nonempty trees remain fail-closed pending the real mapped-owner qualification in Task 12.

## TDD and failure coverage

- Portable recovery tests cover union sorting/deduplication, canonical identity rejection, cleanup/attempt neutralization ordering, first-error preservation, every destructive-stage failure, outside-canary preservation, and final re-inventory race detection.
- Linux descriptor tests cover admission remaining closed until locked reconciliation, cgroup-only, v2 directory-only, exact empty journal-free orphans, rejection of a nonempty journal-free layout, corrupt metadata preservation after cgroup neutralization, and unknown/wrong-mode active entries.
- Root-lock tests prove the recovery capability retains the exclusive flock after the original lock object is dropped and serializes same-process callers.
- Journal tests cover the exact v2 schema, all lifecycle states, persisted `Destroyed`, v1 diagnostic non-authority, missing versus present-invalid records, backend/layout mismatch, truncation, symlink/`.next` preservation, and rejection of a diagnostic PID while its live sentinel remains untouched.
- Existing Task 10 cgroup/dirfd suites continue covering absolute traversal deadlines, kill/read failures, residual nested cgroups, replaced descriptors, symlinked controls, mount/device changes, swapped ancestors/inodes, and failure-atomic removal/fsync.

## Verification

- `cargo fmt --all -- --check`: exit 0.
- `cargo clippy --all-targets --all-features -- -D warnings`: exit 0.
- Host `cargo test job::execution_domain::linux::reconcile_test -- --nocapture`: **6 passed**.
- Native arm64 Linux container recovery suite: **11 passed**.
- Host journal suite: **16 passed**; native arm64 Linux journal suite: **27 passed**.
- Host daemon suite outside the restricted sandbox: **39 passed**; native arm64 Linux daemon suite: **42 passed**. The Linux rerun used a target-backed `TMPDIR` because the existing daemon guard intentionally rejects a resource root under the container's shared `/tmp` ancestor.
- Host execution-domain suite outside the restricted sandbox: **135 passed**. The restricted run produced three classified fixture `EPERM` failures while creating Unix sockets/FIFOs; the unchanged elevated rerun was green.
- Native arm64 Linux `cargo check --offline --lib`: exit 0 without warnings. The container image did not include the `clippy` component; the complete host Clippy gate above is green.
- Final elevated `cargo test --all-targets --all-features -- --test-threads=1`: library **1094 passed, 23 ignored**; every integration target passed.
- `git diff --check`: exit 0.

## Qualification boundary

Task 11 proves the recovery state machine, durable provenance rules, descriptor capability flow, and native Linux recovery fixtures without activating the public sandbox. Task 12 still owns qualification on a real Debian host with systemd-delegated cgroup v2, real RootlessKit and subordinate UID/GID mappings, subordinate-owned nonempty writable trees, live/nested descendants, mounts, cleanup-worker crash/timeout, and peer-attempt canaries. No pathname, PID, journal text, trusted-v1 record, or permissive owner fallback was introduced for that missing qualification.
