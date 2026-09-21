# Plan B Task 10 — bounded destruction, rollback, and mapped-owner cleanup

## Delivered

- Added one bounded terminal destroy driver. It closes admission, persists `Destroying`, attempts graceful shutdown and pidfd-scoped TERM, proves recursive cgroup emptiness, escalates once through `cgroup.kill`, reaps/drains, closes retained handles, proves mount absence, removes exact retained sockets, cleans the descriptor-bound filesystem, removes cgroups bottom-up, fsyncs the active root, and only then marks the attempt destroyed. The first failure is retained while later safe neutralization still runs; no uncertain proof can reach unlink.
- Consolidated strict ownership in `StrictCleanupRecord`: kernel domain, attempt cgroup, bound active/attempt/rootfs directories, lifecycle journal, writable roots, exact runtime-socket capabilities, mapped cleanup configuration, and a reverse-discharged creation-stage stack. Provisioning failures use the same destroy path; partial cgroup construction has deterministic rollback, and a failed rollback quarantines/poisons instead of publishing partial `Ready` state.
- Made manager destruction cancellation-safe. It performs bounded workspace-reader revocation, keeps the backend outside command-future unwind, returns the backend's real `DestroyReport`, and drops retained backend descriptors before releasing the clean capacity permit. A failed destroy retains the exact backend/partial cleanup authority and capacity permit for retry. Manager-owned reader revocation is not treated as proof for external cache/deploy/artifact/service revocation.
- Added cgroup membership capture through pidfds and recursive empty proof with bounded cooperative polling. A timeout cannot leave detached blocking proof work. Cleanup workers receive a deterministic short-lived sibling cgroup and its bootstrap evidence is retained if kill/empty/remove cannot be proven.
- Added the short-lived mapped-owner cleanup authority without a resident helper or per-job user pool. RootlessKit is configured with a static single subuid/subgid range and its actual uid/gid maps plus empty supplementary groups are verified. The pre-Tokio internal worker receives bounded `SOCK_SEQPACKET`/`SCM_RIGHTS` batches, enters fresh user/mount namespaces, pivots into a minimal root, closes unrelated descriptors, inventories every allowlisted writable root before mutation, and revalidates parent/name/open-FD identity before bottom-up unlink and fsync.
- Worker inventory separates namespace-visible ownership from supervisor-verified raw host ownership, rejects overflow/unmapped aliases, foreign mounts/devices/unknown roots, and treats symlink/FIFO/hardlink entries as non-followed leaves. RootlessKit and future Docker sockets use typed root/name/inode/mount/owner capabilities; ordinary `BoundDir` same-EUID checks were not weakened.
- Pinned the cleanup executable and `newuidmap`/`newgidmap` helpers with retained `O_PATH` identities and executes them via `/proc/self/fd`; helper waits are deadline-bounded and kill/reap on timeout. The strict backend retains validated mount/PID namespace descriptors received over `SCM_RIGHTS`, and closes them before the no-mount proof. Public `sandboxed` activation remains fail-closed and trusted-host behavior remains unchanged.

## TDD and review closure

- Portable destroy fakes cover exact ordering, graceful versus forced kill, TERM/protocol and cgroup-read errors, every proof/destructive failure, first-error retention, and the invariant that failure before absence proof cannot mutate the filesystem.
- Manager/reader tests cover bounded reader revocation, dropped replies/handles, command cancellation with post actions, panic cleanup, poison-before-permit, and external capability revoke before destroy/completion.
- Native Linux tests cover exact static map parsing, map text verification, credential/FD-bound protocol, whole-inventory-before-mutation, budget exhaustion, peer canaries, directory swaps, socket identity, transactional cgroup creation, joined timeout proof, and launcher bootstrap/shutdown.
- Independent pre-audit findings were closed for lost first errors, pre-recursion directory swaps, missing Docker writable root, partial cgroup ownership, mutable helper paths, unbounded helper waits, bootstrap capability leakage, socket absence retry, protocol-error kill escalation, external-revocation authorization, and backend-FD release ordering.
- Independent post-commit review findings were all accepted and closed: external revocation now has explicit `Unpublished`/`Required`/`Proven` states; failed teardown retains retry authority and permit; namespace capabilities are retained and identity-checked; `KernelReady` leaves the durable journal in `Provisioning`; every traversal/helper wait uses the original absolute deadline; and unused future-C1 production seams were removed or deferred to tests.
- Retry tests cover `Quarantined` teardown continuation, exact record retention, no fabricated external revocation proof, stage-ledger idempotence, namespace-handle transfer/closure, and absolute traversal/helper deadlines.

## Verification

- `cargo fmt --all -- --check`: exit 0.
- `cargo clippy --all-targets --all-features -- -D warnings`: exit 0.
- `cargo test job::execution_domain::linux::destroy_test -- --nocapture`: **9 passed**.
- `cargo test job::execution_domain -- --nocapture` outside the restricted sandbox: **128 passed**. The first restricted run had exactly three classified fixture `EPERM` failures while creating Unix sockets/FIFOs; the unchanged elevated rerun was green.
- `cargo test runner::instance::instance_test -- --nocapture` outside the restricted sandbox: **50 passed**.
- `cargo test --all-targets --all-features -- --test-threads=1` outside the restricted sandbox: library **1085 passed, 23 ignored**; every integration target passed.
- Native arm64 Linux container: the new namespace-handle transfer, synchronous cgroup-deadline, bounded child kill/reap, and launcher-handshake regressions passed; `cargo check --offline --lib` exited 0 without warnings. The broader Linux filter passed **103** tests, ignored **16**, and classified five environment-only failures: two require a non-root UID, two require the native rootfs fixture, and the launcher fake was corrected then rerun green.
- `git diff --check`: exit 0.

## Qualification boundary

Task 10 proves the portable destruction state machine and Linux descriptor/map/protocol primitives, but does **not** claim production-native mapped cleanup qualification. A real Debian host fixture with delegated cgroup v2, RootlessKit, `newuidmap`/`newgidmap`, subordinate-owned `0700` trees, original namespace death, worker crash/timeout, and peer-attempt canaries remains an explicit Task 12 gate. No fallback was added for its absence, and public sandbox activation remains blocked.

The full rootless-DinD Docker acceptance suite was not rerun: Task 10 does not activate or alter Docker action call sites, and its new real userns/cgroup worker qualification belongs to the Task 12 native fixture rather than Docker Desktop's restricted container environment.
