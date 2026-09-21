# SDD ledger — plan: docs/superpowers/plans/2026-09-20-chimera-sandboxed-linux-domain.md

Base: d3dda79c1c9cac15807c2bd6b840b939437096e5 (`origin/main`, squash merge of PR #64)

Ruling: standing delegation permits uninterrupted implementation, review, PR creation and squash-only merge. The user explicitly requested final-result orchestration without manual PR management and later required that every integration into `main` use squash merge.

## Preflight scan

| Scope | Producer / consumer | Result |
| --- | --- | --- |
| Task 1 | Value contracts, canonical paths, environment ownership, structured failures | Foundation only; no incomplete runtime methods. |
| Tasks 2–4 | Resource limits, dirfd filesystem ownership, cgroup enforcement | Sequential: typed limits feed cgroup creation before child launch. |
| Tasks 5–7 | Bounded protocol, PID 1 launcher, rootfs/hardening/command execution | Sequential implementation stream; launcher consumes earlier paths and cgroup contracts. |
| Task 8 | Workflow state bridge | Consumes StepFilesId and protocol; no host path authority crosses the domain boundary. |
| Task 9 | Manager sole ownership and trusted migration | Integrates all producers; preserves trusted-host behavior. |
| Tasks 10–11 | Cancellation/destruction and durable reconciliation | Must follow ownership integration to prove cleanup and restart behavior. |
| Task 12 | Native Debian qualification and contract handoff | Final Plan B gate; activation remains fail-closed until later C/D/E work. |

Task 1: fix round 1/5 (1 addressed, 0 open — complete normative command/cancel/outcome/destroy value contracts; commits cb3efb3..f4b66f7)

Task 1: complete (commits d3dda79..f4b66f7, scoped re-review clean)

Task 2: complete (commit 925b24f, review clean)

Task 3: fix round 1/5 (3 addressed, 0 open — trusted compatibility, complete shared poison, writable hardlinks; commits 5d00f67..fe0019c)

Task 3: complete (commits 5d00f67..fe0019c, scoped re-review clean)

Task 4: fix round 1/5 (2 addressed, 0 open — standard systemd delegation permissions and streaming bounded inventory; commits fddd591..c06fbc6)

Task 4: complete (commits fddd591..c06fbc6, scoped re-review clean)

Task 5: fix round 1/5 (1 addressed, 0 open — snapshot chunk test crosses a UTF-8 codepoint boundary; commits b92d4cc..02244f2)

Task 5: complete (commits b92d4cc..02244f2, scoped re-review clean)

Task 6: fix round 1/5 (1 addressed, 0 open — immutable inputs resist RW remount and hardlink aliases; commits 9d77802..25bcdd0)

Task 6: complete (commits 9d77802..25bcdd0, scoped re-review clean)

Task 7: complete (commit debf6df, review clean)

Task 8 consumer note: bind `CommandSpec.state` through the state bridge; Task 7 intentionally rejects it.

Task 8: fix round 1/5 (1 addressed, 0 open — terminal FD release, bounded prepared transactions, verified partial rollback; commits 9725f77..ee8d25f)

Task 8: complete (commits 9725f77..ee8d25f, scoped re-review clean)

Task 9 consumer notes: promote/select strict B3/B4 backends; consume correlated `CommandRejected`; preserve monotonic command IDs; translate output receiver close into `CancelCommand(HandleDropped)`.

Task 9: complete after six independent review rounds (commits 538413b..808562d; final re-review PASS with 0 open P0/P1/P2). Manager owns lifecycle/permit/state, trusted-host compatibility is preserved, private Linux B3/B4 selection and path mapping are compiled but fail-closed, protocol cancellation is explicitly acknowledged/correlated and bounded under backpressure, workflow state is applied atomically, workspace reads are descriptor-bound and budgeted, and interrupted Docker exec uses bounded host-authoritative container recovery before snapshot/post. Final host verification: fmt/diff-check/clippy green; 1072 passed, 23 ignored, every integration suite green. Focused rootless DinD recovery suite 8/8 and real Docker action transaction 1/1. Public sandbox activation remains fail-closed; Task 10 owns the retained cleanup proof and C1/E own private Docker endpoint/activation.

Task 10: complete (commits a211e0f..5379450; final independent re-review PASS with 0 open P0/P1/P2). One retained strict cleanup record and bounded destroy driver now prove cgroup/process, handle/mount, socket, mapped writable-tree, attempt filesystem, and cgroup absence before clean permit release; provisioning rollback uses the same authority and reverse-discharged stage ledger. The short-lived exact-map cleanup worker has no idle daemon/user pool and ordinary `BoundDir` checks remain strict. Final host gate: 1086 passed, 23 ignored, all integrations green; native arm64 Linux focused gates cover cleanup, launcher, cgroup, exact namespace capability validation, deadline-bound reap, and injected observation failures. Public sandbox activation remains fail-closed; Task 12 retains real Debian RootlessKit/userns/cgroup qualification.

Task 10: fix round 1/5 (commit 51d6e69; 6 addressed, 0 open — no fabricated external revocation, retained teardown authority and idempotent retry, retained namespace capabilities, non-Ready durable KernelReady state, absolute teardown bounds, and removal/deferment of unused future-C1 seams). Host fmt/clippy/diff-check and full serial suite are green: 1085 passed, 23 ignored, every integration target passed. Native arm64 Linux focused namespace-transfer, cgroup-deadline, helper-reap, and launcher-handshake regressions are green; Task 12 retains the real Debian RootlessKit/userns/cgroup qualification boundary.

Task 10: fix round 2/5 (commit dc9e909; 3 addressed, 0 open — late destructive retry skips discharged kernel/cgroup work, timed-out helper/worker authority is bounded and retained for retry, and received namespace FDs require exact nsfs/type/identity proof). Focused host destroy suite 10/10 and native Linux namespace/reap regressions are green; native Linux lib check is clean. Elevated full serial gate: 1086 passed, 23 ignored, every integration target green. Task 12 remains the only real Debian RootlessKit/userns/cgroup qualification boundary.

Task 10: fix round 3/5 (commit 5379450; 2 addressed, 0 open — observation errors atomically reinsert exact pending child/cgroup/bootstrap authority, and forced-kill evidence survives late destructive failure/retry). Injected native `try_wait` failure retry and host two-pass forced-kill report regressions are green. Final elevated full serial gate: 1086 passed, 23 ignored, every integration target green; final independent re-review PASS with no introduced P0/P1/P2.

Task 11: complete (implementation commit recorded by this handoff). A live unforgeable `RootLockProof`, pinned active/cgroup roots and same-process single-flight gate now protect a complete non-mutating ownership inventory before bounded cgroup neutralization and descriptor-bound cleanup. Linux journal v2 is distinct from trusted v1; missing journals authorize only an exact empty creation-prefix, malformed evidence is preserved, cgroups are removed last, and a final union recheck gates admission. Host fmt/clippy/diff-check and full serial suite are green: 1094 passed, 23 ignored, every integration target passed. Native arm64 Linux recovery 11/11, journal 27/27 and daemon 42/42 are green. Public sandbox activation remains fail-closed; Task 12 retains real Debian systemd/RootlessKit/subuid/cgroup qualification.

Task 11: fix round 1/5 (review-fix commit recorded by this handoff; 6 addressed, 0 open — recursive normal/nested cgroup removal, retained-FD deletion after swap, single-shot admission and JoinError poison, exact mount path, independent cgroup neutralization on active-root errors, and direct nested/journal mode provenance). Final host fmt/clippy/diff-check and full serial suite are green: 1094 passed, 23 ignored, every integration target passed. Native arm64 Linux reconciliation 16/16, dirfd 23/23 with two privileged fixtures ignored, and cgroup 32/32 under UID1000 are green; real Debian production qualification remains Task 12.

Task 11: fix round 2/5 (review-fix commit recorded by this handoff; 2 addressed, 0 open — active/attempt owner+full-mode revalidation immediately before bound deletion and exact `0o7777` mode checks rejecting special bits). Four native RED cases are GREEN: dirfd 27/27 with two privileged fixtures ignored; recovery 16/16. Host fmt/clippy/diff-check and final elevated full serial suite are green: 1094 passed, 23 ignored, every integration target passed. Task 12 native qualification boundary unchanged.

Plan C consumer note: managed dockerd needs a separate policy and explicit retained-capability lifetime; never reuse the workflow child policy.

Deferred contract for Task 10/C: rootless Docker may leave subordinate-UID files and non-traversable directories. Cleanup must define an owned user-namespace/idmapped cleanup capability; do not solve this by globally weakening owner checks.
