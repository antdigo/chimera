# CHM-02 acceptance report — 2026-09-18

This report covers Dockerfile-based action execution only. It does not approve
production rollout, GHCR push, deploy, webhook or poll stages. All numbers
below were observed on branch commits up to and including `83ccee4`.

## Observed commands (macOS host, aarch64 Docker Desktop)

- `cargo build`: PASS.
- `cargo clippy --all-targets -- -D warnings`: PASS — zero warnings.
- `cargo fmt -- --check`: PASS.
- `cargo test`: PASS — 893 passed, 0 failed, 43 ignored (the ignored set is
  the Docker Engine suite below).
- `cargo test --features acceptance-tests --test dockerfile_actions_test --no-run`:
  PASS — acceptance binary compiled; no acceptance test was executed.

## Docker Engine gate (macOS rootless DinD runbook, `--test-threads=2`)

Nested Docker 29.8.1 rootless daemon, containerd v2.3.5, classic image store
(`--feature containerd-snapshotter=false`), arm64 VM building `linux/amd64`
through QEMU:

- `docker::build::build_test` (lib): 16/16 PASS — includes the D-06 pair
  (`cancelling_build_stops_engine_work_and_never_publishes_image`,
  `timed_out_build_returns_bounded_and_never_publishes_image`), which now prove
  engine liveness through a marker the RUN step streams and prove stoppage by
  the absence of the internal tag after a window exceeding natural completion.
- `docker::exec`, `docker::resources`: PASS.
- `job::action::docker::docker_test` (lib): PASS — including both
  `engine_action_contents_come_from_pinned_context_after_{root,symlink_root}_replacement`
  and the container-cancellation trio.
- `tests/composite_test.rs`: 1/1 PASS. `tests/docker_test.rs`: 12/12 PASS.
- `tests/dockerfile_actions_test.rs`: 12/12 PASS (D-01…D-09, D-11 at
  executor level, real builds, pre/main/post reuse, cancel/timeout + retry).
- `tests/job_docker_config_docker_test.rs`: 3/4 — the pre-existing C-10
  `pinned_buildx_flow_uses_job_config_and_original_socket` fails with
  `HTTP 401 Unauthorized` because the harness downloads the pinned public
  actions from api.github.com with the fake job token. Added by main's
  `1e2d228` (per-job Docker credentials) and never executed before: the
  fork's last CI run predates it (2026-08-26, v0.1.3), and no earlier macOS
  gate reached that binary. Not addressed in this branch (CHM-03 lineage).

| ID | Evidence | Result |
|---|---|---|
| D-01 | `dockerfile_action_builds_and_propagates_exit_code`, `successfully_built_dockerfile_action_propagates_nonzero_exit_code` on Engine | PASS |
| D-02 | `subdirectory_dockerfile_uses_action_root_as_context` on Engine | PASS |
| D-03 | ignore rules + `context_symlink_escape_fails_before_action_container_starts` on Engine; build-context unit suite 26/26 | PASS |
| D-04 | `changed_context_rebuilds_while_unchanged_context_hits_cache` on Engine | PASS |
| D-05 | `concurrent_same_context_builds_once` on Engine; build-cache unit suite 14/14 | PASS |
| D-06 | Engine cancellation/timeout pair with streamed-marker liveness proof and post-window publication-absence proof; executor-level cancel/timeout + same-key retry | PASS |
| D-07 | `missing_cached_image_is_rebuilt`, `same_daemon_reuse_skips_present_image_and_rebuilds_missing_image` on Engine | PASS |
| D-08 | `dockerfile_action_reuses_image_for_pre_main_post` on Engine (one build, per-phase reuse, inputs/args/env/state) | PASS |
| D-09 | `prebuilt_metadata_and_inline_docker_actions_still_run` on Engine | PASS |
| D-10 | exact-pin rootless Hadolint deliberately not executed (controller ruling) | NOT RUN |
| D-11 | `synthetic_secrets_stay_out_of_context_and_logs` on Engine with real uploaded logs; canary unit suite | PASS |

## Review-fix verification (CHM-02 review)

1. Trusted-directory pinning: descriptor-backed resolution, metadata reads and
   context traversal with root/symlink-swap regressions — unit suites and the
   two pinned-context Engine tests PASS. A Linux-only defect found and fixed
   along the way: all descriptor clones share one readdir offset, so the
   second traversal of one capability (pre/main/post lifecycle) enumerated an
   empty directory (`83ccee4`, regression test included).
2. `.dockerignore` BOM/escaped-`#` and unanchored leading/trailing slash
   semantics — unit regressions PASS.
3. Extraction preserves only `mode & 0o111` — unit regressions PASS.
4. Cache publication bounded by cancel/deadline — deterministic publication
   tests PASS (`e211ed5`).
5. Timeout-log send bounded; argument values structurally excluded from
   tracing (`resolved_arg_count` only) — real-timeout regression and both
   branch capture tests PASS (`b680c3a`).
6. D-06 proves real Engine work stoppage (`5eb3677` + marker-based rework in
   `134199d`).

## Design adjudications recorded during acceptance

- Cross-process `/proc/<pid>/fd` bind mounts are impossible on runc-based
  engines (bind sources must belong to the caller's mount namespace; proven
  experimentally on rootless and rootful daemons). Dockerfile actions
  therefore mount no per-action runtime directory: contents reach the image
  only through the descriptor-pinned build context, and the shared
  `/github/actions:ro` cache mount remains.
- The build adapter keeps classic BuilderV1 because it is the only `/build`
  mode that streams progress into the masking pipeline; the REST BuildKit
  path returns aux frames only. Engines with the containerd image store
  cannot export BuilderV1 builds — an open limitation, not silently worked
  around (documented in `docs/dockerfile-actions.md`).

## Open rollout gates

- Engines running the containerd image store (Docker 29+ default on fresh
  installs) cannot build Dockerfile actions until a BuildKit session adapter
  exists; the macOS/CI nested daemons pin the classic store meanwhile.
- D-10 requires separate authorization on a controlled rootless stand.
- CHM-03 must provide explicit per-job registry auth before private base
  images; public bases only until then.
- A retention policy is required before mass rollout; global Docker prune is
  forbidden.
- Upstream masking and broader post/cancellation semantics remain separate
  gates.
- Pre-existing (main lineage, first executed here): the C-10 buildx flow test
  downloads pinned public actions with a fake token and fails with 401.
