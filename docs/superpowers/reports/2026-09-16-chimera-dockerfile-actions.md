# CHM-02 acceptance report — 2026-09-16

This report covers Dockerfile-based action execution only. It does not approve
production rollout, GHCR push, deploy, webhook or poll stages.

## Observed commands

- `cargo test --features acceptance-tests --test dockerfile_actions_test --no-run`:
  PASS — the acceptance test binary compiled; no test was executed.
- `cargo test docker::build_context::build_context_test`: PASS — 20 passed,
  0 failed.
- `cargo test docker::build_cache::build_cache_test`: PASS — 12 passed,
  0 failed.
- `cargo test docker::build::build_test`: PARTIAL — 10 unit tests passed,
  0 failed and 7 real-Engine tests remained ignored.
- `cargo test job::action::docker::docker_test`: PARTIAL — 21 unit tests passed,
  0 failed and 3 focused real-Engine lifecycle tests remained ignored.
- `cargo test docker::build::build_test::progress_formatter`: PASS — 6 passed,
  including Engine-ID sentinel and ordinary-command-output preservation cases.
- `cargo fmt --check`: PASS — no formatting diff.
- `cargo build`: PASS.
- `cargo clippy -- -D warnings`: PASS — zero warnings.
- `cargo test`: PASS — 18 test binaries reported 594 passed, 0 failed and
  37 ignored.
- Focused adapter timeout and lifecycle cancellation ignored selectors:
  environmental NOT RUN (exit 101) — all reached `Socket not found:
  /var/run/docker.sock` before testing Engine behavior. The adapter cancellation
  selector was not launched because the execution policy denied a potentially
  state-changing Engine test; this was not bypassed.
- Focused executor cancellation/timeout and D-01 non-zero ignored selectors:
  environmental NOT RUN (exit 101) — their exact build-process/entrypoint
  canaries were not reached with the same unavailable Engine.
- D-10 exact-pin execution: NOT RUN by controller ruling; no token lookup,
  GitHub/network request or rootless-stand discovery was attempted.

## Engine cancellation gate

NOT RUN. The real-Engine cancellation proof remains an open rollout gate; no
Docker Engine/API metadata was observed or printed in this environment.

| ID | Evidence | Result |
|---|---|---|
| D-01 | success and non-zero entrypoint propagation fixtures both require Docker Engine | NOT RUN |
| D-02 | `subdirectory_dockerfile_uses_action_root_as_context` requires Docker Engine | NOT RUN |
| D-03 | build-context unit suite: 20 passed; Docker ignore/symlink integration cases require Engine | PARTIAL — unit PASS; Engine NOT RUN |
| D-04 | `changed_context_rebuilds_while_unchanged_context_hits_cache` requires Docker Engine | NOT RUN |
| D-05 | build-cache suite: 12 passed, including concurrency; `concurrent_same_context_builds_once` requires Engine | PARTIAL — unit PASS; Engine NOT RUN |
| D-06 | build-cache and lifecycle budget unit prerequisites passed; adapter/executor fixtures use exact copied-file process markers; real-Engine failure/cancellation/cleanup proofs remain unavailable | NOT RUN — unit prerequisites PASS; Engine cancellation gate open |
| D-07 | build-cache daemon-scope and missing-image unit cases passed; `missing_cached_image_is_rebuilt` requires Engine | PARTIAL — unit PASS; Engine NOT RUN |
| D-08 | `dockerfile_action_reuses_image_for_pre_main_post` requires Docker Engine | NOT RUN |
| D-09 | inline Docker/pre-built metadata regression requires Docker Engine | NOT RUN |
| D-10 | exact-pin rootless Hadolint command deliberately not executed | NOT RUN |
| D-11 | filtered-context unit suite and six build-progress formatting/redaction unit tests passed; Engine synthetic canaries unavailable | PARTIAL — unit PASS; Engine NOT RUN |

## Open rollout gates

- Run the real-Engine ignored suite, especially cancellation, on the deployed
  rootless Docker version before rollout.
- Run D-10 only with separate authorization on a controlled rootless stand.
- CHM-03 must provide explicit per-job registry auth before private base images.
- A retention policy is required before mass rollout; global Docker prune is forbidden.
- Upstream masking and broader post/cancellation semantics remain separate gates.
