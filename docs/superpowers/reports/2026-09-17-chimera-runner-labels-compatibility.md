# CHM-04 runner context compatibility — acceptance report

Дата локальной приёмки: 2026-09-17.
Спецификация: `docs/superpowers/specs/2026-09-17-chimera-runner-labels-compatibility.md`.

| ID | Status | Automated evidence |
|---|---|---|
| L-01 | PASS | `runner_labels_are_a_typed_array_without_environment_setup`; `runner_object_matches_property_access_and_preserves_existing_properties` |
| L-02 | PASS | `runner_labels_use_exact_array_membership`; `original_runner_labels_condition_runs_after_success_and_failure` |
| L-03 | PASS | `runner_labels_use_exact_array_membership`; `contains_returns_false_for_an_empty_array_fixture` |
| L-04 | PASS | `runner_environment_is_self_hosted`; ignored Docker test `container_action_receives_self_hosted_runner_context` |
| L-05 | PASS | `runner_object_matches_property_access_and_preserves_existing_properties`; existing `runner_context_in_expressions` regression |
| L-06 | PASS | `runner_owned_properties_override_environment_values`; `workflow_environment_cannot_spoof_runner_owned_context`; builder accepts only its job-local map and never reads process-global env |
| L-07 | PASS | `parallel_jobs_keep_runner_context_isolated`; `composite_substeps_share_runner_context`; `post_action_uses_the_same_runner_context` |
| L-08 | PASS | `original_runner_labels_condition_runs_after_success_and_failure` writes isolated markers after both success and an ordinary hard failure |
| L-09 | PASS characterization | `original_runner_labels_condition_survives_failure_and_cancellation`; `pre_cancelled_job_reaches_runner_labels_step` observes timeline `InProgress`, then the already-cancelled process produces job conclusion `Cancelled` |

Verification commands completed successfully:

- `cargo fmt --all -- --check`
- `cargo build`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo test -- --ignored` — the full ignored suite was executed through the macOS rootless-DinD runbook (`docs/testing-macos-docker.md`): exit 0, all suites ok, 0 failures, including 4/4 `job_docker_config_docker_test` and `tests/docker_test` 12/12 with `container_action_receives_self_hosted_runner_context`.

## Boundaries

- `runner.labels` is exactly `["self-hosted"]`; it is not the registration's complete server-side label set.
- No registration, GitHub API, `runs-on`, CLI, importer, assignment, shell-variable visibility, or workspace-cleanup behavior changed.
- L-09 proves condition evaluation and scheduler reachability only. It does not promise completion after SIGKILL, crash, or every cancellation path.
- No online canary was run. A canary of the unchanged external workflow remains a separately authorized check and is not required for this locally verified implementation.
