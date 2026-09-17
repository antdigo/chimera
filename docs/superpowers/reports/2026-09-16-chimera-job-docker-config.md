# CHM-03 Acceptance Report

## Status

The static and non-Docker evidence below is green. C-03 and C-10 remain
**unverified**, not passed: this host has no `/var/run/docker.sock`, and the
previous ignored, Docker-mutating commands were denied before execution. They were
not retried. Validation of those two cases requires an authorized Docker-capable
host.

## Documentation correction: Task 7 fix round 1

The operator and README wording now describes the enforced boundary precisely:
conflicting job-, step-, and `GITHUB_ENV`-level `DOCKER_CONFIG` values are rejected
before the affected host spawn, but an already-running same-UID process can alter
its own environment or use `docker --config`. The stale recovery procedure now
requires a recursive cgroup-v2 membership inspection, real non-symlink `0700`
daemon-owned root and exact attempt directories, canonical exact-path checks, and
stop/no-delete/no-restart on missing, unavailable, or uncertain evidence. The
README also provides a rootless systemd drop-in that sets `DOCKER_HOST`,
`XDG_RUNTIME_DIR`, and `PATH` without setting daemon-level `DOCKER_CONFIG`.

## Documentation correction: Task 7 fix round 2

The README now labels the base unit as rootful system-Docker only. Its rootless
alternative uses empty `After=` and `Requires=` assignments before restoring only
`After=network-online.target`, so it does not inherit a system `docker.service`
dependency. It also requires the daemon UID's rootless Docker user service and
socket to be enabled and available, with user-service persistence/linger where
needed.

| ID | Evidence and status |
|---|---|
| C-01 | Passed: `tests/job_docker_config_test.rs::concurrent_jobs_use_distinct_configs` |
| C-02 | Passed: `tests/job_docker_config_test.rs::sequential_jobs_start_empty_and_use_new_paths` |
| C-03 | Unverified Docker runtime: `tests/job_docker_config_docker_test.rs::concurrent_logout_does_not_remove_other_job_credentials` (`#[ignore]`) |
| C-04 | Passed: `tests/job_docker_config_test.rs::pre_main_post_share_config_until_post_finishes` |
| C-05 | Passed: `tests/job_docker_config_test.rs::{cleanup_runs_for_all_job_outcomes,cancellation_records_descendant_survival_after_owner_cleanup}`; `src/job/docker_config_test.rs::cleanup_is_idempotent_and_keeps_neighbor`. The descendant probe separately proves owner-directory removal, records that the exact child inherited the job config and survived that removal, then terminates that exact test-owned PID. |
| C-06 | Passed: `src/job/docker_config_test.rs::read_only_root_fails_without_fallback`; `src/runner/instance_test.rs::successful_job_reports_failed_when_docker_config_cleanup_fails` |
| C-07 | Passed: `src/job/docker_config_test.rs::stale_root_with_live_child_is_not_removed`; `src/daemon_test.rs::startup_preparation_rejects_stale_job_resources_without_deleting_them`; [`stale-job-resources` recovery](../../job-docker-config.md#stale-job-resources-recovery) |
| C-08 | Passed: `src/job/docker_config_test.rs::{umask_zero_still_creates_private_paths,prepare_rejects_symlink_root,cleanup_refuses_config_symlink_without_touching_target,cleanup_refuses_moved_root_replaced_by_symlink,cleanup_refuses_replacement_attempt_at_same_path,generated_id_collision_is_rejected}`; `src/daemon_test.rs::{second_lock_cannot_replace_live_lock,dropping_lock_does_not_remove_replacement_inode}` |
| C-09 | Passed: `src/job/execute_test.rs::{step_environment_cannot_override_docker_config,job_environment_cannot_override_docker_config,github_env_cannot_override_docker_config,matching_override_is_allowed,host_command_rejects_default_docker_credential_helpers_on_effective_path,host_command_allows_non_executable_default_credential_helper,host_command_prefers_step_path_and_falls_back_to_non_utf8_inherited_path}`; `tests/job_docker_config_test.rs::{step_env_override_fails_before_spawn,implicit_default_credential_helper_fails_before_spawn,github_env_override_fails_before_next_spawn,matching_step_environment_is_allowed,matching_github_env_is_allowed,legacy_set_env_override_fails_before_next_spawn}`; no process-global mutation |
| C-10 | Unverified Docker/Buildx runtime: `tests/job_docker_config_docker_test.rs::pinned_buildx_flow_uses_job_config_and_original_socket` (`#[ignore]`). Pure passing guards require an explicit coherent rootless Unix endpoint, parse daemon security options for `name=rootless`, and reject missing, failed, cancelled, duplicated, or unrelated pinned post completion records. |
| C-11 | Passed: `src/job/docker_config_test.rs::daemon_docker_config_is_not_copied_or_modified`; `tests/job_docker_config_test.rs::inherited_daemon_config_is_neither_used_nor_modified`; `src/job/execute_test.rs::host_command_explicitly_overrides_inherited_docker_config` |

All credentials used by the suite are synthetic. C-03 and C-10 target a local
registry; no GitHub Container Registry push, deployment, or unchanged-workflow
production canary is part of this report. Process-tree escape remains an explicitly
documented limitation. The bounded C-05 probe now observes a descendant that inherited
`DOCKER_CONFIG`, survived owner-directory cleanup, and was then killed by its exact
recorded PID; unlink still is not presented as proof that a surviving process forgot
credentials it already read or opened.

The green evidence is limited to formatting, compilation, Clippy, and non-ignored
tests. The ignored Docker runtime suite is deliberately excluded from the PASS
claim until an authorized host with a usable Docker endpoint runs it.
