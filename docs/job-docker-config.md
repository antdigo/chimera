# Per-job Docker configuration

Chimera creates `<root>/job-resources/<local-attempt-uuid>/docker/config.json`
for every acquired job. The directory is private to the daemon UID and is removed
only after all post actions finish. `DOCKER_CONFIG` is reserved for host steps;
a workflow may repeat the generated value but may not redirect it.

The directory prevents accidental credential sharing between jobs. It does not
isolate processes running under the same UID, Docker daemon access, or descendants
that escape Chimera's current process-tree cancellation.

Docker actions and job containers do not receive or mount this host path. Named
contexts, credential helpers, CLI plugins, and credentials from `$HOME/.docker`
are not imported.

## `stale-job-resources` recovery

1. Stop the Chimera service and do not restart it while inspection is in progress.
2. Identify the service cgroup with `systemctl show chimera.service -p ControlGroup`
   and verify that it contains no processes. A stopped daemon PID alone is not proof
   that job descendants exited.
3. Verify that no related Docker build/push operation is still consuming the exact
   local attempt UUID. If process ownership is uncertain, stop; do not delete or restart.
4. Without opening `config.json`, verify the exact root/attempt owner, mode and path:
   `stat -c '%U:%G %a %n' <root>/job-resources <root>/job-resources/<uuid>`.
   Reject symlinks or a path outside the canonical Chimera root.
5. Obtain explicit authorization to remove only
   `<root>/job-resources/<uuid>`. Do not glob, prune Docker, inspect credential
   contents, or remove neighboring/user Docker directories.
6. Remove that exact generated attempt directory, confirm `job-resources` is empty,
   then start Chimera again. A cleanup error is handled by the same procedure.

On Debian/systemd installations using rootless Docker, the service environment must
pass through `DOCKER_HOST`, `XDG_RUNTIME_DIR`, and `PATH` for the daemon UID. A
daemon-level `DOCKER_CONFIG` is not a job configuration and must not be used as a
fallback: Chimera supplies the generated per-job value only to host steps.
