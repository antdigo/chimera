# Per-job Docker configuration

Chimera creates `<root>/job-resources/<local-attempt-uuid>/docker/config.json`
for every acquired job. The directory is private to the daemon UID and is removed
only after all post actions finish. `DOCKER_CONFIG` is reserved for host steps:
Chimera rejects conflicting job-, step-, and `GITHUB_ENV`-level values before the
affected host spawn, while allowing a workflow to repeat the generated value.

The directory prevents accidental credential sharing between jobs. It is not a
sandbox or isolation from an untrusted same-UID job: an already-running host
process can change its own environment or invoke `docker --config`. It also does
not isolate Docker daemon access or descendants that escape Chimera's current
process-tree cancellation.

Docker actions and job containers do not receive or mount this host path. Named
contexts, credential helpers, CLI plugins, and credentials from `$HOME/.docker`
are not imported.

## Host `PATH` prerequisite

Docker on Linux may implicitly select `docker-credential-pass` or
`docker-credential-secretservice` even when `config.json` contains exactly `{}`.
Those helpers use external stores that are not isolated by separate config directories.
Chimera therefore checks the effective child `PATH` before every host spawn, including
workflow changes made between steps, and rejects an executable default helper with a
`reserved-host-capability` diagnostic. The supported fail-closed configuration is to
exclude both helpers from the Chimera service and workflow `PATH` until explicit helper
isolation is available. A non-executable file does not trigger this check.

This pre-spawn check and the cleanup path/inode validation prevent accidental sharing
and replacement; they do not guarantee safety against an adversarial same-UID process
racing filesystem or `PATH` changes after validation.

## `stale-job-resources` recovery

1. Stop the Chimera service and do not restart it while inspection is in progress.
2. On a cgroup-v2 system, resolve the service cgroup and inspect it recursively, read-only:
   ```bash
   cgroup=$(systemctl show chimera.service -p ControlGroup --value)
   test -n "$cgroup" && systemd-cgls --all "$cgroup"
   ```
   The output must show no PID entries in that cgroup or any descendant. A stopped
   daemon PID alone is not proof that job descendants exited. If `ControlGroup` is
   empty, the cgroup cannot be inspected, or any membership is uncertain, stop: do
   not delete and do not restart.
3. Verify that no related Docker build/push operation is still consuming the exact
   local attempt UUID. If process ownership is uncertain, stop; do not delete or restart.
4. Without opening `config.json`, verify the exact root and attempt path. Both
   `<root>/job-resources` and `<root>/job-resources/<uuid>` must be real,
   non-symlink directories, mode `0700`, and owned by the daemon UID. Confirm the
   exact owner, mode, and path with:
   `stat -c '%U:%G %a %n' <root>/job-resources <root>/job-resources/<uuid>`.
   Reject a missing, empty, unavailable, uncertain, symlinked, or non-canonical
   path; the attempt path must be the exact UUID child of the canonical Chimera root.
   In any such case, do not delete and do not restart.
5. Obtain explicit authorization to remove only
   `<root>/job-resources/<uuid>`. Do not glob, prune Docker, inspect credential
   contents, or remove neighboring/user Docker directories.
6. Remove that exact generated attempt directory, confirm `job-resources` is empty,
   then start Chimera again. A cleanup error is handled by the same procedure.

On Debian/systemd installations using rootless Docker, the service environment must
pass through `DOCKER_HOST`, `XDG_RUNTIME_DIR`, and `PATH` for the daemon UID. See
the [rootless systemd drop-in in the README](../README.md#rootless-docker-alternative).
A daemon-level `DOCKER_CONFIG` is not a job configuration and must not be used as a
fallback: Chimera supplies the generated per-job value only to host steps.
