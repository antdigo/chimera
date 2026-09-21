# Sandboxed policy diagnostics (D0)

The sandboxed execution profile is unavailable in this build. `chimera doctor` is a read-only diagnostic command, and `chimera install-policy --render` only prints a proposed systemd drop-in. Neither command activates a sandbox, installs a file, applies eBPF policy, restarts a service, or changes the Chimera root. The default execution profile remains `trusted-host`.

## Commands

Use an existing root with an existing `config.toml`:

```sh
chimera doctor --root /var/lib/chimera --json
chimera install-policy --render --root /var/lib/chimera
```

Doctor exits nonzero if any check is failed or unverified. In D0, `activation` always fails with `sandboxed_unavailable`; `activation_available` is always `false`. A satisfied individual check does not imply the profile is supported. `network_effective` and `network_negative_probes` remain unverified because rendered unit text cannot prove live BPF attachment or blocked connections. Outside the exact `chimera.service` cgroup, those checks are necessarily unverified. The command reads local platform prerequisites, but it does not enter the service cgroup or run sentinels. Missing or malformed configuration fails without creating defaults, and diagnostic errors intentionally omit configuration values.

`install-policy --render` requires a configured network policy and a live host-interface address inventory. Its output includes the digest and a proposed `chimera.service.d/50-sandbox-network.conf` fragment. The fragment is a review artifact, not proof that the running unit enforces it. There is no `--apply` option. A later authorized operator workflow may copy the reviewed fragment to the unit drop-in directory, reload systemd, and restart the service. This command does none of those operations. Re-render, review, and restart after host addresses change; stale address inventories can invalidate the intended denial set.

## Prerequisites and limitations

The storage bound requires a dedicated ext4 or XFS filesystem mounted at the Chimera root, with a capacity no greater than the configured maximum, no writable nested mounts, and no aliases of that filesystem outside the root. The D0 probe can inspect that arrangement on Linux. Project-quota and btrfs quota mechanisms are not proven by the D0 probe and must not be treated as a pass. A passing dedicated-filesystem observation is local evidence only; it is not sandbox activation.

The probe and revalidation also inspect existing `work`, `tmp`, `job-resources`, `cache`, `actions`, `externals`, and `tool-cache` directories relative to the pinned root descriptor. Symlinks and different backing devices or mount identities are rejected. The cache tree is checked recursively, including `cache/entries`, `cache/data`, `cache/tmp`, blob-prefix directories, and existing files. Traversal is bounded; a tree exceeding the inspection budget is unverified. Missing directories are permitted and are never created by inspection.

These checks are a point-in-time observation, not protection against concurrent path replacement. D1 must synchronize observation, directory creation, revalidation, and use with all writers; preserve descriptor-relative no-follow access through cache and job setup; and prevent untrusted writers from replacing checked ancestors or introducing foreign mounts. Rechecking before use alone does not close the race. Native qualification must prove that lifecycle invariant before activation; the D0 daemon gate remains closed.

The public `PolicyError` contract follows the D0 plan. Missing config/network policy uses `MissingPolicy("config" | "network")`; invalid root/config/host-address/storage observations use `InvalidObservation` with a fixed field name. A known capacity, mount, or writable-path violation is `StorageUnbounded`; replacement of a pinned identity is `StorageIdentityChanged`. Doctor classifies both storage failures as failed, retaining its `storage_bound_mismatch` report category. Unavailable observations remain unverified. `Io(std::io::Error)` preserves the cause for programmatic inspection, while its displayed message omits underlying error text; errors no longer implement `Copy`, `Clone`, or equality.

The network drop-in is service-wide egress policy. It covers the supervisor and RootlessKit/slirp processes as well as jobs, so any public resolver needed for DNS must remain reachable through the allowed public path. DNS resolution and registry access also depend on the planned capability integration; a rendered policy alone does not establish those bridges. A live service-generation inspection and native negative sentinels are still required for S-01 and S-05 evidence. In particular, the daemon must observe effective BPF policy and deny controlled forbidden destinations while a public control remains reachable. D0 doctor cannot provide that evidence.

Even with a future active sandbox, containers and the supervisor share a host kernel. Kernel attack surface and host-level resource contention remain residual risks; policy rendering is not a substitute for runtime enforcement or operational isolation.
