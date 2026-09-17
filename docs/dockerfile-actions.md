# Dockerfile-based actions

Chimera supports repository and local actions whose metadata declares
`runs.using: docker` and `runs.image: Dockerfile` or a relative path ending in
`Dockerfile`. The action directory is the build context; a Dockerfile in a
subdirectory does not change the context root.

## Safety and credentials

Dockerfile paths must remain inside the canonical action directory. Context
packing rejects path traversal, symlinks escaping that directory and special
files. `.dockerignore` is applied before bytes are sent to Docker, and a
`<Dockerfile>.dockerignore` next to the selected Dockerfile takes precedence.
Registry credentials are accepted only from the explicit per-job integration
owned by CHM-03; Chimera never falls back to a daemon-wide Docker config. Until
CHM-03 supplies that resource, Dockerfile actions support only public base images.

## Cache and cancellation

The daemon keeps an in-memory, runner/repository/daemon-scoped cache keyed by
the exact filtered context and fixed build options. Identical concurrent
requests share one build. Cache state is lost on restart, missing images are
rebuilt, and successful internal images remain in Docker. The current resolver
does not expose a separate resolved commit; the filtered context bytes, not a
mutable requested ref, are authoritative for reuse.

Build preparation, lock waiting, Engine streaming and action execution share
the step deadline. Cancellation closes the Engine request and prevents action
container startup. Support is gated by the real-Engine cancellation test for
the deployed Docker version.

## Limits

Only `linux/amd64` is supported. Build args, secrets, SSH forwarding,
multi-platform output, cross-daemon cache sharing, retention and automatic
Docker pruning are not implemented. Mutable base-image refresh is governed by
Docker's local layer cache and is not a reproducibility guarantee. Passing the
automated suite does not authorize production rollout or fix unrelated
upstream masking/post-step limitations.
