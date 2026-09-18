# Dockerfile-based actions

Chimera supports repository and local actions whose metadata declares
`runs.using: docker` and `runs.image: Dockerfile` or a relative path ending in
`Dockerfile`. The action directory is the build context; a Dockerfile in a
subdirectory does not change the context root.

## Safety and credentials

Dockerfile paths must remain inside the canonical action directory. Context
packing rejects path traversal, symlinks escaping that directory and special
files. `.dockerignore` is applied before bytes are sent to Docker, and a
`<Dockerfile>.dockerignore` next to the selected Dockerfile takes precedence;
a single UTF-8 BOM at the start of an ignore file is tolerated, and `\#`
escapes a literal leading `#`. Like Docker itself, leading or trailing slashes
in ignore patterns do not anchor a rule to the context root.

On Linux the resolved action directory is pinned by open descriptors
(`O_DIRECTORY | O_NOFOLLOW`, one `openat` step per component): `action.yml`
is read and the build context is packed through those descriptors, so renaming
or replacing the directory at its old pathname after resolution cannot change
what is read, sent to the daemon, or baked into the image. Other Unix builds
cannot offer that guarantee and instead re-validate the saved `dev`/`inode`
identity before security-sensitive use, failing closed on any mismatch — a
portability fallback, not an equivalent of the descriptor pin. Neither
mechanism claims protection against in-place mutation of file contents.

The action directory is deliberately not mounted into the action container at
runtime. Its contents reach the image exclusively through the pinned build
context (a `COPY` in the Dockerfile is the supported way to ship action files),
and the shared remote-action cache stays available read-only at
`/github/actions`. A per-action runtime bind would either reopen the
pathname-swap window or require a `/proc/<pid>/fd` bind source, which runc
containers cannot accept: bind-mount sources resolve inside the caller's
mount namespace, and runc always mounts within the container's own.

Extracted action archives keep only the executable bits (`mode & 0o111`) of
each regular file; setuid, setgid, sticky and extra write bits never transfer.

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

Build preparation, lock waiting, publication and Engine streaming share the
step deadline, and the same budget bounds the wait for the in-memory cache
lock: a cancellation or deadline that lands between a finished build and the
cache publication step leaves the image unindexed rather than blocking the
step or publishing late. Cancellation closes the Engine request, stops the
intermediate build container and prevents action container startup. Support is
gated by the real-Engine cancellation test for the deployed Docker version:
it proves the intermediate container is running before cancelling and then
observes the Engine stop it.

## Limits

Only `linux/amd64` is supported. Build args, secrets, SSH forwarding,
multi-platform output, cross-daemon cache sharing, retention and automatic
Docker pruning are not implemented. Mutable base-image refresh is governed by
Docker's local layer cache and is not a reproducibility guarantee. Passing the
automated suite does not authorize production rollout or fix unrelated
upstream masking/post-step limitations.

Builds use the classic BuilderV1 `/build` path because it is the only mode
that streams build progress into the job's masking pipeline. Engines running
the containerd image store (the Docker 29+ default on fresh installations)
cannot export BuilderV1 images — such daemons fail builds with
`NotFound: content digest ...`; the REST BuildKit alternative drops progress
text entirely. Supporting containerd-store engines requires a BuildKit
session adapter and is an open follow-up, as is documented in the acceptance
report.
