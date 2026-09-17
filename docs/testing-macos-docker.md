# Running Docker Tests on macOS

Chimera's Docker tests execute Linux containers and include a rootless Buildx
acceptance flow. On Linux, a compatible rootless Docker socket can be exposed
directly. On macOS, Docker Desktop runs its daemon inside a Linux VM, so the host
and daemon do not share either `/var/run/docker.sock` or the same loopback
interface.

This runbook reproduces the verified macOS setup: a pinned rootless
Docker-in-Docker daemon runs inside Docker Desktop, while a pinned Linux Rust
container compiles and runs the test suite against that daemon. The exact pin set
below was verified on Apple Silicon (`arm64`); fail closed on another architecture
until equivalent immutable pins have passed the same suite.

Run every command from the repository root in the same Bash shell. Stop at the
first error; do not continue with a partially prepared environment. Only one copy
of this setup may run at a time because its outer Docker resource names are fixed.

## Why the shared network namespace is required

`AuthenticatedRegistry` publishes its random port on `127.0.0.1` as seen by the
Docker daemon under test. Docker Desktop's `-p 127.0.0.1:...` normally publishes
that port on macOS, but a daemon inside the Docker Desktop VM cannot reach that
macOS loopback address as its own `127.0.0.1`.

The test runner therefore uses:

```text
--network container:chimera-job-docker-config-rootless-dind
```

The runner, rootless daemon, registry port-forwarding helper, and BuildKit
`network=host` driver then see one Linux network namespace and one loopback
interface. Do not replace this with macOS port publishing, `--network host`, or
`host.docker.internal`; those configurations do not exercise the required
rootless endpoint consistently.

## Security boundary

The C-10 test may download source only for these public actions at their exact
commit pins:

```text
docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5
docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee
docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
```

They are fetched from `https://codeload.github.com`. C-03 and C-10 use only a
local registry and synthetic credentials. Do not substitute GHCR, deployment
credentials, production secrets, unpinned action refs, or a production workflow.
Do not use `docker system prune` for setup or cleanup.

The full ignored suite also exercises existing tests whose image references are
currently tag-based: `alpine:latest`, `alpine:3.19`, `nginx:alpine`,
`redis:7-alpine`, and `ubuntu:latest`. The nested daemon may pull those images on
the first full run. The immutable pins below cover the C-10 harness and the tools
used to run it; they do not make those pre-existing test references immutable.

## 1. Check Docker Desktop and prepare constants

The active Docker context must point to a running Docker Desktop engine. Start in
a shell where `DOCKER_HOST` is not redirecting the host CLI to another daemon.

```bash
test "$(uname -s)" = "Darwin"
test "$(uname -m)" = "arm64"
docker context show
docker version
docker info >/dev/null
cargo fetch --locked
```

Define the verified image pins and test-owned resource names:

```bash
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

SCRATCH="$ROOT/.tmp/macos-docker-tests"
TOOLS="$SCRATCH/linux-tools"
IMAGE_ARCHIVE="$SCRATCH/rootless-dind-images.tar"

DIND_NAME="chimera-job-docker-config-rootless-dind"
DIND_RUNTIME_VOLUME="chimera-job-docker-config-dind-runtime"
DIND_TMP_VOLUME="chimera-job-docker-config-dind-tmp"
TARGET_VOLUME="chimera-job-docker-config-linux-target"
CARGO_VOLUME="chimera-job-docker-config-cargo-home"

RUST_IMAGE="rust@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f"
NODE_IMAGE="node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5"
DOCKER_CLI_IMAGE="docker@sha256:9f36dfce2d1fd053d700a4eca00c358df79bf7d8cb69d4a9e8d9981af18834ea"
DIND_IMAGE="docker@sha256:c876e00a0d81f592492fc80acd92b3ee13d2160e962b4d01676c52d9434e84b4"

REGISTRY_DIGEST="sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
HTTPD_DIGEST="sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567"
BUILDKIT_IMAGE_ID="sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"

REGISTRY_IMAGE="registry@$REGISTRY_DIGEST"
HTTPD_IMAGE="httpd@$HTTPD_DIGEST"
BUILDKIT_IMAGE="moby/buildkit@$BUILDKIT_IMAGE_ID"
```

The setup deliberately refuses to reuse a previous scratch directory. If this
check fails, run the cleanup section before proceeding:

```bash
test ! -e "$SCRATCH"
test -d "$HOME/.cargo/registry"
mkdir -p "$TOOLS/bin" "$TOOLS/cli-plugins"
```

## 2. Pull pinned images and extract Linux tools

The macOS `docker` and `node` executables cannot run inside the Linux test
container. Extract their Linux binaries from pinned images:

```bash
docker pull "$RUST_IMAGE"
docker pull "$NODE_IMAGE"
docker pull "$DOCKER_CLI_IMAGE"
docker pull "$DIND_IMAGE"
docker pull "$REGISTRY_IMAGE"
docker pull "$HTTPD_IMAGE"
docker pull "$BUILDKIT_IMAGE"

# These fixed temporary names make stale setup state visible instead of silently
# reusing it.
docker create --name chimera-macos-docker-cli-extract "$DOCKER_CLI_IMAGE"
docker cp chimera-macos-docker-cli-extract:/usr/local/bin/docker \
  "$TOOLS/bin/docker"
docker cp \
  chimera-macos-docker-cli-extract:/usr/local/libexec/docker/cli-plugins/docker-buildx \
  "$TOOLS/cli-plugins/docker-buildx"
docker rm -- chimera-macos-docker-cli-extract

docker create --name chimera-macos-node-extract "$NODE_IMAGE"
docker cp chimera-macos-node-extract:/usr/local/bin/node "$TOOLS/bin/node"
docker rm -- chimera-macos-node-extract
```

## 3. Create writable volumes and start rootless DinD

The test runner uses UID/GID `1000:1000`. Named volumes avoid writes into the
read-only source tree and are chowned before either container starts:

```bash
for volume in \
  "$DIND_RUNTIME_VOLUME" \
  "$DIND_TMP_VOLUME" \
  "$TARGET_VOLUME" \
  "$CARGO_VOLUME"
do
  docker volume create "$volume"
done

docker run --rm \
  --user root \
  --entrypoint chown \
  -v "$DIND_RUNTIME_VOLUME:/run/user/1000" \
  -v "$DIND_TMP_VOLUME:/chimera-tmp" \
  -v "$TARGET_VOLUME:/cargo-target" \
  -v "$CARGO_VOLUME:/cargo" \
  "$DIND_IMAGE" \
  -R 1000:1000 /run/user/1000 /chimera-tmp /cargo-target /cargo

docker run -d \
  --privileged \
  --name "$DIND_NAME" \
  -e DOCKER_TLS_CERTDIR= \
  -e XDG_RUNTIME_DIR=/run/user/1000 \
  -v "$DIND_RUNTIME_VOLUME:/run/user/1000" \
  -v "$DIND_TMP_VOLUME:/chimera-tmp" \
  "$DIND_IMAGE"
```

`--privileged` applies only to the outer test container. The daemon inside it
must still report the rootless security marker required by C-10. Wait up to one
minute and fail closed if the marker is absent:

```bash
security_options=""
for _ in $(seq 1 60); do
  if security_options="$(docker exec \
    -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
    "$DIND_NAME" \
    docker info --format '{{json .SecurityOptions}}' 2>/dev/null)"
  then
    break
  fi
  sleep 1
done

printf '%s\n' "$security_options"
case "$security_options" in
  *'"name=rootless"'*) ;;
  *)
    docker logs "$DIND_NAME"
    echo "rootless Docker preflight failed" >&2
    false
    ;;
esac
```

## 4. Define the Linux test runner

This function mounts the current worktree read-only. Cargo output, temporary
files, the rootless socket, and `$HOME` live only in test-owned volumes. Cargo is
offline inside the runner and reads the host's previously fetched registry cache.
Docker operations still use the nested daemon, and C-10 still needs outbound
access to the three pinned codeload archives.

```bash
run_in_chimera_test_container() {
  docker run --rm \
    --user 1000:1000 \
    --network "container:$DIND_NAME" \
    -v "$DIND_RUNTIME_VOLUME:/run/user/1000" \
    -v "$DIND_TMP_VOLUME:/chimera-tmp" \
    -v "$TARGET_VOLUME:/cargo-target" \
    -v "$CARGO_VOLUME:/cargo" \
    -v "$HOME/.cargo/registry:/cargo/registry:ro" \
    -v "$ROOT:/work:ro" \
    -v "$SCRATCH:/test-assets:ro" \
    -w /work \
    -v "$TOOLS/bin/docker:/usr/local/bin/docker:ro" \
    -v "$TOOLS/bin/node:/usr/local/bin/node:ro" \
    -v "$TOOLS/cli-plugins/docker-buildx:/usr/local/libexec/docker/cli-plugins/docker-buildx:ro" \
    -e HOME=/chimera-tmp/home \
    -e CARGO_HOME=/cargo \
    -e CARGO_NET_OFFLINE=true \
    -e CARGO_TARGET_DIR=/cargo-target \
    -e TMPDIR=/chimera-tmp \
    -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
    -e XDG_RUNTIME_DIR=/run/user/1000 \
    -e CHIMERA_TEST_BUILDKIT_IMAGE_ID="$BUILDKIT_IMAGE_ID" \
    "$RUST_IMAGE" \
    "$@"
}
```

Verify the injected Linux tools before loading images:

```bash
run_in_chimera_test_container rustc --version
run_in_chimera_test_container node --version
run_in_chimera_test_container docker version
run_in_chimera_test_container docker buildx version
```

## 5. Preload the C-10 images into the nested daemon

Pulling an image into Docker Desktop does not make it available to the nested
rootless daemon. Save the pinned images on the host, load them through the Linux
CLI connected to the rootless socket, and create the two tags used by the test
harness:

```bash
docker save --output "$IMAGE_ARCHIVE" \
  "$REGISTRY_IMAGE" \
  "$HTTPD_IMAGE" \
  "$BUILDKIT_IMAGE"

run_in_chimera_test_container \
  docker load --input /test-assets/rootless-dind-images.tar
run_in_chimera_test_container docker tag "$REGISTRY_DIGEST" registry:2
run_in_chimera_test_container docker tag "$HTTPD_DIGEST" httpd:2.4-alpine

test "$(run_in_chimera_test_container \
  docker image inspect --format '{{.Id}}' "$BUILDKIT_IMAGE_ID")" \
  = "$BUILDKIT_IMAGE_ID"
```

Do not replace `CHIMERA_TEST_BUILDKIT_IMAGE_ID` with a tag. C-10 intentionally
requires an already-local immutable image ID and never asks Buildx to download a
BuildKit image.

## 6. Run the tests

### One focused test

Use this form while diagnosing C-10:

```bash
run_in_chimera_test_container \
  cargo test --offline \
  --test job_docker_config_docker_test \
  pinned_buildx_flow_uses_job_config_and_original_socket \
  -- --ignored --exact --nocapture
```

### All four job Docker-config runtime tests

```bash
job_config_docker_tests=(
  concurrent_logout_does_not_remove_other_job_credentials
  docker_cli_atomic_rewrite_stays_private
  docker_action_does_not_receive_host_config
  pinned_buildx_flow_uses_job_config_and_original_socket
)

for test_name in "${job_config_docker_tests[@]}"; do
  run_in_chimera_test_container \
    cargo test --offline \
    --test job_docker_config_docker_test \
    "$test_name" \
    -- --ignored --exact --nocapture
done
```

### Required final ignored suite

This is the command that satisfies the repository's Docker verification gate:

```bash
run_in_chimera_test_container cargo test --offline -- --ignored
```

`--offline` applies to Cargo only. The first full run may still download the
existing tag-based Docker test images listed in the security section. C-10 may
also download its three action archives at the exact SHA pins.

## 7. Verify test cleanup

After a successful suite, both commands should print nothing. Image cache entries
are expected and are not a cleanup failure.

```bash
docker exec \
  -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
  "$DIND_NAME" \
  docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}'

docker exec \
  -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
  "$DIND_NAME" \
  docker volume ls --format '{{.Name}}'
```

## 8. Cleanup

Run this after success or failure. It removes only the fixed resources owned by
this runbook. It deliberately leaves the host's downloaded image cache intact and
never runs a global prune.

```bash
docker rm --force --volumes -- "$DIND_NAME" 2>/dev/null || true
docker rm --force --volumes -- \
  chimera-macos-docker-cli-extract \
  chimera-macos-node-extract \
  2>/dev/null || true

for volume in \
  "$DIND_RUNTIME_VOLUME" \
  "$DIND_TMP_VOLUME" \
  "$TARGET_VOLUME" \
  "$CARGO_VOLUME"
do
  docker volume rm "$volume" 2>/dev/null || true
done

if test "$SCRATCH" = "$ROOT/.tmp/macos-docker-tests"; then
  rm -rf -- "$SCRATCH"
fi

unset -f run_in_chimera_test_container
```

Confirm that no outer test resources remain:

```bash
if docker ps -a --format '{{.Names}}' | grep -Eq \
  '^(chimera-job-docker-config-|chimera-macos-(docker-cli|node)-extract$)'
then
  echo "a Chimera Docker test container remains" >&2
  false
fi

if docker volume ls --format '{{.Name}}' | grep -q '^chimera-job-docker-config-'; then
  echo "a Chimera Docker test volume remains" >&2
  false
fi
```

## Troubleshooting

### Docker Desktop is unavailable or stuck

Check:

```bash
docker desktop status
docker version
docker info
```

If Docker Desktop remains in `stopping` or its API returns HTTP 500, restarting it
may recover the VM. A restart interrupts every local Docker workload, so an agent
must obtain explicit user approval before running:

```bash
docker desktop restart
```

### Rootless preflight fails

Inspect the daemon rather than weakening the test:

```bash
docker logs "$DIND_NAME"
docker exec "$DIND_NAME" ls -la /run/user/1000
docker exec \
  -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
  "$DIND_NAME" \
  docker info --format '{{json .SecurityOptions}}'
```

The socket must be `/run/user/1000/docker.sock`, `DOCKER_HOST` must be
`unix:///run/user/1000/docker.sock`, and the JSON array must contain the exact
string `name=rootless`. Do not bypass these C-10 guards.

### Registry login reports connection refused

Confirm that every Linux test-runner invocation contains:

```text
--network container:chimera-job-docker-config-rootless-dind
```

Publishing the registry to macOS loopback is not a substitute. The nested daemon
and BuildKit must reach the registry through the shared Linux loopback interface.

### Buildx or BuildKit preflight fails

Check both the plugin mount and the nested image identity:

```bash
run_in_chimera_test_container docker buildx version
run_in_chimera_test_container \
  docker image inspect --format '{{.Id}}' "$BUILDKIT_IMAGE_ID"
```

The second command must print exactly `$BUILDKIT_IMAGE_ID`. If it does not, repeat
the preload step; do not set a tag or ask Buildx to pull implicitly.

### A pinned action cannot be installed

The test process needs outbound HTTPS access to `codeload.github.com`. Verify the
SHA constants at the top of `tests/job_docker_config_docker_test.rs`; do not switch
to a branch or release tag. Global PAX metadata in codeload tarballs is covered by
`pinned_action_extraction_accepts_global_pax_metadata`. If extraction regresses,
run that unit test rather than modifying a downloaded archive.

### A test fails without enough context

Run the exact test with `--nocapture`, then inspect the rootless daemon:

```bash
run_in_chimera_test_container \
  cargo test --offline \
  --test job_docker_config_docker_test \
  TEST_NAME \
  -- --ignored --exact --nocapture

docker logs "$DIND_NAME"
```

The Docker test helper includes the failed CLI arguments and stderr in its error.
Do not add production logging or weaken cleanup assertions solely to diagnose the
harness.

## Updating pins

Treat the digests in this file as one verified set. When an update is necessary:

1. Resolve every replacement to an immutable digest; never replace a digest with
   a mutable tag.
2. Confirm that the BuildKit reference's inspected `.Id` is the exact value passed
   through `CHIMERA_TEST_BUILDKIT_IMAGE_ID`.
3. Re-extract the Linux Docker CLI, Buildx plugin, and Node binary from the new
   pinned images.
4. Run the four focused job Docker-config tests and the complete ignored suite.
5. Update this runbook and its verification evidence in the same change.

Action SHAs remain defined by `tests/job_docker_config_docker_test.rs`; the values
listed here must match that source exactly.
