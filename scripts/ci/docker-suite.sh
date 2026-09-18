#!/usr/bin/env bash
# Runs one shard of the ignored Docker test suite against a throwaway nested
# rootless daemon on a Linux CI runner.
#
# Inputs (environment):
#   SUITE_ARGS    cargo test target selection, e.g. "--test docker_test" or "--lib" (required)
#   TEST_FILTERS  extra libtest arguments after "--": name filters or --skip lists (optional)
#   SHARD_NAME    prefix for the Docker resources this run creates (default: "suite")
#
# The cargo target dir and the shared Node-externals cache live on bind mounts
# under .tmp/ so the workflow can cache them between runs. Ownership flips to
# the container's uid 1000 on the way in and back to the invoking user in the
# EXIT trap, which runs even when the suite fails — otherwise the workflow's
# cache save step cannot archive them.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHARD_NAME="${SHARD_NAME:-suite}"
SUITE_ARGS="${SUITE_ARGS:?SUITE_ARGS is required, e.g. '--test docker_test'}"
TEST_FILTERS="${TEST_FILTERS:-}"

DIND_IMAGE="docker@sha256:c876e00a0d81f592492fc80acd92b3ee13d2160e962b4d01676c52d9434e84b4"
CLI_IMAGE="docker@sha256:9f36dfce2d1fd053d700a4eca00c358df79bf7d8cb69d4a9e8d9981af18834ea"
NODE_IMAGE="node@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d"
RUST_IMAGE="rust@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f"
BUILDKIT_REFERENCE="moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"

DIND_NAME="chimera-ci-$SHARD_NAME-dind"
CLI_EXTRACT_NAME="chimera-ci-$SHARD_NAME-cli-extract"
NODE_EXTRACT_NAME="chimera-ci-$SHARD_NAME-node-extract"
RUNTIME_VOLUME="chimera-ci-$SHARD_NAME-runtime"
TMP_VOLUME="chimera-ci-$SHARD_NAME-tmp"
CARGO_VOLUME="chimera-ci-$SHARD_NAME-cargo"
TOOLS="$REPO_ROOT/.tmp/ci-docker-tools-$SHARD_NAME"
TARGET_BIND="$REPO_ROOT/.tmp/ci-docker-target"
EXTERNALS_BIND="$REPO_ROOT/.tmp/ci-test-externals"
INVOKING_OWNER="$(id -u):$(id -g)"

cleanup() {
  docker rm -f "$DIND_NAME" "$CLI_EXTRACT_NAME" "$NODE_EXTRACT_NAME" >/dev/null 2>&1 || true
  docker volume rm "$RUNTIME_VOLUME" "$TMP_VOLUME" "$CARGO_VOLUME" >/dev/null 2>&1 || true
  docker run --rm --user root --entrypoint chown \
    -v "$TARGET_BIND":/cargo-target \
    -v "$EXTERNALS_BIND":/chimera-tmp/chimera-test-externals \
    "$DIND_IMAGE" -R "$INVOKING_OWNER" /cargo-target /chimera-tmp/chimera-test-externals \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$TOOLS/bin" "$TOOLS/cli-plugins" "$TARGET_BIND" "$EXTERNALS_BIND"

# The workflow prefetches these in the background while caches restore; the
# daemon dedupes concurrent pulls of the same digest, so this is a cheap re-check.
pull_pids=()
for image in "$DIND_IMAGE" "$CLI_IMAGE" "$NODE_IMAGE" "$RUST_IMAGE" "$BUILDKIT_REFERENCE"; do
  docker pull "$image" >/dev/null &
  pull_pids+=("$!")
done
for pid in "${pull_pids[@]}"; do
  wait "$pid"
done

# Extract the pinned Linux docker CLI, Buildx plugin, and Node binary that the
# in-container test suite resolves from PATH.
extract_cli_tools() {
  docker create --name "$CLI_EXTRACT_NAME" "$CLI_IMAGE" >/dev/null
  docker cp "$CLI_EXTRACT_NAME":/usr/local/bin/docker "$TOOLS/bin/docker"
  docker cp \
    "$CLI_EXTRACT_NAME":/usr/local/libexec/docker/cli-plugins/docker-buildx \
    "$TOOLS/cli-plugins/docker-buildx"
  docker rm "$CLI_EXTRACT_NAME" >/dev/null
}

extract_node() {
  docker create --name "$NODE_EXTRACT_NAME" "$NODE_IMAGE" >/dev/null
  docker cp "$NODE_EXTRACT_NAME":/usr/local/bin/node "$TOOLS/bin/node"
  docker rm "$NODE_EXTRACT_NAME" >/dev/null
}

extract_cli_tools &
cli_extract_pid=$!
extract_node
wait "$cli_extract_pid"

for volume in "$RUNTIME_VOLUME" "$TMP_VOLUME" "$CARGO_VOLUME"; do
  docker volume create "$volume" >/dev/null
done
docker run --rm --user root --entrypoint chown \
  -v "$RUNTIME_VOLUME":/run/user/1000 \
  -v "$TMP_VOLUME":/chimera-tmp \
  -v "$EXTERNALS_BIND":/chimera-tmp/chimera-test-externals \
  -v "$CARGO_VOLUME":/cargo \
  -v "$TARGET_BIND":/cargo-target \
  "$DIND_IMAGE" -R 1000:1000 /run/user/1000 /chimera-tmp /cargo /cargo-target

# The nested daemon must report the rootless security marker the per-job
# Docker config tests (C-10) fail closed on. The classic image store keeps
# BuilderV1 builds (and their streamed progress) working; the containerd
# store cannot export them.
docker run -d --privileged --name "$DIND_NAME" \
  -e DOCKER_TLS_CERTDIR= \
  -e XDG_RUNTIME_DIR=/run/user/1000 \
  -v "$RUNTIME_VOLUME":/run/user/1000 \
  -v "$TMP_VOLUME":/chimera-tmp \
  "$DIND_IMAGE" \
  --feature containerd-snapshotter=false

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
    exit 1
    ;;
esac

# C-10 requires BuildKit as an already-local immutable image and never lets
# Buildx download it; preload it into the nested daemon. Neither digest
# references nor the host daemon's image ID survive a docker save/load
# round-trip: the loaded image keeps no RepoTags or RepoDigests, and daemons
# with different image stores assign different IDs to the same content. The ID
# the nested daemon itself reports on load is the only stable handle.
BUILDKIT_TAR="$TOOLS/buildkit.tar"
docker save --output "$BUILDKIT_TAR" "$BUILDKIT_REFERENCE"
docker cp "$BUILDKIT_TAR" "$DIND_NAME":/tmp/chimera-buildkit.tar
docker exec --user root "$DIND_NAME" chown 1000:1000 /tmp/chimera-buildkit.tar
load_output="$(docker exec \
  -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
  "$DIND_NAME" docker load --input /tmp/chimera-buildkit.tar)"
BUILDKIT_IMAGE_ID="$(printf '%s\n' "$load_output" | sed -n 's/^Loaded image ID: //p')"
test -n "$BUILDKIT_IMAGE_ID"
docker exec \
  -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
  "$DIND_NAME" docker image inspect --format '{{.Id}}' "$BUILDKIT_IMAGE_ID"

# The suite runs in the daemon's network namespace so the test registry's
# 127.0.0.1 port publishing and BuildKit share one loopback interface with the
# tests themselves. BuilderV1 builds flake when many tests drive the single
# nested daemon in parallel, so the ignored suite is bounded to two threads (the
# same limit the macOS gate runbook §6 established). Sharding across jobs, not
# threads, is what parallelizes the suite.
# shellcheck disable=SC2086  # SUITE_ARGS and TEST_FILTERS are fixed CI matrix strings
docker run --rm \
  --user 1000:1000 \
  --network "container:$DIND_NAME" \
  -v "$RUNTIME_VOLUME":/run/user/1000 \
  -v "$TMP_VOLUME":/chimera-tmp \
  -v "$EXTERNALS_BIND":/chimera-tmp/chimera-test-externals \
  -v "$CARGO_VOLUME":/cargo \
  -v "$TARGET_BIND":/cargo-target \
  -v "$HOME/.cargo/registry":/cargo/registry:ro \
  -v "$REPO_ROOT":/work:ro \
  -w /work \
  -v "$TOOLS/bin/docker":/usr/local/bin/docker:ro \
  -v "$TOOLS/bin/node":/usr/local/bin/node:ro \
  -v "$TOOLS/cli-plugins/docker-buildx":/usr/local/libexec/docker/cli-plugins/docker-buildx:ro \
  -e HOME=/chimera-tmp/home \
  -e CARGO_HOME=/cargo \
  -e CARGO_NET_OFFLINE=true \
  -e CARGO_TARGET_DIR=/cargo-target \
  -e CARGO_PROFILE_DEV_DEBUG=0 \
  -e CARGO_INCREMENTAL=0 \
  -e TMPDIR=/chimera-tmp \
  -e DOCKER_HOST=unix:///run/user/1000/docker.sock \
  -e XDG_RUNTIME_DIR=/run/user/1000 \
  -e CHIMERA_TEST_BUILDKIT_IMAGE_ID="$BUILDKIT_IMAGE_ID" \
  "$RUST_IMAGE" \
  cargo test --offline $SUITE_ARGS -- --ignored --test-threads=2 $TEST_FILTERS
