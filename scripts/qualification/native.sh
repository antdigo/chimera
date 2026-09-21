#!/usr/bin/env bash
set -euo pipefail

if test "$#" -ne 1; then
  echo 'InvalidConfig' >&2
  exit 2
fi
case "$1" in /*) ;; *) echo 'InvalidConfig' >&2; exit 2 ;; esac
if ! test -f "$1" || test -L "$1"; then
  echo 'InvalidConfig' >&2
  exit 2
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
mkdir -p "$PWD/target/chimera-tests"
export TMPDIR="$PWD/target/chimera-tests"
export CHIMERA_QUALIFICATION_CONFIG="$1"
# A unique owned log avoids clobbering another run or following a /tmp symlink.
qualification_log=$(mktemp "$TMPDIR/chimera-sandboxed-native.XXXXXX")
printf 'Qualification log: %s\n' "$qualification_log" >&2
cargo test --features acceptance-tests --test sandboxed_qualification_test \
  native_sandboxed_release_qualification -- --ignored --exact --test-threads=1 \
  > "$qualification_log" 2>&1
