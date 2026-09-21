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

invalid_path() {
  echo 'InvalidConfig' >&2
  exit 2
}

qualification_uid=$(/usr/bin/id -u)
qualification_os=$(/usr/bin/uname -s)

protected_directory() {
  local directory=$1 allow_sticky=$2 private=${3:-0}
  local metadata owner mode
  test ! -L "$directory" && test -d "$directory" || invalid_path
  case "$qualification_os" in
    Linux) metadata=$(/usr/bin/stat -c '%u %a' -- "$directory") || invalid_path ;;
    Darwin) metadata=$(/usr/bin/stat -f '%u %p' "$directory") || invalid_path ;;
    *) invalid_path ;;
  esac
  read -r owner mode <<< "$metadata"
  [[ $owner =~ ^[0-9]+$ && $mode =~ ^[0-7]+$ ]] || invalid_path
  mode=$((8#$mode))
  test "$owner" = 0 || test "$owner" = "$qualification_uid" || invalid_path
  if ((mode & 0022)); then
    test "$allow_sticky" = 1 && test "$owner" = 0 && ((mode & 01000)) || invalid_path
  fi
  if test "$private" = 1; then
    test "$owner" = "$qualification_uid" && (( (mode & 07777) == 0700 )) || invalid_path
  fi
}

qualification_source=${BASH_SOURCE[0]}
case "$qualification_source" in
  /*) ;;
  *) qualification_source="$PWD/${qualification_source#./}" ;;
esac
case "$qualification_source" in
  */scripts/qualification/native.sh) qualification_checkout=${qualification_source%/scripts/qualification/native.sh} ;;
  *) invalid_path ;;
esac
case "$qualification_checkout" in *$'\n'*|*$'\r'*) invalid_path ;; esac

# Verify each parent before traversing its child. Root and the service UID are
# trusted not to mutate this ancestry; each edge must resist untrusted replacement.
qualification_current=/
protected_directory "$qualification_current" 1
IFS=/ read -r -a qualification_parts <<< "${qualification_checkout#/}"
for qualification_part in "${qualification_parts[@]}"; do
  case "$qualification_part" in ''|.|..) invalid_path ;; esac
  qualification_current="${qualification_current%/}/$qualification_part"
  protected_directory "$qualification_current" 1
done
protected_directory "$qualification_checkout" 0
cd -- "$qualification_checkout"
umask 077
for qualification_directory in "$qualification_checkout/target" "$qualification_checkout/target/chimera-tests"; do
  if test ! -e "$qualification_directory" && test ! -L "$qualification_directory"; then
    mkdir -- "$qualification_directory" || invalid_path
  fi
  protected_directory "$qualification_directory" 0
done

qualification_parent="$qualification_checkout/target/chimera-tests"
qualification_invocation=$(mktemp -d "$qualification_parent/run.XXXXXX")
test "${qualification_invocation%/*}" = "$qualification_parent" || invalid_path
protected_directory "$qualification_invocation" 0 1
export TMPDIR="$qualification_invocation"
export CHIMERA_QUALIFICATION_CONFIG="$1"
qualification_log="$qualification_invocation/cargo.log"
# Noclobber creates the file exclusively. Keep this inode open: later pathname
# replacement cannot redirect Cargo output or truncate an unrelated file.
set -o noclobber
if ! { exec 3> "$qualification_log"; } 2>/dev/null; then
  invalid_path
fi
printf 'Qualification log: %s\n' "$qualification_log" >&2
cargo test --features acceptance-tests --test sandboxed_qualification_test \
  native_sandboxed_release_qualification -- --ignored --exact --test-threads=1 \
  >&3 2>&1
