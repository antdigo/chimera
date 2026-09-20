#!/bin/sh
set -eu

slots=${1:-20}
case "$slots" in
    ''|*[!0-9]*)
        echo "slots must be a positive integer" >&2
        exit 2
        ;;
    0|1)
        echo "slots must be at least two" >&2
        exit 2
        ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
image=${CHIMERA_PROTOTYPE_IMAGE:-docker:29-dind-rootless}

exec docker run --rm --privileged --user root \
    --entrypoint /bin/sh \
    --env "PROBE_SLOTS=$slots" \
    --volume "$script_dir/lab-probe.sh:/prototype/lab-probe.sh:ro" \
    "$image" /prototype/lab-probe.sh
