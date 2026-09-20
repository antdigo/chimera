#!/bin/sh
set -eu

slots=${PROBE_SLOTS:-20}
probe_root=/probe
pid_file=$probe_root/rootlesskit.pids
image=alpine:3.22

say() {
    printf '\n==> %s\n' "$*"
}

rootlesskit_pid() {
    rk_state_dir=$1
    ps -o pid,comm,args | awk -v marker="--state-dir=$rk_state_dir" \
        '$2 == "rootlesskit" && index($0, marker) { print $1; exit }'
}

wait_for_socket() {
    wait_socket=$1
    wait_log=$2
    wait_attempt=0
    while [ "$wait_attempt" -lt 120 ]; do
        if docker --host="unix://$wait_socket" version >/dev/null 2>&1; then
            return 0
        fi
        wait_attempt=$((wait_attempt + 1))
        sleep 0.5
    done
    tail -120 "$wait_log" >&2 || true
    return 1
}

stop_recorded_daemons() {
    [ -f "$pid_file" ] || return 0

    while IFS= read -r stop_pid; do
        [ -n "$stop_pid" ] || continue
        kill -TERM "$stop_pid" 2>/dev/null || true
    done <"$pid_file"

    stop_attempt=0
    while [ "$stop_attempt" -lt 40 ]; do
        stop_alive=0
        while IFS= read -r stop_pid; do
            [ -n "$stop_pid" ] || continue
            if kill -0 "$stop_pid" 2>/dev/null; then
                stop_alive=1
            fi
        done <"$pid_file"
        [ "$stop_alive" -eq 0 ] && break
        stop_attempt=$((stop_attempt + 1))
        sleep 0.25
    done

    while IFS= read -r stop_pid; do
        [ -n "$stop_pid" ] || continue
        kill -KILL "$stop_pid" 2>/dev/null || true
    done <"$pid_file"

    stop_attempt=0
    while [ "$stop_attempt" -lt 20 ]; do
        stop_alive=0
        while IFS= read -r stop_pid; do
            [ -n "$stop_pid" ] || continue
            if kill -0 "$stop_pid" 2>/dev/null; then
                stop_alive=1
            fi
        done <"$pid_file"
        [ "$stop_alive" -eq 0 ] && break
        stop_attempt=$((stop_attempt + 1))
        sleep 0.1
    done

    : >"$pid_file"
}

cleanup() {
    stop_recorded_daemons
}
trap cleanup EXIT INT TERM

start_plain_daemon() {
    start_slot=$1
    start_base=$probe_root/slots/$start_slot
    mkdir -p "$start_base/home" "$start_base/run" "$start_base/data" "$start_base/exec" "$start_base/rk"
    chown -R rootless:rootless "$start_base"

    su -s /bin/sh rootless -c "
        exec env \
            HOME='$start_base/home' \
            XDG_RUNTIME_DIR='$start_base/run' \
            DOCKER_TLS_CERTDIR= \
            DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS='--state-dir=$start_base/rk --pidns --cgroupns --utsns --ipcns' \
            /usr/local/bin/dockerd-entrypoint.sh dockerd \
                --host=unix://$start_base/run/docker.sock \
                --data-root=$start_base/data \
                --exec-root=$start_base/exec \
                --pidfile=$start_base/run/dockerd.pid \
                --storage-driver=vfs
    " >"$start_base/daemon.log" 2>&1 &

    wait_for_socket "$start_base/run/docker.sock" "$start_base/daemon.log"
    started_pid=$(rootlesskit_pid "$start_base/rk")
    [ -n "$started_pid" ]
    echo "$started_pid" >>"$pid_file"
}

assert_absent() {
    absent_endpoint=$1
    absent_kind=$2
    absent_name=$3
    if docker --host="$absent_endpoint" "$absent_kind" inspect "$absent_name" >/dev/null 2>&1; then
        echo "$absent_kind $absent_name leaked across Docker endpoints" >&2
        exit 1
    fi
}

say "starting $slots rootless Docker daemons under one UID"
mkdir -p "$probe_root/slots"
: >"$pid_file"
start_seconds=$(date +%s)
slot_index=1
while [ "$slot_index" -le "$slots" ]; do
    start_plain_daemon "$slot_index"
    slot_index=$((slot_index + 1))
done
elapsed=$(( $(date +%s) - start_seconds ))
echo "started=$slots elapsed_seconds=$elapsed"

first_child=$(cat "$probe_root/slots/1/rk/child_pid")
cp "/proc/$first_child/uid_map" "$probe_root/expected.uid_map"
slot_index=2
while [ "$slot_index" -le "$slots" ]; do
    child=$(cat "$probe_root/slots/$slot_index/rk/child_pid")
    cmp -s "$probe_root/expected.uid_map" "/proc/$child/uid_map" || {
        echo "slot $slot_index has a different uid_map" >&2
        exit 1
    }
    slot_index=$((slot_index + 1))
done
echo "shared_uid_map:"
sed 's/^/  /' "$probe_root/expected.uid_map"

rss_kib=0
processes=0
for pid in $(ps -o pid,comm | awk \
    '$2 == "rootlesskit" || $2 == "exe" || $2 == "slirp4netns" || $2 == "dockerd" || $2 == "containerd" { print $1 }'); do
    rss=$(awk '$1 == "VmRSS:" { print $2 }' "/proc/$pid/status" 2>/dev/null || true)
    rss_kib=$((rss_kib + ${rss:-0}))
    processes=$((processes + 1))
done
echo "idle_processes=$processes idle_rss_kib=$rss_kib"

say "checking endpoint metadata isolation and the expected bind-mount escape"
one="unix://$probe_root/slots/1/run/docker.sock"
two="unix://$probe_root/slots/2/run/docker.sock"
docker --host="$one" volume create slot-one-volume >/dev/null
assert_absent "$two" volume slot-one-volume
echo peer-secret >"$probe_root/slots/2/peer-secret"
docker --host="$one" pull "$image" >/dev/null
leaked=$(docker --host="$one" run --rm \
    --mount "type=bind,src=$probe_root/slots/2/peer-secret,dst=/probe,readonly" \
    "$image" cat /probe)
[ "$leaked" = peer-secret ]
echo "expected_negative_test=plain_daemon_can_read_peer_path"

say "stopping the scale set"
stop_recorded_daemons
remaining=$(ps -o comm,args | awk \
    '($1 == "rootlesskit" || $1 == "dockerd" || $1 == "containerd") && index($0, "/probe/slots/") { count++ } END { print count + 0 }')
[ "$remaining" -eq 0 ]
echo "remaining_scale_processes=$remaining"

say "building a throwaway private rootfs"
private=$probe_root/private
rootfs=$private/rootfs
mkdir -p "$rootfs"
(
    cd /
    tar -cf - bin etc home lib opt root sbin usr var
) | tar -C "$rootfs" -xf -

mkdir -p \
    "$private/rk" \
    "$rootfs/.oldroot" \
    "$rootfs/proc" \
    "$rootfs/sys" \
    "$rootfs/dev" \
    "$rootfs/tmp" \
    "$rootfs/run/rootlesskit" \
    "$rootfs/run/chimera/exec" \
    "$rootfs/var/lib/chimera/docker" \
    "$rootfs/workspace"
echo workspace-ok >"$rootfs/workspace/proof"
echo host-secret >/host-secret
mkdir -p /peer
echo peer-secret >/peer/secret
touch "$private/daemon.log"
chown -R rootless:rootless \
    "$private/rk" \
    "$rootfs/.oldroot" \
    "$rootfs/run" \
    "$rootfs/var/lib/chimera" \
    "$rootfs/workspace" \
    "$private/daemon.log"

su -s /bin/sh rootless -c "
    exec rootlesskit \
        --net=slirp4netns \
        --mtu=1500 \
        --disable-host-loopback \
        --port-driver=builtin \
        --state-dir=$private/rk \
        --pidns --cgroupns --utsns --ipcns \
        sh -euc '
            mount --bind $rootfs $rootfs
            mount --make-rprivate $rootfs
            mount --bind $private/rk $rootfs/run/rootlesskit
            mount --rbind /dev $rootfs/dev
            mount --make-rslave $rootfs/dev
            mount --rbind /sys $rootfs/sys
            mount --make-rslave $rootfs/sys
            mount -t proc proc $rootfs/proc
            cd $rootfs
            pivot_root . .oldroot
            cd /
            umount -l /.oldroot
            export HOME=/home/rootless
            export XDG_RUNTIME_DIR=/run/chimera
            export ROOTLESSKIT_STATE_DIR=/run/rootlesskit
            exec /usr/local/bin/docker-init -- /usr/local/bin/dockerd \
                --host=unix:///run/chimera/docker.sock \
                --data-root=/var/lib/chimera/docker \
                --exec-root=/run/chimera/exec \
                --pidfile=/run/chimera/dockerd.pid \
                --storage-driver=vfs
        '
" >"$private/daemon.log" 2>&1 &

private_socket=$rootfs/run/chimera/docker.sock
wait_for_socket "$private_socket" "$private/daemon.log"
private_pid=$(rootlesskit_pid "$private/rk")
[ -n "$private_pid" ]
echo "$private_pid" >>"$pid_file"
private_endpoint="unix://$private_socket"

say "checking full Docker API inside pivot_root"
docker --host="$private_endpoint" pull "$image" >/dev/null
docker --host="$private_endpoint" volume create private-volume >/dev/null
docker --host="$private_endpoint" run -d --name private-owned \
    -v private-volume:/data "$image" sleep 300 >/dev/null
docker --host="$private_endpoint" exec private-owned \
    sh -c 'echo volume-ok >/data/proof'
[ "$(docker --host="$private_endpoint" exec private-owned cat /data/proof)" = volume-ok ]
[ "$(docker --host="$private_endpoint" run --rm \
    --mount type=bind,src=/workspace/proof,dst=/probe,readonly \
    "$image" cat /probe)" = workspace-ok ]

for forbidden in /host-secret /peer/secret /var/run/docker.sock; do
    if docker --host="$private_endpoint" run --rm \
        --mount "type=bind,src=$forbidden,dst=/probe,readonly" \
        "$image" true >/dev/null 2>&1; then
        echo "forbidden bind unexpectedly succeeded: $forbidden" >&2
        exit 1
    fi
done
docker --host="$private_endpoint" run --rm \
    --mount type=bind,src=/.oldroot,dst=/probe,readonly \
    "$image" sh -c 'test ! -e /probe/host-secret && test ! -e /probe/peer'
echo "forbidden_binds=denied"

say "checking buildx docker-container driver"
client=$probe_root/buildx-client
context=$probe_root/build-context
mkdir -p "$client" "$context"
printf '%s\n' 'FROM alpine:3.22' 'RUN echo buildx-ok >/proof' >"$context/Dockerfile"
DOCKER_HOST="$private_endpoint" DOCKER_CONFIG="$client" \
    docker buildx create --name prototype-builder --driver docker-container --use >/dev/null
DOCKER_HOST="$private_endpoint" DOCKER_CONFIG="$client" \
    docker buildx inspect --bootstrap >/dev/null
DOCKER_HOST="$private_endpoint" DOCKER_CONFIG="$client" \
    docker buildx build --load -t chimera-prototype:buildx "$context" >/dev/null
[ "$(docker --host="$private_endpoint" run --rm chimera-prototype:buildx cat /proof)" = buildx-ok ]
echo "buildx_docker_container=ok"

say "destroying the private domain"
stop_recorded_daemons
remaining=$(ps -o comm,args | awk \
    '($1 == "rootlesskit" || $1 == "dockerd" || $1 == "containerd") && index($0, "/probe/") { count++ } END { print count + 0 }')
[ "$remaining" -eq 0 ]
echo "remaining_prototype_processes=$remaining"
echo "RESULT=PASS"
