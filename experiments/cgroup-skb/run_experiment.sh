#!/usr/bin/env bash
# EXPERIMENT (#323): drive traffic through a test cgroup and measure what
# cgroup_skb sees, what identity it preserves, and how many events it produces.
#
# Creates its own cgroup, attaches only there, and removes it afterwards.
set -uo pipefail

CG=/sys/fs/cgroup/aegis_skb_experiment
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"
mkdir -p "$OUT"

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }

cleanup() {
    # Move any stragglers back to root so the cgroup can be removed.
    if [ -f "$CG/cgroup.procs" ]; then
        while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs"
    fi
    rmdir "$CG" 2>/dev/null
}
trap cleanup EXIT

rmdir "$CG" 2>/dev/null
mkdir -p "$CG" || { echo "cannot create test cgroup"; exit 1; }
echo "test cgroup: $CG (id=$(stat -c %i "$CG"))"

# Traffic generator: runs INSIDE the test cgroup.
traffic() {
    local phase="$1"
    echo "$BASHPID" > "$CG/cgroup.procs" 2>/dev/null
    case "$phase" in
      short)   # one short TCP connection, the "HTTP-like" case
        timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22; printf "x\n" >&3; head -c 64 <&3' >/dev/null 2>&1
        ;;
      refused) timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' >/dev/null 2>&1 ;;
      udp)     timeout 3 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(50): s.sendto(b'x'*64,('127.0.0.1',9))
" >/dev/null 2>&1 ;;
      bulk)    timeout 8 bash -c '
          dd if=/dev/zero bs=64K count=400 2>/dev/null | timeout 6 nc -q1 127.0.0.1 9099 2>/dev/null' >/dev/null 2>&1 ;;
      dns)     timeout 3 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(b'\x00'*32,('127.0.0.53',53)); s.recvfrom(512)
except Exception: pass
" >/dev/null 2>&1 ;;
    esac
}

run_phase() {
    local name="$1" secs="$2" emit="$3"
    echo "--- phase: $name (emit=$emit) ---"
    ( cd "$HERE" && ./skb_probe "$CG" --seconds "$secs" --emit "$emit" \
        --json "$OUT/$name.jsonl" > "$OUT/$name.txt" 2>&1 ) &
    local probe=$!
    sleep 2
    traffic "$name"
    wait $probe
    grep -E "packets observed|events emitted|skb_cgid|current_cgid|unparsed|ringbuf|^ok|^unsup|^truncated|^fragment|^v6" "$OUT/$name.txt" | sed 's/^/    /'
}

# Listener for the bulk case so the connection is accepted rather than refused.
( timeout 20 nc -l -p 9099 > /dev/null 2>&1 & ) 2>/dev/null

for p in short refused udp dns bulk; do
    run_phase "$p" 8 1
done

echo
echo "results written to $OUT"
