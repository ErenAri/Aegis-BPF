#!/usr/bin/env bash
# Resource behaviour under sustained policy reloads.
#
# Each reload allocates a fresh inner map per policy domain. The two-slot design
# intentionally retains one complete inactive generation so post-flip cleanup
# does not pay another RCU grace period per policy map. The next reload replaces
# that inactive generation. If references grow beyond those two generations,
# the map count rises without bound and the agent eventually fails to allocate.
# This measures that directly rather than inferring it.
set -uo pipefail

BIN="${BIN:-./build/aegisbpf}"
WORK="${WORKDIR:-$(mktemp -d)}"
RELOADS="${RELOADS:-300}"
mkdir -p "$WORK"

printf 'version=6\n\n[deny_path]\n/tmp/aegis_leak_target\n\n[deny_port]\n4444:tcp:egress\n' > "$WORK/a.conf"
printf 'version=6\n\n[deny_path]\n/tmp/aegis_leak_target\n\n[deny_port]\n5555:tcp:egress\n' > "$WORK/b.conf"
echo target > /tmp/aegis_leak_target

# bpftool is per-kernel; build the libbpf probe so this works in a VM too.
PROBE="$WORK/slot_probe"
cc -O2 -o "$PROBE" "$(dirname "$0")/../tools/slot_probe.c" -lbpf 2>/dev/null || {
    echo "cannot build tools/slot_probe.c; map counts unavailable"; exit 2; }

pid="$(pgrep -x aegisbpf | head -1)"
[ -n "$pid" ] || { echo "no agent running"; exit 2; }

sample() {
    local maps rss locked pins
    maps=$("$PROBE" map-count 2>/dev/null || echo -1)
    rss=$(awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    locked=$(awk '/VmLck/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    pins=$(find /sys/fs/bpf/aegisbpf -type f 2>/dev/null | wc -l)
    echo "$maps $rss $locked $pins"
}

read -r m0 r0 l0 p0 <<<"$(sample)"
[ "$m0" -lt 0 ] && { echo "map count unreadable; refusing to report a leak result"; exit 2; }
echo "before : bpf_maps=$m0 rss_kb=$r0 locked_kb=$l0 pinned=$p0"

for i in $(seq 1 "$RELOADS"); do
    if [ $((i % 2)) -eq 0 ]; then p=a; else p=b; fi
    "$BIN" policy apply "$WORK/$p.conf" >/dev/null 2>&1
    if [ $((i % 100)) -eq 0 ]; then
        read -r m r l pn <<<"$(sample)"
        echo "  after $i reloads: bpf_maps=$m rss_kb=$r locked_kb=$l pinned=$pn"
    fi
done

# Replaced inactive inner maps are freed by RCU, so settle before the final
# reading. One complete inactive generation is expected to remain resident.
sleep 5
read -r m1 r1 l1 p1 <<<"$(sample)"
echo "after  : bpf_maps=$m1 rss_kb=$r1 locked_kb=$l1 pinned=$p1"

dm=$((m1 - m0)); dr=$((r1 - r0)); dp=$((p1 - p0))
echo
echo "delta over $RELOADS reloads: bpf_maps=$dm rss_kb=$dr pinned=$dp"

fail=0
# 16 policy maps per generation. Relative to a one-generation starting state,
# one retained inactive generation contributes +16 maps; one extra RCU-delayed
# replacement can transiently make that +32. More than that after settling is
# outside the bounded two-slot contract.
if [ "$dm" -gt 32 ]; then echo "FAIL: BPF map count grew by $dm (expected <=32 with one retained inactive generation)"; fail=1; fi
if [ "$dp" -ne 0 ]; then echo "FAIL: pinned object count changed by $dp"; fail=1; fi
# RSS is noisy; a real fd/allocation leak over 300 reloads is far larger.
if [ "$dr" -gt 20480 ]; then echo "FAIL: RSS grew by ${dr} kB"; fail=1; fi

fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
echo "agent open fds: $fds"
[ "$fds" -gt 512 ] && { echo "FAIL: agent holds $fds file descriptors"; fail=1; }

rm -f /tmp/aegis_leak_target
[ "$fail" -eq 0 ] && echo "PASS: no unbounded growth across $RELOADS reloads" || exit 1
