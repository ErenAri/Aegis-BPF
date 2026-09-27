#!/usr/bin/env bash
# Measure the cost of one ARRAY_OF_MAPS update on each supported kernel.
#
# The apparent "stalls" in the kernel matrix came from this one syscall, so the
# cost belongs in the evidence rather than in an argument. On kernels where
# map_update_elem() on a map-in-map waits for an RCU grace period, the figure
# jumps by orders of magnitude the moment every CPU is busy -- which is exactly
# the condition the stress and leak phases create. Newer kernels do not wait,
# and the same code is fast there.
#
# Each measurement runs twice per kernel: once on an idle guest, once with every
# guest CPU spinning. Both numbers matter; only their ratio explains the stall.
#
# Env: KERNELS (default: all in the matrix table), RUN_ROOT (shared kernel cache)
# Exit: 0 if every kernel produced a measurement, 1 otherwise.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${RUN_ROOT:-/tmp/aegis-kernel-matrix}"
KCACHE="$RUN_ROOT/kernels"
# Under RUN_ROOT, next to the matrix's own run directories. virtme-ng prints a
# warning that the host's /tmp is hidden in the guest, but the --rwdir path is
# 9p-mounted explicitly and is the one place the guest can both read the staged
# binary and write results back. Staging outside it (e.g. under $HOME) makes
# the guest fail to boot at all: vng exits 255 before running anything.
OUT="${OUT:-$RUN_ROOT/mapinmap-cost-$(date +%Y%m%dT%H%M%S)}"
LOCK="$RUN_ROOT/.vm.lock"
mkdir -p "$OUT"

command -v vng >/dev/null 2>&1 || { echo "virtme-ng (vng) not installed"; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm not available"; exit 1; }

BIN="$OUT/mapinmap_cost"
gcc -O2 -o "$BIN" "$REPO/tools/mapinmap_cost.c" -lbpf || { echo "build failed"; exit 1; }

# Reuse whatever the matrix already downloaded; this script never fetches.
shopt -s nullglob

kernels="${KERNELS:-}"
if [ -z "$kernels" ]; then
    for d in "$KCACHE"/*/; do kernels="$kernels $(basename "$d")"; done
fi

rc=0
exec {lockfd}>"$LOCK"
flock "$lockfd"
for label in $kernels; do
    kimg=$(ls "$KCACHE/$label"/boot/vmlinuz-* 2>/dev/null | head -1)
    if [ -z "$kimg" ]; then
        echo "$label: no cached kernel image, skipped"
        continue
    fi
    log="$OUT/$label.txt"
    rm -f "$OUT/measured.txt"
    timeout 600 script -qec "vng --rwdir=$OUT --memory 4G --cpus 4 --run $kimg \
        -- $REPO/scripts/mapinmap_cost_guest.sh $OUT" \
        /dev/null < /dev/null > "$OUT/$label.console" 2>&1
    [ -f "$OUT/measured.txt" ] && mv "$OUT/measured.txt" "$log"
    if [ -f "$log" ] && grep -q GUEST_DONE "$log"; then
        idle=$(sed -n '/--- idle ---/,/--- loaded ---/p' "$log" | grep -m1 mean_ms | cut -d= -f2)
        load=$(sed -n '/--- loaded ---/,$p'              "$log" | grep -m1 mean_ms | cut -d= -f2)
        kver=$(grep -m1 '^kernel=' "$log" | cut -d= -f2)
        printf '%-20s %-24s idle %8s ms   loaded %8s ms\n' "$label" "$kver" "$idle" "$load"
        printf '{"label":"%s","kernel":"%s","idle_ms":%s,"loaded_ms":%s}\n' \
            "$label" "$kver" "${idle:-null}" "${load:-null}" >> "$OUT/cost.jsonl"
    else
        echo "$label: no measurement (see $log and $OUT/$label.console)"
        rc=1
    fi
done
flock -u "$lockfd"

echo
echo "results: $OUT"
exit $rc
