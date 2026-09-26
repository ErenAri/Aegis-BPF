#!/usr/bin/env bash
# Guest half of scripts/mapinmap_cost_matrix.sh. See that script for why.
#
# Lives in the repo, which the guest sees through the shared rootfs, while the
# output directory is the 9p-mounted --rwdir the guest writes results into.
#
# Usage: mapinmap_cost_guest.sh <out-dir>
set -u
OUT="${1:?usage: mapinmap_cost_guest.sh <out-dir>}"
BIN="$OUT/mapinmap_cost"
exec > "$OUT/measured.txt" 2>&1

echo "kernel=$(uname -r)"
echo "uname=$(uname -a)"
[ -x "$BIN" ] || { echo "ERROR: $BIN missing inside the guest"; exit 1; }

echo "--- idle ---"
"$BIN" 32

echo "--- loaded ---"
# Saturate every CPU: this is the condition the stress and leak phases create,
# and the one under which an RCU grace period stops being free.
for _ in $(seq 1 "$(nproc)"); do (timeout 30 bash -c 'while :; do :; done') & done
sleep 2
"$BIN" 32
wait 2>/dev/null

echo "GUEST_DONE"
