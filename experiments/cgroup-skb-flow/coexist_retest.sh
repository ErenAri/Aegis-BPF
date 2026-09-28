#!/usr/bin/env bash
# §23: coexistence retest, now that aggregation and maps are involved.
# Phase 1 proved the bare hook composed; this checks the aggregating version
# does too, and that its maps are cleaned up independently of the incumbent.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_flow_coex
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
trap 'rmdir "$CG" 2>/dev/null; rm -f /sys/fs/bpf/coex_inc2 2>/dev/null' EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

cat > /tmp/coex_inc2.bpf.c <<'BPF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
SEC("cgroup/skb") int other_ing(struct __sk_buff *skb){ (void)skb; return 1; }
char LICENSE[] SEC("license") = "GPL";
BPF
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I"$HERE/../../build" -c /tmp/coex_inc2.bpf.c -o /tmp/coex_inc2.bpf.o 2>/dev/null

rm -f /sys/fs/bpf/coex_inc2
bpftool prog load /tmp/coex_inc2.bpf.o /sys/fs/bpf/coex_inc2 2>/dev/null
bpftool cgroup attach "$CG" ingress pinned /sys/fs/bpf/coex_inc2 multi 2>&1 | head -1
echo "--- incumbent only ---"; bpftool cgroup show "$CG" 2>/dev/null | sed 's/^/    /'

( cd "$HERE" && timeout 14 ./flow_probe "$CG" --seconds 9 --quiet > /tmp/coex_flow.txt 2>&1 ) &
P=$!
sleep 3
echo "--- with the aggregating prototype attached ---"; bpftool cgroup show "$CG" 2>/dev/null | sed 's/^/    /'
N=$(bpftool cgroup show "$CG" 2>/dev/null | grep -cE "other_ing|aegis_flow_")
echo "    programs attached simultaneously: $N"
echo "--- prototype maps (must be separate from the incumbent) ---"
bpftool map show 2>/dev/null | grep -E "flows|counters|tuple5" | sed 's/^/    /' | head -4
wait $P
echo "--- after prototype detach: incumbent must survive ---"; bpftool cgroup show "$CG" 2>/dev/null | sed 's/^/    /'
echo "--- prototype maps after exit (freed with the object) ---"
bpftool map show 2>/dev/null | grep -cE "name flows|name tuple5" | sed 's/^/    remaining prototype maps: /'
bpftool cgroup detach "$CG" ingress pinned /sys/fs/bpf/coex_inc2 2>/dev/null
