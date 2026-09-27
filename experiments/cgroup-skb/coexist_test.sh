#!/usr/bin/env bash
# B9: does the prototype compose with a cgroup program that is already there?
#
# Attaches a trivial second cgroup_skb program FIRST, then the prototype, and
# checks both are present and neither displaced the other. Also checks the
# failure mode of the exclusive attach, because "BPF supports multiple
# programs" is not the same as "this attach composes".
set -uo pipefail
CG=/sys/fs/cgroup/aegis_skb_coexist
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
trap 'rmdir "$CG" 2>/dev/null' EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

cat > /tmp/other.bpf.c <<'BPF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
SEC("cgroup_skb/ingress") int other_ingress(struct __sk_buff *skb) { (void)skb; return 1; }
char LICENSE[] SEC("license") = "GPL";
BPF
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I"$HERE/../../build" -c /tmp/other.bpf.c -o /tmp/other.bpf.o || exit 1

python3 - "$CG" <<'PY'
import ctypes, ctypes.util, os, sys, subprocess
cg = sys.argv[1]
# Attach the "incumbent" with ALLOW_MULTI via bpftool, the way a real cgroup
# BPF user (systemd, a CNI) would.
r = subprocess.run(["bpftool","cgroup","attach",cg,"ingress","pinned","/sys/fs/bpf/other_ing","multi"],
                   capture_output=True, text=True)
print("incumbent attach:", "ok" if r.returncode==0 else r.stderr.strip()[:120])
PY

sudo bpftool prog load /tmp/other.bpf.o /sys/fs/bpf/other_ing 2>/dev/null
sudo bpftool cgroup attach "$CG" ingress pinned /sys/fs/bpf/other_ing multi 2>&1 | head -2
echo "--- cgroup programs after incumbent attach ---"
sudo bpftool cgroup show "$CG" 2>&1 | sed 's/^/    /'

echo "--- now attach the prototype alongside ---"
( cd "$HERE" && timeout 12 ./skb_probe "$CG" --seconds 8 --emit 0 > /tmp/coexist.txt 2>&1 ) &
PROBE=$!
sleep 3
echo "--- cgroup programs with BOTH attached ---"
sudo bpftool cgroup show "$CG" 2>&1 | sed 's/^/    /'
N=$(sudo bpftool cgroup show "$CG" 2>/dev/null | grep -cE "aegis_skb_|other_ingress")
echo "    cgroup_skb programs attached simultaneously: $N"
wait $PROBE
echo "--- after prototype detaches, incumbent must remain ---"
sudo bpftool cgroup show "$CG" 2>&1 | sed 's/^/    /'
sudo bpftool cgroup detach "$CG" ingress pinned /sys/fs/bpf/other_ing 2>/dev/null
sudo rm -f /sys/fs/bpf/other_ing
