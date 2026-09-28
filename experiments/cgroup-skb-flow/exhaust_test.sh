#!/usr/bin/env bash
# §22: what happens when an attacker-controlled workload drives cardinality
# past the map bound? Local only -- all traffic to 127.x, nothing leaves.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_flow_exh
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
N="${N:-120000}"
cleanup(){ pkill -9 -x flow_probe 2>/dev/null
  [ -d "$CG" ] && { while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs" 2>/dev/null; rmdir "$CG" 2>/dev/null; }; }
trap cleanup EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

echo "driving $N distinct destinations (map bound is 65536 entries)"
( cd "$HERE" && ./flow_probe "$CG" --seconds 60 --idle 60000 --sweep 2000 --quiet \
    > "$OUT/exhaust.txt" 2>&1 ) &
P=$!
sleep 2
# UDP sendto to N distinct 127.x addresses: one packet each, no handshake,
# so cardinality rises as fast as the sender can loop.
python3 - "$CG" "$N" <<'PY'
import socket,os,sys
cg,n=sys.argv[1],int(sys.argv[2])
open(cg+"/cgroup.procs","w").write(str(os.getpid()))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(n):
    a=f"127.{(i>>16)&255}.{(i>>8)&255}.{(i&255) or 1}"
    try: s.sendto(b"x"*32,(a, 1024+(i%64)))
    except Exception: pass
print(f"    sender finished {n} datagrams")
PY
RSS_BEFORE=$(grep VmRSS /proc/$P/status 2>/dev/null | awk '{print $2}')
wait $P
echo
grep -E "packets observed|flow keys|summaries|peak map|map-full|live at exit|evicted|observation loss" "$OUT/exhaust.txt" | sed 's/^/  /'
echo
echo "  memory: LRU_HASH 65536 entries x (key 32B + value 64B + overhead)"
python3 -c "print(f'  theoretical max map memory ~= {65536*(32+64)/1048576:.1f} MiB (excl. kernel per-entry overhead)')"
