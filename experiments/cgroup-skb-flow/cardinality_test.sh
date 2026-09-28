#!/usr/bin/env bash
# §8/§11: does aggregation stay bounded, and was dropping the local port right?
#
# Runs traffic shapes with very different flow structure and records both the
# chosen key's cardinality and (via the shadow map) what a 5-tuple key would
# have cost for the same traffic.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_flow_card
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
cleanup(){ pkill -9 -x flow_probe 2>/dev/null
  [ -d "$CG" ] && { while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs" 2>/dev/null; rmdir "$CG" 2>/dev/null; }; }
trap cleanup EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

run_case() {
  local name="$1" secs="$2"; shift 2
  ( cd "$HERE" && ./flow_probe "$CG" --seconds "$secs" --idle 2000 --sweep 500 --shadow 1 \
      --json "$OUT/card_$name.jsonl" --quiet > "$OUT/card_$name.txt" 2>&1 ) &
  local P=$!
  sleep 2
  python3 - "$CG" "$name" <<'PY'
import socket,os,sys,time,random
cg,name=sys.argv[1],sys.argv[2]
open(cg+"/cgroup.procs","w").write(str(os.getpid()))
def tcp(host,port,t=0.2):
    s=socket.socket(); s.settimeout(t)
    try: s.connect((host,port))
    except Exception: pass
    finally: s.close()
if name=="many_short":          # 400 connections, ONE destination
    for _ in range(400): tcp("127.0.0.1", 9)
elif name=="fan_out":           # 400 DISTINCT destinations
    for i in range(400): tcp(f"127.{(i>>16)&255}.{(i>>8)&255}.{i&255}", 80)
elif name=="port_scan":         # one host, 400 ports
    for p in range(1000,1400): tcp("127.0.0.1", p)
elif name=="udp_burst":
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    for _ in range(3000): 
        try: s.sendto(b"x"*64,("127.0.0.1",9))
        except Exception: pass
elif name=="long_lived":
    s=socket.socket()
    try:
        s.connect(("127.0.0.1",9))
    except Exception: pass
    time.sleep(3)
PY
  wait $P
  local pkts keys summ peak t5 full
  pkts=$(grep -oP 'packets observed\s*:\s*\K[0-9]+' "$OUT/card_$name.txt")
  keys=$(grep -oP 'flow keys created\s*:\s*\K[0-9]+' "$OUT/card_$name.txt")
  summ=$(grep -oP 'summaries exported\s*:\s*\K[0-9]+' "$OUT/card_$name.txt")
  peak=$(grep -oP 'peak map occupancy\s*:\s*\K[0-9]+' "$OUT/card_$name.txt")
  t5=$(grep -oP '5-tuple keys \(shadow\)\s*:\s*\K[0-9]+' "$OUT/card_$name.txt")
  full=$(grep -oP 'map-full \(insert fail\)\s*:\s*\K[0-9]+' "$OUT/card_$name.txt")
  printf "%-12s pkts=%-7s keys=%-6s summaries=%-6s peak=%-6s 5tuple=%-7s mapfull=%-4s reduction=%sx\n" \
    "$name" "${pkts:-?}" "${keys:-?}" "${summ:-?}" "${peak:-?}" "${t5:-?}" "${full:-?}" \
    "$(python3 -c "print(f'{${pkts:-0}/max(${summ:-1},1):.0f}')" 2>/dev/null)"
}

printf "%-12s %s\n" "workload" "chosen key (cgroup+peer) vs 5-tuple shadow"
for c in many_short fan_out port_scan udp_burst long_lived; do run_case "$c" 12; done
