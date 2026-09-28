#!/usr/bin/env bash
# §15/§16: is LSM + flow materially better than either alone?
#
# Runs the REAL Aegis agent (audit-only, no policy) for exec events and the flow
# prototype on the same container cgroup, then joins on cgroup id -- never on IP.
#
# Two workloads, same container image, same network: one benign, one scanning.
# The question is whether either source alone can tell them apart.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"; chmod 777 "$OUT" 2>/dev/null
IMG=alpine:3.20
BIN="$REPO/build/aegisbpf"

[ -x "$BIN" ] || { echo "build the agent first"; exit 1; }
docker image inspect "$IMG" >/dev/null 2>&1 || docker pull -q "$IMG" >/dev/null

CID=""
cleanup(){
  [ -n "${AGENT:-}" ] && kill "$AGENT" 2>/dev/null
  pkill -9 -x flow_probe 2>/dev/null
  [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1
  rm -rf /sys/fs/bpf/aegisbpf 2>/dev/null
}
trap cleanup EXIT

run_scenario() {
  local name="$1" script="$2"
  docker rm -f aegis_corr >/dev/null 2>&1
  CID=$(docker run -d --name aegis_corr "$IMG" sleep 200)
  local SHORT="${CID:0:12}"
  local CG
  CG=$(find /sys/fs/cgroup -maxdepth 4 -type d -name "*${CID}*" 2>/dev/null | head -1)
  [ -n "$CG" ] || { echo "cgroup not found"; return 1; }
  local CGID; CGID=$(stat -c %i "$CG")

  rm -rf /sys/fs/bpf/aegisbpf 2>/dev/null
  "$BIN" run --audit --allow-unsigned-bpf --log-level=warn --log-format=json \
      > "$OUT/agent_$name.jsonl" 2>&1 &
  AGENT=$!
  sleep 12

  ( cd "$HERE" && ./flow_probe "$CG" --seconds 20 --idle 1500 --sweep 400 \
      --json "$OUT/flow_$name.jsonl" --quiet > "$OUT/flow_$name.txt" 2>&1 ) &
  local PROBE=$!
  sleep 2
  docker exec "$SHORT" sh -c "$script" >/dev/null 2>&1 || true
  wait $PROBE
  kill "$AGENT" 2>/dev/null; wait "$AGENT" 2>/dev/null; AGENT=""
  docker rm -f "$SHORT" >/dev/null 2>&1; CID=""
  echo "$CGID"
}

echo "=== scenario A: benign (one endpoint, repeated) ==="
CG_A=$(run_scenario benign '
  for i in $(seq 1 30); do nc -z -w1 127.0.0.1 9 2>/dev/null; done
  for i in $(seq 1 10); do nc -z -w1 127.0.0.1 9 2>/dev/null; done')
echo "    container cgid: $CG_A"

echo "=== scenario B: fan-out scan (many endpoints) ==="
CG_B=$(run_scenario scan '
  mkdir -p /tmp/.x && cp /bin/busybox /tmp/.x/nc && chmod +x /tmp/.x/nc
  for i in $(seq 1 60); do /tmp/.x/nc -z -w1 127.0.9.$i 80 2>/dev/null; done
  for p in 21 22 23 25 3306 5432 6379 8080 9200 27017; do /tmp/.x/nc -z -w1 127.0.0.1 $p 2>/dev/null; done')
echo "    container cgid: $CG_B"

echo
echo "================ CORRELATION ================"
python3 - "$OUT" "$CG_A" "$CG_B" <<'PY'
import json,sys,os
from collections import Counter, defaultdict
out, cga, cgb = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

def flows(name):
    p=os.path.join(out,f"flow_{name}.jsonl")
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []

def execs(name, cgid):
    p=os.path.join(out,f"agent_{name}.jsonl"); rows=[]; pids=set()
    if not os.path.exists(p): return rows
    for l in open(p):
        l=l.strip()
        if not l.startswith("{"): continue
        try: e=json.loads(l)
        except Exception: continue
        if e.get("type")=="exec" and e.get("cgid")==cgid:
            rows.append(e); pids.add(e.get("pid"))
        elif e.get("type")=="exec_argv" and e.get("pid") in pids:
            rows.append(e)
    return rows

for name,cgid in (("benign",cga),("scan",cgb)):
    fl=[f for f in flows(name) if f["cgroup_id"]==cgid]
    ex=execs(name,cgid)
    peers={(f["remote"],f["remote_port"]) for f in fl if f["dir"]=="egress"}
    ips={f["remote"] for f in fl if f["dir"]=="egress"}
    syn=sum(f["syn"] for f in fl); rst=sum(f["rst"] for f in fl)
    pkts=sum(f["packets"] for f in fl)
    comms=Counter(e.get("comm") for e in ex if e.get("type")=="exec")
    argvs=[" ".join(e.get("argv",[])[:2]) for e in ex if e.get("type")=="exec_argv"]
    print(f"\n--- {name.upper()} (cgid {cgid}) ---")
    print(f"  LSM  : {len(ex)} exec-related events, comms={dict(comms.most_common(4))}")
    if argvs: print(f"         sample argv: {argvs[:3]}")
    print(f"  FLOW : {len(fl)} summaries, {pkts} packets, {len(ips)} distinct peer IPs,"
          f" {len(peers)} distinct peer endpoints")
    print(f"         syn={syn} rst={rst}")
    print(f"  JOIN : cgid {cgid} -> "
          f"{'HIGH FAN-OUT' if len(ips)>10 else 'low fan-out'}, "
          f"{'SYN-heavy' if syn>20 else 'normal SYN'}")
PY
