#!/usr/bin/env bash
# §5/§25: verify the flow prototype on each supported kernel.
# Verifier acceptance is NOT treated as semantic proof: this also attaches to a
# real cgroup, drives traffic, and checks the observed identity equals that
# cgroup's inode.
set -u
OUT="${1:?out dir}"
HERE="${AEGIS_EXP:-/home/ern42/CLionProjects/aegisbpf/experiments/cgroup-skb-flow}"
mkdir -p "$OUT"; exec > "$OUT/log.txt" 2>&1
echo "kernel=$(uname -r)"
mount -t bpf bpffs /sys/fs/bpf 2>/dev/null
cd "$HERE" || exit 1

echo "--- load / verifier ---"
./flow_probe --check; echo "check_rc=$?"

CG=/sys/fs/cgroup/aegis_flow_kv
rmdir "$CG" 2>/dev/null; mkdir -p "$CG" 2>/dev/null || { echo "cgroup_create=FAIL"; echo ALL_DONE; exit 0; }
TRUE=$(stat -c %i "$CG")
echo "cgroup_inode=$TRUE"

./flow_probe "$CG" --seconds 10 --idle 800 --sweep 300 --json "$OUT/f.jsonl" --quiet > "$OUT/probe.txt" 2>&1 &
P=$!
sleep 2
python3 - "$CG" <<'PY' 2>/dev/null
import socket,os,sys
open(sys.argv[1]+"/cgroup.procs","w").write(str(os.getpid()))
for i in range(1,25):
    s=socket.socket(); s.settimeout(0.2)
    try: s.connect((f"127.0.9.{i}", 80))
    except Exception: pass
    s.close()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(50):
    try: u.sendto(b"x"*32,("127.0.0.1",9))
    except Exception: pass
PY
wait $P
grep -E "packets observed|flow keys|summaries|peak map|evicted|parse errors" "$OUT/probe.txt"
python3 - "$OUT/f.jsonl" "$TRUE" <<'PY' 2>/dev/null
import json,sys
rows=[json.loads(l) for l in open(sys.argv[1])] if __import__('os').path.exists(sys.argv[1]) else []
truth=int(sys.argv[2])
if not rows: print("identity=NO_FLOWS"); raise SystemExit
ok=sum(1 for r in rows if r["cgroup_id"]==truth)
print(f"identity_match={ok}/{len(rows)}")
print(f"identity_distinct={len({r['cgroup_id'] for r in rows})}")
ing=[r for r in rows if r['dir']=='ingress']; egr=[r for r in rows if r['dir']=='egress']
for nm,rs in (("ingress",ing),("egress",egr)):
    if rs: print(f"{nm}_match={sum(1 for r in rs if r['cgroup_id']==truth)}/{len(rs)}")
PY
rmdir "$CG" 2>/dev/null
echo ALL_DONE
