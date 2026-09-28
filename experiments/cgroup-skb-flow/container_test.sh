#!/usr/bin/env bash
# §6: does bpf_skb_cgroup_id() attribute REAL container traffic correctly?
#
# Phase 1 never tested a nested container cgroup, so this is the gate.
# Ground truth is the container's actual cgroup inode, read from the host --
# never inferred from IP, per the brief.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
IMG=alpine:3.20

command -v docker >/dev/null || { echo "docker unavailable"; exit 77; }
docker image inspect "$IMG" >/dev/null 2>&1 || docker pull -q "$IMG" >/dev/null 2>&1

CID=""
cleanup(){ [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1; }
trap cleanup EXIT

echo "=== starting container ==="
CID=$(docker run -d --name aegis_flow_ct "$IMG" sleep 300 2>/dev/null || \
      { docker rm -f aegis_flow_ct >/dev/null 2>&1; docker run -d --name aegis_flow_ct "$IMG" sleep 300; })
CID_SHORT="${CID:0:12}"
echo "container: $CID_SHORT"

# Ground truth: the container's cgroup path on the host, and its inode.
CGPATH=""
for cand in \
  "/sys/fs/cgroup/system.slice/docker-${CID}.scope" \
  "/sys/fs/cgroup/docker/${CID}" \
  "$(find /sys/fs/cgroup -maxdepth 4 -type d -name "*${CID_SHORT}*" 2>/dev/null | head -1)"; do
  [ -n "$cand" ] && [ -d "$cand" ] && { CGPATH="$cand"; break; }
done
[ -n "$CGPATH" ] || { echo "cannot locate container cgroup"; exit 1; }
TRUE_CGID=$(stat -c %i "$CGPATH")
echo "cgroup path : $CGPATH"
echo "TRUE cgid   : $TRUE_CGID   <- ground truth (cgroup inode, not IP)"

# Attach to the CONTAINER's cgroup.
( cd "$HERE" && ./flow_probe "$CGPATH" --seconds 22 --idle 1500 --sweep 400 \
    --json "$OUT/container.jsonl" > "$OUT/container.txt" 2>&1 ) &
PROBE=$!
sleep 2

echo "=== container -> external, container -> host ==="
HOST_IP=$(ip -4 addr show docker0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
docker exec "$CID_SHORT" sh -c "
  for i in \$(seq 1 5); do wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null; done
  for i in \$(seq 1 5); do nc -z -w1 ${HOST_IP:-172.17.0.1} 22 2>/dev/null; done
  ping -c 3 -W 1 ${HOST_IP:-172.17.0.1} >/dev/null 2>&1
  nslookup example.com 2>/dev/null >/dev/null
" 2>/dev/null || true

echo "=== host -> container (ingress attribution) ==="
CT_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CID_SHORT" 2>/dev/null)
echo "container IP: $CT_IP"
if [ -n "$CT_IP" ]; then
  for i in 1 2 3; do timeout 1 bash -c "exec 3<>/dev/tcp/$CT_IP/9" 2>/dev/null; done
  ping -c 3 -W 1 "$CT_IP" >/dev/null 2>&1 || true
fi

wait $PROBE
echo
echo "=== results ==="
grep -E "packets observed|flow keys|summaries|peak map|REDUCTION|parse errors|map-full" "$OUT/container.txt" | sed 's/^/  /'
echo
echo "=== IDENTITY CHECK: observed cgid vs ground truth $TRUE_CGID ==="
python3 - "$OUT/container.jsonl" "$TRUE_CGID" <<'PY'
import json,sys
from collections import Counter
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
truth=int(sys.argv[2])
if not rows: print("  NO FLOWS OBSERVED"); sys.exit(0)
c=Counter(r["cgroup_id"] for r in rows)
match=sum(n for k,n in c.items() if k==truth)
other=sum(n for k,n in c.items() if k!=truth)
print(f"  summaries total     : {len(rows)}")
print(f"  cgid == ground truth: {match}")
print(f"  cgid != ground truth: {other}")
for k,n in c.most_common(5):
    print(f"     cgid={k:<12} n={n}  {'<- TRUE' if k==truth else ''}")
byd=Counter((r['dir'], r['cgroup_id']==truth) for r in rows)
for (d,ok),n in sorted(byd.items()):
    print(f"  {d:<8} {'correct' if ok else 'WRONG':<8} {n}")
PY
