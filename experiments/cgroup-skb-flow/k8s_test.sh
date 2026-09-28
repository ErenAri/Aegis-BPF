#!/usr/bin/env bash
# §7: does bpf_skb_cgroup_id() survive Kubernetes -- pod cgroups nested inside
# the kind node container, traffic crossing veth and kube-proxy?
#
# kind runs the node as a Docker container, so pod cgroups are nested two deep.
# Ground truth is the pod's cgroup inode as the HOST sees it. Never IP.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
CTX=kind-aegisflow
KUBECTL="${KUBECTL:-/home/ern42/.local/bin/kubectl}"
export KUBECONFIG="${KUBECONFIG:-/home/ern42/.kube/config}"
NODE=aegisflow-control-plane

"$KUBECTL" --context "$CTX" get nodes >/dev/null 2>&1 || { echo "cluster unavailable"; exit 77; }

"$KUBECTL" --context "$CTX" delete pod aegisflow-client --ignore-not-found >/dev/null 2>&1
"$KUBECTL" --context "$CTX" run aegisflow-client --image=alpine:3.20 --restart=Never \
   --command -- sleep 600 >/dev/null 2>&1
"$KUBECTL" --context "$CTX" wait --for=condition=Ready pod/aegisflow-client --timeout=90s >/dev/null 2>&1 \
   || { echo "pod not ready"; "$KUBECTL" --context "$CTX" describe pod aegisflow-client | tail -10; exit 1; }

UID_=$("$KUBECTL" --context "$CTX" get pod aegisflow-client -o jsonpath='{.metadata.uid}')
echo "pod uid: $UID_"

# The pod's cgroup lives inside the node container's cgroup namespace, which the
# host sees under the node container's own scope.
NODE_CG=$(find /sys/fs/cgroup -maxdepth 4 -type d -name "*${NODE}*" 2>/dev/null | head -1)
[ -n "$NODE_CG" ] || NODE_CG=$(find /sys/fs/cgroup -maxdepth 5 -type d -path "*kubelet*" 2>/dev/null | head -1)
POD_CG=$(find /sys/fs/cgroup -maxdepth 8 -type d -name "*${UID_//-/_}*" 2>/dev/null | head -1)
[ -n "$POD_CG" ] || POD_CG=$(find /sys/fs/cgroup -maxdepth 8 -type d -name "*${UID_}*" 2>/dev/null | head -1)

echo "node cgroup : ${NODE_CG:-<not found>}"
echo "pod  cgroup : ${POD_CG:-<not found>}"

TARGET_CG="${POD_CG:-$NODE_CG}"
[ -n "$TARGET_CG" ] || { echo "no attachable cgroup found"; exit 1; }
TRUE_CGID=$(stat -c %i "$TARGET_CG")
SCOPE=$([ -n "$POD_CG" ] && echo "pod" || echo "node (pod cgroup not locatable from host)")
echo "attach scope: $SCOPE"
echo "TRUE cgid   : $TRUE_CGID  (cgroup inode, ground truth)"

( cd "$HERE" && ./flow_probe "$TARGET_CG" --seconds 25 --idle 1500 --sweep 400 \
    --json "$OUT/k8s.jsonl" > "$OUT/k8s.txt" 2>&1 ) &
PROBE=$!
sleep 2

echo "=== pod -> DNS (ClusterIP, kube-proxy), pod -> external, pod -> pod ==="
"$KUBECTL" --context "$CTX" exec aegisflow-client -- sh -c '
  nslookup kubernetes.default 2>/dev/null >/dev/null
  nslookup example.com 2>/dev/null >/dev/null
  for i in 1 2 3; do wget -q -T2 -O /dev/null http://1.1.1.1/ 2>/dev/null; done
  for i in 1 2 3; do nc -z -w1 10.96.0.1 443 2>/dev/null; done
' >/dev/null 2>&1 || true

wait $PROBE
echo
grep -E "packets observed|flow keys|summaries|peak map|REDUCTION|evicted|parse errors" "$OUT/k8s.txt" | sed 's/^/  /'
echo
echo "=== IDENTITY: observed cgid vs ground truth $TRUE_CGID (scope: $SCOPE) ==="
python3 - "$OUT/k8s.jsonl" "$TRUE_CGID" <<'PY'
import json,sys
from collections import Counter
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
truth=int(sys.argv[2])
if not rows: print("  NO FLOWS"); sys.exit(0)
c=Counter(r["cgroup_id"] for r in rows)
print(f"  summaries: {len(rows)}   distinct cgids: {len(c)}")
for k,n in c.most_common(6):
    print(f"     cgid={k:<12} n={n:<4} {'<- ground truth' if k==truth else ''}")
match=sum(n for k,n in c.items() if k==truth)
print(f"  matching ground truth: {match}/{len(rows)}")
byd=Counter((r['dir'], r['cgroup_id']==truth) for r in rows)
for (d,ok),n in sorted(byd.items()): print(f"  {d:<8} {'correct' if ok else 'other':<7} {n}")
PY
"$KUBECTL" --context "$CTX" delete pod aegisflow-client --ignore-not-found >/dev/null 2>&1
