#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="aegisbpf"
DEMO_NS="aegisbpf-demo"
BIN_PATH="/usr/bin/aegisbpf"
TARGET_FILE="/tmp/aegisbpf-demo-secret"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }
}

require_cmd kubectl
require_cmd helm

cleanup() {
  set +e
  kubectl delete -f demo/k8s-workload.yaml >/dev/null 2>&1 || true
  helm uninstall aegisbpf -n "$NAMESPACE" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[1] install AegisBPF via Helm"
helm install aegisbpf ./helm/aegisbpf \
  --namespace "$NAMESPACE" \
  --create-namespace >/dev/null

kubectl rollout status daemonset -n "$NAMESPACE" >/dev/null

echo "[2] deploy demo workload"
kubectl apply -f demo/k8s-workload.yaml >/dev/null
kubectl wait --for=condition=Ready pod/aegisbpf-demo-workload -n "$DEMO_NS" --timeout=60s

NODE=$(kubectl get pod aegisbpf-demo-workload -n "$DEMO_NS" -o jsonpath='{.spec.nodeName}')
AGENT_POD=$(kubectl get pods -n "$NAMESPACE" -o wide | grep "$NODE" | grep aegisbpf | awk '{print $1}' | head -n1)

echo "[3] baseline file read"
kubectl exec -n "$DEMO_NS" aegisbpf-demo-workload -- cat "$TARGET_FILE" >/dev/null
echo "baseline success"

echo "[4] apply deny rule"
kubectl exec -n "$NAMESPACE" "$AGENT_POD" -- "$BIN_PATH" block add "$TARGET_FILE"

sleep 2

echo "[5] verify block"
if kubectl exec -n "$DEMO_NS" aegisbpf-demo-workload -- cat "$TARGET_FILE" >/dev/null 2>&1; then
  echo "FAIL: file not blocked"
  exit 1
fi

echo "SUCCESS: file access blocked"

echo "[6] demo network block"
kubectl exec -n "$NAMESPACE" "$AGENT_POD" -- "$BIN_PATH" network deny add --ip 1.1.1.1

if kubectl exec -n "$DEMO_NS" aegisbpf-demo-workload -- wget -q -T 3 -O - http://1.1.1.1 >/dev/null 2>&1; then
  echo "FAIL: network not blocked"
  exit 1
fi

echo "SUCCESS: network blocked"

echo "[7] break-glass"
kubectl exec -n "$NAMESPACE" "$AGENT_POD" -- "$BIN_PATH" emergency-disable --reason demo
sleep 2

if kubectl exec -n "$DEMO_NS" aegisbpf-demo-workload -- cat "$TARGET_FILE" >/dev/null 2>&1; then
  echo "SUCCESS: break-glass restored access"
else
  echo "FAIL: break-glass failed"
  exit 1
fi

echo "Demo completed successfully"
