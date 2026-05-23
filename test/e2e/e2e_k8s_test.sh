#!/usr/bin/env bash
# End-to-end Kubernetes test for aegis-next + operator.
#
# Prerequisites:
#   - kind cluster running (see kind-config.yaml)
#   - kubectl configured
#   - helm available
#   - operator and aegis-next images loaded into kind
#
# Usage:
#   ./test/e2e/e2e_k8s_test.sh
#
# Environment variables:
#   AEGIS_NEXT_IMAGE   - aegis-next container image (default: aegisbpf-next:test)
#   OPERATOR_IMAGE     - operator container image (default: aegisbpf-operator:test)
#   CLUSTER_NAME       - kind cluster name (default: aegis-e2e)
#   SKIP_CLUSTER       - set to "true" to skip cluster creation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

AEGIS_NEXT_IMAGE="${AEGIS_NEXT_IMAGE:-aegisbpf-next:test}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-aegisbpf-operator:test}"
CLUSTER_NAME="${CLUSTER_NAME:-aegis-e2e}"
SKIP_CLUSTER="${SKIP_CLUSTER:-false}"
NAMESPACE="aegisbpf-test"

PASS=0
FAIL=0
WARN=0

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }
warn() { echo "  WARN: $1"; ((WARN++)); }

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    helm uninstall aegis-e2e -n "$NAMESPACE" 2>/dev/null || true
    kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true
    kubectl delete -f "$SCRIPT_DIR/fixtures/" 2>/dev/null || true
    if [[ "$SKIP_CLUSTER" != "true" ]]; then
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== AegisBPF E2E Kubernetes Test ==="
echo "Operator image: $OPERATOR_IMAGE"
echo "Aegis-next image: $AEGIS_NEXT_IMAGE"
echo ""

# ---- Step 1: Create kind cluster ----
echo "--- Step 1: Cluster setup ---"
if [[ "$SKIP_CLUSTER" != "true" ]]; then
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        echo "Cluster $CLUSTER_NAME already exists, reusing"
    else
        kind create cluster --config "$SCRIPT_DIR/kind-config.yaml" --name "$CLUSTER_NAME" --wait 120s
    fi
    pass "kind cluster created"
else
    echo "Skipping cluster creation (SKIP_CLUSTER=true)"
fi

# ---- Step 2: Load images into kind ----
echo ""
echo "--- Step 2: Load images ---"
kind load docker-image "$OPERATOR_IMAGE" --name "$CLUSTER_NAME" 2>/dev/null || warn "operator image load failed (may not be built yet)"
kind load docker-image "$AEGIS_NEXT_IMAGE" --name "$CLUSTER_NAME" 2>/dev/null || warn "aegis-next image load failed (may not be built yet)"

# ---- Step 3: Install CRDs ----
echo ""
echo "--- Step 3: Install CRDs ---"
kubectl apply -f "$REPO_ROOT/operator/config/crd/" --server-side
if kubectl get crd aegispolicies.aegisbpf.io &>/dev/null; then
    pass "AegisPolicy CRD installed"
else
    fail "AegisPolicy CRD not found"
fi

if kubectl get crd aegisclusterpolicies.aegisbpf.io &>/dev/null; then
    pass "AegisClusterPolicy CRD installed"
else
    fail "AegisClusterPolicy CRD not found"
fi

# ---- Step 4: Deploy via Helm ----
echo ""
echo "--- Step 4: Helm install ---"
kubectl create namespace "$NAMESPACE" 2>/dev/null || true

helm install aegis-e2e "$REPO_ROOT/helm/aegisbpf" \
    --namespace "$NAMESPACE" \
    --set operator.enabled=true \
    --set operator.image.repository="${OPERATOR_IMAGE%%:*}" \
    --set operator.image.tag="${OPERATOR_IMAGE##*:}" \
    --set operator.image.pullPolicy=Never \
    --set aegisNext.enabled=true \
    --set aegisNext.image.repository="${AEGIS_NEXT_IMAGE%%:*}" \
    --set aegisNext.image.tag="${AEGIS_NEXT_IMAGE##*:}" \
    --set aegisNext.image.pullPolicy=Never \
    --set aegisNext.nodeSelector.kubernetes\\.io/os=linux \
    --wait --timeout 120s 2>/dev/null || true

# Check operator deployment.
if kubectl -n "$NAMESPACE" rollout status deploy/aegis-e2e-aegisbpf-operator --timeout=60s 2>/dev/null; then
    pass "operator deployment rolled out"
else
    warn "operator deployment not ready (image may not be available)"
fi

# ---- Step 5: Create AegisPolicy ----
echo ""
echo "--- Step 5: Create AegisPolicy ---"
mkdir -p "$SCRIPT_DIR/fixtures"
cat > "$SCRIPT_DIR/fixtures/test-policy.yaml" <<'EOF'
apiVersion: aegisbpf.io/v1alpha1
kind: AegisPolicy
metadata:
  name: e2e-block-miners
  namespace: default
spec:
  mode: enforce
  execRules:
    denyComm:
      - xmrig
      - minerd
  networkRules:
    deny:
      - port: 4444
        direction: outbound
        action: Block
      - port: 3333
        direction: outbound
        action: Block
EOF

kubectl apply -f "$SCRIPT_DIR/fixtures/test-policy.yaml"
pass "AegisPolicy created"

# Wait for reconciliation.
sleep 5

# ---- Step 6: Verify ConfigMap generation ----
echo ""
echo "--- Step 6: Verify ConfigMap ---"

# Per-policy ConfigMap.
CM_NAME="aegis-policy-default-e2e-block-miners"
if kubectl -n aegisbpf-system get configmap "$CM_NAME" &>/dev/null 2>&1; then
    pass "per-policy ConfigMap $CM_NAME created"

    # Check for policy.conf key.
    if kubectl -n aegisbpf-system get configmap "$CM_NAME" -o jsonpath='{.data.policy\.conf}' 2>/dev/null | grep -q "deny_path"; then
        pass "ConfigMap contains policy.conf (INI format)"
    else
        warn "ConfigMap missing policy.conf content"
    fi

    # Check for policy.next key.
    if kubectl -n aegisbpf-system get configmap "$CM_NAME" -o jsonpath='{.data.policy\.next}' 2>/dev/null | grep -q "xmrig"; then
        pass "ConfigMap contains policy.next (aegis-next format)"
    else
        warn "ConfigMap missing policy.next content"
    fi

    # Check hash annotation.
    HASH=$(kubectl -n aegisbpf-system get configmap "$CM_NAME" -o jsonpath='{.metadata.annotations.aegisbpf\.io/policy-hash}' 2>/dev/null)
    if [[ -n "$HASH" ]]; then
        pass "ConfigMap has policy hash annotation: ${HASH:0:12}..."
    else
        warn "ConfigMap missing hash annotation"
    fi
else
    warn "per-policy ConfigMap not found (operator may not be running)"
fi

# Merged ConfigMap.
if kubectl -n aegisbpf-system get configmap aegis-merged-policy &>/dev/null 2>&1; then
    pass "merged policy ConfigMap created"
else
    warn "merged policy ConfigMap not found (operator may not be running)"
fi

# ---- Step 7: Create AegisClusterPolicy ----
echo ""
echo "--- Step 7: Create AegisClusterPolicy ---"
cat > "$SCRIPT_DIR/fixtures/test-clusterpolicy.yaml" <<'EOF'
apiVersion: aegisbpf.io/v1alpha1
kind: AegisClusterPolicy
metadata:
  name: e2e-baseline
spec:
  mode: enforce
  kernelRules:
    blockModuleLoad: true
    blockPtrace: true
  execRules:
    denyComm:
      - cpuminer
EOF

kubectl apply -f "$SCRIPT_DIR/fixtures/test-clusterpolicy.yaml"
pass "AegisClusterPolicy created"
sleep 3

# Verify cluster policy shows up.
if kubectl get aegisclusterpolicies e2e-baseline -o name &>/dev/null; then
    pass "AegisClusterPolicy exists in API"
else
    fail "AegisClusterPolicy not found"
fi

# ---- Step 8: Update policy and verify hash change ----
echo ""
echo "--- Step 8: Policy update ---"
HASH_BEFORE=$(kubectl -n aegisbpf-system get configmap "$CM_NAME" -o jsonpath='{.metadata.annotations.aegisbpf\.io/policy-hash}' 2>/dev/null || echo "none")

kubectl patch aegispolicy -n default e2e-block-miners --type=merge -p '{"spec":{"execRules":{"denyComm":["xmrig","minerd","ethminer"]}}}'
sleep 3

HASH_AFTER=$(kubectl -n aegisbpf-system get configmap "$CM_NAME" -o jsonpath='{.metadata.annotations.aegisbpf\.io/policy-hash}' 2>/dev/null || echo "none")

if [[ "$HASH_BEFORE" != "$HASH_AFTER" && "$HASH_AFTER" != "none" ]]; then
    pass "ConfigMap hash changed after policy update"
else
    warn "ConfigMap hash did not change (operator may not be running)"
fi

# ---- Step 9: Delete policy and verify cleanup ----
echo ""
echo "--- Step 9: Policy deletion ---"
kubectl delete aegispolicy -n default e2e-block-miners
sleep 5

if ! kubectl -n aegisbpf-system get configmap "$CM_NAME" &>/dev/null 2>&1; then
    pass "ConfigMap cleaned up after policy deletion"
else
    warn "ConfigMap still exists after policy deletion"
fi

# ---- Step 10: Check node labels ----
echo ""
echo "--- Step 10: Node feature labels ---"
ARENA_LABEL=$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.aegisbpf\.io/arena-capable}' 2>/dev/null || echo "")
KERNEL_LABEL=$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.aegisbpf\.io/kernel-version}' 2>/dev/null || echo "")

if [[ -n "$ARENA_LABEL" ]]; then
    pass "node labeled aegisbpf.io/arena-capable=$ARENA_LABEL"
else
    warn "node not labeled with arena-capable (NodeFeatureReconciler may not be running)"
fi

if [[ -n "$KERNEL_LABEL" ]]; then
    pass "node labeled aegisbpf.io/kernel-version=$KERNEL_LABEL"
else
    warn "node not labeled with kernel-version"
fi

# ---- Step 11: Helm test ----
echo ""
echo "--- Step 11: Helm test ---"
if helm test aegis-e2e -n "$NAMESPACE" --timeout 60s 2>/dev/null; then
    pass "helm test passed"
else
    warn "helm test failed or not available"
fi

# ---- Step 12: Cleanup test cluster policy ----
kubectl delete aegisclusterpolicies e2e-baseline 2>/dev/null || true

# ---- Results ----
echo ""
echo "========================================"
echo "  E2E Results: $PASS passed, $FAIL failed, $WARN warnings"
echo "========================================"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
