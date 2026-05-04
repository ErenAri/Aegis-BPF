#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <namespace> <policy-name>"
  echo "example: $0 aegisbpf-demo demo-block-file-and-network"
}

if [ "$#" -ne 2 ]; then
  usage
  exit 1
fi

POLICY_NS="$1"
POLICY_NAME="$2"
SYSTEM_NS="${AEGIS_SYSTEM_NAMESPACE:-aegisbpf-system}"
STATE_CM="aegis-agent-state-${POLICY_NS}-${POLICY_NAME}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing dependency: $1" >&2
    exit 1
  }
}

require_cmd kubectl
require_cmd jq

if ! kubectl get aegispolicy "$POLICY_NAME" -n "$POLICY_NS" >/dev/null 2>&1; then
  echo "policy not found: ${POLICY_NS}/${POLICY_NAME}" >&2
  exit 1
fi

echo "AegisPolicy explanation"
echo "======================"
echo "Policy: ${POLICY_NS}/${POLICY_NAME}"
echo

echo "Status"
echo "------"
kubectl get aegispolicy "$POLICY_NAME" -n "$POLICY_NS" -o json | jq -r '
  .status as $s |
  "phase: \($s.phase // "Unknown")",
  "message: \($s.message // "")",
  "appliedNodes: \($s.appliedNodes // 0)",
  "lastAppliedAt: \($s.lastAppliedAt // "never")",
  "observedGeneration: \($s.observedGeneration // 0)"
'

echo

echo "Conditions"
echo "----------"
kubectl get aegispolicy "$POLICY_NAME" -n "$POLICY_NS" -o json | jq -r '
  (.status.conditions // [])[] |
  "- \(.type): \(.status) reason=\(.reason) message=\(.message)"
' || true

echo

echo "Workload selector"
echo "-----------------"
kubectl get aegispolicy "$POLICY_NAME" -n "$POLICY_NS" -o json | jq -r '
  .spec.workloadSelector // .spec.selector // {}'

echo

echo "Desired policy rules"
echo "--------------------"
kubectl get aegispolicy "$POLICY_NAME" -n "$POLICY_NS" -o json | jq -r '
  if .spec.fileRules.deny then
    .spec.fileRules.deny[] | "- file deny path=\(.path // "") action=\(.action // "Block")"
  else empty end,
  if .spec.networkRules.deny then
    .spec.networkRules.deny[] | "- network deny ip=\(.ip // "") cidr=\(.cidr // "") port=\(.port // "") protocol=\(.protocol // "") direction=\(.direction // "") action=\(.action // "Block")"
  else empty end
'

echo

echo "Applied agent state"
echo "-------------------"
if ! kubectl get configmap "$STATE_CM" -n "$SYSTEM_NS" >/dev/null 2>&1; then
  echo "No persisted agent state found. The controller may not have reconciled yet, or no workloads matched."
  exit 0
fi

kubectl get configmap "$STATE_CM" -n "$SYSTEM_NS" -o jsonpath='{.data.state\.json}' | jq -r '
  .nodes as $nodes |
  if (($nodes | length) == 0) then
    "No rules currently applied to any node."
  else
    $nodes | to_entries[] |
    "node: \(.key)",
    (.value[] | "  - key=\(.key) add=\(.add | join(" ")) del=\(.del | join(" "))")
  end
'

echo

echo "Interpretation"
echo "--------------"
echo "- Desired policy rules come from the AegisPolicy spec."
echo "- Applied agent state is the controller-owned diff state actually pushed to node agents."
echo "- If desired rules exist but applied state is empty, check matching pods, node agent health, and policy status.conditions."
