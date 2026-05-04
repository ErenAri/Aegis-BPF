#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="$1"
NAMESPACE=$(yq e '.metadata.namespace' "$POLICY_FILE")
APP_LABEL=$(yq e '.spec.workloadSelector.podSelector.matchLabels.app' "$POLICY_FILE")

if [ "$APP_LABEL" = "null" ]; then
  echo "Only supports simple app label selector"
  exit 1
fi

PODS=$(kubectl get pods -n "$NAMESPACE" -l app="$APP_LABEL" -o jsonpath='{.items[*].metadata.name}')

for POD in $PODS; do
  NODE=$(kubectl get pod "$POD" -n "$NAMESPACE" -o jsonpath='{.spec.nodeName}')
  AGENT=$(kubectl get pods -n aegisbpf -o wide | grep "$NODE" | grep aegisbpf | awk '{print $1}' | head -n1)

  echo "Node: $NODE Agent: $AGENT"

  for f in $(yq e '.spec.fileRules.deny[].path' "$POLICY_FILE"); do
    kubectl exec -n aegisbpf "$AGENT" -- /usr/bin/aegisbpf block add "$f"
  done

  for ip in $(yq e '.spec.networkRules.deny[].ip' "$POLICY_FILE"); do
    kubectl exec -n aegisbpf "$AGENT" -- /usr/bin/aegisbpf network deny add --ip "$ip"
  done

done

echo "Policy applied"
