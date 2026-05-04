# Policy Audit & Explainability (Kubernetes)

This guide explains how to understand *what* an AegisPolicy did, *where* it was applied, and *why*.

## Sources of truth

1. **AegisPolicy.status**
   - `phase`: Applied / Error
   - `message`: controller summary
   - `appliedNodes`: number of nodes with enforcement
   - `conditions`: Ready / Degraded with reasons

2. **Controller state (ConfigMap)**
   - Name: `aegis-agent-state-<namespace>-<policy>`
   - Namespace: `aegisbpf-system` (default)
   - Contains JSON with per-node applied rules (keys + CLI commands)

3. **Workload selection**
   - `spec.workloadSelector` or `spec.selector`
   - Determines which pods → nodes are targeted

## Quick explain

Use the helper script:

```bash
scripts/explain_k8s_policy.sh <namespace> <policy-name>
```

It prints:
- Status and conditions
- Desired rules from the spec
- Applied rules per node from controller state
- Interpretation notes

## Manual inspection

### Status

```bash
kubectl get aegispolicy <name> -n <ns> -o yaml
```

### Applied state

```bash
kubectl get cm aegis-agent-state-<ns>-<name> -n aegisbpf-system -o json | jq -r '.data["state.json"]' | jq
```

### Matching pods / nodes

```bash
kubectl get pods -n <ns> -l <selector>
```

## Common scenarios

- **No rules applied**
  - No matching pods
  - Agents not running on nodes
  - Controller reported `Error` in status

- **Partial application**
  - Check `conditions` for Degraded
  - Inspect failed nodes in status message

- **Rules present but not effective**
  - Verify correct path/IP/port
  - Ensure direction/protocol flags are correct

## Design notes

- The controller persists applied state to ensure idempotent reconciliation.
- Explainability reads from that state rather than inferring from desired spec only.
- This avoids "last write wins" ambiguity and shows the actual enforced rules.
