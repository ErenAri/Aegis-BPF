# Kubernetes Rollout: Audit Everywhere + Enforce on Labeled Nodes

This guide provides a deterministic production rollout for mixed-capability
fleets:

- Audit DaemonSet on all nodes.
- Enforce DaemonSet only on `aegisbpf.io/enforce-capable=true` nodes.

## 1) Install in mixed mode

```bash
helm upgrade --install aegisbpf helm/aegisbpf \
  --namespace aegisbpf \
  --create-namespace \
  --set deployment.mode=both \
  --set agent.enforceGateMode=fail-closed \
  --set agent.requireEnforceReadiness=true
```

## 2) Generate node posture from capabilities report

On each node (or via privileged debug pod), evaluate posture:

```bash
python3 scripts/evaluate_capability_posture.py \
  --input /var/lib/aegisbpf/capabilities.json \
  --strict \
  --out-json /var/lib/aegisbpf/capabilities.posture.json \
  --out-labels-json /var/lib/aegisbpf/capabilities.labels.json
```

## 3) Label enforce-capable nodes

```bash
kubectl label node <node-name> aegisbpf.io/enforce-capable=true --overwrite
```

Optional cleanup for non-capable nodes:

```bash
kubectl label node <node-name> aegisbpf.io/enforce-capable-
```

## 4) Verify placement

```bash
kubectl -n aegisbpf get ds,pods -o wide
kubectl get nodes -L aegisbpf.io/enforce-capable
```

Expected:

- `*-audit` DaemonSet pods on all schedulable nodes.
- `*-enforce` DaemonSet pods only on labeled nodes.

## 5) Verify enforce readiness and posture

```bash
kubectl -n aegisbpf exec ds/aegisbpf-enforce -- aegisbpf health --require-enforce
kubectl -n aegisbpf exec ds/aegisbpf-enforce -- aegisbpf capabilities --json
```

## 6) Run one deny-path probe

Use a known denied target (example policy-dependent):

```bash
kubectl -n aegisbpf exec ds/aegisbpf-enforce -- sh -lc 'cat /etc/shadow >/dev/null'
```

Expect non-zero exit in enforce mode for protected/denied paths.

## 7) Admission hardening for exec access

Kubernetes RBAC alone cannot reliably enforce pod-label-scoped `pods/exec`.
Use one of:

- **OPA Gatekeeper** policy: allow `pods/exec` only in `aegisbpf` namespace and
  only for approved break-glass group subjects.
- **Kyverno** policy: deny `pods/exec` requests outside AegisBPF targets or
  missing required subject constraints.

Also require break-glass reasons with ticket IDs:

- `aegisbpf emergency-disable --reason "TICKET=<id> ..."`
- `aegisbpf emergency-enable --reason "TICKET=<id> ..."`

## 8) Operational defaults

- Keep `agent.enforceGateMode=fail-closed` for production.
- Use `audit-fallback` only with explicit risk acceptance and alerting.
- Keep `deployment.mode=both` during mixed-capability migrations.
