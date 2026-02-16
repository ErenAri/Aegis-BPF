# Helm Enforce Gating Contract

Status: **normative**

This contract defines required defaults and template behavior for Kubernetes
deployment posture.

## Defaults

- `agent.enforceGateMode=fail-closed`
- `agent.requireEnforceReadiness=true`
- `deployment.mode=auto`
- `enforceNodeSelector.aegisbpf.io/enforce-capable="true"`

## Template Requirements

- Runtime args must include:
  - `--enforce-gate-mode={{ .ctx.Values.agent.enforceGateMode }}`
- Enforce readiness probe must use:
  - `aegisbpf health --require-enforce`
- `deployment.mode=both` must render:
  - one audit DaemonSet (all nodes / default selector)
  - one enforce DaemonSet constrained by `enforceNodeSelector`

## Anti-Drift Rule

Helm defaults, template behavior, and runtime gating must remain aligned.
Any drift is a contract failure and must block merge.
