# Kubernetes RBAC (Emergency Control / Break-Glass)

This project intentionally avoids building a SaaS control plane. In Kubernetes,
**governance** for emergency controls is handled with:
- Kubernetes RBAC for `pods/exec`
- human process (approvals, tickets)
- auditable node-local logs + metrics/events emitted by AegisBPF

## Key Principle

An `exec` session into the AegisBPF pod is effectively **node-privileged**.
Treat `pods/exec` permissions for this workload as equivalent to root access.

## Minimal Enterprise Setup

- Deploy AegisBPF in a dedicated namespace.
- Use an SSO/MFA backed group for break-glass operators.
- Grant that group **only** `pods/exec` access in that namespace.
- Require a ticket id in the `--reason` string (example: `TICKET=INC-1234`).

The Helm chart can optionally install a namespace-scoped break-glass Role +
RoleBinding:
- `helm/aegisbpf/values.yaml`:
  - `rbac.breakglass.enabled=true`
  - `rbac.breakglass.subjectKind=Group`
  - `rbac.breakglass.subjectName=<your-group>`

## Important RBAC Limitation

Kubernetes RBAC cannot reliably express "allow `pods/exec` only for pods with
label X" using pure RBAC.

For stricter environments, add an admission policy with Gatekeeper or Kyverno:
- allow `pods/exec` only in the AegisBPF namespace, and
- only for the break-glass group, and
- only targeting AegisBPF pods (by label/name conventions).

This keeps "break-glass" narrowly scoped without introducing a custom control
plane.

## Operational Procedure

Use the runbook: `docs/runbooks/RECOVERY_break_glass.md`.

The primary mechanism is:
- `aegisbpf emergency-disable --reason "TICKET=... <reason>"`
- `aegisbpf emergency-enable --reason "TICKET=... <reason>"`

Use `aegisbpf emergency-status --json` to confirm posture and verify that the
emergency toggle audit trail is present on the node.

