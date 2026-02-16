# Enforcement Guarantees

Status: **normative**

This document defines what AegisBPF guarantees, what is best-effort, and what
is explicitly not guaranteed.

## Default Behavioral Contract

- Default enforce gate mode: `fail-closed`
- Default production recommendation: enforce readiness must require enforce
  capability (`aegisbpf health --require-enforce`)
- Explicit fallback mode (`audit-fallback`) is opt-in and must be treated as a
  reduced-security posture.

## Guaranteed

- In enforce mode with required hooks/capabilities present, deny/protect rules
  are kernel-enforced.
- Missing required capabilities in `fail-closed` mode cause enforce startup
  failure (non-zero).
- Runtime posture transitions emit explicit state-change events with reason
  codes.
- Emergency disable does not hide telemetry; transition evidence remains in
  state/events/logs.
- Capability report includes machine-readable blockers and requirements.

## Best-Effort

- Audit-mode fallback visibility on heterogeneous fleets.
- Userspace helper/evaluator workflows that consume capability artifacts.
- Perf SLO summary import into runtime metrics (depends on summary artifact
  availability).
- Path-level observability under namespace/mount aliasing.

## Not Guaranteed

- Enforcement when kernel prerequisites are missing and fallback is allowed by
  policy/config.
- Strong identity guarantees for workloads executing from unsupported
  filesystems/configurations outside documented constraints.
- Cluster-wide policy orchestration or centralized RBAC governance (no control
  plane in this project).
- Absolute immunity to host-root compromise, kernel compromise, or physical
  compromise.

## Fail-Closed vs Fail-Open Matrix

- `--enforce-gate-mode=fail-closed`:
  - required capability missing -> startup fails (no pretend enforce).
- `--enforce-gate-mode=audit-fallback`:
  - required capability missing -> startup continues in `AUDIT_FALLBACK`.
- audit mode:
  - enforcement is not guaranteed; telemetry remains active where available.

## Operator Interpretation Rule

If `runtime_state != ENFORCE`, treat the node as **not meeting enforce
guarantees** until root cause is remediated and posture is revalidated.
