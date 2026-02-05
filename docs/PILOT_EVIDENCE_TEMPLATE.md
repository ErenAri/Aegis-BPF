# Pilot Evidence Template

Use this template for weekly design-partner pilot evidence during
Super-Phase B and Super-Phase C.

## Pilot metadata

- Pilot ID:
- Environment owner:
- Date range:
- Deployment model (systemd/k8s):
- Kernel + distro:
- Policy contract version:

## Reliability and safety KPIs

- Rollback attempts:
- Rollback success rate (target: 100%):
- Rollback p99 duration (target: <=5s):
- Break-glass activations:
- Degraded-mode incidents:

## Detection/enforcement KPIs

- Total block decisions:
- False-positive reports:
- Confirmed true positives:
- Unexplained event drop ratio (target: <0.1%):
- Silent partial attach incidents (target: 0):

## Performance KPIs

- Workload profile:
- Baseline syscall p95:
- With-agent syscall p95:
- Delta % (target: <=5%):
- CPU overhead under pilot load:

## Operator feedback

- Top friction points:
- Top value points:
- Policy authoring pain points:
- Explainability quality (`why denied`) score:

## Evidence links

- CI/workflow runs:
- Dashboards:
- Incident tickets:
- Runbook usage notes:

## Actions

- P0 fixes (owner/date):
- P1 improvements (owner/date):
- Claim changes needed (`ENFORCED`/`AUDITED`/`PLANNED`):
