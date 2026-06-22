# Pilot Evidence Report - internal-a - 2026W06

## Pilot metadata

- Pilot ID: internal-a
- Pilot class: internal staging pilot (pre-design-partner)
- Environment owner: platform-security
- Date range: 2026-02-01 to 2026-02-07
- Deployment model (systemd/k8s): systemd
- Kernel + distro: ubuntu-24.04 / 6.8
- Policy contract version: v1

## Reliability and safety KPIs

- Rollback attempts: 120
- Rollback success rate (target: 100%): 100%
- Rollback p99 duration (target: <=5s): 0.92s
- Break-glass activations: 0
- Degraded-mode incidents: 0

## Detection/enforcement KPIs

- Total block decisions: 15422
- False-positive reports: 0
- Confirmed true positives: 4
- Unexplained event drop ratio (target: <0.1%): 0.00%
- Silent partial attach incidents (target: 0): 0

## Performance KPIs

- Workload profile: web-api + batch ingest
- Baseline syscall p95: 2.04us
- With-agent syscall p95: 2.10us
- Delta % (target: <=5%): 2.94%
- CPU overhead under pilot load: 2.1%

## Operator feedback

- Top friction points: policy iteration speed during initial tuning
- Top value points: deterministic deny explanation and rollback confidence
- Policy authoring pain points: policy diff readability for large lists
- Explainability quality (`why denied`) score: 4.6/5

## Differentiation KPIs

- Time-to-correct-policy (median minutes): 14
- Time-to-diagnose-deny (median minutes): 9
- Operator cognitive load (steps to resolve incident): 6

## Evidence links

- CI/workflow runs: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/go-live-gate.yml
- Dashboards: config/grafana/dashboard.json
- Incident tickets: none
- Runbook usage notes: docs/runbooks/ALERT_high_block_rate.md

## Actions

- P0 fixes (owner/date): none
- P1 improvements (owner/date): improve policy diff readability / docs / 2026-03-15
- Claim changes needed (`ENFORCED`/`AUDITED`/`PLANNED`): none
