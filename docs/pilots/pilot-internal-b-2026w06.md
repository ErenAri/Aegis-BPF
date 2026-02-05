# Pilot Evidence Report - internal-b - 2026W06

## Pilot metadata

- Pilot ID: internal-b
- Pilot class: internal staging pilot (pre-design-partner)
- Environment owner: runtime-platform
- Date range: 2026-02-01 to 2026-02-07
- Deployment model (systemd/k8s): kubernetes
- Kernel + distro: debian-12 / 6.1
- Policy contract version: v1

## Reliability and safety KPIs

- Rollback attempts: 98
- Rollback success rate (target: 100%): 100%
- Rollback p99 duration (target: <=5s): 1.14s
- Break-glass activations: 0
- Degraded-mode incidents: 0

## Detection/enforcement KPIs

- Total block decisions: 11807
- False-positive reports: 1
- Confirmed true positives: 3
- Unexplained event drop ratio (target: <0.1%): 0.02%
- Silent partial attach incidents (target: 0): 0

## Performance KPIs

- Workload profile: worker pods + sidecar telemetry
- Baseline syscall p95: 2.28us
- With-agent syscall p95: 2.37us
- Delta % (target: <=5%): 3.95%
- CPU overhead under pilot load: 2.8%

## Operator feedback

- Top friction points: first-time key trust-store provisioning
- Top value points: clear block/audit split and low overhead
- Policy authoring pain points: cgroup selection ergonomics
- Explainability quality (`why denied`) score: 4.4/5

## Evidence links

- CI/workflow runs: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/kernel-matrix.yml
- Dashboards: config/grafana/dashboard.json
- Incident tickets: none
- Runbook usage notes: docs/runbooks/INCIDENT_false_positive_block.md
