# Pilot Evidence Reports

This directory stores public-safe weekly pilot evidence reports.

Rules:

- Keep at least two active pilot reports under version control.
- Use file names `pilot-<env>-<yyyywWW>.md`.
- Label each report as `internal staging pilot` or `design-partner pilot`.
- Internal staging pilots are product-readiness evidence only. They are not
  external validation and must not be counted as published design-partner case
  studies.
- Use `docs/PILOT_EVIDENCE_TEMPLATE.md` for every weekly report.
- Redact customer names, hostnames, IP addresses, ticket IDs, and dashboards
  before committing public evidence.

Current reports:

- `pilot-internal-a-2026w06.md` - internal staging pilot, systemd deployment.
- `pilot-internal-b-2026w06.md` - internal staging pilot, Kubernetes deployment.
