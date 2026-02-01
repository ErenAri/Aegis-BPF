# Production Readiness Checklist

This checklist captures the minimum bar for a senior-level, production-ready
release. Items are grouped by priority. Track completion and evidence as you
deliver each requirement.

## P0 (must-have before production)
- Policy format is versioned, validated, and backward-compatible (or has a
  clear migration plan).
- Safe rollout/rollback for policy changes (apply + reset + export + audit of
  last applied policy).
- Verified enforcement mode when BPF LSM is enabled; explicit audit-only mode
  when fallback is used.
- Health checks for prerequisites (cgroup v2, bpffs, BTF, BPF LSM) and pinned
  map availability.
- Clear failure modes: enforce fails closed; audit fallback fails open with
  explicit warnings.
- CI builds on supported distros and architectures.

## P1 (strongly recommended before wide rollout)
- Structured logging and metrics export (journald/Prometheus/SIEM).
- Perf regression tests on realistic workloads.
- Compatibility testing across supported kernel versions.
- Policy signature or integrity checks for production deployments.
- Packaging for target OSes (deb/rpm) and systemd integration.

## P2 (quality and operational maturity)
- Upgrade/migration guide for pinned maps and policy format.
- Integration docs for incident response and SOC workflows.
- Automated e2e tests in a VM or containerized kernel CI.
- Multi-tenant policy support and namespace isolation.

## Evidence log (fill as you complete)
- CI build matrix: GitHub Actions on ubuntu-22.04 and ubuntu-24.04 + arm64 build via QEMU
- Health check command: `./build/aegisbpf health`
- Policy lifecycle: lint/apply/export/show/rollback with v1 format
- Policy integrity: sha256 verification via `policy apply --sha256` or env vars
- Packaging: systemd unit in `packaging/systemd/` + CPack TGZ/DEB/RPM
- Metrics export: `./build/aegisbpf metrics [--out <path>]`
- Structured logging: JSON stdout with optional journald (`--log=journald`)
- Service hardening: systemd sandboxing and capability bounds in unit file
- Perf harness: `scripts/perf_open_bench.sh` + `scripts/perf_compare.sh` (see `docs/PERF.md`)
- Upgrade/migration runbook: `docs/UPGRADE.md`
- Incident response runbook: `docs/INCIDENT_RESPONSE.md`
