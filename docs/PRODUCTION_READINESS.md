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
- Metrics export: `./build/aegisbpf metrics [--out <path>] [--detailed]`
  (`--detailed` is for short-lived debugging only; default output is cardinality-safe)
- Structured logging: JSON stdout with optional journald (`--log=journald`)
- Service hardening: systemd sandboxing and capability bounds in unit file
- Perf harness: `scripts/perf_open_bench.sh` + `scripts/perf_compare.sh` (see `docs/PERF.md`)
- Real workload perf suite: `scripts/perf_workload_suite.sh`
- Enforce smoke test: `scripts/smoke_enforce.sh`
- Audit smoke test: `scripts/smoke_audit.sh`
- Audit fallback smoke test: `scripts/smoke_audit_fallback.sh`
- Environment verification: `scripts/verify_env.sh [--strict]`
- Event schema validation: `scripts/validate_event_schema.py` + `tests/event_samples/`
- SBOM generation: `sbom` job in `.github/workflows/ci.yml`
- Release provenance attestations: `actions/attest-build-provenance` in `.github/workflows/release.yml`
- Reproducibility gate: `scripts/check_reproducible_build.sh` + `.github/workflows/reproducibility.yml`
- Release-readiness quality gate: `scripts/release_readiness.sh` + `.github/workflows/release-readiness.yml`
- Security automation: `.github/workflows/security.yml` (CodeQL, dependency review, gitleaks)
- Dependency update automation: `.github/dependabot.yml` (GitHub Actions) + `renovate.json` (CMake/regex-managed deps)
- E2E workflow: `.github/workflows/e2e.yml`
- Soak reliability workflow: `.github/workflows/soak.yml` + `scripts/soak_reliability.sh`
- Staging canary workflow: `.github/workflows/canary.yml` + `scripts/canary_gate.sh`
- Perf regression workflow: `.github/workflows/perf.yml`
- Kernel matrix workflow: `.github/workflows/kernel-matrix.yml`
- Nightly fuzz workflow: `.github/workflows/nightly-fuzz.yml`
- Release drill workflow: `.github/workflows/release-drill.yml` + `scripts/release_drill.sh`
- Upgrade/migration runbook: `docs/UPGRADE.md`
- Key rotation/revocation runbook: `docs/KEY_MANAGEMENT.md`
- Key rotation drill workflow: `.github/workflows/key-rotation-drill.yml` + `scripts/key_rotation_drill.sh`
- Aggregated go-live evidence workflow: `.github/workflows/go-live-gate.yml`
- Incident evidence collection script: `scripts/collect_incident_bundle.sh`
- Incident drill workflow: `.github/workflows/incident-drill.yml`
- Incident response runbook: `docs/INCIDENT_RESPONSE.md`
- Operational runbook pack: `docs/runbooks/` (alerts/incidents/maintenance/recovery)
- Support and deprecation policy: `docs/SUPPORT_POLICY.md`
- Final go/no-go checklist: `docs/GO_LIVE_CHECKLIST.md`
- Branch-protection baseline: `docs/BRANCH_PROTECTION.md` + `scripts/check_branch_protection.sh`
- Branch-protection audit workflow: `.github/workflows/branch-protection-audit.yml`
