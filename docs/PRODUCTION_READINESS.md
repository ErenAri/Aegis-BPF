# Production Readiness Checklist

This checklist captures the minimum bar for a senior-level, production-ready
release. Items are grouped by priority. Track completion and evidence as you
deliver each requirement.

For public CI evidence, see `docs/EVIDENCE.md`.
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
- Runtime posture transitions are explicit (`ENFORCE`, `AUDIT_FALLBACK`,
  `DEGRADED`) and can be forced fail-closed with `run --strict-degrade`.
- CI builds on supported distros and architectures.

## P1 (strongly recommended before wide rollout)
- Structured logging and metrics export (journald/Prometheus/SIEM).
- Perf regression tests on realistic workloads.
- Compatibility testing across supported kernel versions.
- Policy signature or integrity checks for production deployments.
- Packaging for target OSes (deb/rpm) and systemd integration.
- Explicit threat model with in-scope/out-of-scope boundaries and blind spots.

## P2 (quality and operational maturity)
- Upgrade/migration guide for pinned maps and policy format.
- Integration docs for incident response and SOC workflows.
- Automated e2e tests in a VM or containerized kernel CI.
- Multi-tenant policy support and namespace isolation.

## Evidence log (fill as you complete)
- CI build matrix: GitHub Actions on ubuntu-22.04 and ubuntu-24.04 + arm64 build via QEMU
- Health check command: `./build/aegisbpf health`
- Diagnostic command: `./build/aegisbpf doctor [--json]`
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
- Reference enforcement slice: `scripts/reference_enforcement_slice.sh`
- Environment verification: `scripts/verify_env.sh [--strict]`
- Event schema validation: `scripts/validate_event_schema.py` + `tests/event_samples/`
- Runtime state-change contract: `type=state_change` events (`config/event-schema.json`)
- Failure-mode regression contract: `tests/check_failure_modes_contract.py` (parser, signature, map-full, verifier, rollback paths)
- SBOM generation: `sbom` job in `.github/workflows/ci.yml`
- Release provenance attestations: `actions/attest-build-provenance` in `.github/workflows/release.yml`
- Reproducibility gate: `scripts/check_reproducible_build.sh` + `.github/workflows/reproducibility.yml`
- Release-readiness quality gate: `scripts/release_readiness.sh` + `.github/workflows/release-readiness.yml`
- Security automation: `.github/workflows/security.yml` (CodeQL, dependency review, gitleaks)
- Dependency update automation: `.github/dependabot.yml` (GitHub Actions) + `renovate.json` (CMake/regex-managed deps)
- E2E workflow: `.github/workflows/e2e.yml`
- Kernel file-enforcement matrix (114 logical checks): `scripts/e2e_file_enforcement_matrix.sh` (run from `.github/workflows/e2e.yml` and `.github/workflows/kernel-matrix.yml` with summary/metadata artifacts, including `skipped_checks` when bind-mount alias checks cannot run)
- Filesystem matrix: `scripts/e2e_fs_matrix.sh` (overlayfs/bind/tmpfs/symlink/hardlink behavior)
- Namespace matrix: `scripts/e2e_namespace_matrix.sh` (mount/pid/network namespace behavior)
- Kernel matrix summary validator: `scripts/validate_e2e_matrix_summary.py` (`--min-total-checks 100 --max-failed-checks 0`)
- Soak reliability workflow: `.github/workflows/soak.yml` + `scripts/soak_reliability.sh`
- Chaos ringbuf overflow check: `scripts/chaos_ringbuf_overflow.sh` (runs in `e2e.yml`)
- Staging canary workflow: `.github/workflows/canary.yml` + `scripts/canary_gate.sh`
- Perf regression workflow: `.github/workflows/perf.yml`
- Perf canonical SLO gate: `scripts/perf_slo_check.sh` (`perf-slo-report.md`, `perf-slo-summary.json`)
- Performance baseline report: `docs/PERF_BASELINE.md`
- Perf artifact schema validation: `scripts/validate_perf_artifacts.py` + `artifacts/perf/perf-evidence-report.md`
- Perf canonical evidence artifact: `scripts/generate_perf_baseline_artifact.py` (`perf-baseline-canonical.json`, `perf-baseline-canonical.md`)
- Release perf hard gate: `perf-gate` job in `.github/workflows/release.yml` (`release-perf-evidence`)
- Hosted benchmark trend workflow (advisory): `.github/workflows/benchmark.yml`
- Kernel matrix workflow: `.github/workflows/kernel-matrix.yml`
- Kernel matrix run evidence: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/21735329269 (2026-02-06)
- Nightly fuzz workflow: `.github/workflows/nightly-fuzz.yml`
- Parser-change fuzz gate: `parser-fuzz` job in `.github/workflows/ci.yml` + `scripts/run_parser_fuzz_changed.sh`
- Release drill workflow: `.github/workflows/release-drill.yml` + `scripts/release_drill.sh`
- Upgrade/migration runbook: `docs/UPGRADE.md`
- Key rotation/revocation runbook: `docs/KEY_MANAGEMENT.md`
- Key rotation drill workflow: `.github/workflows/key-rotation-drill.yml` + `scripts/key_rotation_drill.sh`
- Capability contract validator: `scripts/validate_capability_contract.py` (documents vs systemd capability bounds)
- Capability/posture anti-drift contract: `scripts/validate_capability_posture_contract.py` + `docs/CAPABILITY_POSTURE_CONTRACT.md`
- Capability posture evaluator: `scripts/evaluate_capability_posture.py` (machine-readable posture + Kubernetes label outputs)
- Helm enforce-gating contract: `tests/check_helm_posture_contract.py` + `docs/HELM_ENFORCE_GATING_CONTRACT.md`
- Kubernetes mixed-mode rollout contract: `tests/check_k8s_rollout_contract.py` + `docs/K8S_ROLLOUT_AUDIT_ENFORCE.md`
- Enforcement guarantees contract: `tests/check_guarantees_contract.py` + `docs/ENFORCEMENT_GUARANTEES.md`
- Ops observability contract: `tests/check_ops_observability_contract.py` + `config/grafana/aegisbpf-ops-minimal.json` + `config/prometheus/alerts.yml`
- Optional posture label automation: `postureAutomation.enabled=true` in `helm/aegisbpf/values.yaml` (node label sidecar + cluster RBAC templates)
- Key-rotation artifact evidence: `artifacts/meta-security/key-rotation-summary.json` + `artifacts/meta-security/capability-contract-report.md`
- Aggregated go-live evidence workflow: `.github/workflows/go-live-gate.yml`
- Incident evidence collection script: `scripts/collect_incident_bundle.sh`
- Incident drill workflow: `.github/workflows/incident-drill.yml`
- Incident response runbook: `docs/INCIDENT_RESPONSE.md`
- Operational runbook pack: `docs/runbooks/` (alerts/incidents/maintenance/recovery)
- Support and deprecation policy: `docs/SUPPORT_POLICY.md`
- Threat model and bypass boundaries: `docs/THREAT_MODEL.md`
- Policy runtime semantics: `docs/POLICY_SEMANTICS.md`
- Enforcement semantics whitepaper: `docs/ENFORCEMENT_SEMANTICS_WHITEPAPER.md`
- Edge‑case compliance suite: `docs/EDGE_CASE_COMPLIANCE_SUITE.md`
- Edge‑case compliance results: `docs/EDGE_CASE_COMPLIANCE_RESULTS.md`
- Metrics interpretation guide: `docs/METRICS_OPERATIONS.md`
- Explainability CLI: `aegisbpf explain` (see `docs/PRODUCTION_DEPLOYMENT_BLUEPRINT.md`)
- Production deployment blueprint: `docs/PRODUCTION_DEPLOYMENT_BLUEPRINT.md`
- Public CI evidence map: `docs/EVIDENCE.md`
- CI kernel-e2e execution strategy: `docs/CI_EXECUTION_STRATEGY.md`
- Branch-protection baseline: `docs/BRANCH_PROTECTION.md` + `scripts/check_branch_protection.sh`
- Branch-protection audit workflow: `.github/workflows/branch-protection-audit.yml`

## Evidence artifacts

The canonical evidence artifacts live in GitHub Actions runs:
- Kernel matrix artifacts: `kernel-matrix-<runner>` (kernel/distro metadata + logs)
- CI artifacts: build/test logs + benchmark JSON
- Release readiness: `release_readiness.sh` logs and scorecards

Update this checklist with run URLs when validating a release.
