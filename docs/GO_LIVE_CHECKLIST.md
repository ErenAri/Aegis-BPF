# Go-Live Checklist

This checklist is the final go/no-go gate for a senior-level production
release.

Use one row per release candidate (RC). Every item must be marked pass with
attached evidence.

Evidence entries must include direct URLs (workflow run, artifact, dashboard,
or incident ticket) rather than free-form notes.

## RC metadata

- Release candidate:
- Commit SHA:
- Build date (UTC):
- Release owner:
- Security approver:
- SRE approver:

## 1) Mandatory CI/CD gates

- [ ] `CI` workflow green (build/test/lint/sanitizers/security)
  - Evidence:
- [ ] `Release Readiness` workflow green
  - Evidence:
- [ ] `E2E (BPF LSM)` workflow green
  - Evidence:
- [ ] `Kernel Matrix` workflow green on all supported kernels
  - Evidence:
- [ ] `Perf Regression` workflow green
  - Evidence:
- [ ] Branch protection required checks are configured (`scripts/check_branch_protection.sh`)
  - Evidence:

## 2) Staging canary + soak

- [ ] Audit canary passed (`scripts/canary_gate.sh` with `PHASE=audit`)
  - Evidence:
- [ ] Enforce canary passed (`PHASE=enforce`, `ENFORCE_SIGNAL=term`)
  - Evidence:
- [ ] Soak reliability thresholds met (ringbuf drops, drop ratio `<0.1%`, RSS growth)
  - Evidence:
- [ ] False-positive review completed with security/SRE sign-off
  - Evidence:
- [ ] Rollback drill executed successfully during canary
  - Evidence:

## 3) Performance certification

- [ ] Microbench gate passed (`scripts/perf_compare.sh`)
  - Evidence:
- [ ] Real workload suite passed (`scripts/perf_workload_suite.sh`)
  - Evidence:
- [ ] Overhead stays within product targets in `docs/PRODUCT.md`
  - Evidence:

## 4) Release operations proof

- [ ] Release drill passed (`scripts/release_drill.sh`)
  - Evidence:
- [ ] Artifact checksums generated and verified
  - Evidence:
- [ ] Package content checks passed (DEB/RPM include binary + service unit)
  - Evidence:
- [ ] Upgrade compatibility check passed (`tests/check_upgrade_compat.py`)
  - Evidence:
- [ ] Signed artifact verification walkthrough validated
  - Evidence:
- [ ] Capability contract report attached (`capability-contract-report.md`)
  - Evidence:
- [ ] `Go-Live Gate` workflow artifact bundle generated
  - Evidence:
- [ ] Product excellence scorecard completed (`docs/RELEASE_READINESS_SCORECARD.md`)
  - Evidence:

## 5) Operational readiness

- [ ] Incident drill passed (`.github/workflows/incident-drill.yml`)
  - Evidence:
- [ ] Key rotation drill passed (`scripts/key_rotation_drill.sh`)
  - Evidence:
- [ ] Independent security review findings closed/triaged (`docs/EXTERNAL_REVIEW_STATUS.md`)
  - Evidence:
- [ ] Pilot evidence reports collected (`docs/pilots/`)
  - Evidence:
- [ ] Alert routing verified (paging path tested end-to-end)
  - Evidence:
- [ ] Dashboards and SLO alerts verified against staging signals
  - Evidence:

## 6) Final approval

- [ ] Security sign-off
  - Name / date:
- [ ] SRE sign-off
  - Name / date:
- [ ] Product/engineering sign-off
  - Name / date:
- [ ] Go for release `vX.Y.Z`
  - Approved by / date:
