# Market Leadership Scorecard

Use this scorecard for release go/no-go decisions.

Status values:
- `GREEN`: target met with linked evidence.
- `YELLOW`: near target, approved exception with owner/date.
- `RED`: target missed; release blocked.

## Category targets

| Category | KPI | Target | Evidence |
|---|---|---|---|
| Defensibility | Kernel e2e coverage | `>=60` enforced cases | CI artifact + test report |
| Defensibility | Portability matrix | `>=4` kernels, `>=2` distro families | Kernel matrix workflow |
| Defensibility | Ambiguous policy outcomes | `0` in golden vectors | Decision-vector tests |
| Defensibility | Silent partial attaches | `0` | Attach matrix tests + health evidence |
| Survivability | Rollback reliability | `100%` over `1,000` stress iterations | Rollback stress artifact |
| Survivability | Rollback speed | `p99 <= 5s` | Canary/soak evidence |
| Survivability | Unexplained event drops | `<0.1%` sustained | Soak + metrics evidence |
| Performance | Syscall overhead (p95) | `<=5%` (stretch `<=3%`) | Perf workflow artifacts |
| Trust | Signed release completeness | `100%` artifacts signed + SBOM + provenance | Release workflow artifacts |
| Trust | External review criticals | `0` unresolved critical findings | `docs/EXTERNAL_REVIEW_STATUS.md` |
| Adoption | Pilot environments | `>=2` active pilots | Weekly reports in `docs/pilots/` |

## Current status snapshot (updated 2026-02-05)

| KPI | Status | Notes |
|---|---|---|
| Kernel e2e coverage (`>=60`) | `GREEN` | Phase-2 matrix floor enforced by contract tests and CI validators |
| Portability matrix (`>=4 kernels`, `>=2 distros`) | `GREEN` | Kernel matrix workflows and Phase-4 contract active |
| Ambiguous policy outcomes (`0`) | `GREEN` | Parser/contract tests pass |
| Silent partial attaches (`0`) | `GREEN` | Attach-contract hard-fail and regression test in place |
| Rollback reliability (`100%` over `1,000`) | `GREEN` | Phase-3 rollback stress gate enforces `>=1000` iterations |
| Rollback speed (`p99 <= 5s`) | `GREEN` | Rollback control-path test with time budget enforced |
| Unexplained event drops (`<0.1%`) | `GREEN` | Soak gate enforces drop-ratio threshold with minimum event volume |
| Syscall overhead p95 (`<=5%`) | `GREEN` | Perf validator enforces p95 ratio gates (`<=1.05`) |
| Signed release completeness (`100%`) | `GREEN` | Release workflow checks remain required |
| External review criticals (`0`) | `YELLOW` | Tracking doc is active; independent review closure evidence still in progress |
| Pilot environments (`>=2`) | `YELLOW` | Two internal pilot reports are present; design-partner pilots still pending |

## Release claim mapping (required)

For each release claim, include all four references:

1. Spec section (contract semantics/threat model)
2. Test suite or contract test
3. CI artifact link
4. Runbook/operator guidance

Claims not mapped to evidence must be downgraded to `PLANNED` or removed.

## Release approval block

- [ ] All scorecard rows are `GREEN` or approved `YELLOW` exceptions.
- [ ] No `RED` rows remain.
- [ ] Exception owners and remediation dates are recorded.
- [ ] Go-live checklist (`docs/GO_LIVE_CHECKLIST.md`) is complete.
