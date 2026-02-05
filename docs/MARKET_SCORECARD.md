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
| Adoption | Pilot environments | `>=2` active pilots | Pilot evidence pack (`docs/PILOT_EVIDENCE_TEMPLATE.md`) |

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
