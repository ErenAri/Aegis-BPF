# ALERT: Performance SLO Gate Breach

## Alert Description and Severity
- **Alert name:** `AegisBPFPerfSLOGateFailed`
- **Severity:** warning
- **Impact:** canonical performance SLO summary reports one or more failed rows; production overhead budget may be exceeded.

## Diagnostic Steps
1. Check perf metrics:
   - `aegisbpf metrics | grep -E 'perf_slo_(summary_present|gate_pass|failed_rows)'`
2. Inspect perf summary artifact:
   - `cat /var/lib/aegisbpf/perf-slo-summary.json`
3. Review latest perf workflow evidence:
   - `artifacts/perf/perf-slo-report.md`
   - `artifacts/perf/perf-baseline-canonical.json`
4. Correlate with runtime factors:
   - CPU governor, kernel version, node contention, policy size.

## Resolution Procedures
1. Confirm breach reproducibility on pinned perf host/class.
2. Identify failing workload rows and affected metrics.
3. Roll back recent performance-impacting change if breach is regressional.
4. If accepted degradation is intentional, update budgets/evidence with explicit sign-off.

## Escalation Path
1. Performance owner for benchmark root-cause analysis.
2. Security owner if enforcement reductions are considered.
3. Release manager if tag/release gate is impacted.

## Post-Incident Checklist
- [ ] Archive failing perf evidence artifacts
- [ ] Document root cause and remediation commit
- [ ] Re-run canonical perf gate and store passing evidence
- [ ] Update baseline documentation if budgets changed
