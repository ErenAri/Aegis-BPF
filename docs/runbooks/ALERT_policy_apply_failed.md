# ALERT: Policy Apply Failed

## Alert Description and Severity
- **Alert source:** policy deployment pipeline / operator alerting
- **Severity:** warning (single failure), critical (repeated failures)
- **Impact:** intended policy changes are not enforced; drift risk increases.

## Diagnostic Steps
1. Validate policy syntax and signatures:
   - `aegisbpf policy lint /path/to/policy.conf`
   - `aegisbpf policy apply /path/to/policy.signed --require-signature --verbose`
2. Check file permissions/ownership on policy and key material.
3. Inspect service logs:
   - `journalctl -u aegisbpf -S -30m`
4. Confirm required BPF maps are healthy:
   - `aegisbpf health --json`

## Resolution Procedures
1. Fix syntax/signature/permission issue and retry apply.
2. If deployment is blocked, rollback to last known-good signed policy.
3. If map/layout mismatch appears, follow upgrade compatibility runbook before retry.
4. Record exact failure message and corrected artifact hash.

## Escalation Path
1. On-call platform engineer.
2. Security owner for signature/key trust issues.
3. Maintainers if bug is reproducible on current release.

## Post-Incident Checklist
- [ ] Deployment pipeline marked green
- [ ] Final applied policy hash recorded
- [ ] Root cause documented
- [ ] Follow-up issue opened if tooling/documentation gap found
