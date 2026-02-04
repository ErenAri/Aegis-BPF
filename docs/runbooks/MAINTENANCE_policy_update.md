# MAINTENANCE: Policy Update

## Alert Description and Severity
- **Use when:** routine policy rollout or urgent policy fix
- **Severity:** planned change / medium risk
- **Impact:** changes runtime enforcement decisions.

## Diagnostic Steps
1. Validate policy file:
   - `aegisbpf policy lint /path/to/policy.conf`
2. Validate signature bundle in staging:
   - `aegisbpf policy apply /path/to/policy.signed --require-signature --verbose`
3. Confirm upgrade compatibility (N-1 to N where applicable).
4. Capture baseline metrics before rollout.

## Resolution Procedures
1. Apply signed policy to canary hosts first.
2. Monitor block rate and ringbuf drop alerts for regression.
3. Roll out in staged batches across environments.
4. If regressions occur, rollback immediately to previous signed bundle.

## Escalation Path
1. Release engineer/on-call platform.
2. Security approver for enforcement-impacting changes.
3. Maintainers for parser/engine incompatibility.

## Post-Incident Checklist
- [ ] Final policy version and hash recorded
- [ ] Canary and production validation completed
- [ ] Regression notes captured
- [ ] Changelog/release notes updated
