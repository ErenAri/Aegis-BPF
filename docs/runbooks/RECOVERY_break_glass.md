# RECOVERY: Break Glass

## Alert Description and Severity
- **Use when:** critical business impact requires temporary enforcement bypass
- **Severity:** critical
- **Impact:** security posture is intentionally reduced for recovery.

## Diagnostic Steps
1. Confirm outage/impact and failed normal mitigation paths.
2. Identify affected services and blast radius.
3. Verify incident commander approval and timestamp.
4. Start an audit log record before action.

## Resolution Procedures
1. Enable break-glass marker:
   - `touch /etc/aegisbpf/break_glass`
2. Restart/reload service if required by deployment policy.
3. Keep strict timebox (for example, 15-30 minutes) and monitor continuously.
4. Remove break-glass marker immediately after mitigation:
   - `rm -f /etc/aegisbpf/break_glass`
5. Re-apply corrected signed policy and confirm health.

## Escalation Path
1. Incident commander + security lead approval required.
2. Platform owner executes change.
3. Executive/security governance notification for high-impact incidents.

## Post-Incident Checklist
- [ ] Approval chain and timestamps recorded
- [ ] Time-in-break-glass measured
- [ ] Permanent fix deployed
- [ ] Postmortem completed with prevention actions
