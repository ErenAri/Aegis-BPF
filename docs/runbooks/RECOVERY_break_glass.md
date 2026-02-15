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
1. Ensure approval is recorded (IC + security lead) and create an incident
   ticket ID (required for `--reason`).
2. Disable enforcement (preferred, immediate, auditable):
   - `aegisbpf emergency-disable --reason "TICKET=INC-1234 <short reason>"`
   - Kubernetes example:
     - `kubectl -n <ns> exec ds/<aegisbpf-enforce-ds> -- aegisbpf emergency-disable --reason "TICKET=INC-1234 ..."`
3. Verify posture:
   - `aegisbpf emergency-status --json`
   - `aegisbpf health`
4. Keep a strict timebox (for example, 15-30 minutes) and monitor continuously.
5. Re-enable enforcement:
   - `aegisbpf emergency-enable --reason "TICKET=INC-1234 mitigation complete"`
6. Verify enforcement resumed:
   - `aegisbpf emergency-status --json`
   - run a quick deny probe relevant to your deployment (for example a known
     denied path should return `EACCES` when enforcement is active).
7. If the CLI path is unavailable, fall back to the marker-file break-glass:
   - enable: `touch /etc/aegisbpf/break_glass`
   - disable: `rm -f /etc/aegisbpf/break_glass`
8. Re-apply corrected signed policy and confirm health.

## Escalation Path
1. Incident commander + security lead approval required.
2. Platform owner executes change.
3. Executive/security governance notification for high-impact incidents.

## Post-Incident Checklist
- [ ] Approval chain and timestamps recorded
- [ ] Time-in-break-glass measured
- [ ] Permanent fix deployed
- [ ] Postmortem completed with prevention actions
