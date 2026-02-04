# INCIDENT: Agent Crash

## Alert Description and Severity
- **Typical alert:** `AegisBPFAgentDown`
- **Severity:** critical
- **Impact:** userspace enforcement/observability pipeline is degraded; pinned BPF state may persist.

## Diagnostic Steps
1. Check service status:
   - `systemctl status aegisbpf`
2. Inspect crash logs/core hints:
   - `journalctl -u aegisbpf -S -30m`
3. Verify kernel/BPF readiness:
   - `aegisbpf health --json`
4. Confirm pinned maps still present under `/sys/fs/bpf/aegis/`.

## Resolution Procedures
1. Restart service and verify health checks pass.
2. Re-apply last signed policy if state is inconsistent.
3. If recurring crash, move to audit mode temporarily and collect incident bundle.
4. Preserve logs and reproduction steps before any host reboot.

## Escalation Path
1. On-call SRE.
2. Platform owner if repeated restarts occur in <30 minutes.
3. Maintainers/security team for crash triage and patch decision.

## Post-Incident Checklist
- [ ] MTTR recorded
- [ ] Crash signature captured
- [ ] Regression test added (if code defect)
- [ ] Runbook updated with learned mitigation
