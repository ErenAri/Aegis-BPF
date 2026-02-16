# ALERT: Emergency Toggle Storm

## Alert Description and Severity
- **Alert name:** `AegisBPFEmergencyToggleStorm`
- **Severity:** warning
- **Impact:** repeated emergency enable/disable transitions indicate operational instability or potential abuse of break-glass controls.

## Diagnostic Steps
1. Inspect emergency status:
   - `aegisbpf emergency-status --json`
2. Check transition telemetry:
   - `aegisbpf metrics | grep -E 'emergency_toggle_transitions_total|emergency_toggle_storm_active'`
3. Review control log:
   - `tail -n 200 /var/lib/aegisbpf/control_log.jsonl`
4. Confirm operator actions in Kubernetes audit logs / terminal logs.

## Resolution Procedures
1. Freeze emergency toggles until incident commander approves next action.
2. Validate current target state (`enabled` or `disabled`) and keep it stable.
3. Reconcile with ticket/approval trail (`TICKET=<id>` in reason strings).
4. If unauthorized changes are suspected, rotate credentials and restrict exec access immediately.

## Escalation Path
1. SRE on-call to stabilize the node posture.
2. Security incident lead for governance and potential abuse investigation.
3. IAM/platform team for RBAC hardening if policy violations are confirmed.

## Post-Incident Checklist
- [ ] Identify all toggle actors and timestamps
- [ ] Confirm ticket correlation for each transition
- [ ] Record final emergency state and enforcement posture
- [ ] Apply RBAC/admission hardening follow-up actions
