# ALERT: Runtime Posture Degraded

## Alert Description and Severity
- **Alert name:** `AegisBPFRuntimeStateDegraded`
- **Severity:** critical
- **Impact:** node posture is not `ENFORCE` (`AUDIT_FALLBACK` or `DEGRADED`), so fail-closed enforcement guarantees are reduced.

## Diagnostic Steps
1. Confirm runtime posture metrics:
   - `aegisbpf metrics | grep -E 'aegisbpf_runtime_state|aegisbpf_enforce_capable'`
2. Check daemon capability report:
   - `aegisbpf capabilities --json`
3. Inspect recent state transitions and reason codes:
   - `journalctl -u aegisbpf --since '30 min ago' | grep AEGIS_STATE_CHANGE`
4. Validate enforce prerequisites on node:
   - `aegisbpf health --json`

## Resolution Procedures
1. Identify blocker (`enforce_blockers` / reason code) and resolve prerequisite:
   - missing hooks/capability -> fix kernel or policy requirements
   - missing IMA appraisal -> adjust node hardening or policy gating
2. If intentional emergency operation is active, follow break-glass runbook and ticket process.
3. Restart daemon after prerequisite remediation:
   - `sudo systemctl restart aegisbpf`
4. Verify posture restored:
   - `aegisbpf capabilities --json` shows `runtime_state=ENFORCE`

## Escalation Path
1. On-call SRE for node-level remediation.
2. Security on-call for policy/gating decision and risk acceptance.
3. Platform owner if cluster-wide capability fragmentation persists.

## Post-Incident Checklist
- [ ] Record blocker/reason code and affected nodes
- [ ] Capture timestamps for fallback/degraded window
- [ ] Document remediation and verification evidence
- [ ] Update rollout gating or kernel baseline if required
