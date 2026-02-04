# ALERT: High Block Rate

## Alert Description and Severity
- **Alert names:** `AegisBPFHighBlockRate`, `AegisBPFVeryHighBlockRate`
- **Severity:** warning (high), critical (very high)
- **Impact:** potential attack in progress or policy misconfiguration causing excessive blocking.

## Diagnostic Steps
1. Check current rate and scope:
   - `aegisbpf metrics | grep -E 'aegisbpf_blocks_total|aegisbpf_net_blocks_total'`
2. Inspect detailed offenders (short-lived debug):
   - `aegisbpf stats --detailed`
3. Review recent event logs by `trace_id`/`exec_id`:
   - `journalctl -u aegisbpf -S -30m | grep -E 'trace_id|exec_id|action'`
4. Confirm latest policy change:
   - `aegisbpf policy show`

## Resolution Procedures
1. If malicious activity is confirmed, keep enforcement and contain the workload/cgroup.
2. If false positives are dominant, adjust deny rules and re-apply signed policy.
3. If noise is from one workload, scope policy using cgroup controls before broad relaxations.
4. Track rollback decision and command output in the incident ticket.

## Escalation Path
1. On-call security engineer (initial triage).
2. Platform owner if policy rollback or workload quarantine is required.
3. Security lead for critical alerts sustained >15 minutes.

## Post-Incident Checklist
- [ ] Root cause classified (attack vs config drift vs rollout bug)
- [ ] Policy changes reviewed and approved
- [ ] Detection thresholds tuned if needed
- [ ] Incident timeline captured with key `trace_id` values
