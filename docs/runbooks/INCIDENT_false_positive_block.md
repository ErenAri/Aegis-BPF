# INCIDENT: False Positive Block

## Alert Description and Severity
- **Trigger:** legitimate workload blocked unexpectedly
- **Severity:** warning to critical (based on business impact)
- **Impact:** service disruption while enforcement is otherwise healthy.

## Diagnostic Steps
1. Capture impacted process and `trace_id`/`exec_id` from logs.
2. Identify matching rule (`path`, `inode`, `network`, `cidr`, `port`).
3. Validate cgroup scope and policy source commit.
4. Confirm whether issue reproduces in audit mode.

## Resolution Procedures
1. Apply targeted exception (prefer scoped cgroup allow over broad deny removal).
2. Re-run policy lint/sign/apply flow and verify with impacted service owner.
3. If immediate unblocking is required, follow break-glass runbook and record approval.
4. Backport corrected policy to active release branches as needed.

## Escalation Path
1. Service owner + on-call security engineer.
2. Platform lead for policy rollback authorization.
3. Maintainers if parser/engine bug is suspected.

## Post-Incident Checklist
- [ ] False-positive rule documented and corrected
- [ ] Business impact window recorded
- [ ] Detection/QA gap captured in backlog
- [ ] Customer/internal communication completed
