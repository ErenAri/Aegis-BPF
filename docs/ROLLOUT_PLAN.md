# AegisBPF Production Rollout Plan

**Purpose:** Safe, phased deployment strategy for AegisBPF to production
**Audience:** SREs, DevOps Engineers, Security Teams
**Last Updated:** 2026-02-07

---

## Overview

This document outlines the recommended approach for rolling out AegisBPF enforcement to production environments. The strategy emphasizes safety through gradual rollout, continuous monitoring, and quick rollback capabilities.

**Key Principles:**
- Start with audit-only mode (shadow traffic)
- Validate at each phase before proceeding
- Maintain rollback capability at all times
- Monitor for false positives and performance impact
- Document lessons learned

---

## Rollout Phases

### Phase 0: Pre-Deployment Validation

**Duration:** 1-2 weeks
**Scope:** Test/staging environments
**Goal:** Verify functionality and establish baseline

#### Prerequisites

- [ ] All unit tests passing (165/165)
- [ ] E2E tests passing on target kernel version
- [ ] Security audit completed
  - [ ] Ed25519 signature verification reviewed
  - [ ] BPF verifier bypass disabled in production builds
- [ ] Documentation complete
  - [ ] RUNBOOK_RECOVERY.md
  - [ ] CAPACITY_PLANNING.md
  - [ ] MONITORING_GUIDE.md
- [ ] Monitoring stack ready
  - [ ] Prometheus configured
  - [ ] Grafana dashboards imported
  - [ ] Alerts configured and tested
  - [ ] Runbooks linked to alerts
- [ ] Performance baseline captured
  - [ ] Latency: p50, p95, p99
  - [ ] Throughput: ops/sec
  - [ ] Resource usage: CPU, memory

#### Validation Tests

```bash
# 1. Kernel compatibility check
sudo aegisbpf health

# 2. Load test in audit mode
sudo aegisbpf run --audit --log-level=info &
aegisbpf apply policy.yml
# Run load test for 1 hour
# Monitor: CPU < 5%, memory < 50MB, no crashes

# 3. Enforcement smoke test (non-production)
sudo aegisbpf run --enforce
aegisbpf block add --path /tmp/test-block.txt
# Verify block works, then clear
aegisbpf block clear
```

#### Go/No-Go Criteria

 **GO** if:
- Health check passes on all target kernel versions
- Performance overhead < 30% in audit mode
- No memory leaks during 24h soak test
- Recovery procedures tested and documented
- On-call team trained on runbooks

 **NO-GO** if:
- Kernel compatibility issues detected
- Performance degradation > 30%
- Crash or instability during soak testing
- Monitoring gaps identified

---

### Phase 1: Shadow Mode (Audit-Only)

**Duration:** 2-4 weeks
**Scope:** Production, audit-only mode
**Goal:** Gather real-world data without enforcement

#### Deployment

```bash
# Deploy in audit mode (does not block)
sudo systemctl stop aegisbpf  # if running
sudo cp /path/to/aegisbpf /usr/bin/aegisbpf
sudo aegisbpf run --audit --log-level=info --metrics-port=9090
```

#### What to Monitor

1. **False Positive Rate**
   - Review all "would block" events
   - Identify legitimate traffic being blocked
   - Tune policy to reduce false positives

2. **Performance Impact**
   ```promql
   # CPU usage
   aegisbpf_cpu_usage_percent < 5

   # Event rate
   rate(aegisbpf_blocks_total[5m])

   # Ring buffer health
   rate(aegisbpf_ringbuf_drops_total[5m]) == 0
   ```

3. **Application Health**
   - Monitor application error rates
   - Check latency metrics
   - Correlate with BPF events

#### Success Criteria

- [ ] False positive rate < 0.01%
- [ ] Performance overhead < 5% CPU
- [ ] No ring buffer drops
- [ ] Policy tuned for workload
- [ ] On-call comfortable with tooling

#### Rollout Decision

After 2-4 weeks of shadow mode:
- **Proceed to Phase 2** if success criteria met
- **Extend shadow mode** if false positives detected
- **Halt rollout** if fundamental issues found

---

### Phase 2: Test Environment Enforcement

**Duration:** 1-2 weeks
**Scope:** Test/staging with real enforcement
**Goal:** Validate enforcement doesn't break applications

#### Deployment

```bash
# Switch to enforcement mode in test environment
sudo systemctl stop aegisbpf
sudo aegisbpf run --enforce --log-level=info --metrics-port=9090
```

#### Test Plan

1. **Functional Tests**
   - Run full application test suite
   - Verify normal operations work
   - Confirm denied paths are blocked

2. **Chaos Tests**
   ```bash
   # Test ring buffer overflow handling
   scripts/chaos_ringbuf_overflow.sh

   # Test map capacity limits
   # Add entries until map fills, verify graceful degradation
   ```

3. **Recovery Tests**
   ```bash
   # Test daemon crash recovery
   sudo killall -9 aegisbpf
   # Verify automatic restart
   systemctl status aegisbpf

   # Test policy rollback
   aegisbpf apply bad-policy.yml  # intentionally break
   # Verify rollback procedure works
   ```

#### Success Criteria

- [ ] All functional tests pass
- [ ] Chaos tests demonstrate resilience
- [ ] Recovery procedures validated
- [ ] No unexpected application failures
- [ ] Rollback tested and working

---

### Phase 3: Canary Deployment (5%)

**Duration:** 1 week
**Scope:** 5% of production hosts
**Goal:** Detect production-specific issues early

#### Canary Selection

Select hosts that are:
- Representative of production workload
- Non-critical (can tolerate brief outage)
- Well-monitored
- Owned by a friendly team (early adopters)

Example Terraform/Ansible:
```hcl
# Terraform example
resource "aws_instance" "app" {
  count = 100

  # Tag 5% as canary
  tags = {
    aegisbpf_canary = count.index < 5 ? "true" : "false"
  }
}
```

#### Deployment Script

```bash
#!/bin/bash
# scripts/canary_deploy.sh
CANARY_PERCENTAGE=5

# Select hosts
HOSTS=$(ansible-inventory --list | jq -r '.all.hosts[]' | shuf | head -n $(($(wc -l) * $CANARY_PERCENTAGE / 100)))

# Deploy to canary hosts
for host in $HOSTS; do
  ssh $host "sudo systemctl stop aegisbpf"
  scp aegisbpf $host:/usr/bin/aegisbpf
  scp policy.yml $host:/etc/aegisbpf/policy.yml
  ssh $host "sudo aegisbpf run --enforce --metrics-port=9090"
done

echo "Canary deployed to $CANARY_PERCENTAGE% of hosts"
echo "Monitor metrics and check for issues"
```

#### Canary Monitoring

**Critical Metrics (5-minute check):**
```bash
# Check canary health
for host in $CANARY_HOSTS; do
  curl -sf http://$host:9090/health || echo "FAIL: $host"
done

# Check for excessive blocks
aegisbpf_blocks_total rate > 100/sec  # Alert threshold
```

**Daily Review:**
- Review all block events
- Check application error logs
- Compare canary vs non-canary metrics
- Interview canary host owners

#### Go/No-Go Decision

**After 1 week:**

 **Proceed** if:
- No increase in application errors
- Block rate is expected
- No unexpected blocks of legitimate traffic
- Performance impact < 5%
- On-call reports no issues

 **Rollback** if:
- Application errors increased
- Unexpected blocks detected
- Performance degradation
- On-call escalations

**Rollback Procedure:**
```bash
# scripts/rollback.sh
scripts/canary_deploy.sh --disable
# or
for host in $CANARY_HOSTS; do
  ssh $host "sudo systemctl stop aegisbpf"
  ssh $host "sudo systemctl disable aegisbpf"
done
```

---

### Phase 4: Gradual Rollout (25% → 50% → 100%)

**Duration:** 6-8 weeks
**Scope:** Progressive expansion
**Goal:** Full production deployment

#### Week 1-2: 25% Rollout

- Deploy to 25% of production hosts
- Include diverse workload types
- Monitor closely for 2 weeks

**Success Criteria:**
- [ ] No increase in errors
- [ ] Block rate stable
- [ ] Performance acceptable
- [ ] No false positives

#### Week 3-4: 50% Rollout

- Deploy to 50% of production hosts
- Include critical services (with extra caution)

**Success Criteria:**
- [ ] Application SLOs maintained
- [ ] No escalations
- [ ] Capacity planning validated

#### Week 5-8: 100% Rollout

- Deploy to remaining production hosts
- Announce completion to organization

**Success Criteria:**
- [ ] Full production coverage
- [ ] SLOs met for 1 week
- [ ] Documented lessons learned
- [ ] Runbooks updated with real issues

---

## Rollback Procedures

### Emergency Rollback (Complete)

```bash
#!/bin/bash
# Emergency: disable enforcement immediately
ansible all -m systemd -a "name=aegisbpf state=stopped"
ansible all -m systemd -a "name=aegisbpf enabled=no"

echo "AegisBPF disabled on all hosts"
echo "Enforcement will not restart on reboot"
echo "Investigate root cause before re-enabling"
```

### Partial Rollback (Canary Only)

```bash
#!/bin/bash
# Rollback canary hosts only
ansible canary -m systemd -a "name=aegisbpf state=stopped"
echo "Canary hosts disabled. Non-canary hosts still enforcing."
```

### Policy Rollback (Keep Running)

```bash
# Rollback to previous policy without stopping daemon
aegisbpf block clear  # Clear all deny rules
aegisbpf apply /etc/aegisbpf/policy.previous.yml
```

---

## Monitoring During Rollout

### Dashboard: Rollout Health

**Panel 1: Deployment Progress**
```promql
# Hosts with AegisBPF running
count(aegisbpf_up == 1)

# Total hosts in fleet
count(up{job="node-exporter"})

# Rollout percentage
count(aegisbpf_up == 1) / count(up{job="node-exporter"}) * 100
```

**Panel 2: Block Rate by Host**
```promql
# Identify outlier hosts
topk(10, rate(aegisbpf_blocks_total[5m]))
```

**Panel 3: Application Impact**
```promql
# Error rate (split by canary/non-canary)
rate(app_errors_total{canary="true"}[5m])
rate(app_errors_total{canary="false"}[5m])
```

### Alerts During Rollout

```yaml
# Extra-sensitive alerts during rollout
alert: RolloutHighBlockRate
expr: rate(aegisbpf_blocks_total[5m]) > 10
for: 2m  # Shorter than normal 5m
severity: warning
annotations:
  summary: "Unusually high block rate during rollout"
  description: "Review logs and consider pausing rollout"

alert: RolloutApplicationErrors
expr: |
  rate(app_errors_total{rollout_phase!=""}[5m]) >
  rate(app_errors_total{rollout_phase="baseline"}[5m]) * 1.1
for: 5m
severity: critical
annotations:
  summary: "Application errors increased during rollout"
  runbook: docs/ROLLOUT_PLAN.md#rollback-procedures
```

---

## Communication Plan

### Pre-Rollout

**T-2 weeks:**
- Announce rollout plan to engineering teams
- Share documentation links
- Schedule office hours for questions

**T-1 week:**
- Reminder email with rollout schedule
- Highlight monitoring dashboards
- Provide escalation contacts

### During Rollout

**Daily:**
- Post status update in #infrastructure channel
- Report: hosts deployed, issues found, next steps

**After each phase:**
- Retrospective with stakeholders
- Document lessons learned
- Update runbooks with real issues

### Post-Rollout

**T+1 week:**
- Full retrospective meeting
- Publish rollout report
- Update documentation with lessons learned

---

## Rollout Checklist

### Before Starting

- [ ] All prerequisites completed
- [ ] Monitoring stack operational
- [ ] Runbooks tested
- [ ] On-call trained
- [ ] Stakeholders notified
- [ ] Rollback procedure tested

### Phase 1: Shadow Mode

- [ ] Deploy audit-only to production
- [ ] Monitor for 2-4 weeks
- [ ] Analyze false positives
- [ ] Tune policy
- [ ] Review with security team

### Phase 2: Test Environment

- [ ] Enable enforcement in test
- [ ] Run full test suite
- [ ] Execute chaos tests
- [ ] Validate recovery procedures
- [ ] Get sign-off from QA

### Phase 3: Canary (5%)

- [ ] Select canary hosts
- [ ] Deploy enforcement to canary
- [ ] Monitor for 1 week
- [ ] Review daily metrics
- [ ] Get feedback from canary owners
- [ ] Go/no-go decision

### Phase 4: Gradual Rollout

- [ ] Deploy to 25% (monitor 2 weeks)
- [ ] Deploy to 50% (monitor 2 weeks)
- [ ] Deploy to 100% (monitor 2 weeks)
- [ ] Validate SLOs maintained
- [ ] Document lessons learned

### Post-Rollout

- [ ] Retrospective completed
- [ ] Runbooks updated
- [ ] Rollout report published
- [ ] Remove canary labels
- [ ] Normalize monitoring alerts
- [ ] Transition to BAU operations

---

## Lessons Learned Template

After each phase, document:

### What Went Well
- (Examples from actual rollout)

### What Went Wrong
- (Issues encountered)

### Action Items
- (How to improve for next phase)

### Metrics
- False positive rate: X%
- Performance impact: X% CPU
- Rollback count: X
- Time to detect issues: X minutes

---

## Appendix: Example Policy Evolution

### Phase 1: Minimal Policy (Shadow)
```yaml
# policy-shadow.yml
version: 1
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
```

### Phase 2: Tuned Policy (After Analysis)
```yaml
# policy-tuned.yml
version: 1
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
    - /etc/ssh/ssh_host_*_key  # Added after analysis
allow:
  cgroups:
    - /system.slice/sshd.service  # Allow sshd to read keys
```

### Phase 3: Production Policy (Full)
```yaml
# policy-production.conf
version: 1
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
    - /etc/ssh/ssh_host_*_key
    - /root/.ssh/id_*
  inodes:
    # High-value targets discovered during rollout
    - "12345678:90"  # /var/db/secrets
allow:
  cgroups:
    - /system.slice/sshd.service
    - /system.slice/backup.service
```

---

**Last Updated:** 2026-02-07
**Next Review:** After Phase 4 completion
**Owner:** SRE Team
