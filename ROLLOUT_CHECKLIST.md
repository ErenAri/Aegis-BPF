# AegisBPF Production Rollout Checklist

**Project:** AegisBPF Runtime Security Agent
**Started:** 2026-02-07
**Status:** Phase 0 - Pre-Deployment Validation

---

## Phase 0: Pre-Deployment Validation ✅

**Duration:** Completed 2026-02-07
**Goal:** Verify all prerequisites before production deployment

### Prerequisites

- [x] **All unit tests passing** (165/165)
  - CI validation complete
  - E2E tests available and validated

- [x] **Security audit completed**
  - [x] Ed25519 signature verification audited (SECURE - 5/5 stars)
  - [x] BPF verifier bypass analysis (Disabled in Release)
  - [x] Binary hardening verified (FORTIFY, PIE, RELRO)

- [x] **Documentation complete**
  - [x] RUNBOOK_RECOVERY.md (5 recovery scenarios)
  - [x] CAPACITY_PLANNING.md (BPF map limits, scaling)
  - [x] MONITORING_GUIDE.md (Prometheus, Grafana, alerts)
  - [x] ROLLOUT_PLAN.md (5-phase deployment strategy)

- [x] **Monitoring stack ready**
  - [x] Prometheus alert rules configured (config/prometheus/alerts.yml)
  - [x] Grafana datasource provisioning
  - [x] Docker Compose quick-start (config/monitoring/)
  - [x] AlertManager with PagerDuty integration
  - [x] Dashboard templates in MONITORING_GUIDE.md
  - [ ] Monitoring stack deployed in target environment (deploy when ready)

- [x] **Deployment automation**
  - [x] scripts/canary_deploy.sh (percentage-based deployment)
  - [x] scripts/rollback.sh (emergency + canary + policy rollback)
  - [x] scripts/phase0_validation.sh (automated prerequisite checking)

- [x] **Policy file ready**
  - [x] config/policy-production.yml created
  - [x] Minimal baseline policy (sensitive files only)
  - [x] Designed for expansion based on Phase 1 analysis
  - [ ] Policy approved by security team (when deploying)

- [ ] **Performance baseline captured** (target environment)
  - [ ] Deploy to target environment
  - [ ] Run audit mode for 1 hour
  - [ ] Verify CPU < 5%, Memory < 50MB
  - [ ] No crashes or instability

- [ ] **Team readiness** (when deploying)
  - [ ] On-call team trained on runbooks
  - [ ] Rollback procedure practiced
  - [ ] Escalation contacts documented
  - [ ] Communication plan reviewed

### Go/No-Go Decision

**Status:** ✅ PHASE 0 COMPLETE - Ready for Phase 1

**Achievements:**
- ✅ All code prerequisites met
- ✅ Documentation comprehensive
- ✅ Monitoring infrastructure ready to deploy
- ✅ Deployment automation tested
- ✅ Production policy prepared

**Remaining (Target Environment):**
- Deploy monitoring stack to production environment
- Capture performance baseline on actual hardware
- Conduct team training sessions
- Get security team approval

**Next Phase:**
Phase 1: Shadow Mode (Audit-Only) - 2-4 weeks
Deploy to production in audit mode, gather real-world data

---

## Phase 1: Shadow Mode (Audit-Only) ⬜

**Duration:** 2-4 weeks
**Scope:** Production environment, audit mode
**Goal:** Gather real-world data without enforcement

### Tasks

- [ ] Deploy AegisBPF in audit mode to production
- [ ] Monitor for 2-4 weeks minimum
- [ ] Analyze all "would block" events
- [ ] Identify and fix false positives
- [ ] Tune policy based on real traffic
- [ ] Document observed patterns

### Success Criteria

- [ ] False positive rate < 0.01%
- [ ] Performance overhead < 5% CPU
- [ ] No ring buffer drops
- [ ] Policy refined for workload
- [ ] On-call team comfortable with tooling

### Metrics to Collect

- [ ] Total events logged
- [ ] Block events by path
- [ ] Block events by cgroup
- [ ] Performance impact (CPU, memory)
- [ ] Application correlation (errors vs blocks)

---

## Phase 2: Test Environment Enforcement ⬜

**Duration:** 1-2 weeks
**Scope:** Test/staging with enforcement
**Goal:** Validate enforcement doesn't break applications

### Tasks

- [ ] Enable enforcement in test environment
- [ ] Run full application test suite
- [ ] Execute chaos tests (ringbuf overflow, map capacity)
- [ ] Test recovery procedures
- [ ] Validate rollback works

### Success Criteria

- [ ] All functional tests pass
- [ ] Chaos tests show resilience
- [ ] Recovery procedures validated
- [ ] No unexpected application failures
- [ ] Rollback tested successfully

---

## Phase 3: Canary Deployment (5%) ⬜

**Duration:** 1 week
**Scope:** 5% of production hosts
**Goal:** Detect production-specific issues early

### Tasks

- [ ] Select canary hosts (non-critical, well-monitored)
- [ ] Deploy enforcement to 5% of fleet
- [ ] Monitor canary metrics 24x7
- [ ] Daily review of block events
- [ ] Interview canary host owners

### Success Criteria

- [ ] No increase in application errors
- [ ] Block rate matches expectations
- [ ] No unexpected blocks of legitimate traffic
- [ ] Performance impact < 5%
- [ ] No on-call escalations

### Canary Hosts

*To be selected:*
- [ ] Host 1: [hostname]
- [ ] Host 2: [hostname]
- [ ] Host 3: [hostname]
- [ ] Host 4: [hostname]
- [ ] Host 5: [hostname]

---

## Phase 4: Gradual Rollout ⬜

### Week 1-2: 25% Rollout

- [ ] Deploy to 25% of production hosts
- [ ] Include diverse workload types
- [ ] Monitor for 2 weeks
- [ ] No increase in errors
- [ ] Block rate stable
- [ ] Performance acceptable

### Week 3-4: 50% Rollout

- [ ] Deploy to 50% of production hosts
- [ ] Include critical services
- [ ] Monitor for 2 weeks
- [ ] Application SLOs maintained
- [ ] No escalations

### Week 5-8: 100% Rollout

- [ ] Deploy to all production hosts
- [ ] Monitor for 2 weeks
- [ ] Full production coverage
- [ ] SLOs met consistently
- [ ] Document lessons learned

---

## Post-Rollout ⬜

### Final Validation

- [ ] All hosts running AegisBPF
- [ ] Monitoring dashboards operational
- [ ] Alerts firing correctly
- [ ] On-call runbooks updated
- [ ] Performance SLOs met

### Documentation

- [ ] Rollout retrospective completed
- [ ] Lessons learned documented
- [ ] Runbooks updated with real issues
- [ ] Rollout report published

### Transition to BAU

- [ ] Remove canary labels
- [ ] Normalize monitoring alerts
- [ ] Update capacity planning
- [ ] Schedule quarterly review

---

## Rollback Events

*Document any rollbacks that occur:*

| Date | Phase | Scope | Reason | Resolution |
|------|-------|-------|--------|------------|
| -    | -     | -     | -      | -          |

---

## Lessons Learned

### What Went Well
- *To be filled during rollout*

### What Went Wrong
- *To be filled during rollout*

### Action Items
- *To be filled during rollout*

---

## Metrics Summary

### Phase 0 Validation
- **Tests Passed:** 165/165 unit tests
- **Security Issues:** 0 critical
- **Documentation:** Complete

### Phase 1 Shadow Mode
- **Duration:** TBD
- **Events Logged:** TBD
- **False Positives:** TBD
- **Performance Impact:** TBD

### Phase 2 Test Enforcement
- **Duration:** TBD
- **Tests Passed:** TBD
- **Issues Found:** TBD

### Phase 3 Canary (5%)
- **Duration:** TBD
- **Hosts Deployed:** TBD
- **Blocks/sec:** TBD
- **Application Impact:** TBD

### Phase 4 Gradual Rollout
- **25% Rollout:** TBD
- **50% Rollout:** TBD
- **100% Rollout:** TBD

---

**Last Updated:** 2026-02-07
**Next Review:** Daily during rollout
**Owner:** SRE Team
