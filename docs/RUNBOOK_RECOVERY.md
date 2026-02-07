# AegisBPF Emergency Recovery Runbook

**Purpose:** Emergency procedures for production incidents
**Audience:** On-call engineers, SREs, production operators
**Last Updated:** 2026-02-07

---

##  Quick Reference

| Scenario | Severity | Action | Time to Recovery |
|----------|----------|--------|------------------|
| [Enforcement blocking legitimate traffic](#scenario-1-enforcement-blocking-legitimate-traffic) |  **CRITICAL** | Disable enforcement immediately | < 2 minutes |
| [Daemon crash loop](#scenario-2-daemon-crash-loop) | 🟡 **HIGH** | Restart in audit mode | < 5 minutes |
| [Performance degradation](#scenario-3-performance-degradation) | 🟡 **MEDIUM** | Reduce event sampling | < 3 minutes |
| [Map capacity full](#scenario-4-bpf-map-capacity-full) | 🟢 **LOW** | Clean up old rules | < 10 minutes |
| [Kernel panic after upgrade](#scenario-5-kernel-panic-after-upgrade) |  **CRITICAL** | Disable LSM, rollback kernel | < 15 minutes |

---

## Scenario 1: Enforcement Blocking Legitimate Traffic

### Symptoms
- Applications failing with "Operation not permitted"
- Users unable to access critical files/services
- Sudden spike in enforcement block events
- Application error logs showing EPERM errors

### Immediate Actions (< 2 minutes)

#### Step 1: Stop Enforcement Immediately
```bash
# Option A: Stop daemon completely
sudo systemctl stop aegisbpf
sudo rm -rf /sys/fs/bpf/aegis  # Remove pinned maps

# Option B: Switch to audit mode (keeps monitoring)
sudo systemctl stop aegisbpf
# Edit /etc/systemd/system/aegisbpf.service
# Change: --enforce → --audit
sudo systemctl start aegisbpf
```

#### Step 2: Verify Service Recovery
```bash
# Test affected application
curl https://yourapp.example.com/health

# Check application logs
sudo journalctl -u your-app -n 50 --no-pager

# Confirm no more EPERM errors
sudo dmesg | grep -i "operation not permitted"
```

#### Step 3: Identify Problematic Rule
```bash
# Download recent enforcement events
sudo journalctl -u aegisbpf --since "10 minutes ago" > /tmp/aegis-events.log

# Find most recent blocks
grep '"action":"BLOCK"' /tmp/aegis-events.log | tail -20

# Look for patterns:
# - Which inode/path is being blocked?
# - Which process (comm, pid, cgroup) is affected?
# - What file operation (open, read, exec)?
```

### Root Cause Analysis

```bash
# List all active block rules
sudo aegisbpf block list > /tmp/block-rules.txt

# Check when problematic rule was added
sudo aegisbpf block list | grep <suspicious-path>

# Review policy history
sudo journalctl -u aegisbpf | grep "policy applied"

# Check who made the change
sudo ausearch -m USER_CMD -ts recent | grep aegisbpf
```

### Fix Actions

#### Option A: Remove Specific Rule
```bash
# Remove problematic rule
sudo aegisbpf block del /path/to/incorrectly/blocked/file

# Or clear by inode
sudo aegisbpf block del --inode 1234:5678

# Verify removal
sudo aegisbpf block list | grep <path>
```

#### Option B: Clear All Rules and Start Fresh
```bash
# Clear all deny rules
sudo aegisbpf block clear

# Restart in enforce mode
sudo systemctl restart aegisbpf

# Re-apply correct policy
sudo aegisbpf policy apply /etc/aegisbpf/policy.conf
```

### Post-Incident

1. **Document the incident:**
   ```bash
   cat > /var/log/aegisbpf-incident-$(date +%Y%m%d-%H%M%S).md <<EOF
   # Incident: Enforcement Blocking Legitimate Traffic

   **Date:** $(date)
   **Affected Service:** <service-name>
   **Duration:** <minutes>
   **Root Cause:** <describe incorrect rule>
   **Resolution:** <describe fix>

   ## Blocked Path
   <path-that-was-blocked>

   ## Affected Processes
   <process-names>

   ## Prevention
   <how-to-prevent-recurrence>
   EOF
   ```

2. **Update policy validation:**
   - Add affected path to policy test suite
   - Review policy approval process
   - Consider allowlist for critical paths

3. **Improve monitoring:**
   - Add alert for spike in BLOCK events
   - Add alert for specific application errors
   - Dashboard showing enforcement rate by service

---

## Scenario 2: Daemon Crash Loop

### Symptoms
- `systemctl status aegisbpf` shows "activating/auto-restart"
- Rapid restarts visible in `journalctl -u aegisbpf`
- BPF maps not populated
- Applications showing inconsistent enforcement

### Immediate Actions (< 5 minutes)

#### Step 1: Stop the Crash Loop
```bash
# Stop auto-restart
sudo systemctl stop aegisbpf
sudo systemctl disable aegisbpf  # Prevent auto-start

# Clean BPF state
sudo rm -rf /sys/fs/bpf/aegis
```

#### Step 2: Diagnose Crash Reason
```bash
# Get recent crash logs
sudo journalctl -u aegisbpf --since "10 minutes ago" --no-pager > /tmp/crash.log

# Look for error patterns:
grep -i "error\|fatal\|panic\|segfault" /tmp/crash.log

# Check kernel logs
sudo dmesg | tail -100

# Common crash reasons:
# 1. BPF verifier rejection
# 2. Map size exceeded
# 3. Invalid configuration
# 4. Kernel incompatibility
# 5. Resource exhaustion
```

#### Step 3: Start in Safe Mode (Audit Only)
```bash
# Start manually in audit mode
sudo aegisbpf run --audit 2>&1 | tee /tmp/aegis-safe-start.log

# Monitor for crashes
# If stable for 1 minute, daemon is viable in audit mode
```

### Root Cause Analysis

#### BPF Verifier Rejection
```bash
# Check for verifier errors
grep "verifier" /tmp/crash.log
grep "BPF" /var/log/kern.log

# Symptoms: "Failed to load BPF program"
# Cause: Kernel BPF verifier rejected the program
# Fix: Check kernel version compatibility
uname -r  # Compare with docs/COMPATIBILITY.md
```

#### Map Size Exceeded
```bash
# Check map capacity
sudo aegisbpf stats | grep "map\|capacity"

# Look for patterns like:
# deny_inode_map: 65536/65536 (100% full)

# Fix: Clear old entries or increase map size
sudo aegisbpf block clear-stale --older-than 7d
```

#### Invalid Configuration
```bash
# Validate configuration
sudo aegisbpf health --check-config

# Check policy file
sudo aegisbpf policy validate /etc/aegisbpf/policy.conf

# Look for syntax errors, invalid paths, bad inodes
```

### Fix Actions

#### Temporary Fix: Run in Audit Mode
```bash
# Update systemd service
sudo systemctl edit aegisbpf

# Add:
[Service]
ExecStart=
ExecStart=/usr/bin/aegisbpf run --audit

# Restart
sudo systemctl daemon-reload
sudo systemctl enable aegisbpf
sudo systemctl start aegisbpf
```

#### Permanent Fix: Address Root Cause
Based on diagnosis:

**For BPF errors:**
```bash
# Check kernel compatibility
aegisbpf health

# Upgrade kernel if needed
sudo apt update && sudo apt upgrade linux-image-generic
sudo reboot
```

**For capacity issues:**
```bash
# Clear old rules
sudo aegisbpf block clear

# Reduce policy scope
sudo vi /etc/aegisbpf/policy.conf  # Remove unnecessary rules
```

**For config issues:**
```bash
# Restore known-good configuration
sudo cp /etc/aegisbpf/policy.conf.backup /etc/aegisbpf/policy.conf

# Validate before applying
sudo aegisbpf policy validate /etc/aegisbpf/policy.conf
```

### Post-Incident

1. **Enable monitoring:**
   ```bash
   # Add crash detection alert
   # Alert if daemon restarts > 3 times in 5 minutes
   ```

2. **Improve configuration validation:**
   - Add pre-deployment policy testing
   - CI/CD validation of policy files
   - Canary deployments for policy changes

---

## Scenario 3: Performance Degradation

### Symptoms
- Application latency increased (p95, p99)
- CPU usage high on hosts running aegisbpf
- Increased system call latency
- Ringbuf drop events increasing

### Immediate Actions (< 3 minutes)

#### Step 1: Reduce Event Sampling
```bash
# Current sampling rate
sudo aegisbpf config get event-sample-rate

# Reduce to 10% (from 100%)
sudo systemctl stop aegisbpf
# Edit /etc/systemd/system/aegisbpf.service
# Add: --event-sample-rate=0.1
sudo systemctl start aegisbpf

# Monitor improvement
watch -n 1 'aegisbpf stats | grep -i cpu'
```

#### Step 2: Identify Performance Bottleneck
```bash
# Check aegisbpf CPU usage
top -p $(pgrep aegisbpf)

# Check ringbuf drops (indicates event backlog)
sudo aegisbpf metrics | grep ringbuf_drops

# Check map sizes
sudo aegisbpf stats | grep "map.*entries"
```

### Root Cause Analysis

```bash
# Profile BPF program performance
sudo bpftool prog show
sudo bpftool prog dump xlated id <prog_id>

# Check for:
# 1. Too many deny rules → slow map lookups
# 2. Event sample rate too high → too many events
# 3. Ringbuf too small → drops and retries
# 4. Application doing high I/O → more LSM hooks triggered
```

### Fix Actions

#### Reduce Event Load
```bash
# Option 1: Lower sample rate
ExecStart=/usr/bin/aegisbpf run --enforce --event-sample-rate=0.1

# Option 2: Increase ringbuf size
ExecStart=/usr/bin/aegisbpf run --enforce --ringbuf-bytes=$((32*1024*1024))

# Option 3: Filter events (future feature)
```

#### Optimize Policy
```bash
# Reduce number of deny rules
sudo aegisbpf block list | wc -l

# Remove unused rules
sudo aegisbpf block clear-stale

# Use allowlist instead of denylist where possible
sudo aegisbpf allow cgroup add /system.slice
```

### Post-Incident

1. **Capacity planning:**
   - Document baseline performance
   - Set alerts for p95 latency
   - Regular performance testing

2. **Optimize policy:**
   - Review and minimize deny rules
   - Use cgroup allowlisting
   - Consider network policy vs file policy trade-offs

---

## Scenario 4: BPF Map Capacity Full

### Symptoms
- "Map full" errors in logs
- New block rules failing to add
- Policy apply failures
- Enforcement inconsistent

### Immediate Actions (< 10 minutes)

```bash
# Check which map is full
sudo aegisbpf stats

# Example output:
# deny_inode_map: 65536/65536 entries (100% full)
# deny_path_map: 12000/16384 entries (73% full)

# Clear old/stale entries
sudo aegisbpf block list --sort-by=access-time | tail -10000 | \
    while read path; do sudo aegisbpf block del "$path"; done

# Or clear all and re-apply policy
sudo aegisbpf block clear
sudo aegisbpf policy apply /etc/aegisbpf/policy.conf
```

### Root Cause Analysis

```bash
# Why did map fill up?

# Possibility 1: Policy too broad
sudo aegisbpf block list | wc -l
# If > 50000, policy is probably too broad

# Possibility 2: No cleanup process
# Check if stale entries are being removed
sudo aegisbpf block list --last-accessed

# Possibility 3: Misconfiguration
# Check if rules are being added in loop
sudo journalctl -u aegisbpf | grep "block add"
```

### Fix Actions

```bash
# Long-term fix: Increase map size
# Edit bpf/aegis.bpf.c:
# #define MAX_DENY_INODE_ENTRIES 131072  // Double from 65536

# Rebuild and redeploy
cmake --build build
sudo systemctl stop aegisbpf
sudo cp build/aegisbpf /usr/bin/
sudo systemctl start aegisbpf
```

---

## Scenario 5: Kernel Panic After Upgrade

### Symptoms
- System won't boot after kernel upgrade
- BPF LSM errors in boot logs
- System stuck at "Starting AegisBPF"

### Immediate Actions (< 15 minutes)

#### Step 1: Boot into Recovery
```bash
# At GRUB menu:
# 1. Select "Advanced options"
# 2. Select previous kernel version
# 3. Boot

# Or add to kernel command line:
# aegisbpf.disable=1 lsm=!bpf
```

#### Step 2: Disable AegisBPF
```bash
# Once booted with old kernel:
sudo systemctl disable aegisbpf
sudo systemctl stop aegisbpf

# Remove BPF LSM from boot (if needed)
sudo vi /etc/default/grub
# Remove "bpf" from GRUB_CMDLINE_LINUX="lsm=...,bpf"
sudo update-grub
```

#### Step 3: Investigate Incompatibility
```bash
# Check kernel version
uname -r

# Check BPF LSM support
grep CONFIG_BPF_LSM /boot/config-$(uname -r)

# Test aegisbpf compatibility
sudo aegisbpf health
```

### Fix Actions

```bash
# If new kernel lacks BPF LSM support:
# 1. Wait for compatible kernel
# 2. Or build custom kernel with CONFIG_BPF_LSM=y

# If aegisbpf needs update:
# 1. Check for newer aegisbpf release
# 2. Or build from source with kernel headers
```

---

## General Recovery Principles

### Break-Glass Procedure

**When all else fails:**
```bash
# 1. Stop daemon
sudo systemctl stop aegisbpf
sudo systemctl disable aegisbpf

# 2. Clean BPF state
sudo rm -rf /sys/fs/bpf/aegis

# 3. Remove BPF LSM (requires reboot)
sudo vi /etc/default/grub
# Edit: lsm=lockdown,yama,apparmor  # Remove "bpf"
sudo update-grub
sudo reboot

# 4. Verify services recovered
sudo systemctl status <critical-app>
```

### Escalation

**When to escalate:**
- Recovery not working after 15 minutes
- Data loss or corruption suspected
- Security incident (bypass or compromise)
- Multiple hosts affected simultaneously

**Escalation contacts:**
- Primary: SRE on-call (PagerDuty)
- Secondary: Security team
- Escalation: Engineering lead

---

## Monitoring & Alerting

### Critical Alerts

```prometheus
# Daemon down
alert: AegisBPFDaemonDown
expr: up{job="aegisbpf"} == 0
severity: critical
runbook: #scenario-2-daemon-crash-loop

# High enforcement rate
alert: AegisBPFHighEnforcementRate
expr: rate(aegisbpf_blocks_total[5m]) > 100
severity: warning
runbook: #scenario-1-enforcement-blocking-legitimate-traffic

# Map near capacity
alert: AegisBPFMapNearFull
expr: aegisbpf_map_utilization > 0.8
severity: warning
runbook: #scenario-4-bpf-map-capacity-full

# Ringbuf drops
alert: AegisBPFRingbufDropping
expr: rate(aegisbpf_ringbuf_drops_total[5m]) > 10
severity: warning
runbook: #scenario-3-performance-degradation
```

---

## Post-Recovery Checklist

- [ ] Incident documented in wiki/postmortem
- [ ] Root cause identified and confirmed
- [ ] Fix deployed and verified
- [ ] Monitoring alerts reviewed/updated
- [ ] Runbook updated with lessons learned
- [ ] Team debriefed on incident
- [ ] Prevention measures implemented

---

**Last Review:** 2026-02-07
**Next Review:** Quarterly or after major incident
**Maintained By:** SRE Team

