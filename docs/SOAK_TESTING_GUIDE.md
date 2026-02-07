# AegisBPF Extended Soak Testing Guide

**Purpose:** Long-running stability and performance validation
**Duration:** 1-2 weeks minimum
**Target:** Task #16 completion
**Last Updated:** 2026-02-07

---

## Overview

Soak testing validates that AegisBPF remains stable under continuous operation for extended periods. This catches issues like memory leaks, resource exhaustion, performance degradation, and rare race conditions that don't appear in short tests.

---

## Test Environment

### Recommended Setup

**Hardware:**
- Your i9-13900H development machine
- Or a dedicated test VM/container
- Minimum: 4 cores, 8GB RAM

**OS:**
- Linux kernel 5.10+ with BPF LSM support
- Same or similar to production environment
- Kernel 6.14.0-37-generic (your current setup) is excellent

**Load:**
- Normal development workload OR
- Synthetic workload generator OR
- Production-like traffic replay

---

## Test Scenarios

### Scenario 1: Shadow Mode Soak (Low Risk)

**Duration:** 7-14 days
**Mode:** Audit-only (no enforcement)
**Goal:** Validate observation overhead is negligible

```bash
# Start daemon in background
sudo ./build/aegisbpf run --audit > /var/log/aegisbpf-soak.log 2>&1 &
DAEMON_PID=$!
echo $DAEMON_PID > /tmp/aegisbpf-soak.pid

# Apply production policy
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Let it run for 1-2 weeks with normal system usage
```

**What to Monitor:**
- CPU usage over time (expect: <2% sustained)
- Memory usage over time (expect: <50MB sustained, no growth)
- Ring buffer drops (expect: 0 or very rare)
- Daemon crashes (expect: 0)
- System stability (no kernel panics, no OOM kills)

### Scenario 2: Enforcement Mode Soak (Higher Risk)

**Duration:** 7-14 days
**Mode:** Enforce (active blocking)
**Goal:** Validate enforcement doesn't cause instability

```bash
# Only run this after Scenario 1 passes!
sudo ./build/aegisbpf run --enforce > /var/log/aegisbpf-enforce-soak.log 2>&1 &
DAEMON_PID=$!

# Apply policy
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Monitor for false positives and system issues
```

**What to Monitor:**
- Same as Scenario 1, plus:
- False positive blocks (expect: near zero)
- Application errors correlated with blocks
- System call latency impact

### Scenario 3: Stress Soak (High Load)

**Duration:** 3-7 days
**Goal:** Validate under sustained high load

```bash
# Start daemon
sudo ./build/aegisbpf run --audit &

# Generate continuous filesystem activity
while true; do
    # Touch files that match deny rules
    for i in {1..100}; do
        cat /etc/shadow > /dev/null 2>&1 || true
        cat /root/.ssh/id_rsa > /dev/null 2>&1 || true
        sleep 0.01
    done
done &

# Let run for 3-7 days
```

**What to Monitor:**
- Ring buffer drop rate (should stabilize, not grow unbounded)
- BPF map capacity (should not fill up)
- CPU/memory under sustained load

---

## Monitoring During Soak

### Automated Metrics Collection

Create a monitoring script that runs every 5 minutes:

```bash
#!/bin/bash
# soak_monitor.sh

LOG="/var/log/aegisbpf-soak-metrics.csv"

# CSV header (run once)
if [ ! -f "$LOG" ]; then
    echo "timestamp,cpu_pct,mem_mb,blocks,ringbuf_drops,map_deny_path,map_deny_inode,map_allow_cgroup" > "$LOG"
fi

# Get daemon PID
PID=$(cat /tmp/aegisbpf-soak.pid 2>/dev/null)
if [ -z "$PID" ] || ! ps -p $PID > /dev/null 2>&1; then
    echo "$(date +%s),DAEMON_DEAD,0,0,0,0,0,0" >> "$LOG"
    exit 1
fi

# Collect metrics
CPU=$(ps -p $PID -o %cpu= | awk '{print $1}')
MEM=$(ps -p $PID -o rss= | awk '{print $1/1024}')

# Get BPF stats
STATS=$(sudo ./build/aegisbpf stats 2>/dev/null)
BLOCKS=$(echo "$STATS" | grep "Total blocks:" | awk '{print $3}')
DROPS=$(echo "$STATS" | grep "Ringbuf drops:" | awk '{print $3}')

# Get map entry counts
METRICS=$(sudo ./build/aegisbpf metrics 2>/dev/null)
DENY_PATH=$(echo "$METRICS" | grep "aegisbpf_deny_path_entries" | awk '{print $2}')
DENY_INODE=$(echo "$METRICS" | grep "aegisbpf_deny_inode_entries" | awk '{print $2}')
ALLOW_CGROUP=$(echo "$METRICS" | grep "aegisbpf_allow_cgroup_entries" | awk '{print $2}')

# Log data
echo "$(date +%s),$CPU,$MEM,${BLOCKS:-0},${DROPS:-0},${DENY_PATH:-0},${DENY_INODE:-0},${ALLOW_CGROUP:-0}" >> "$LOG"
```

**Install as cron job:**
```bash
chmod +x scripts/soak_monitor.sh
# Run every 5 minutes
echo "*/5 * * * * /home/ern42/CLionProjects/aegisbpf/scripts/soak_monitor.sh" | crontab -
```

### Manual Checks (Daily)

```bash
# Check daemon is alive
pgrep -f "aegisbpf run" || echo "DAEMON DEAD!"

# Check resource usage
ps aux | grep aegisbpf

# Check for errors in logs
tail -100 /var/log/aegisbpf-soak.log | grep -i error

# Check statistics
sudo ./build/aegisbpf stats

# Check system logs for BPF issues
sudo dmesg | grep -i bpf | tail -20
```

---

## Success Criteria

### Phase 1: Shadow Mode (1 week minimum)

 **Stability:**
- [ ] Zero daemon crashes
- [ ] Zero kernel panics or BPF errors
- [ ] Zero OOM kills

 **Performance:**
- [ ] CPU usage: sustained <2% (p99 <5%)
- [ ] Memory usage: <50MB sustained, no growth trend
- [ ] Memory growth: <1MB per day (indicates no leaks)

 **Correctness:**
- [ ] Ring buffer drops: <0.01% of events
- [ ] BPF map entries stable (not growing unbounded)
- [ ] No unexplained system slowdowns

### Phase 2: Enforcement Mode (1 week minimum)

All Phase 1 criteria, plus:

 **Enforcement:**
- [ ] False positive rate: <0.01%
- [ ] No legitimate application failures
- [ ] Block events correlate with expected policy violations

---

## Failure Analysis

### If Daemon Crashes

1. **Collect crash info:**
   ```bash
   # Check exit status
   tail -100 /var/log/aegisbpf-soak.log

   # Check kernel logs
   sudo dmesg | tail -100

   # Check core dumps
   ls -l /var/crash/ core.*
   ```

2. **Reproduce in debugger:**
   ```bash
   # Build with debug symbols
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   make

   # Run under gdb
   sudo gdb --args ./build/aegisbpf run --audit
   ```

3. **File issue:** Create GitHub issue with logs and reproduction steps

### If Memory Grows

1. **Check for leaks:**
   ```bash
   # Run with valgrind (very slow!)
   sudo valgrind --leak-check=full --show-leak-kinds=all \\
       ./build/aegisbpf run --audit
   ```

2. **Analyze map growth:**
   ```bash
   # Monitor map entries over time
   watch -n 60 'sudo ./build/aegisbpf metrics | grep _entries'
   ```

### If Performance Degrades

1. **Profile hot paths:**
   ```bash
   # Use perf to find hot functions
   sudo perf record -p $(pgrep aegisbpf) -g -- sleep 60
   sudo perf report
   ```

2. **Check BPF program performance:**
   ```bash
   # Check BPF stats
   sudo bpftool prog show
   ```

---

## Analysis Scripts

### Plot Metrics Over Time

```python
#!/usr/bin/env python3
# plot_soak_metrics.py

import pandas as pd
import matplotlib.pyplot as plt

# Read CSV
df = pd.read_csv('/var/log/aegisbpf-soak-metrics.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

# Plot resource usage
fig, axes = plt.subplots(3, 1, figsize=(12, 10))

# CPU
axes[0].plot(df['timestamp'], df['cpu_pct'])
axes[0].set_ylabel('CPU %')
axes[0].set_title('AegisBPF CPU Usage Over Time')
axes[0].grid(True)

# Memory
axes[1].plot(df['timestamp'], df['mem_mb'])
axes[1].set_ylabel('Memory (MB)')
axes[1].set_title('AegisBPF Memory Usage Over Time')
axes[1].grid(True)

# Ringbuf drops
axes[2].plot(df['timestamp'], df['ringbuf_drops'])
axes[2].set_ylabel('Ring Buffer Drops')
axes[2].set_title('Ring Buffer Drops Over Time')
axes[2].grid(True)

plt.tight_layout()
plt.savefig('/tmp/aegisbpf-soak-analysis.png')
print("Saved plot to /tmp/aegisbpf-soak-analysis.png")
```

---

## Reporting

### After Soak Test Completion

Create report with:

1. **Duration:** How long the test ran
2. **Workload:** What the system was doing
3. **Resource Metrics:** Average/p95/p99 CPU and memory
4. **Stability:** Number of crashes, errors, restarts
5. **Performance:** Ring buffer drops, BPF errors
6. **Graphs:** CPU/memory/drops over time

**Example Report:**
```markdown
# Soak Test Report: 14-Day Shadow Mode

**Duration:** 2026-01-15 to 2026-01-29 (14 days)
**Mode:** Audit-only
**Workload:** Normal development (compiles, tests, web browsing)
**System:** i9-13900H, 32GB RAM, Kernel 6.14.0-37

## Results

 **PASS** - All criteria met

**Stability:**
- Uptime: 14 days, 0 crashes
- Zero kernel errors

**Performance:**
- CPU: avg 0.8%, p95 1.2%, p99 2.1%
- Memory: avg 8.2MB, max 9.1MB, no growth
- Ring buffer drops: 0

**Events:**
- Total blocks (audit): 42,156
- Top blocked paths: /etc/shadow (40,123), /root/.ssh/id_rsa (2,033)

## Recommendation

 Ready for Phase 2 (Enforcement Mode Soak)
```

---

## Quick Start

```bash
# 1. Start soak test
sudo ./build/aegisbpf run --audit > /var/log/aegisbpf-soak.log 2>&1 &
echo $! > /tmp/aegisbpf-soak.pid

# 2. Apply policy
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# 3. Install monitoring
chmod +x scripts/soak_monitor.sh
echo "*/5 * * * * $(pwd)/scripts/soak_monitor.sh" | crontab -

# 4. Let run for 1-2 weeks

# 5. Daily checks
sudo ./build/aegisbpf stats
ps aux | grep aegisbpf

# 6. After 1-2 weeks, stop and analyze
sudo pkill -TERM aegisbpf
python3 scripts/plot_soak_metrics.py
```

---

**Last Updated:** 2026-02-07
**Next Review:** After first soak test completion
**Owner:** Development Team
