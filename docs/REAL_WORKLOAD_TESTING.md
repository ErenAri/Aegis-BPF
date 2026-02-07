# AegisBPF Real Workload Performance Testing

**Purpose:** Measure AegisBPF performance impact on actual production workloads
**Duration:** 1-3 days per workload type
**Target:** Task #17 completion
**Last Updated:** 2026-02-07

---

## Overview

Real workload testing measures AegisBPF's performance impact on actual applications and usage patterns, not synthetic benchmarks. This validates that the overhead is acceptable for your specific use cases before production deployment.

**Key Metrics:**
- Application latency (p50, p95, p99)
- Throughput (requests/second, operations/second)
- Resource usage (CPU, memory)
- Error rates
- User experience impact

---

## Test Methodology

### Baseline Capture (Day 1)

1. **Run workload WITHOUT AegisBPF**
2. **Capture baseline metrics** for comparison
3. **Document workload characteristics**

### With AegisBPF (Day 2-3)

1. **Run same workload WITH AegisBPF** in audit mode
2. **Capture metrics** under identical conditions
3. **Compare against baseline**

### Success Criteria

 **Performance Impact:**
- Latency increase: <5% at p95, <10% at p99
- Throughput decrease: <5%
- CPU overhead: <2% additional
- Memory overhead: <50MB

 **Stability:**
- No increase in error rates
- No application failures
- No system instability

---

## Workload Categories

### 1. Web Server / API Service

**Characteristics:**
- High request rate
- Low latency requirements
- File I/O for logs, configs
- Network connections

**Example: nginx / Node.js API**

```bash
# Baseline (without AegisBPF)
# Start your web server
systemctl start nginx

# Load test with wrk
wrk -t 8 -c 200 -d 60s --latency http://localhost:8080/api/endpoint

# Record results:
# - Requests/sec
# - Latency p50, p95, p99
# - CPU usage: ps aux | grep nginx
# - Memory usage: ps aux | grep nginx
```

**With AegisBPF:**

```bash
# Start AegisBPF in audit mode
sudo ./build/aegisbpf run --audit &

# Apply policy
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Run same load test
wrk -t 8 -c 200 -d 60s --latency http://localhost:8080/api/endpoint

# Compare results
# Calculate overhead: (with_aegis - baseline) / baseline * 100%
```

**Expected Impact:**
- Latency: +1-3% (mostly in file opens for logs)
- Throughput: <1% decrease
- CPU: +1-2%

### 2. Database Server

**Characteristics:**
- Heavy file I/O
- Many open file descriptors
- Sensitive data files
- High IOPS

**Example: PostgreSQL / MySQL**

```bash
# Baseline test with pgbench
pgbench -c 10 -j 4 -t 10000 mydatabase

# Record:
# - TPS (transactions per second)
# - Latency average, p95, p99
# - CPU usage
# - Disk I/O (iostat -x 1)

# With AegisBPF
sudo ./build/aegisbpf run --audit &
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Same test
pgbench -c 10 -j 4 -t 10000 mydatabase
```

**Expected Impact:**
- TPS: <2% decrease
- Latency: +2-5% (file I/O overhead)
- CPU: +2-3%

** Warning:** Database files often need allow rules if they match deny patterns.

### 3. Build System / CI/CD

**Characteristics:**
- Extremely file I/O heavy
- Many file opens/closes
- Spawns many processes
- Accesses many different files

**Example: Compile a large C++ project**

```bash
# Baseline
cd ~/my-large-project
make clean
time make -j$(nproc)

# Record:
# - Build time
# - CPU usage (top -b -n 1 | grep make)
# - File operations (strace -c make -j$(nproc) 2>&1 | tail -20)

# With AegisBPF
sudo ./build/aegisbpf run --audit &
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Same build
make clean
time make -j$(nproc)

# Check for blocks
sudo ./build/aegisbpf stats --detailed
```

**Expected Impact:**
- Build time: +5-15% (high file I/O overhead)
- This is typically acceptable for build systems
- CPU: +3-5%

** Important:** Check `aegisbpf stats --detailed` for false positives! Build systems may access sensitive files legitimately.

### 4. Container Runtime

**Characteristics:**
- Process spawning
- Network namespaces
- File system layering
- cgroup management

**Example: Docker container lifecycle**

```bash
# Baseline
time docker run --rm ubuntu:22.04 /bin/bash -c "echo test && ls -la"
time docker run --rm ubuntu:22.04 apt update

# Record:
# - Container start time
# - Command execution time
# - CPU/memory overhead

# With AegisBPF
sudo ./build/aegisbpf run --audit &
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Same operations
time docker run --rm ubuntu:22.04 /bin/bash -c "echo test && ls -la"
time docker run --rm ubuntu:22.04 apt update

# Check cgroup handling
sudo ./build/aegisbpf stats --detailed | grep -A 10 "Top blocked cgroups"
```

**Expected Impact:**
- Container start time: +1-5%
- Command execution: <2%
- May need cgroup allow rules for system containers

### 5. File Intensive Applications

**Characteristics:**
- Heavy read/write operations
- Many file opens
- Log processing, backups

**Example: Log processing with grep/awk**

```bash
# Generate test data
dd if=/dev/urandom bs=1M count=1000 | base64 > /tmp/test.log

# Baseline
time grep "pattern" /tmp/test.log | wc -l
time awk '{sum+=$1} END {print sum}' /tmp/numbers.txt

# With AegisBPF
sudo ./build/aegisbpf run --audit &
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Same operations
time grep "pattern" /tmp/test.log | wc -l
time awk '{sum+=$1} END {print sum}' /tmp/numbers.txt
```

**Expected Impact:**
- Processing time: +5-10% for small files
- Processing time: <1% for large files (overhead amortized)

---

## Automated Testing Scripts

### Web Service Load Test

```bash
#!/bin/bash
# test_web_performance.sh

SERVICE_URL="http://localhost:8080/api/health"
DURATION=60
CONNECTIONS=200
THREADS=8

echo "=== AegisBPF Web Service Performance Test ==="

# Function to run load test
run_test() {
    local label=$1
    echo ""
    echo "Testing: $label"
    wrk -t $THREADS -c $CONNECTIONS -d ${DURATION}s --latency $SERVICE_URL 2>&1 | tee /tmp/wrk-${label}.txt

    # Extract metrics
    RPS=$(grep "Requests/sec:" /tmp/wrk-${label}.txt | awk '{print $2}')
    P50=$(grep "50%" /tmp/wrk-${label}.txt | awk '{print $2}')
    P99=$(grep "99%" /tmp/wrk-${label}.txt | awk '{print $2}')

    echo "$label,$RPS,$P50,$P99" >> /tmp/performance-results.csv
}

# Ensure service is running
if ! curl -sf $SERVICE_URL > /dev/null; then
    echo "ERROR: Service not responding at $SERVICE_URL"
    exit 1
fi

# CSV header
echo "test,rps,p50,p99" > /tmp/performance-results.csv

# Baseline test (no AegisBPF)
if pgrep -f "aegisbpf run" > /dev/null; then
    echo "WARNING: AegisBPF is running. Stop it for baseline test."
    echo "Run: sudo pkill -f 'aegisbpf run'"
    exit 1
fi

run_test "baseline"

# Start AegisBPF
echo ""
echo "Starting AegisBPF..."
sudo ./build/aegisbpf run --audit > /tmp/aegisbpf-perf-test.log 2>&1 &
DAEMON_PID=$!
sleep 3

if ! ps -p $DAEMON_PID > /dev/null; then
    echo "ERROR: AegisBPF failed to start"
    exit 1
fi

# Apply policy
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

# Test with AegisBPF
run_test "with-aegisbpf"

# Calculate overhead
echo ""
echo "=== Results ==="
python3 <<'PYTHON'
import csv

with open('/tmp/performance-results.csv') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

baseline = rows[0]
with_aegis = rows[1]

def calc_overhead(baseline_val, with_aegis_val):
    b = float(baseline_val)
    a = float(with_aegis_val)
    return ((a - b) / b) * 100

rps_overhead = calc_overhead(baseline['rps'], with_aegis['rps'])

print(f"Baseline RPS:      {baseline['rps']}")
print(f"With AegisBPF RPS: {with_aegis['rps']}")
print(f"Overhead:          {rps_overhead:.2f}%")
print()
print(f"Baseline p50:      {baseline['p50']}")
print(f"With AegisBPF p50: {with_aegis['p50']}")
print()
print(f"Baseline p99:      {baseline['p99']}")
print(f"With AegisBPF p99: {with_aegis['p99']}")

if abs(rps_overhead) < 5:
    print("\n PASS: Overhead within acceptable range (<5%)")
else:
    print(f"\n FAIL: Overhead too high ({rps_overhead:.2f}%)")
PYTHON

# Cleanup
sudo pkill -f "aegisbpf run"
```

### Database Benchmark

```bash
#!/bin/bash
# test_db_performance.sh

DB_NAME="perftest"
SCALE=10
CLIENTS=10
TRANSACTIONS=10000

echo "=== AegisBPF Database Performance Test ==="

# Initialize test database
psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
psql -c "CREATE DATABASE $DB_NAME;"
pgbench -i -s $SCALE $DB_NAME

run_pgbench() {
    local label=$1
    echo ""
    echo "Testing: $label"
    pgbench -c $CLIENTS -j 4 -t $TRANSACTIONS $DB_NAME 2>&1 | tee /tmp/pgbench-${label}.txt

    TPS=$(grep "tps =" /tmp/pgbench-${label}.txt | awk '{print $3}')
    LAT=$(grep "latency average" /tmp/pgbench-${label}.txt | awk '{print $4}')

    echo "$label,$TPS,$LAT" >> /tmp/db-performance.csv
}

echo "test,tps,latency_ms" > /tmp/db-performance.csv

# Baseline
run_pgbench "baseline"

# With AegisBPF
sudo ./build/aegisbpf run --audit &
sleep 3
sudo ./build/aegisbpf policy apply ./config/policy-production.conf

run_pgbench "with-aegisbpf"

# Results
echo ""
echo "=== Results ==="
cat /tmp/db-performance.csv

# Cleanup
sudo pkill -f "aegisbpf run"
```

---

## Analysis

### Calculating Overhead

```python
#!/usr/bin/env python3
# analyze_performance.py

baseline_latency_p99 = 45.2  # ms
with_aegis_latency_p99 = 47.8  # ms

overhead_pct = ((with_aegis_latency_p99 - baseline_latency_p99) / baseline_latency_p99) * 100

print(f"Baseline p99: {baseline_latency_p99}ms")
print(f"With AegisBPF p99: {with_aegis_latency_p99}ms")
print(f"Overhead: {overhead_pct:.2f}%")

if overhead_pct < 5:
    print(" Within acceptable range (<5%)")
elif overhead_pct < 10:
    print(" Marginal (5-10%) - review if acceptable")
else:
    print(" Too high (>10%) - investigate")
```

### Common Patterns

**High overhead (>10%):**
- Many small file operations → Check if deny rules are too broad
- Hitting deny rules frequently → Add allow rules for legitimate access
- Ring buffer drops → Increase --ringbuf-bytes or reduce --event-sample-rate

**Acceptable overhead (<5%):**
- Large file operations (overhead amortized)
- CPU-bound workloads (minimal file I/O)
- Network-heavy workloads (file I/O not on hot path)

---

## Optimization

### If Overhead is Too High

1. **Check for false positives:**
   ```bash
   sudo ./build/aegisbpf stats --detailed
   # Look for unexpected blocks
   ```

2. **Add allow rules:**
   ```bash
   # If legitimate services are being blocked
   sudo ./build/aegisbpf allow add /system.slice/myapp.service
   ```

3. **Reduce event sampling:**
   ```bash
   # Only log every 100th event (reduces overhead)
   sudo ./build/aegisbpf run --audit --event-sample-rate=100
   ```

4. **Increase ring buffer:**
   ```bash
   # Reduce drops under high load
   sudo ./build/aegisbpf run --audit --ringbuf-bytes=2097152  # 2MB
   ```

5. **Use inode rules instead of path rules:**
   ```bash
   # Inode lookup is faster than path matching
   sudo ./build/aegisbpf block add --inode /etc/shadow
   ```

---

## Reporting Template

```markdown
# AegisBPF Real Workload Performance Test Report

**Date:** 2026-02-07
**Tester:** John Doe
**System:** i9-13900H, 32GB RAM, Kernel 6.14.0-37

## Workload: Web API Service (Node.js + nginx)

**Baseline (without AegisBPF):**
- Requests/sec: 25,432
- Latency p50: 12.3ms
- Latency p95: 28.1ms
- Latency p99: 45.2ms
- CPU usage: 45%

**With AegisBPF (audit mode):**
- Requests/sec: 24,987
- Latency p50: 12.5ms
- Latency p95: 28.9ms
- Latency p99: 47.8ms
- CPU usage: 47%

**Overhead:**
- Throughput: -1.75%
- Latency p99: +5.75%
- CPU: +2%

**AegisBPF Stats:**
- Blocks (audit): 1,234
- Ring buffer drops: 0
- Memory usage: 8.2MB

**Verdict:**  PASS - Overhead within acceptable range

**Notes:**
- Most blocks were log file access (expected)
- No false positives detected
- No application errors
- System remained stable
```

---

## Next Steps

After completing real workload tests:

1.  **Document results** in report format above
2.  **Share with team** for review
3.  **Adjust policy** if false positives found
4.  **Optimize** if overhead too high
5.  **Proceed to Phase 1** (Shadow Mode) if tests pass

---

**Last Updated:** 2026-02-07
**Next Review:** After first real workload test
**Owner:** Development Team
