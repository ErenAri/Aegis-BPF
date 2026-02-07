# AegisBPF Capacity Planning Guide

**Purpose:** Understanding resource limits and scaling considerations
**Audience:** SREs, System Architects, DevOps Engineers
**Last Updated:** 2026-02-07

---

## Executive Summary

AegisBPF uses kernel BPF maps with **fixed maximum sizes**. Understanding these limits is critical for production deployment to avoid capacity issues.

**Key Takeaway:** Plan for 65,536 max unique files/inodes being actively blocked per host.

---

## BPF Map Size Limits

### File/Inode Enforcement Maps

| Map Name | Max Entries | Purpose | Memory per Entry | Total Memory |
|----------|-------------|---------|------------------|--------------|
| `deny_inode_map` | **65,536** | Exact inode blocking | ~16 bytes | ~1 MB |
| `deny_path_map` | 16,384 | Path-based blocking | ~264 bytes | ~4 MB |
| `deny_bloom_map` | 16,384 | Fast path bloom filter | ~8 bytes | ~128 KB |
| `deny_exact_map` | 65,536 | Exact SHA256 matching | ~40 bytes | ~2.5 MB |
| `deny_inode_stats_map` | 65,536 | Block event counters | ~16 bytes | ~1 MB |

**Total File Enforcement:** ~9 MB kernel memory

### Network Enforcement Maps

| Map Name | Max Entries | Purpose | Memory per Entry | Total Memory |
|----------|-------------|---------|------------------|--------------|
| `deny_ipv4_map` | 65,536 | IPv4 address blocking | ~8 bytes | ~512 KB |
| `deny_ipv6_map` | 65,536 | IPv6 address blocking | ~20 bytes | ~1.3 MB |
| `deny_port_map` | 4,096 | Port blocking | ~8 bytes | ~32 KB |
| `deny_cidr_v4_map` | 16,384 | IPv4 CIDR ranges | ~12 bytes | ~192 KB |
| `deny_cidr_v6_map` | 16,384 | IPv6 CIDR ranges | ~24 bytes | ~384 KB |
| `net_ip_stats_map` | 16,384 | Connection stats | ~24 bytes | ~384 KB |

**Total Network Enforcement:** ~2.8 MB kernel memory

### Process Tracking Maps

| Map Name | Max Entries | Purpose | Memory per Entry | Total Memory |
|----------|-------------|---------|------------------|--------------|
| `process_tree_map` | **65,536** | Process ancestry | ~32 bytes | ~2 MB |
| `allow_cgroup_map` | 1,024 | Cgroup allowlist | ~8 bytes | ~8 KB |
| `survival_allowlist_map` | 256 | Critical process allowlist | ~8 bytes | ~2 KB |
| `enforce_signal_state_map` | 65,536 | Per-process enforcement state | ~16 bytes | ~1 MB |

**Total Process Tracking:** ~3 MB kernel memory

### Ring Buffer (Event Log)

| Component | Default Size | Adjustable | Max Recommended |
|-----------|-------------|------------|-----------------|
| `ringbuf` | 16 MB | Yes (`--ringbuf-bytes`) | 64 MB |

**Total Ring Buffer:** 16 MB kernel memory (default)

---

## Total Memory Footprint

| Component | Memory Usage |
|-----------|--------------|
| File Enforcement Maps | ~9 MB |
| Network Enforcement Maps | ~2.8 MB |
| Process Tracking Maps | ~3 MB |
| Ring Buffer | 16 MB (default) |
| **Total Kernel Memory** | **~31 MB** |
| Userspace Daemon | ~20-50 MB RSS |
| **Total per Host** | **~50-80 MB** |

---

## What Happens When Maps Fill Up?

### Graceful Degradation (No Crashes)

When a map reaches capacity:

1. **New entries are rejected** with error logged
2. **Existing entries continue to work** normally
3. **Enforcement continues** for already-blocked items
4. **No kernel panic or daemon crash**

### Example Scenario

```bash
# Map at capacity
$ sudo aegisbpf block add /new/file
Error: Failed to add block rule: Map full (65536/65536 entries)

# Existing blocks still work
$ cat /already/blocked/file
cat: /already/blocked/file: Operation not permitted  #  Still blocked

# Enforcement continues
$ sudo aegisbpf stats
deny_inode_map: 65536/65536 entries (100% FULL)
Total blocks: 1,234,567 events
```

### Log Messages

```
[ERROR] Failed to insert into deny_inode_map: E2BIG (map full)
[WARN] deny_inode_map at capacity (65536/65536), new rules will fail
[INFO] Consider clearing stale entries or increasing MAX_DENY_INODE_ENTRIES
```

---

## Capacity Planning by Use Case

### Small Deployment (< 100 files)

**Use Case:** Block specific sensitive files
```
Examples:
- /etc/shadow
- /root/.ssh/id_rsa
- /app/secrets/api_keys.json
- /var/lib/database/master.key
```

**Capacity Needed:** < 0.1% of default limits

**Recommendation:**  Default limits are fine

---

### Medium Deployment (100-10,000 files)

**Use Case:** Block entire directories or multiple services
```
Examples:
- All files in /secrets/
- Multiple application config directories
- Database files
- Log files with sensitive data
```

**Capacity Needed:** < 15% of default limits

**Recommendation:**  Default limits are sufficient

**Monitoring:** Watch map utilization, alert at >80%

---

### Large Deployment (10,000-60,000 files)

**Use Case:** Broad policy enforcement across many applications
```
Examples:
- Enterprise-wide policy (1000s of applications)
- Multi-tenant systems
- Shared infrastructure
```

**Capacity Needed:** 15-90% of default limits

**Recommendation:**  Monitor closely

**Actions:**
1. Implement stale entry cleanup (remove unused rules weekly)
2. Use cgroup allowlisting to exempt trusted workloads
3. Alert at >70% capacity
4. Have plan to increase map size if needed

---

### Very Large Deployment (>60,000 files)

**Use Case:** Attempting to block most files on system

**Capacity Needed:** >90% of default limits

**Recommendation:**  Rethink architecture

**Problems:**
- Approaching map capacity limits
- High memory usage
- Slower map lookups
- Not sustainable

**Alternative Approaches:**
1. **Use allowlisting instead:** Block everything except specific cgroups/processes
2. **Policy per service:** Deploy separate aegisbpf instances per service
3. **Network-only enforcement:** Use network rules instead of file rules
4. **Consider alternative tools:** SELinux, AppArmor for broad policies

---

## Increasing Map Capacity

### When to Increase

- Consistently hitting 80%+ capacity
- Legitimate need to block >60,000 unique inodes
- Policy growth projected to exceed limits

### How to Increase

**Step 1: Edit BPF Constants**

File: `bpf/aegis.bpf.c`

```c
// Before
#define MAX_DENY_INODE_ENTRIES 65536

// After (double capacity)
#define MAX_DENY_INODE_ENTRIES 131072
```

**Step 2: Rebuild**

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Step 3: Test Memory Impact**

```bash
# Check map memory usage
sudo bpftool map list | grep deny_inode
# Verify memory allocation (should be ~2x previous)

# Test with high load
sudo ./build/aegisbpf health
```

**Step 4: Deploy**

```bash
# Canary deployment first
# Deploy to 5% of hosts, monitor for 1 week
# Then gradual rollout

sudo systemctl stop aegisbpf
sudo cp build/aegisbpf /usr/bin/
sudo systemctl start aegisbpf
```

### Memory Impact

Doubling map sizes:

| Map | Before | After | Delta |
|-----|--------|-------|-------|
| deny_inode_map | 65K entries | 131K entries | +1 MB |
| process_tree_map | 65K entries | 131K entries | +2 MB |
| Total | ~31 MB | ~34 MB | **+3 MB** |

**Impact:** Minimal - modern servers can easily handle this

---

## Ring Buffer Sizing

### Default: 16 MB

Holds ~1 million events before wrapping

**Calculation:**
```
Event size: ~200 bytes average
Buffer size: 16 MB = 16,777,216 bytes
Capacity: 16,777,216 / 200 = ~83,000 events
```

### When to Increase

**Symptoms of too-small ringbuf:**
- Frequent ringbuf drop events
- `aegisbpf_ringbuf_drops_total` metric increasing
- Events missing from logs

**Check current drops:**
```bash
sudo aegisbpf metrics | grep ringbuf_drops
# aegisbpf_ringbuf_drops_total 1234

# If drops > 0.1% of events, increase size
```

### How to Increase

```bash
# Edit systemd service
sudo systemctl edit aegisbpf

[Service]
ExecStart=
ExecStart=/usr/bin/aegisbpf run --enforce --ringbuf-bytes=$((64*1024*1024))
# 64 MB ring buffer

sudo systemctl daemon-reload
sudo systemctl restart aegisbpf
```

### Recommended Sizes by Event Rate

| Event Rate | Ringbuf Size | Can Buffer |
|------------|--------------|------------|
| < 100/sec | 16 MB (default) | ~14 minutes |
| 100-1000/sec | 32 MB | ~7 minutes |
| 1000-10000/sec | 64 MB | ~3 minutes |
| > 10000/sec | 128 MB | ~1 minute |

**Note:** Ring buffer is lossy - events are dropped when full. Size appropriately for your event processing speed.

---

## Process Limits

### Maximum Concurrent Processes: 65,536

**Map:** `process_tree_map`

**What counts:**
- All processes on the system (if tracking enabled)
- Used for ancestry checking and cgroup resolution

**Capacity planning:**
```bash
# Check current process count
ps aux | wc -l

# Typical servers:
# - Web server: 100-500 processes
# - Database: 50-200 processes
# - Container host: 500-5000 processes
# - Large Kubernetes node: 2000-10000 processes
```

**Recommendation:**
- Default 65K limit is sufficient for 99% of deployments
- Even large Kubernetes nodes rarely exceed 10K processes

---

## Network Policy Limits

### Maximum Denied IPs/CIDRs

| Rule Type | Max Entries | Typical Use |
|-----------|-------------|-------------|
| IPv4 addresses | 65,536 | Block specific IPs |
| IPv6 addresses | 65,536 | Block specific IPs |
| IPv4 CIDRs | 16,384 | Block IP ranges |
| IPv6 CIDRs | 16,384 | Block IP ranges |
| Ports | 4,096 | Block specific ports |

**Total addressable space:**
- Can block ~65K individual IPs + ~16K ranges
- Sufficient for most use cases (blocklists, GeoIP blocking, etc.)

**Example Capacity Usage:**

```bash
# Block known malicious IPs (feeds)
# Typical feeds: 1000-10000 IPs
# Capacity used: 1.5-15%

# Block entire country ranges
# Example: Block all China CIDRs (~7000 ranges)
# Capacity used: ~43% of CIDR map

# Block all non-RFC1918 private IPs
# 3 CIDR rules
# Capacity used: <0.1%
```

---

## Monitoring Map Utilization

### Prometheus Metrics (Recommended)

```prometheus
# Map utilization (add to aegisbpf metrics output)
aegisbpf_map_utilization{map="deny_inode"} 0.45  # 45% full
aegisbpf_map_utilization{map="deny_path"} 0.12   # 12% full
aegisbpf_map_utilization{map="process_tree"} 0.08

# Alert when >80% full
alert: AegisBPFMapNearCapacity
expr: aegisbpf_map_utilization > 0.8
severity: warning
```

### Manual Checks

```bash
# Check all map sizes
sudo aegisbpf stats | grep "map:"

# Output example:
# deny_inode_map: 12345/65536 entries (18.8%)
# deny_path_map: 234/16384 entries (1.4%)
# process_tree_map: 1567/65536 entries (2.4%)

# Alert if any >80%
sudo aegisbpf stats | awk '/map:/ {
    split($2, a, "/");
    pct = (a[1]/a[2])*100;
    if (pct > 80) print "WARNING:", $0, "is", pct"% full"
}'
```

---

## Cleanup Strategies

### Automatic Cleanup (Recommended)

```bash
# Daily cron job to remove stale entries
cat > /etc/cron.daily/aegisbpf-cleanup <<'EOF'
#!/bin/bash
# Remove block rules not accessed in 30 days
sudo aegisbpf block list --last-accessed-before 30d | \
    xargs -n1 sudo aegisbpf block del
EOF

chmod +x /etc/cron.daily/aegisbpf-cleanup
```

### Manual Cleanup

```bash
# List oldest entries
sudo aegisbpf block list --sort-by=access-time | head -100

# Remove specific entries
sudo aegisbpf block del /path/to/old/file

# Remove by age
sudo aegisbpf block clear --older-than 90d

# Nuclear option: clear everything
sudo aegisbpf block clear
```

### Policy-Driven Cleanup

```toml
# /etc/aegisbpf/cleanup-policy.toml
[cleanup]
enabled = true
schedule = "daily"  # daily, weekly, monthly
retain_days = 30     # Keep rules accessed in last 30 days
min_access_count = 1 # Keep rules with at least 1 access

[cleanup.exclude]
# Never clean these patterns
paths = [
    "/etc/shadow",
    "/root/.ssh/*",
    "/app/secrets/*"
]
```

---

## Scaling Patterns

### Horizontal Scaling (Per-Host Limits)

**Pattern:** Each host has its own aegisbpf instance with independent limits

```
Host A: 65K inode limit
Host B: 65K inode limit
Host C: 65K inode limit
Total capacity: 195K inodes (across 3 hosts)
```

**Advantage:** Linear scaling
**Disadvantage:** Policy must be distributed to each host

---

### Vertical Scaling (Increase Map Sizes)

**Pattern:** Increase BPF map sizes on each host

```
Before: 65K inode limit per host
After: 131K inode limit per host (2x)
```

**Advantage:** Simple, no architecture change
**Disadvantage:** Requires rebuild, memory usage increases

---

### Policy Segmentation

**Pattern:** Different policies per service/cgroup

```bash
# Service A: Block /service-a-secrets/*
# Service B: Block /service-b-secrets/*
# Each uses <1000 rules

# Instead of:
# - Blocking all secrets (>60K rules)

# Use cgroup allowlisting:
sudo aegisbpf allow cgroup add /service-a.slice
sudo aegisbpf allow cgroup add /service-b.slice
# Only block specific services, allow rest
```

---

## Capacity Planning Worksheet

**Use this to plan your deployment:**

```
1. How many files will you block?
   [ ] < 100 files          → Default limits OK
   [ ] 100-10,000 files     → Default limits OK, monitor
   [ ] 10,000-60,000 files  → Monitor closely, plan cleanup
   [ ] > 60,000 files       → Rethink architecture

2. Expected event rate?
   [ ] < 100 events/sec     → 16 MB ringbuf OK
   [ ] 100-1000 events/sec  → 32 MB ringbuf
   [ ] > 1000 events/sec    → 64+ MB ringbuf

3. Max concurrent processes on host?
   [ ] < 1,000              → Default OK
   [ ] 1,000-10,000         → Default OK
   [ ] > 10,000             → Monitor process_tree_map

4. Network rules?
   [ ] < 1,000 IPs/CIDRs    → Default OK
   [ ] 1,000-10,000         → Monitor utilization
   [ ] > 10,000             → May need to increase maps

5. Cleanup strategy?
   [ ] Manual               → Risk of map full
   [ ] Weekly cron          → Good
   [ ] Daily automated      → Best

6. Monitoring in place?
   [ ] No monitoring        → High risk
   [ ] Manual checks        → Medium risk
   [ ] Prometheus alerts    → Low risk
```

---

## Summary Recommendations

###  Best Practices

1. **Monitor map utilization** - Alert at 70-80% capacity
2. **Implement automated cleanup** - Remove stale entries weekly
3. **Use cgroup allowlisting** - Exempt trusted workloads
4. **Size ringbuf appropriately** - Match event rate
5. **Plan for growth** - Track policy size over time
6. **Test capacity limits** - Know what happens when full

###  Warning Signs

- Map utilization consistently >80%
- Frequent "map full" errors
- Ringbuf drops increasing
- Performance degradation

###  Action Required

- Map at 90%+ capacity → Clean up immediately
- Ringbuf drops >1% → Increase size or reduce events
- Policy growing >1K rules/week → Review policy design

---

**Last Updated:** 2026-02-07
**Next Review:** Quarterly
**Maintained By:** SRE Team + Platform Engineering

