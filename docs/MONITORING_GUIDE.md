# AegisBPF Monitoring & Alerting Guide

**Purpose:** Configure comprehensive monitoring for production deployments
**Audience:** SREs, DevOps Engineers, Platform Teams
**Last Updated:** 2026-02-07

---

## Quick Start

**Minimum viable monitoring:**
```bash
# 1. Daemon health
curl http://localhost:9090/metrics | grep aegisbpf_up

# 2. Enforcement events
aegisbpf stats | grep "Total blocks"

# 3. System impact
top -p $(pgrep aegisbpf)
```

---

## Metrics Endpoints

### Prometheus Metrics (Port 9090)

**Enable metrics endpoint:**
```bash
# Add to systemd service
ExecStart=/usr/bin/aegisbpf run --enforce --metrics-port=9090
```

**Scrape configuration:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'aegisbpf'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

### Available Metrics

#### Daemon Health
```
aegisbpf_up{version="1.0.0"} 1
aegisbpf_daemon_uptime_seconds 3600
aegisbpf_daemon_start_timestamp_seconds 1704672000
```

#### Enforcement Events
```
aegisbpf_blocks_total{action="BLOCK"} 1234
aegisbpf_blocks_total{action="TERM"} 56
aegisbpf_blocks_total{action="KILL"} 2
aegisbpf_blocks_total{action="INT"} 0

aegisbpf_blocks_by_path{path="/etc/shadow"} 100
aegisbpf_blocks_by_inode{inode="1234567:890"} 50
```

#### BPF Map Utilization
```
aegisbpf_map_entries{map="deny_inode"} 12345
aegisbpf_map_capacity{map="deny_inode"} 65536
aegisbpf_map_utilization{map="deny_inode"} 0.188  # 18.8%

aegisbpf_map_entries{map="deny_path"} 234
aegisbpf_map_capacity{map="deny_path"} 16384
aegisbpf_map_utilization{map="deny_path"} 0.014  # 1.4%
```

#### Ring Buffer
```
aegisbpf_ringbuf_drops_total 0
aegisbpf_ringbuf_events_total 1234567
aegisbpf_ringbuf_drop_rate 0.0  # drops / events
```

#### Performance
```
aegisbpf_cpu_usage_percent 2.5
aegisbpf_memory_rss_bytes 25165824  # 24 MB
aegisbpf_event_processing_latency_microseconds{quantile="0.5"} 50
aegisbpf_event_processing_latency_microseconds{quantile="0.95"} 150
aegisbpf_event_processing_latency_microseconds{quantile="0.99"} 500
```

---

## Critical Alerts

### 1. Daemon Down

**Alert:**
```yaml
alert: AegisBPFDaemonDown
expr: aegisbpf_up == 0
for: 1m
severity: critical
annotations:
  summary: "AegisBPF daemon is down on {{ $labels.instance }}"
  description: "Enforcement is not active. Investigate immediately."
  runbook: docs/RUNBOOK_RECOVERY.md#scenario-2-daemon-crash-loop
```

**Dashboard:**
```promql
# Uptime graph
aegisbpf_daemon_uptime_seconds

# Restart count (increases indicate crashes)
changes(aegisbpf_daemon_start_timestamp_seconds[1h])
```

---

### 2. High Enforcement Rate

**Alert:**
```yaml
alert: AegisBPFHighBlockRate
expr: rate(aegisbpf_blocks_total[5m]) > 100
for: 5m
severity: warning
annotations:
  summary: "High enforcement rate: {{ $value }} blocks/sec"
  description: "Possible misconfigured policy or attack in progress"
  runbook: docs/RUNBOOK_RECOVERY.md#scenario-1-enforcement-blocking-legitimate-traffic
```

**Dashboard:**
```promql
# Enforcement rate by action
rate(aegisbpf_blocks_total[5m])

# Top blocked paths
topk(10, aegisbpf_blocks_by_path)
```

---

### 3. Map Near Capacity

**Alert:**
```yaml
alert: AegisBPFMapNearFull
expr: aegisbpf_map_utilization > 0.80
for: 10m
severity: warning
labels:
  map: "{{ $labels.map }}"
annotations:
  summary: "BPF map {{ $labels.map }} is {{ $value | humanizePercentage }} full"
  description: "Approaching capacity limit. Clean up stale entries or increase map size."
  runbook: docs/RUNBOOK_RECOVERY.md#scenario-4-bpf-map-capacity-full
```

**Dashboard:**
```promql
# Map utilization over time
aegisbpf_map_utilization

# Map growth rate
deriv(aegisbpf_map_entries[1h])
```

---

### 4. Ringbuf Dropping Events

**Alert:**
```yaml
alert: AegisBPFRingbufDropping
expr: rate(aegisbpf_ringbuf_drops_total[5m]) > 10
for: 5m
severity: warning
annotations:
  summary: "Ring buffer dropping {{ $value }} events/sec"
  description: "Event processing cannot keep up. Consider increasing ringbuf size or reducing sample rate."
  runbook: docs/RUNBOOK_RECOVERY.md#scenario-3-performance-degradation
```

**Dashboard:**
```promql
# Drop rate
rate(aegisbpf_ringbuf_drops_total[5m])

# Drop percentage
rate(aegisbpf_ringbuf_drops_total[5m]) / rate(aegisbpf_ringbuf_events_total[5m]) * 100
```

---

### 5. Performance Degradation

**Alert:**
```yaml
alert: AegisBPFHighCPU
expr: aegisbpf_cpu_usage_percent > 50
for: 10m
severity: warning
annotations:
  summary: "AegisBPF using {{ $value }}% CPU"
  description: "High CPU usage. Check event rate and map sizes."
  runbook: docs/RUNBOOK_RECOVERY.md#scenario-3-performance-degradation

alert: AegisBPFHighMemory
expr: aegisbpf_memory_rss_bytes > 100000000  # 100 MB
for: 10m
severity: warning
annotations:
  summary: "AegisBPF using {{ $value | humanize }}B memory"
  description: "Memory usage high. Check for leaks or excessive map usage."
```

**Dashboard:**
```promql
# CPU usage
aegisbpf_cpu_usage_percent

# Memory usage trend
aegisbpf_memory_rss_bytes

# Event processing latency
histogram_quantile(0.99, aegisbpf_event_processing_latency_microseconds)
```

---

## Grafana Dashboards

### Dashboard 1: Overview

**Panels:**

1. **System Health** (Stat panel)
   - Query: `aegisbpf_up`
   - Display: ✅ UP / ❌ DOWN

2. **Enforcement Rate** (Graph)
   - Query: `rate(aegisbpf_blocks_total[5m])`
   - Unit: ops/sec

3. **Map Utilization** (Gauge)
   - Query: `aegisbpf_map_utilization`
   - Thresholds: Green <70%, Yellow 70-85%, Red >85%

4. **Ringbuf Health** (Graph)
   - Query: `rate(aegisbpf_ringbuf_drops_total[5m])`
   - Alert if > 0

### Dashboard 2: Enforcement Detail

**Panels:**

1. **Blocks by Action** (Pie chart)
   - Query: `sum by (action) (aegisbpf_blocks_total)`

2. **Top Blocked Paths** (Table)
   - Query: `topk(20, aegisbpf_blocks_by_path)`

3. **Blocks Over Time** (Graph)
   - Query: `rate(aegisbpf_blocks_total[5m])`
   - Breakdown by action

4. **Block Event Timeline** (Log panel)
   - Query: `{job="aegisbpf"} |= "action"`
   - Loki logs

### Dashboard 3: Performance

**Panels:**

1. **CPU Usage** (Graph)
   - Query: `aegisbpf_cpu_usage_percent`

2. **Memory Usage** (Graph)
   - Query: `aegisbpf_memory_rss_bytes`

3. **Event Latency** (Heatmap)
   - Query: `aegisbpf_event_processing_latency_microseconds`

4. **Map Growth Rate** (Graph)
   - Query: `deriv(aegisbpf_map_entries[1h])`

---

## Log Monitoring

### Structured Logs (JSON)

**Enable JSON logging:**
```bash
ExecStart=/usr/bin/aegisbpf run --enforce --log-format=json
```

**Log levels:**
- `DEBUG`: Verbose operational details
- `INFO`: Normal events (policy applied, rules added)
- `WARN`: Potential issues (map near full, verification skipped)
- `ERROR`: Failures (BPF load failed, map insert failed)
- `FATAL`: Critical failures (daemon cannot start)

### Important Log Patterns

#### Successful Enforcement Event
```json
{
  "level": "INFO",
  "msg": "enforcement_event",
  "action": "BLOCK",
  "path": "/etc/shadow",
  "inode": "1234567:890",
  "pid": 12345,
  "comm": "cat",
  "uid": 1000,
  "cgroup": "/user.slice/user-1000.slice",
  "timestamp": "2026-02-07T10:30:45Z"
}
```

#### Map Full Error
```json
{
  "level": "ERROR",
  "msg": "Failed to insert into deny_inode_map",
  "error": "E2BIG (map full)",
  "map": "deny_inode_map",
  "current_entries": 65536,
  "max_entries": 65536
}
```

#### BPF Load Failure
```json
{
  "level": "ERROR",
  "msg": "BPF program load failed",
  "error": "verifier rejected: invalid memory access",
  "program": "lsm/file_open"
}
```

### Loki Queries

```logql
# All errors
{job="aegisbpf"} |= "level\":\"ERROR"

# Enforcement events
{job="aegisbpf"} |= "enforcement_event"

# Map full errors
{job="aegisbpf"} |= "map full"

# Rate of enforcement by action
rate({job="aegisbpf"} |= "action\":\"BLOCK" [5m])
```

---

## Application Impact Monitoring

### Correlated Metrics

Monitor application metrics alongside AegisBPF:

```promql
# Application error rate vs enforcement rate
rate(app_errors_total[5m]) and rate(aegisbpf_blocks_total[5m])

# Application latency vs BPF CPU
histogram_quantile(0.99, app_latency_seconds) and aegisbpf_cpu_usage_percent
```

### Recommended Application Alerts

```yaml
alert: AppErrorsAfterEnforcement
expr: |
  rate(app_errors_total[5m]) > 10
  and
  changes(aegisbpf_blocks_total[5m]) > 0
for: 5m
severity: critical
annotations:
  summary: "Application errors correlate with enforcement"
  description: "Check if aegisbpf is blocking legitimate traffic"
```

---

## Health Checks

### Liveness Probe

```bash
# Check if daemon is responding
curl -f http://localhost:9090/health || exit 1
```

### Readiness Probe

```bash
# Check if enforcement is active
aegisbpf stats >/dev/null 2>&1 || exit 1
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 9090
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  exec:
    command: ["/usr/bin/aegisbpf", "health"]
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

## SLOs & SLIs

### Service Level Indicators

| SLI | Target | Measurement |
|-----|--------|-------------|
| **Availability** | 99.9% | `aegisbpf_up == 1` |
| **False Positive Rate** | < 0.01% | Blocks on allowed paths |
| **Event Processing Latency** | p99 < 500µs | `aegisbpf_event_processing_latency_microseconds{quantile="0.99"}` |
| **Ringbuf Drop Rate** | < 0.1% | `rate(aegisbpf_ringbuf_drops_total) / rate(aegisbpf_ringbuf_events_total)` |

### Service Level Objectives

```yaml
# 99.9% uptime SLO (30-day window)
slo_uptime_30d:
  expr: avg_over_time(aegisbpf_up[30d]) >= 0.999

# Event processing SLO
slo_event_latency_p99:
  expr: |
    histogram_quantile(0.99,
      aegisbpf_event_processing_latency_microseconds
    ) < 500
```

---

## Incident Response Integration

### PagerDuty Integration

```yaml
# alertmanager.yml
receivers:
  - name: 'aegisbpf-oncall'
    pagerduty_configs:
      - service_key: '<pagerduty-integration-key>'
        severity: '{{ .GroupLabels.severity }}'
        description: '{{ .GroupLabels.alertname }}: {{ .CommonAnnotations.summary }}'
        details:
          runbook: '{{ .CommonAnnotations.runbook }}'

route:
  routes:
    - match:
        job: aegisbpf
      receiver: 'aegisbpf-oncall'
      group_by: ['alertname', 'severity']
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 4h
```

---

## Capacity Trending

### Weekly Reports

```promql
# Map growth (entries added per week)
increase(aegisbpf_map_entries[7d])

# Event volume trend
avg_over_time(rate(aegisbpf_blocks_total[5m])[7d:])

# CPU usage trend
avg_over_time(aegisbpf_cpu_usage_percent[7d])
```

### Capacity Forecasting

```python
# Example: Forecast when map will reach capacity
import pandas as pd
from sklearn.linear_model import LinearRegression

# Get map entries over time
df = prometheus_query("aegisbpf_map_entries{map='deny_inode'}[30d]")

# Fit trend
model = LinearRegression()
model.fit(df.index.values.reshape(-1, 1), df.values)

# Predict when reaching 65536
capacity = 65536
days_until_full = (capacity - df.values[-1]) / model.coef_[0]

print(f"Map will be full in {days_until_full:.0f} days")
```

---

## Monitoring Checklist

### Initial Deployment

- [ ] Prometheus scraping configured
- [ ] Grafana dashboards imported
- [ ] Critical alerts configured (daemon down, high block rate)
- [ ] PagerDuty integration tested
- [ ] Runbooks linked in alert annotations
- [ ] Log aggregation (Loki/ELK) configured
- [ ] Baseline metrics captured

### Ongoing

- [ ] Weekly review of map utilization trends
- [ ] Monthly SLO review
- [ ] Quarterly capacity planning
- [ ] Alert tuning (reduce false positives)
- [ ] Dashboard updates for new metrics

---

## Example Monitoring Stack

```yaml
# docker-compose.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9091:9090"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"

  promtail:
    image: grafana/promtail:latest
    volumes:
      - /var/log:/var/log
      - ./promtail-config.yml:/etc/promtail/config.yml
```

---

**Last Updated:** 2026-02-07
**Maintained By:** SRE Team
**Next Review:** Quarterly

