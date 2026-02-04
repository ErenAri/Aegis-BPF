# AegisBPF SIEM Integration Guide

This document describes how to integrate AegisBPF events with popular Security Information and Event Management (SIEM) systems.

## Event Format

AegisBPF emits events in JSON format to stdout or journald. See [event-schema.json](../config/event-schema.json) for the complete JSON Schema.

### Event Types

| Event | Description |
|-------|-------------|
| `exec` | Process execution observed |
| `block` | File open observed or blocked (audit/enforce) |

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Event type (`exec` or `block`) |
| `pid` | integer | Process ID |
| `ppid` | integer | Parent process ID |
| `start_time` | integer | Process start time (kernel clock) |
| `exec_id` | string | Stable execution identifier (`pid:start_time`) |
| `trace_id` | string | Correlation identifier (equal to `exec_id`) |
| `cgid` | integer | Cgroup ID |
| `cgroup_path` | string | Cgroup path |
| `comm` | string | Command name (max 16 chars) |

### Block-specific Fields

| Field | Type | Description |
|-------|------|-------------|
| `parent_start_time` | integer | Parent process start time |
| `parent_exec_id` | string | Stable parent execution identifier |
| `parent_trace_id` | string | Parent correlation identifier |
| `ino` | integer | Inode number |
| `dev` | integer | Device number |
| `path` | string | Path of the file when available |
| `resolved_path` | string | Canonical path (if different) |
| `action` | string | `AUDIT` (audit-only) or enforce action (`TERM`/`KILL`/`INT`/`BLOCK`) |

Note: when enforcement is inode-based, `path` may be empty; use `ino` + `dev` for correlation.

## Splunk Integration

### Using HTTP Event Collector (HEC)

1. Configure AegisBPF to output JSON to stdout:
   ```bash
   aegisbpf run --log=stdout --log-format=json
   ```

2. Use a log shipper (e.g., Fluentd, Vector) to forward to Splunk HEC:
   ```yaml
   # Vector config example
   [sources.aegisbpf]
   type = "journald"
   include_units = ["aegisbpf"]

   [transforms.parse_aegisbpf]
   type = "remap"
   inputs = ["aegisbpf"]
   source = '''
   . = parse_json!(.message)
   '''

   [sinks.splunk]
   type = "splunk_hec"
   inputs = ["parse_aegisbpf"]
   endpoint = "https://splunk.example.com:8088"
   token = "${SPLUNK_HEC_TOKEN}"
   index = "security"
   sourcetype = "aegisbpf"
   ```

### CEF Format (Common Event Format)

For Splunk CEF ingestion, transform AegisBPF events to CEF:

```
CEF:0|AegisBPF|AegisBPF|1.0|BLOCK|File Access Blocked|7|dst=<path> dproc=<comm> msg=<action> cn1=<pid> cn1Label=pid cn2=<ppid> cn2Label=ppid cs1=<cgroup_path> cs1Label=cgroup
```

Field mapping:

| CEF Field | AegisBPF Field |
|-----------|----------------|
| `dst` | `path` |
| `dproc` | `comm` |
| `msg` | `action` |
| `cn1` | `pid` |
| `cn2` | `ppid` |
| `cs1` | `cgroup_path` |
| `deviceCustomDate1` | `start_time` (converted to datetime if desired) |

## Elastic (ELK) Integration

### Filebeat Configuration

```yaml
filebeat.inputs:
  - type: journald
    id: aegisbpf
    include_matches:
      - _SYSTEMD_UNIT=aegisbpf.service

processors:
  - decode_json_fields:
      fields: ["message"]
      target: "aegisbpf"
      overwrite_keys: true

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  index: "aegisbpf-%{+yyyy.MM.dd}"
```

### Index Template

```json
{
  "index_patterns": ["aegisbpf-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "type": { "type": "keyword" },
        "start_time": { "type": "long" },
        "exec_id": { "type": "keyword" },
        "trace_id": { "type": "keyword" },
        "parent_start_time": { "type": "long" },
        "parent_exec_id": { "type": "keyword" },
        "parent_trace_id": { "type": "keyword" },
        "pid": { "type": "integer" },
        "ppid": { "type": "integer" },
        "comm": { "type": "keyword" },
        "path": { "type": "keyword" },
        "resolved_path": { "type": "keyword" },
        "action": { "type": "keyword" },
        "cgid": { "type": "long" },
        "cgroup_path": { "type": "keyword" },
        "dev": { "type": "integer" },
        "ino": { "type": "long" }
      }
    }
  }
}
```

### Kibana Detection Rules

Example detection rule for suspicious activity:

```json
{
  "name": "AegisBPF High Block Rate",
  "description": "Detects high rate of blocked executions indicating potential attack",
  "risk_score": 70,
  "severity": "high",
  "type": "threshold",
  "query": "aegisbpf.type:block",
  "threshold": {
    "field": ["host.name"],
    "value": 100
  },
  "interval": "5m"
}
```

## Generic Syslog Integration

### Syslog Output

Configure rsyslog to forward AegisBPF events:

```bash
# /etc/rsyslog.d/aegisbpf.conf
if $programname == 'aegisbpf' then {
    action(type="omfwd"
           target="syslog.example.com"
           port="514"
           protocol="tcp"
           template="RSYSLOG_SyslogProtocol23Format")
    stop
}
```

### Syslog Message Format

```
<priority>1 <timestamp> <hostname> aegisbpf - - - <json_event>
```

Example:
```
<134>1 2024-01-15T10:30:00.000Z server1 aegisbpf - - - {"type":"block","pid":12345,"ppid":1000,"start_time":123456789,"exec_id":"12345:123456789","trace_id":"12345:123456789","cgid":5678,"cgroup_path":"/sys/fs/cgroup/user.slice/user-1000.slice","comm":"bash","path":"/usr/bin/malware","action":"KILL","ino":123456,"dev":259}
```

## Prometheus/Grafana Integration

For metrics-based monitoring, use the built-in Prometheus endpoint:

```bash
aegisbpf metrics --out /var/lib/prometheus/node-exporter/aegisbpf.prom
```

Key low-cardinality metrics include:
- `aegisbpf_blocks_total`, `aegisbpf_ringbuf_drops_total`
- `aegisbpf_net_blocks_total`, `aegisbpf_net_ringbuf_drops_total`
- `aegisbpf_net_rules_total`
- `aegisbpf_deny_inode_entries`, `aegisbpf_deny_path_entries`, `aegisbpf_allow_cgroup_entries`

For short-lived debugging sessions, export detailed high-cardinality metrics:

```bash
aegisbpf metrics --detailed --out /tmp/aegisbpf.debug.prom
```

See [prometheus/alerts.yml](../config/prometheus/alerts.yml) for alert rules and [grafana/dashboard.json](../config/grafana/dashboard.json) for the Grafana dashboard.

Recommended SLO alerts:
- `AegisBPFEventLossSLOViolation` (event-loss ratio > 0.1%)
- `AegisBPFMetricsStale` (no updates for >30m with active policy)

### OTel-Style Policy Spans

For troubleshooting policy rollouts and runtime startup checks, enable span logs:

```bash
AEGIS_OTEL_SPANS=1 aegisbpf policy apply /etc/aegisbpf/policy.conf
```

This emits structured logs with:
- `message`: `otel_span_start` / `otel_span_end`
- `trace_id`, `span_id`, `parent_span_id`
- `span_name`, `duration_ms`, `status`

Common span names include:
- Policy path: `cli.policy_apply`, `policy.apply`, `policy.apply_internal`, `policy.rollback_last_applied`
- Runtime path: `daemon.run`, `daemon.load_bpf`, `daemon.attach_programs`, `daemon.event_loop`
- Health path: `cli.health`, `health.detect_kernel_features`, `health.load_bpf`

## QRadar Integration

### Log Source Configuration

1. Create a new log source with protocol type "Syslog"
2. Use the following DSM parsing:

```xml
<device_extension>
  <pattern id="aegisbpf_block"
           regex="\"type\":\"block\".*\"pid\":(\d+).*\"path\":\"([^\"]+)\".*\"action\":\"([^\"]+)\""
           capture_groups="pid,path,action">
    <event name="File Access Blocked" category="Security" severity="high"/>
  </pattern>
  <pattern id="aegisbpf_exec"
           regex="\"type\":\"exec\".*\"pid\":(\d+)"
           capture_groups="pid">
    <event name="Execution Observed" category="Audit" severity="low"/>
  </pattern>
</device_extension>
```

### QRadar Custom Properties

| Property Name | Expression |
|---------------|------------|
| AegisBPF PID | `\"pid\":(\d+)` |
| AegisBPF Path | `\"path\":\"([^\"]+)\"` |
| AegisBPF Action | `\"action\":\"([^\"]+)\"` |
| AegisBPF Cgroup | `\"cgroup_path\":\"([^\"]+)\"` |

## Security Onion Integration

### Logstash Filter

```ruby
filter {
  if [program] == "aegisbpf" {
    json {
      source => "message"
      target => "aegisbpf"
    }

    mutate {
      add_field => { "[@metadata][index]" => "so-aegisbpf" }
    }

    if [aegisbpf][type] == "block" {
      mutate {
        add_tag => ["alert", "execution_blocked"]
      }
    }
  }
}
```

## Wazuh Integration

### Custom Decoder

```xml
<!-- /var/ossec/etc/decoders/aegisbpf_decoder.xml -->
<decoder name="aegisbpf">
  <program_name>aegisbpf</program_name>
</decoder>

<decoder name="aegisbpf-block">
  <parent>aegisbpf</parent>
  <regex>"type":"block".*"pid":(\d+).*"path":"([^"]+)".*"action":"(\w+)"</regex>
  <order>pid,path,action</order>
</decoder>
```

### Custom Rules

```xml
<!-- /var/ossec/etc/rules/aegisbpf_rules.xml -->
<group name="aegisbpf,">
  <rule id="100001" level="10">
    <decoded_as>aegisbpf-block</decoded_as>
    <description>AegisBPF: Execution blocked - $(path)</description>
    <group>execution_blocked,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>100001</if_sid>
    <field name="action">KILL</field>
    <description>AegisBPF: File access blocked - $(path)</description>
    <group>malware,</group>
  </rule>
</group>
```

## Timestamp Conversion

AegisBPF emits process `start_time` values (kernel monotonic clock). Use the ingest timestamp for event time, or convert `start_time` if you need a stable process timeline:

```python
import time

def convert_start_time(boot_ns):
    """Convert kernel boot timestamp to wall-clock time."""
    # Read boot time from /proc/stat
    with open('/proc/stat') as f:
        for line in f:
            if line.startswith('btime'):
                boot_time = int(line.split()[1])
                break

    # Convert nanoseconds to seconds and add to boot time
    wall_time = boot_time + (boot_ns / 1e9)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(wall_time))
```

Alternatively, configure journald output which automatically includes wall-clock timestamps.
