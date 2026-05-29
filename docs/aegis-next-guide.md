# aegis-next User Guide

aegis-next is a next-generation BPF runtime security agent built on Linux kernel 6.9+ features (BPF arena maps, sched_ext, open-coded iterators). It provides in-kernel process provenance tracking, policy enforcement, binary authorization, and rate limiting with sub-microsecond overhead.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Policy Rules](#policy-rules)
- [Configuration File](#configuration-file)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Operator Integration](#operator-integration)
- [Event Export](#event-export)
- [Binary Authorization](#binary-authorization)
- [Rate Limiting](#rate-limiting)
- [Self-Protection](#self-protection)
- [Troubleshooting](#troubleshooting)

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Linux kernel | 5.11 (ringbuf-only fallback) | 6.9+ (full arena mode) |
| Kernel config | `CONFIG_BPF_LSM=y` | + `CONFIG_SCHED_CLASS_EXT=y`, `CONFIG_FS_VERITY=y` |
| Boot param | `lsm=...,bpf` | — |
| Capabilities | `CAP_BPF`, `CAP_SYS_ADMIN` | Run as root |

Verify your kernel supports BPF LSM:

```bash
cat /sys/kernel/security/lsm
# Should include "bpf"

cat /proc/config.gz | gunzip | grep CONFIG_BPF_LSM
# CONFIG_BPF_LSM=y
```

## Installation

### From source

```bash
cmake -DBUILD_AEGIS_NEXT=ON -S . -B build
cmake --build build --target aegisbpf-next
sudo cmake --install build --component aegis-next
```

### Container image

```bash
docker build -f prototype/aegis-next/Dockerfile -t aegisbpf-next .
docker run --privileged --pid=host --net=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  aegisbpf-next
```

### Systemd service

After installing, enable the systemd service:

```bash
sudo systemctl enable --now aegisbpf-next
```

The unit file is installed to `/usr/lib/systemd/system/aegisbpf-next.service`. It runs with defense-in-depth hardening (`ProtectSystem=strict`, minimal capabilities).

## Quick Start

```bash
# 1. Start the agent (attaches BPF programs, begins event recording)
sudo aegisbpf-next attach

# 2. In another terminal, check status
sudo aegisbpf-next status

# 3. Load a policy
sudo aegisbpf-next policy load /etc/aegisbpf/examples/policy.rules

# 4. View live events
sudo aegisbpf-next export tail 20

# 5. Walk process lineage
sudo aegisbpf-next graph lineage $$
```

## CLI Reference

### `attach` — Start the agent

```bash
sudo aegisbpf-next attach [flags]
```

| Flag | Description |
|------|-------------|
| `--policy=<file>` | Load policy rules from file at startup |
| `--events=<path>` | Write JSONL events to path (default: `/sys/fs/bpf/aegis_next/events.jsonl`) |
| `--config=<file>` | Read config file (key=value format) |
| `--ocsf` | Use OCSF v1.1 structured output format |

The agent attaches 9 LSM hooks, initializes the arena (or falls back to ringbuf-only mode on older kernels), and begins recording provenance events.

### `status` — System overview

```bash
sudo aegisbpf-next status
```

Shows feature probe results, arena utilization, policy rule count, quarantine entries, and export file status.

### `graph` — Process provenance

```bash
sudo aegisbpf-next graph dump           # Print recent events from arena
sudo aegisbpf-next graph lineage <pid>  # Walk exec lineage for a PID
sudo aegisbpf-next graph stats          # Arena header statistics
```

Requires arena mode (kernel >= 6.9).

### `policy` — Policy management

```bash
sudo aegisbpf-next policy load <file>   # Load/reload rules from file
sudo aegisbpf-next policy list          # Show active policy rules
sudo aegisbpf-next policy clear         # Remove all rules
```

### `export` — Event export

```bash
sudo aegisbpf-next export tail [N]      # Show last N events (default: 10)
```

### `sched` — sched_ext quarantine

```bash
sudo aegisbpf-next sched start          # Attach sched_ext BPF scheduler
sudo aegisbpf-next sched stop           # Detach scheduler
sudo aegisbpf-next sched stats          # Per-CPU quarantine statistics
```

Requires kernel >= 6.12 with `CONFIG_SCHED_CLASS_EXT=y`.

### `auth` — Binary authorization

```bash
sudo aegisbpf-next auth start [--audit|--enforce]
sudo aegisbpf-next auth trust <sha256-digest>
sudo aegisbpf-next auth list
sudo aegisbpf-next auth stats
```

Requires kernel >= 6.7 with `CONFIG_FS_VERITY=y`.

### `rate` — In-kernel rate limiting

```bash
sudo aegisbpf-next rate set fork 30     # Max 30 forks/sec per cgroup
sudo aegisbpf-next rate set conn 50     # Max 50 connects/sec per cgroup
sudo aegisbpf-next rate set file 100    # Max 100 file opens/sec per cgroup
```

### `protect` — Self-protection

```bash
sudo aegisbpf-next protect              # Enable anti-tamper hooks
```

Prevents BPF program detach and map tampering from non-trusted processes.

## Policy Rules

### Format

```
<hook>  <match_type>  <value>  <action>  [kill]
```

| Field | Values |
|-------|--------|
| hook | `exec`, `file`, `conn`, `bind`, `listen` |
| match_type | `comm` (process name), `port` (network port), `cgroup` (cgroup ID), `path` (file path) |
| action | `deny` (block with -EPERM), `allow` (permit), `log` (observe only), `quarantine` (sched_ext throttle) |
| kill | Optional `kill` flag — sends SIGKILL after deny |

Lines starting with `#` are comments. Blank lines are skipped.

### Example policy

```
# Block crypto miners
exec  comm  xmrig   deny  kill
exec  comm  minerd  deny  kill

# Block reverse shell ports
conn  port  4444  deny  kill
conn  port  5555  deny

# Quarantine suspicious tools (throttle, don't kill)
exec  comm  nmap    quarantine

# Log access to sensitive files
file  path  /etc/shadow  log
```

### Included rule packs

| File | Description |
|------|-------------|
| `policy.rules` | General-purpose starter policy |
| `rules-cryptomining.rules` | 16 known miner binaries + Stratum pool ports |
| `rules-reverse-shell.rules` | Common reverse/bind shell patterns |
| `rules-container-escape.rules` | Container breakout prevention |
| `rules-lateral-movement.rules` | SSH/RDP/WinRM/psexec lateral movement |
| `rules-k8s-runtime.rules` | Kubernetes-specific runtime threats |
| `rules-compliance-cis.rules` | CIS benchmark alignment rules |

Rule packs are installed to `/etc/aegisbpf/examples/` and can be combined:

```bash
cat /etc/aegisbpf/examples/rules-cryptomining.rules \
    /etc/aegisbpf/examples/rules-reverse-shell.rules \
    > /etc/aegisbpf/combined-policy.rules
sudo aegisbpf-next policy load /etc/aegisbpf/combined-policy.rules
```

### Hot reload

Update the policy file and reload without restarting:

```bash
sudo aegisbpf-next policy load /etc/aegisbpf/policy.rules
```

The `user_ringbuf` channel delivers new rules to the kernel in zero-copy batches.

## Configuration File

The `--config=<file>` flag reads a key=value config file:

```ini
# /etc/aegisbpf/aegisbpf-next.conf

# Path to policy rules file.
policy=/etc/aegisbpf/policy.rules

# Path for JSONL event export.
events=/var/log/aegisbpf/events.jsonl

# Use OCSF v1.1 structured output (true/false).
ocsf=false
```

Usage:

```bash
sudo aegisbpf-next attach --config=/etc/aegisbpf/aegisbpf-next.conf
```

CLI flags override config file values.

## Kubernetes Deployment

### Helm chart

aegis-next deploys as a DaemonSet via the AegisBPF Helm chart:

```bash
helm install aegisbpf ./helm/aegisbpf \
  --set aegisNext.enabled=true \
  --set operator.enabled=true
```

Key Helm values:

```yaml
aegisNext:
  enabled: true
  image:
    repository: ghcr.io/erenari/aegisbpf-next
    tag: latest
  policyFile: /etc/aegisbpf/policy.next
  eventLogPath: /var/log/aegisbpf/events.jsonl
  ocsf: false
  nodeSelector:
    aegisbpf.io/arena-capable: "true"
  resources:
    limits:
      cpu: 200m
      memory: 256Mi
```

### Node scheduling

The operator's `NodeFeatureReconciler` automatically labels nodes:

- `aegisbpf.io/arena-capable=true` — kernel >= 6.9 with arena support
- `aegisbpf.io/kernel-version=X.Y` — parsed kernel version

The aegis-next DaemonSet targets only arena-capable nodes by default. Override with:

```yaml
aegisNext:
  nodeSelector:
    kubernetes.io/os: linux  # run everywhere
```

## Operator Integration

### Architecture

```
AegisPolicy/AegisClusterPolicy CRD
         │
         ▼
   Operator (reconciler)
         │
         ├── TranslateToINI()      → policy.conf   (mainline daemon)
         └── TranslateToAegisNext() → policy.next   (aegis-next)
         │
         ▼
   ConfigMap: aegis-merged-policy
         │
         ▼
   DaemonSet volume mount
         │
         ▼
   aegis-next reads policy file at startup
```

### Creating a policy via CRD

```yaml
apiVersion: aegisbpf.io/v1alpha1
kind: AegisPolicy
metadata:
  name: block-miners
  namespace: production
spec:
  mode: enforce
  execRules:
    denyComm:
      - xmrig
      - minerd
      - cpuminer
  networkRules:
    deny:
      - port: 4444
        direction: outbound
        action: Block
      - port: 3333
        direction: outbound
        action: Block
```

```bash
kubectl apply -f block-miners.yaml
```

The operator translates this into both INI format (for the mainline daemon) and line-based format (for aegis-next), storing both in the `aegis-merged-policy` ConfigMap.

### Cluster-wide policies

```yaml
apiVersion: aegisbpf.io/v1alpha1
kind: AegisClusterPolicy
metadata:
  name: baseline-security
spec:
  mode: enforce
  execRules:
    denyComm:
      - xmrig
  kernelRules:
    blockModuleLoad: true
    blockPtrace: true
  fileRules:
    deny:
      - path: /etc/shadow
        action: Block
```

Cluster policies merge with namespace policies. The merged result is written to a single ConfigMap consumed by all aegis-next agents.

### Operator Prometheus metrics

| Metric | Description |
|--------|-------------|
| `aegis_operator_policy_reconcile_total{outcome}` | Reconciliation attempts by outcome |
| `aegis_operator_policy_translate_duration_seconds` | CRD → policy translation latency |
| `aegis_operator_active_policies` | Number of active AegisPolicy objects |
| `aegis_operator_configmap_write_errors_total` | ConfigMap write failures |
| `aegis_operator_agent_sync_total{outcome}` | Agent sync attempts |
| `aegis_operator_agent_sync_nodes_applied` | Nodes with synced policy |

## Event Export

### JSONL format

Events are written as one JSON object per line:

```json
{"ts":"2026-05-23T10:15:30.123Z","kind":"exec","pid":1234,"ppid":1200,"tgid":1234,"uid":1000,"comm":"curl","inode":456789,"mnt_ns":4026531840,"pid_ns":4026531836,"path":"/usr/bin/curl"}
```

### OCSF v1.1 format

With `--ocsf`, events follow the Open Cybersecurity Schema Framework:

```json
{"class_uid":1007,"activity_id":1,"time":"2026-05-23T10:15:30.123Z","severity_id":1,"actor":{"process":{"pid":1234,"name":"curl"}},"device":{"hostname":"node-01"}}
```

### File rotation

Event files rotate automatically at 50 MB.

### Viewing events

```bash
# Last 20 events
sudo aegisbpf-next export tail 20

# Follow live (from JSONL file)
tail -f /var/log/aegisbpf/events.jsonl | jq .

# Count events by kind
jq -r .kind /var/log/aegisbpf/events.jsonl | sort | uniq -c | sort -rn
```

## Binary Authorization

Enforce that only trusted binaries (verified via fsverity) can execute:

```bash
# Start in audit mode first
sudo aegisbpf-next auth start --audit

# Trust specific binary digests
sudo aegisbpf-next auth trust $(fsverity digest /usr/bin/bash | awk '{print $1}')

# View trusted list
sudo aegisbpf-next auth list

# Switch to enforce mode
sudo aegisbpf-next auth start --enforce
```

In enforce mode, any binary without a matching fsverity digest is blocked from executing. The digest lookup runs entirely in-kernel for near-zero overhead.

Requires kernel >= 6.7 with `CONFIG_FS_VERITY=y`.

## Rate Limiting

Per-cgroup sliding window rate limiting prevents resource abuse:

```bash
# Fork bomb protection: max 30 forks/sec per cgroup
sudo aegisbpf-next rate set fork 30

# Network flood protection: max 50 connects/sec per cgroup
sudo aegisbpf-next rate set conn 50

# File open flood protection: max 100 opens/sec per cgroup
sudo aegisbpf-next rate set file 100
```

Cgroups exceeding the threshold are automatically quarantined via sched_ext (if available) and logged. Rate tracking runs entirely in-kernel with per-CPU counters.

## Self-Protection

```bash
sudo aegisbpf-next protect
```

Attaches `lsm/bpf` and `lsm/bpf_map` hooks that deny:
- BPF program detach from non-trusted callers
- Map tampering (delete, update) from non-trusted callers

Caller identity is verified by comparing the calling binary's inode against the aegisbpf-next binary.

## Troubleshooting

### Agent won't start

```
ERROR: BPF LSM not available
```

Ensure `bpf` is in your LSM list: `cat /sys/kernel/security/lsm`. If not, add `lsm=landlock,lockdown,yama,integrity,bpf` to your kernel command line.

### Arena mode unavailable

```
aegis-next: arena maps not available, using ringbuf-only fallback
```

Arena maps require kernel >= 6.9. The agent automatically falls back to ringbuf-only mode on older kernels. Graph and lineage commands are not available in fallback mode.

### Policy load fails

```
warning: policy load failed (rc=-1), continuing without policy
```

Check the policy file syntax. Each line must be: `<hook> <match_type> <value> <action> [kill]`. Verify the BPF maps are pinned at `/sys/fs/bpf/aegis_next/`.

### No events exported

Verify the events file path is writable and the agent is running:

```bash
ls -la /var/log/aegisbpf/events.jsonl
sudo aegisbpf-next status
```

### Helm deployment issues

Verify the aegis-next DaemonSet is running:

```bash
kubectl get ds -l app.kubernetes.io/component=aegis-next
kubectl logs -l app.kubernetes.io/component=aegis-next --tail=50
```

Check that nodes are labeled:

```bash
kubectl get nodes -L aegisbpf.io/arena-capable
```
