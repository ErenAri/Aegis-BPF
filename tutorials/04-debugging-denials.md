# Tutorial 4: Debugging Policy Denials

**Difficulty:** Intermediate
**Time:** 10 minutes
**Prerequisites:** Tutorials 1–3 completed

## What You'll Learn

- How to read and interpret block events
- How to identify which rule caused a block
- How to trace process lineage for attribution
- How to investigate false positives
- How to use metrics for troubleshooting

## Understanding Block Events

When AegisBPF blocks an access, it emits a JSON event:

```json
{
  "type": "block",
  "pid": 42531,
  "ppid": 42530,
  "comm": "cat",
  "path": "/etc/shadow",
  "ino": 1835021,
  "dev": 2049,
  "action": "deny",
  "cgid": 1,
  "cgroup_path": "/system.slice/sshd.service",
  "exec_id": "e-42531-1711500000000",
  "parent_exec_id": "e-42530-1711499990000",
  "exec_identity_known": true,
  "verified_exec": false
}
```

### Key Fields

| Field | Meaning |
|-------|---------|
| `type` | Event type (`block`, `net_connect_block`, `kernel_ptrace_block`, etc.) |
| `pid` / `ppid` | Process ID and parent process ID |
| `comm` | Process command name (first 16 chars) |
| `path` | File path being accessed |
| `ino` / `dev` | Inode and device numbers (for inode-based rules) |
| `cgroup_path` | Cgroup path (identifies container/service) |
| `exec_id` | Unique execution ID for process lineage tracking |
| `exec_identity_known` | Whether the binary is in the exec identity allowlist |
| `verified_exec` | Whether the binary passed integrity verification |

## Step 1: Identify the Blocked Process

```bash
# Filter block events from daemon output
sudo aegisbpf daemon 2>&1 | jq 'select(.type == "block")'
```

Look at `comm` (command name) and `cgroup_path` to identify what was blocked.

## Step 2: Check If It's a False Positive

Common false positive scenarios:

### Legitimate service blocked
```json
{"comm": "nginx", "path": "/etc/shadow", "cgroup_path": "/system.slice/nginx.service"}
```

**Question:** Does nginx legitimately need to read `/etc/shadow`?
**Answer:** Yes, if using PAM authentication. **Action:** Add nginx's cgroup to
the allowlist.

```ini
[allow_cgroup]
/sys/fs/cgroup/system.slice/nginx.service
```

### System tool blocked during maintenance
```json
{"comm": "passwd", "path": "/etc/shadow"}
```

**Question:** Is this expected during a password change?
**Answer:** Yes. **Action:** Either use break-glass mode for maintenance or
add an allow_cgroup for the admin session.

## Step 3: Use Audit Mode for Investigation

Switch to audit mode temporarily to stop blocking while you investigate:

```bash
# Emergency disable (keeps logging, stops blocking)
sudo aegisbpf emergency-disable --reason "TICKET=INC-1234 investigating false positives"

# Investigate...

# Re-enable
sudo aegisbpf emergency-enable --reason "TICKET=INC-1234 investigation complete"
```

## Step 4: Use Metrics to Find Patterns

```bash
# See which rules are triggering most
sudo aegisbpf stats --detailed
```

Look for:
- **Unexpectedly high block counts**: May indicate a misconfigured rule
- **Blocks from system services**: May need cgroup allowlisting
- **Network blocks from known services**: May need port exceptions

### Prometheus Queries

```promql
# Top blocked processes (if using --detailed metrics)
topk(10, sum by (cgroup_path) (aegisbpf_blocks_by_cgroup_total))

# Block rate spike (possible false positive storm)
rate(aegisbpf_blocks_total[5m]) > 100
```

## Step 5: Trace Process Lineage

Use `exec_id` and `parent_exec_id` to trace the process tree:

```bash
# Find all events for a specific exec_id
sudo aegisbpf daemon 2>&1 | jq 'select(.exec_id == "e-42531-1711500000000")'
```

This shows you the full chain of execution that led to the blocked access.

## Step 6: Network Block Debugging

Network block events include additional fields:

```json
{
  "type": "net_connect_block",
  "pid": 8821,
  "comm": "curl",
  "remote_ip": "93.184.216.34",
  "remote_port": 443,
  "protocol": "tcp",
  "direction": "egress",
  "rule_type": "deny_ip"
}
```

Use `rule_type` to identify which rule section caused the block:
- `deny_ip` — Exact IP match
- `deny_cidr` — CIDR range match
- `deny_port` — Port/protocol match
- `deny_ip_port` — Combined IP+port match

## Debugging Checklist

- [ ] **Identify the process**: Check `comm` and `cgroup_path`
- [ ] **Check the rule**: Which `deny_*` section matched?
- [ ] **Verify legitimacy**: Does this process need this access?
- [ ] **Check cgroup allowlist**: Should this service be exempted?
- [ ] **Review policy**: Is the deny rule too broad?
- [ ] **Test in audit mode**: Does the fix resolve the issue?
- [ ] **Apply and monitor**: Watch metrics after the policy change

## Common Issues and Solutions

| Symptom | Likely Cause | Solution |
|---------|-------------|----------|
| System service blocked | Missing cgroup allowlist entry | Add to `[allow_cgroup]` |
| Package manager blocked | deny_path too broad | Use more specific paths |
| Health check failing | Network deny blocking health endpoint | Allow the health check cgroup |
| SSH broken | deny_path covering SSH keys | Allow SSH daemon cgroup |
| Systemd units failing | Module load blocked | Allow systemd cgroup or remove `[deny_module_load]` |

## Related Resources

- `aegisbpf policy lint` — Pre-flight policy validation
- `aegisbpf stats --detailed` — Detailed block statistics
- `aegisbpf health --json` — System health check
- `docs/GUARANTEES.md` — Enforcement guarantee details
