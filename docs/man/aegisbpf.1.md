# AEGISBPF(1) - eBPF Runtime Security Agent

## NAME

aegisbpf - eBPF-based runtime security agent for blocking unauthorized process execution

## SYNOPSIS

**aegisbpf** [*GLOBAL-OPTIONS*] *COMMAND* [*COMMAND-OPTIONS*]

## DESCRIPTION

AegisBPF is a runtime security agent that uses eBPF and Linux Security Modules (LSM) to monitor and block process executions based on configurable policies.

The agent can run in two modes:

**Audit mode** (default): Observes and logs all executions without blocking. Uses tracepoints when BPF LSM is unavailable.

**Enforce mode**: Actively blocks executions that match deny rules. Requires BPF LSM to be enabled in the kernel.

## GLOBAL OPTIONS

**--log-level**=*LEVEL*
:   Set logging verbosity. Valid values: debug, info, warn, error. Default: info.

**--log-format**=*FORMAT*
:   Set log output format. Valid values: text, json. Default: text.

## COMMANDS

### run

Start the security agent.

**aegisbpf run** [**--audit**|**--enforce**] [**--enforce-signal**=*SIG*]
[**--allow-sigkill**]
[**--kill-escalation-threshold**=*N*] [**--kill-escalation-window-seconds**=*SECONDS*]
[**--seccomp**] [**--log**=*SINK*]

**--audit**
:   Run in audit-only mode (observe but don't block). This is the default.

**--enforce**
:   Run in enforce mode (block matching executions). Requires BPF LSM.

**--enforce-signal**=*SIG*
:   Signal behavior for enforce mode. Valid values: `term` (default), `kill`, `int`, `none`.
    `none` keeps blocking (`EPERM`) without sending a signal. `kill` is
    disabled by default and requires both:
    - build-time flag: `-DENABLE_SIGKILL_ENFORCEMENT=ON`
    - runtime gate: `--allow-sigkill`
    When enabled, `kill` uses an escalation policy: the agent sends `SIGTERM`
    first and only escalates to `SIGKILL` after repeated deny events in a
    short window.

**--allow-sigkill**
:   Runtime acknowledgement for using `--enforce-signal=kill`. Has no effect
    for other enforce signals.

**--kill-escalation-threshold**=*N*
:   Number of denied operations within the escalation window before `SIGKILL`
    is used when `--enforce-signal=kill`. Minimum: 1. Default: 5.

**--kill-escalation-window-seconds**=*SECONDS*
:   Escalation window size in seconds for `--enforce-signal=kill`. Minimum: 1.
    Default: 30.

**--seccomp**
:   Apply seccomp-bpf filter after initialization for additional hardening.

**--log**=*SINK*
:   Event log destination. Valid values: stdout, journald, both. Default: stdout.

### block

Manage the deny list for blocking executions.

**aegisbpf block add** *PATH*
:   Add a file path to the deny list.

**aegisbpf block del** *PATH*
:   Remove a file path from the deny list.

**aegisbpf block list**
:   List all entries in the deny list.

**aegisbpf block clear**
:   Remove all entries from the deny list and reset statistics.

### allow

Manage the cgroup allowlist.

**aegisbpf allow add** *CGROUP-PATH*
:   Add a cgroup to the allowlist. Processes in allowed cgroups bypass deny rules.

**aegisbpf allow del** *CGROUP-PATH*
:   Remove a cgroup from the allowlist.

**aegisbpf allow list**
:   List all cgroup IDs in the allowlist.

### policy

Manage policy files.

**aegisbpf policy lint** *FILE* [**--fix**] [**--out** *PATH*]
:   Validate a policy file without applying it.

**--fix**
:   Emit a normalized policy file (sorted, deduped sections). Defaults to
    `FILE.fixed` when **--out** is not provided.

**--out** *PATH*
:   Write the normalized policy output to the specified path.

**aegisbpf policy apply** *FILE* [**--reset**] [**--sha256** *HEX*] [**--sha256-file** *PATH*] [**--no-rollback**]
:   Apply a policy file. Options:
    - **--reset**: Clear existing rules before applying.
    - **--sha256**: Verify file matches the specified SHA256 hash.
    - **--sha256-file**: Read expected hash from a file.
    - **--no-rollback**: Don't rollback on failure.

**aegisbpf policy export** *FILE*
:   Export current rules to a policy file.

**aegisbpf policy show**
:   Display the currently applied policy.

**aegisbpf policy rollback**
:   Restore the previously applied policy.

### stats

Display agent statistics.

**aegisbpf stats** [**--detailed**]

Shows:
- Total block count
- Ring buffer drop count

**--detailed**
:   Include high-cardinality debugging breakdowns (paths, cgroups, IPs, ports).

### metrics

Output Prometheus-format metrics.

**aegisbpf metrics** [**--out** *PATH*] [**--detailed**]

**--out** *PATH*
:   Write metrics to file instead of stdout. Use "-" for stdout (default).

**--detailed**
:   Include high-cardinality metrics intended for short-lived debugging sessions.
    Default output is cardinality-safe for Prometheus scraping.

Exported metrics:
- `aegisbpf_blocks_total`
- `aegisbpf_ringbuf_drops_total`
- `aegisbpf_deny_inode_entries`
- `aegisbpf_deny_path_entries`
- `aegisbpf_allow_cgroup_entries`
- `aegisbpf_net_blocks_total{type}`
- `aegisbpf_net_ringbuf_drops_total`
- `aegisbpf_net_rules_total{type}`

High-cardinality metrics (only with **--detailed**):
- `aegisbpf_blocks_by_cgroup_total{cgroup_id,cgroup_path}`
- `aegisbpf_blocks_by_inode_total{inode}`
- `aegisbpf_blocks_by_path_total{path}`
- `aegisbpf_net_blocks_by_ip_total{ip}`
- `aegisbpf_net_blocks_by_port_total{port}`

### health

Check agent prerequisites and status.

**aegisbpf health** [**--json**]

Checks:
- Kernel capability summary (full vs audit-only)
- Cgroup v2, BPF syscall, bpffs, and BTF prerequisites
- Required pinned map accessibility
- Optional network pinned map accessibility (when network maps are present)
- BPF object load and pinned map layout compatibility

**--json**
:   Emit a machine-readable status object with feature flags and per-check booleans.

### doctor

Detailed diagnostics with remediation guidance.

**aegisbpf doctor** [**--json**]

Shows:
- Health check summary
- Enforcement readiness (BPF LSM, BTF, bpffs)
- Pinned map accessibility
- Remediation hints for common failure modes

**--json**
:   Emit a machine-readable diagnostics payload with advice entries.

### explain

Explain a block decision from an event JSON payload.

**aegisbpf explain** *EVENT.JSON* [**--policy** *FILE*] [**--json**]

**EVENT.JSON**
:   A single event JSON line (use `-` to read from stdin). Supports `type=block` events.

**--policy** *FILE*
:   Optional policy file to evaluate rule matches. Defaults to the applied policy
    snapshot when present.

**--json**
:   Emit a machine-readable explanation payload.

Notes:
- Explanation is best-effort and uses the policy snapshot, not the kernel decision path.
- Enforcement is inode-first: inode deny rules take precedence over path matches.

## POLICY FILE FORMAT

Policy files use INI-style syntax:

```
version=1

# Block these paths
[deny_path]
/usr/bin/malware
/opt/dangerous/binary

# Block by inode (dev:inode)
[deny_inode]
259:12345

# Allow processes in these cgroups
[allow_cgroup]
/sys/fs/cgroup/system.slice
cgid:123456
```

## ENVIRONMENT

**AEGIS_BPF_OBJ**
:   Override the path to the BPF object file.

**AEGIS_KEYS_DIR**
:   Override trusted key directory (default: `/etc/aegisbpf/keys`).

**AEGIS_VERSION_COUNTER_PATH**
:   Override signed-policy version counter file (default: `/var/lib/aegisbpf/version_counter`).

**AEGIS_POLICY_APPLIED_PATH**
:   Override applied policy snapshot path.

**AEGIS_POLICY_APPLIED_PREV_PATH**
:   Override rollback policy snapshot path.

**AEGIS_POLICY_APPLIED_HASH_PATH**
:   Override applied policy hash snapshot path.

**AEGIS_POLICY_SHA256**
:   Expected policy SHA256 for `policy apply` when hash flags are not passed.

**AEGIS_POLICY_SHA256_FILE**
:   Path to SHA256 checksum file for `policy apply` when hash flags are not passed.

**AEGIS_OTEL_SPANS**
:   Enable OpenTelemetry-style span logs for policy lifecycle operations
    (`1`, `true`, `yes`, `on`).

## FILES

*/sys/fs/bpf/aegis/**
:   BPF map and link pins.

*/var/lib/aegisbpf/deny.db*
:   Persistent deny list database.

*/var/lib/aegisbpf/policy.applied*
:   Currently applied policy (for rollback).

*/etc/aegisbpf/policy.conf*
:   Default policy file location.

## EXIT STATUS

**0**
:   Success

**1**
:   Error occurred

## EXAMPLES

Start agent in audit mode:
```
sudo aegisbpf run --audit --log=journald
```

Start agent in enforce mode with JSON logging:
```
sudo aegisbpf run --enforce --log-format=json
```

Block a binary:
```
sudo aegisbpf block add /usr/bin/danger
```

Apply a policy with SHA256 verification:
```
sudo aegisbpf policy apply /etc/aegisbpf/policy.conf \
    --sha256 abc123...
```

Export Prometheus metrics:
```
sudo aegisbpf metrics --out /var/lib/prometheus/aegisbpf.prom
```

## REQUIREMENTS

- Linux kernel 5.8+ with BTF support
- BPF LSM enabled for enforce mode (lsm=bpf in kernel cmdline)
- Cgroup v2
- CAP_SYS_ADMIN, CAP_BPF, CAP_PERFMON capabilities

## SEE ALSO

bpftool(8), bpf(2)

## AUTHORS

AegisBPF Team

## BUGS

Report bugs at: https://github.com/aegisbpf/aegisbpf/issues
