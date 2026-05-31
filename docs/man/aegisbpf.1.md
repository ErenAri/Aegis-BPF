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
[**--allow-unsigned-bpf**]
[**--allow-unknown-binary-identity**]
[**--strict-degrade**]
[**--enforce-gate-mode**=*MODE*]
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

**--allow-unsigned-bpf**
:   Break-glass override for BPF object integrity checks. Allows startup when
    the BPF hash file is missing or mismatched. Intended only for emergency
    recovery.

**--allow-unknown-binary-identity**
:   Break-glass override for `version=3` exec allowlist policies (`[allow_binary_hash]`).
    When enabled, processes with unreadable/unknown executable hashes are logged
    but not signaled. This flag does not bypass `VERIFIED_EXEC` protected-resource
    policies (`version=4` `[protect_connect]` / `[protect_path]` / `[protect_runtime_deps]`)
    or `version=5` IMA appraisal posture gating (`[require_ima_appraisal]`).

**--strict-degrade**
:   Enforce fail-closed runtime posture in enforce mode. If startup or runtime
    transitions to `AUDIT_FALLBACK` or `DEGRADED`, the daemon exits non-zero.
    Use this for production nodes that must not silently downgrade enforcement.

**--enforce-gate-mode**=*MODE*
:   Enforcement gating behavior when `--enforce` is requested but required
    kernel capabilities/hooks are missing. Valid values:
    - `fail-closed` (default): refuse to start in enforce mode
    - `audit-fallback`: continue in audit-only mode (explicitly reported)

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

### network

Manage network deny rules (IPv4/IPv6 addresses, CIDR ranges, ports,
IP:port tuples). Rules are enforced at LSM socket hooks.

**aegisbpf network deny add** [**--ip** *IP*] [**--cidr** *CIDR*] [**--port** *PORT* [**--protocol** tcp|udp|any] [**--direction** egress|bind|both]] [**--ip-port** *IP:PORT[:PROTO]*]
:   Add a network deny rule. Address families are auto-detected; ports
    default to all protocols and egress direction.

**aegisbpf network deny del** [*same selectors as add*]
:   Remove a previously added rule.

**aegisbpf network deny list**
:   List all currently loaded network deny rules.

**aegisbpf network deny clear**
:   Remove every network deny rule from the BPF maps.

**aegisbpf network stats**
:   Show per-hook block counters (connect/bind/listen/accept/sendmsg/recvmsg)
    and ring-buffer drops for the network pipeline.

### cgroup

Cgroup-scoped deny rules (v6+ policy format). Rules target a specific
cgroup by path or numeric cgid and apply only to processes inside that
cgroup. See `docs/POLICY.md` for the `[cgroup_deny_*]` sections.

**aegisbpf cgroup deny add** **--cgroup** *PATH*|*cgid:N* {**--inode** *DEV:INO* | **--ip** *IP* | **--port** *PORT* [**--protocol** tcp|udp|any] [**--direction** egress|bind|both]}
:   Add a cgroup-scoped deny rule. Exactly one of `--inode`, `--ip`, or
    `--port` must be specified.

**aegisbpf cgroup deny del** [*same selectors as add*]
:   Remove a previously added cgroup-scoped rule.

**aegisbpf cgroup deny list**
:   List all loaded cgroup-scoped deny rules.

**aegisbpf cgroup deny clear**
:   Remove every cgroup-scoped deny rule.

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

**aegisbpf policy sign** *POLICY.CONF* **--key** *PRIVATE.KEY* **--output** *POLICY.SIGNED*
:   Produce an Ed25519-signed policy bundle.

### keys

Manage the Ed25519 public key store used to verify signed policy
bundles. Keys live under `/etc/aegisbpf/keys/` (override with
`AEGIS_KEYS_DIR`).

**aegisbpf keys list**
:   List all trusted signing keys, one fingerprint per line.

**aegisbpf keys add** *PUBKEY.PUB*
:   Install a public key into the trust store.

### survival

Inspect the survival allowlist, a BPF map of inodes that must always
remain allowed (agent binary, libc, systemd, and friends). Populated at
startup so the daemon never accidentally self-denies.

**aegisbpf survival list**
:   List every inode currently pinned in the survival allowlist.

**aegisbpf survival verify**
:   Re-resolve and confirm the agent's critical binaries are present in
    the allowlist. Returns non-zero if any entry is missing.

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
- `aegisbpf_emergency_toggle_transitions_total`
- `aegisbpf_emergency_toggle_storm_active`
- `aegisbpf_capability_report_present`
- `aegisbpf_capability_contract_valid`
- `aegisbpf_enforce_capable`
- `aegisbpf_runtime_state{state}`
- `aegisbpf_perf_slo_summary_present`
- `aegisbpf_perf_slo_gate_pass`
- `aegisbpf_perf_slo_failed_rows`
- `aegisbpf_deny_inode_entries`
- `aegisbpf_deny_path_entries`
- `aegisbpf_allow_cgroup_entries`
- `aegisbpf_allow_exec_inode_entries`
- `aegisbpf_map_capacity{map}`
- `aegisbpf_map_utilization{map}`
- `aegisbpf_net_blocks_total{type}`
- `aegisbpf_net_ringbuf_drops_total`
- `aegisbpf_net_rules_total{type}`
- `aegisbpf_backpressure_events_total`
- `aegisbpf_backpressure_priority_submitted_total`
- `aegisbpf_backpressure_priority_drops_total`
- `aegisbpf_backpressure_telemetry_drops_total`
- `aegisbpf_hook_latency_total_ns{hook}`
- `aegisbpf_hook_invocations_total{hook}`
- `aegisbpf_hook_latency_max_ns{hook}`
- `aegisbpf_hook_attached{hook}`
- `aegisbpf_file_hooks_attached`
- `aegisbpf_file_hooks_expected`

High-cardinality metrics (only with **--detailed**):
- `aegisbpf_blocks_by_cgroup_total{cgroup_id,cgroup_path}`
- `aegisbpf_blocks_by_inode_total{inode}`
- `aegisbpf_blocks_by_path_total{path}`
- `aegisbpf_net_blocks_by_ip_total{ip}`
- `aegisbpf_net_blocks_by_port_total{port}`

### capabilities

Print the daemon capability report (as written at startup).

**aegisbpf capabilities** [**--json**]

Outputs the contents of the capability report (default:
`/var/lib/aegisbpf/capabilities.json`).
Report contains both integer schema (`schema_version`) and semantic schema
(`schema_semver`) fields for compatibility-aware automation.

### emergency-disable

Emergency enforcement bypass ("kill switch"). This forces audit behavior in
kernel hooks while preserving audit/telemetry.

**aegisbpf emergency-disable** **--reason** *TEXT* [**--reason-pattern** *REGEX*] [**--json**] [**--log**=*SINK*]

**--reason** *TEXT*
:   Required operator-supplied reason (recommended format: `TICKET=<id> ...`).

**--reason-pattern** *REGEX*
:   Optional regex that must match `--reason` (hardening for strict environments).

### emergency-enable

Re-enable enforcement after `emergency-disable`.

**aegisbpf emergency-enable** **--reason** *TEXT* [**--reason-pattern** *REGEX*] [**--json**] [**--log**=*SINK*]

### emergency-status

Show emergency control state.

**aegisbpf emergency-status** [**--json**] [**--log**=*SINK*]

### health

Check agent prerequisites and status.

**aegisbpf health** [**--json**] [**--require-enforce**]

Checks:
- Kernel capability summary (full vs audit-only)
- Cgroup v2, BPF syscall, bpffs, and BTF prerequisites
- BPF object presence and hash verification status
- Required pinned map accessibility
- Optional network pinned map accessibility (when network maps are present)
- BPF object load and pinned map layout compatibility

**--json**
:   Emit a machine-readable status object with feature flags and per-check booleans.

**--require-enforce**
:   Fail when the node is only audit-capable. Use this for enforce-mode readiness
    probes to keep scheduling fail-closed.

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

### probe

Run the kernel feature probe and write a capability report to
`/var/lib/aegisbpf/capabilities.json` (override with
`AEGIS_CAPABILITIES_REPORT_PATH`). The report is used by `doctor`,
the Helm posture sidecar, and the operator to decide whether a node is
enforce-capable.

**aegisbpf probe**
:   Refresh the capability report and print its contents.

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
version=6

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

# Enforce exec identity allowlist (version 3+)
[allow_binary_hash]
sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Protected resources (require VERIFIED_EXEC, version 4+)
[protect_connect]

[protect_runtime_deps]

[require_ima_appraisal]

[deny_comm]
xmrig
minerd

[protect_path]
/etc/shadow

[cgroup_deny_inode]
cgid:123456 259:12345

[cgroup_deny_ip]
cgid:123456 10.0.0.1

[cgroup_deny_port]
cgid:123456 443:tcp:egress
```

## ENVIRONMENT

**AEGIS_BPF_OBJ**
:   Override the path to the BPF object file.

**AEGIS_KEYS_DIR**
:   Override trusted key directory (default: `/etc/aegisbpf/keys`).

**AEGIS_VERSION_COUNTER_PATH**
:   Override signed-policy version counter file (default: `/var/lib/aegisbpf/version_counter`).

**AEGIS_REQUIRE_BPF_HASH**
:   When set to `1/true/yes/on`, require a BPF object hash file during load.

**AEGIS_ALLOW_UNSIGNED_BPF**
:   Break-glass override that allows missing/mismatched BPF hash verification.

**AEGIS_BPF_OBJ_HASH_PATH**
:   Override primary BPF hash file path (default: `/etc/aegisbpf/aegis.bpf.sha256`).

**AEGIS_BPF_OBJ_HASH_INSTALL_PATH**
:   Override fallback installed hash file path (default: `/usr/lib/aegisbpf/aegis.bpf.sha256`).

**AEGIS_POLICY_APPLIED_PATH**
:   Override applied policy snapshot path.

**AEGIS_POLICY_APPLIED_PREV_PATH**
:   Override rollback policy snapshot path.

**AEGIS_POLICY_APPLIED_HASH_PATH**
:   Override applied policy hash snapshot path.

**AEGIS_CAPABILITIES_REPORT_PATH**
:   Override daemon capability report path (default: `/var/lib/aegisbpf/capabilities.json`).
    Report includes hook/capability probes and runtime posture fields
    (`runtime_state`, `state_transitions`).

**AEGIS_ENFORCE_GATE_MODE**
:   Default `--enforce-gate-mode` when not passed on the command line. Valid
    values: `fail-closed` (default), `audit-fallback`.

**AEGIS_NODE_NAME**
:   Optional node name label included in capability reports and emergency
    control audit trails (best-effort). In Kubernetes, set via the downward API
    (`spec.nodeName`).

**AEGIS_CONTROL_STATE_PATH**
:   Override emergency control state snapshot path (default:
    `/var/lib/aegisbpf/control_state.json`).

**AEGIS_CONTROL_LOG_PATH**
:   Override emergency control append-only log path (default:
    `/var/lib/aegisbpf/control_log.jsonl`).

**AEGIS_CONTROL_LOCK_PATH**
:   Override emergency control lock path (default: `/var/lib/aegisbpf/control.lock`).

**AEGIS_CONTROL_LOG_MAX_BYTES**
:   Override emergency control log rotation size cap (bytes).

**AEGIS_CONTROL_LOG_MAX_FILES**
:   Override emergency control log rotated file retention count.

**AEGIS_CONTROL_REASON_MAX_BYTES**
:   Override maximum stored reason size (bytes). Reasons are sanitized and
    truncated.

**AEGIS_CONTROL_STORM_THRESHOLD**
:   Number of transitions in the storm window required to declare a toggle storm.

**AEGIS_CONTROL_STORM_WINDOW_SECONDS**
:   Toggle storm detection window (seconds).

**AEGIS_CONTROL_LOCK_TIMEOUT_SECONDS**
:   Emergency control lock acquisition timeout (seconds).

**AEGIS_POLICY_SHA256**
:   Expected policy SHA256 for `policy apply` when hash flags are not passed.

**AEGIS_POLICY_SHA256_FILE**
:   Path to SHA256 checksum file for `policy apply` when hash flags are not passed.

**AEGIS_OTEL_SPANS**
:   Enable OpenTelemetry-style span logs for policy lifecycle operations
    (`1`, `true`, `yes`, `on`).

## FILES

*/sys/fs/bpf/aegisbpf/**
:   BPF map and link pins.

*/var/lib/aegisbpf/deny.db*
:   Persistent deny list database.

*/var/lib/aegisbpf/policy.applied*
:   Currently applied policy (for rollback).

*/var/lib/aegisbpf/capabilities.json*
:   Startup capability and hook-attach report emitted by daemon.

*/var/lib/aegisbpf/control_state.json*
:   Emergency control state snapshot.

*/var/lib/aegisbpf/control_log.jsonl*
:   Emergency control append-only audit trail (JSONL) with bounded rotation.

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

Emergency disable enforcement (kill switch):
```
sudo aegisbpf emergency-disable --reason "TICKET=INC-1234 immediate mitigation"
```

Show capability report:
```
aegisbpf capabilities --json
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

Report bugs at: https://github.com/ErenAri/Aegis-BPF/issues
