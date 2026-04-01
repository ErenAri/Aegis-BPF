# BPF Map Schema Reference

This document describes every BPF map in AegisBPF, including type, key/value
structures, sizing, access patterns, and lifecycle. It serves as the
authoritative reference for kernel-userspace data contracts.

Maps are defined in `bpf/aegis.bpf.c` and pinned under `/sys/fs/bpf/aegisbpf/`.

---

## Process Tracking

### `process_tree`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `__u32` (PID) |
| Value          | `struct process_info` (16 bytes) |
| Max entries    | 65,536 |
| Pin path       | — (not pinned) |
| Access         | BPF: read/write; Userspace: none |
| Lifecycle      | Populated on fork/exec, cleaned on exit |

Tracks active processes for lineage correlation. The `process_info` struct
contains PID, PPID, start timestamps, and exec-identity flags (verified_exec,
pending_untrusted_args, etc.).

**Key struct:**
```c
__u32 pid;
```

**Value struct:**
```c
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
    __u8  verified_exec;
    __u8  exec_identity_known;
    __u8  pending_untrusted_args;
    __u8  env_shebang_active;
    __u8  env_shebang_script_ok;
    __u8  _pad;
};
```

---

## Allowlists

### `allow_cgroup_map`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `__u64` (cgroup ID) |
| Value          | `__u8` (presence flag) |
| Max entries    | 1,024 |
| Pin path       | `/sys/fs/bpf/aegisbpf/allow_cgroup` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by `block allow add/del` CLI commands |

Cgroup-based allowlist. Processes in allowed cgroups bypass all deny rules.
The agent auto-adds its own cgroup on startup.

### `allow_exec_inode_map`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct inode_id` (16 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 65,536 |
| Pin path       | `/sys/fs/bpf/aegisbpf/allow_exec_inode` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by exec-identity policy |

Inode-based allowlist for verified execution. Binaries whose (dev, ino) pair
is in this map are marked as `verified_exec=1` in the process cache.

**Key struct:**
```c
struct inode_id {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};
```

### `exec_identity_mode_map`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_ARRAY` |
| Key            | `__u32` (index, always 0) |
| Value          | `__u8` (0=disabled, 1=enabled) |
| Max entries    | 1 |
| Pin path       | `/sys/fs/bpf/aegisbpf/exec_identity_mode` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Set on daemon startup based on policy |

Toggle for exec-identity enforcement mode. When enabled, non-verified
binaries may be restricted based on `exec_identity_flags` in `agent_config`.

### `survival_allowlist`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct inode_id` (16 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 256 |
| Pin path       | `/sys/fs/bpf/aegisbpf/survival_allowlist` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Populated on startup with critical system binaries |

Critical binary allowlist. Binaries in this map can **never** be blocked,
regardless of deny rules. Intended for `init`, `systemd`, shells, and the
agent itself.

---

## File Deny Rules

### `deny_inode_map`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct inode_id` (16 bytes) |
| Value          | `__u8` (rule flags) |
| Max entries    | 65,536 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_inode` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by policy apply / block add/del |

Primary file access control map. Lookup is O(1) per file_open/inode_permission.
Value flags: `RULE_FLAG_DENY_ALWAYS=1`, `RULE_FLAG_PROTECT_VERIFIED_EXEC=2`.

### `deny_path_map`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct path_key` (256 bytes) |
| Value          | `__u8` (rule flags) |
| Max entries    | 16,384 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_path` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by policy apply / block add/del |

Path-based deny rules. Used as a fallback when inode resolution is not possible
(e.g., tracepoint mode). The path key is a fixed 256-byte null-padded string.

**Key struct:**
```c
struct path_key {
    char path[256];  /* DENY_PATH_MAX */
};
```

---

## Network Deny Rules

### `deny_ipv4`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `__be32` (IPv4 address, network byte order) |
| Value          | `__u8` (presence flag) |
| Max entries    | 65,536 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_ipv4` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

Exact IPv4 address deny list for socket_connect, socket_accept, socket_sendmsg.

### `deny_ipv6`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct ipv6_key` (16 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 65,536 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_ipv6` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

Exact IPv6 address deny list.

**Key struct:**
```c
struct ipv6_key {
    __u8 addr[16];
};
```

### `deny_port`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct port_key` (4 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_port` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

Port-based deny rules with optional protocol and direction filtering.

**Key struct:**
```c
struct port_key {
    __u16 port;
    __u8  protocol;  /* 0=any, 6=tcp, 17=udp */
    __u8  direction; /* 0=egress, 1=bind, 2=both */
};
```

### `deny_ip_port_v4`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct ip_port_key_v4` (8 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_ip_port_v4` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

Combined IPv4 address + port deny rules for precise endpoint blocking.

**Key struct:**
```c
struct ip_port_key_v4 {
    __be32 addr;
    __u16  port;
    __u8   protocol;  /* 0=any, 6=tcp, 17=udp */
    __u8   _pad;
};
```

### `deny_ip_port_v6`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct ip_port_key_v6` (20 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_ip_port_v6` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

Combined IPv6 address + port deny rules.

**Key struct:**
```c
struct ip_port_key_v6 {
    __u8   addr[16];
    __u16  port;
    __u8   protocol;  /* 0=any, 6=tcp, 17=udp */
    __u8   _pad;
};
```

### `deny_cidr_v4`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_LPM_TRIE` |
| Key            | `struct ipv4_lpm_key` (8 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 16,384 |
| Map flags      | `BPF_F_NO_PREALLOC` |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_cidr_v4` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

CIDR-based IPv4 deny rules using longest-prefix-match trie. Efficient for
subnet-level blocking (e.g., `10.0.0.0/8`).

**Key struct:**
```c
struct ipv4_lpm_key {
    __u32  prefixlen;
    __be32 addr;
};
```

### `deny_cidr_v6`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_LPM_TRIE` |
| Key            | `struct ipv6_lpm_key` (20 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 16,384 |
| Map flags      | `BPF_F_NO_PREALLOC` |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_cidr_v6` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by network deny add/del or policy |

CIDR-based IPv6 deny rules using longest-prefix-match trie.

**Key struct:**
```c
struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8  addr[16];
};
```

---

## Statistics and Counters

### `block_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| Key            | `__u32` (index, always 0) |
| Value          | `struct block_stats_entry` (16 bytes) |
| Max entries    | 1 |
| Pin path       | `/sys/fs/bpf/aegisbpf/block_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Zeroed on load, incremented on every block/drop |

Global file-access block counters. Per-CPU to avoid contention.

**Value struct:**
```c
struct block_stats_entry {
    __u64 blocks;
    __u64 ringbuf_drops;
};
```

### `net_block_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| Key            | `__u32` (index, always 0) |
| Value          | `struct net_stats_entry` (48 bytes) |
| Max entries    | 1 |
| Pin path       | `/sys/fs/bpf/aegisbpf/net_block_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Zeroed on load, incremented per network block |

Network block counters broken down by hook type.

**Value struct:**
```c
struct net_stats_entry {
    __u64 connect_blocks;
    __u64 bind_blocks;
    __u64 listen_blocks;
    __u64 accept_blocks;
    __u64 sendmsg_blocks;
    __u64 ringbuf_drops;
};
```

### `deny_cgroup_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_HASH` |
| Key            | `__u64` (cgroup ID) |
| Value          | `__u64` (block count) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_cgroup_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Auto-created on first block per cgroup |

Per-cgroup block counts for identifying which workloads trigger the most denials.

### `deny_inode_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_HASH` |
| Key            | `struct inode_id` (16 bytes) |
| Value          | `__u64` (block count) |
| Max entries    | 65,536 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_inode_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Auto-created on first block per inode |

Per-inode block counts for identifying hot deny rules.

### `deny_path_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_HASH` |
| Key            | `struct path_key` (256 bytes) |
| Value          | `__u64` (block count) |
| Max entries    | 16,384 |
| Pin path       | `/sys/fs/bpf/aegisbpf/deny_path_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Auto-created on first block per path |

Per-path block counts for identifying hot deny rules.

### `net_ip_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_HASH` |
| Key            | `struct net_ip_key` (20 bytes) |
| Value          | `__u64` (block count) |
| Max entries    | 16,384 |
| Pin path       | `/sys/fs/bpf/aegisbpf/net_ip_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Auto-created on first block per IP |

Per-IP block counts.

**Key struct:**
```c
struct net_ip_key {
    __u8 family;    /* AF_INET=2, AF_INET6=10 */
    __u8 _pad[3];
    __u8 addr[16];
};
```

### `net_port_stats`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_HASH` |
| Key            | `__u16` (port number) |
| Value          | `__u64` (block count) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/net_port_stats` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Auto-created on first block per port |

Per-port block counts.

---

## Agent Configuration

### `agent_meta_map`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_ARRAY` |
| Key            | `__u32` (index, always 0) |
| Value          | `struct agent_meta` (4 bytes) |
| Max entries    | 1 |
| Pin path       | `/sys/fs/bpf/aegisbpf/agent_meta` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Set on daemon startup |

Agent metadata for layout version negotiation between BPF and userspace.

**Value struct:**
```c
struct agent_meta {
    __u32 layout_version;  /* Currently: 1 */
};
```

### `agent_config` (BPF global variable)

| Property       | Value |
|----------------|-------|
| Type           | Global variable (backed by `.data` map) |
| Value          | `struct agent_config` (32 bytes) |
| Pin path       | `/sys/fs/bpf/aegisbpf/agent_config` |
| Access         | BPF: read; Userspace: read/write via map |
| Lifecycle      | Updated on mode changes, deadman, break-glass |

Runtime configuration updated by userspace without reloading BPF programs.

**Value struct:**
```c
struct agent_config {
    __u8  audit_only;                    /* 1=audit-only, 0=enforce */
    __u8  deadman_enabled;
    __u8  break_glass_active;
    __u8  enforce_signal;                /* 0/2/9/15 */
    __u8  emergency_disable;
    __u8  file_policy_empty;             /* Optimization: skip file checks */
    __u8  net_policy_empty;              /* Optimization: skip net checks */
    __u8  exec_identity_flags;
    __u64 deadman_deadline_ns;
    __u32 deadman_ttl_seconds;
    __u32 event_sample_rate;
    __u32 sigkill_escalation_threshold;
    __u32 sigkill_escalation_window_seconds;
};
```

---

## Events

### `events`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_RINGBUF` |
| Max entries    | 16,777,216 (16 MB, `RINGBUF_SIZE_BYTES`) |
| Pin path       | — (not pinned, FD-based access) |
| Access         | BPF: write (reserve/submit); Userspace: read (poll) |
| Lifecycle      | Created on load, consumed continuously by daemon |

Shared ring buffer for all event types. Events are variable-size, prefixed
by a `__u32 type` discriminator followed by the event-specific payload.

**Event union:**
```c
struct event {
    __u32 type;  /* enum event_type */
    union {
        struct exec_event exec;
        struct block_event block;
        struct net_block_event net_block;
    };
};
```

---

## Enforcement

### `enforce_signal_state`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct process_key` (16 bytes) |
| Value          | `struct signal_escalation_state` (16 bytes) |
| Max entries    | 65,536 |
| Pin path       | — (not pinned) |
| Access         | BPF: read/write; Userspace: none |
| Lifecycle      | Created on first deny per process, cleaned on exit |

Tracks per-process deny counts for SIGKILL escalation. When a process
accumulates `sigkill_escalation_threshold` denies within
`sigkill_escalation_window_seconds`, the enforcement signal escalates to
SIGKILL.

**Key struct:**
```c
struct process_key {
    __u32 pid;
    __u64 start_time;
};
```

**Value struct:**
```c
struct signal_escalation_state {
    __u64 window_start_ns;
    __u32 strikes;
    __u32 _pad;
};
```

---

### `diagnostics`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_RINGBUF` |
| Key            | — |
| Value          | `struct diag_event` (88 bytes) |
| Max entries    | 1,048,576 (1 MB) |
| Pin path       | `/sys/fs/bpf/aegisbpf/diagnostics` |
| Access         | BPF: write; Userspace: poll (read-only) |
| Lifecycle      | Created at load, polled alongside events ring buffer |

Separate ring buffer for diagnostic/debug events, isolated from the main
events ring buffer to prevent diagnostic noise from causing back-pressure on
security event delivery. Uses `BPF_RB_NO_WAKEUP` to batch notifications.

**Event struct:**
```c
struct diag_event {
    __u32 type;        /* enum diag_type */
    __u32 _pad;
    __u64 timestamp;
    __u32 data1;
    __u32 data2;
    char msg[64];
};
```

---

### `dead_processes`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_LRU_HASH` |
| Key            | `struct process_key` (16 bytes) |
| Value          | `struct dead_process_info` (72 bytes) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/dead_processes` |
| Access         | BPF: write on exit; Userspace: read-only inspection |
| Lifecycle      | Entries added on process exit, LRU-evicted when full |

Retains metadata about recently exited processes for post-mortem correlation.
When a process exits, its `process_info` is transferred to this LRU map before
deletion from `process_tree`. The LRU eviction policy ensures bounded memory
usage while keeping the most recent exits available.

**Key struct:**
```c
struct process_key {
    __u32 pid;
    __u64 start_time;
};
```

**Value struct:**
```c
struct dead_process_info {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
    __u64 exit_time;
    __u8 verified_exec;
    __u8 exec_identity_known;
    __u8 exec_stage;
    __u8 _pad;
    __u64 exec_ino;
    __u32 exec_dev;
    __u32 _pad2;
    char comm[16];
};
```

---

## Quality & Observability

### `backpressure`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| Key            | `__u32` (index, always 0) |
| Value          | `struct backpressure_stats` (32 bytes) |
| Max entries    | 1 |
| Pin path       | `/sys/fs/bpf/aegisbpf/backpressure` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Zeroed on load, incremented on every event submission attempt |

Dual-path backpressure telemetry. Tracks total event sequence numbers,
priority ring buffer submissions and drops, and telemetry ring buffer drops.
Per-CPU to avoid contention.

**Value struct:**
```c
struct backpressure_stats {
    __u64 seq_total;            /* Total events generated */
    __u64 priority_submitted;   /* Events submitted to priority ring buffer */
    __u64 priority_drops;       /* Priority ring buffer submission failures */
    __u64 telemetry_drops;      /* Telemetry ring buffer submission failures */
};
```

### `hook_latency`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| Key            | `__u32` (hook ID, 0–15) |
| Value          | `struct hook_latency_entry` (32 bytes) |
| Max entries    | 16 |
| Pin path       | `/sys/fs/bpf/aegisbpf/hook_latency` |
| Access         | BPF: read/write; Userspace: read |
| Lifecycle      | Updated on every hook invocation |

Per-hook latency tracking. Each entry accumulates total nanoseconds, invocation
count, and min/max single-invocation times. Per-CPU to avoid contention.

**Value struct:**
```c
struct hook_latency_entry {
    __u64 total_ns;
    __u64 count;
    __u64 max_ns;
    __u64 min_ns;
};
```

**Hook IDs:**
| ID | Hook |
|----|------|
| 0 | `file_open` |
| 1 | `inode_permission` |
| 2 | `openat` (tracepoint) |
| 3 | `socket_connect` |
| 4 | `socket_bind` |
| 5 | `socket_listen` |
| 6 | `socket_accept` |
| 7 | `socket_sendmsg` |
| 8 | `bprm_check_security` |
| 9 | `execve` (tracepoint) |

### `event_approver_inode`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct inode_id` (16 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/event_approver_inode` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by userspace to control event pre-filtering |

Inode-based event pre-filtering (approver/discarder pattern). When an inode is
in this map, events for that inode are suppressed in-kernel, reducing ring buffer
pressure for known-noisy files.

### `event_approver_path`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_HASH` |
| Key            | `struct path_key` (256 bytes) |
| Value          | `__u8` (presence flag) |
| Max entries    | 4,096 |
| Pin path       | `/sys/fs/bpf/aegisbpf/event_approver_path` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Managed by userspace to control event pre-filtering |

Path-based event pre-filtering. Same pattern as `event_approver_inode` but
keyed on path for cases where inode resolution is unavailable.

### `policy_generation`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_ARRAY` |
| Key            | `__u32` (always 0) |
| Value          | `__u64` (monotonic generation counter) |
| Max entries    | 1 |
| Pin path       | `/sys/fs/bpf/aegisbpf/policy_generation` |
| Access         | BPF: read; Userspace: read/write |
| Lifecycle      | Updated after policy shadow→live sync |

Atomic policy commit marker. Userspace bumps `agent_cfg.policy_generation`
before syncing shadow maps to live, then writes the matching value here after
all maps are fully synchronized. BPF hooks compare
`agent_cfg.policy_generation` against the committed value in this map; a
mismatch forces audit mode to avoid enforcing a half-written ruleset.

### `priority_events`

| Property       | Value |
|----------------|-------|
| Type           | `BPF_MAP_TYPE_RINGBUF` |
| Max entries    | 4,194,304 (4 MB) |
| Pin path       | `/sys/fs/bpf/aegisbpf/priority_events` |
| Access         | BPF: write; Userspace: poll (read-only) |
| Lifecycle      | Created at load, polled alongside main events ring buffer |

Dedicated ring buffer for security-critical forensic events. Isolated from the
main events ring buffer to ensure forensic block events are never dropped due
to back-pressure from high-volume exec/audit events. Attached to the same
`ring_buffer` manager via `ring_buffer__add()`.

**Event struct:**
```c
struct forensic_event {
    __u32 type;         /* EVENT_FORENSIC_BLOCK */
    __u32 pid;
    __u32 ppid;
    __u32 _pad;
    __u64 start_time;
    __u64 parent_start_time;
    __u64 cgid;
    char comm[16];
    __u64 ino;
    __u32 dev;
    __u32 uid;
    __u32 gid;
    __u32 _pad2;
    __u64 exec_ino;
    __u32 exec_dev;
    __u8 exec_stage;
    __u8 verified_exec;
    __u8 exec_identity_known;
    __u8 _pad3;
    char action[8];
};
```

---

## Memory Budget Summary

| Map | Entry Size (key+value) | Max Entries | Worst-Case Memory |
|-----|----------------------|-------------|-------------------|
| `process_tree` | 4 + 48 = 52 B | 65,536 | ~3.4 MB |
| `allow_cgroup_map` | 8 + 1 = 9 B | 1,024 | ~9 KB |
| `allow_exec_inode_map` | 16 + 1 = 17 B | 65,536 | ~1.1 MB |
| `survival_allowlist` | 16 + 1 = 17 B | 256 | ~4 KB |
| `deny_inode_map` | 16 + 1 = 17 B | 65,536 | ~1.1 MB |
| `deny_path_map` | 256 + 1 = 257 B | 16,384 | ~4.2 MB |
| `deny_ipv4` | 4 + 1 = 5 B | 65,536 | ~327 KB |
| `deny_ipv6` | 16 + 1 = 17 B | 65,536 | ~1.1 MB |
| `deny_port` | 4 + 1 = 5 B | 4,096 | ~20 KB |
| `deny_ip_port_v4` | 8 + 1 = 9 B | 4,096 | ~37 KB |
| `deny_ip_port_v6` | 20 + 1 = 21 B | 4,096 | ~86 KB |
| `deny_cidr_v4` | 8 + 1 = 9 B | 16,384 | ~147 KB |
| `deny_cidr_v6` | 20 + 1 = 21 B | 16,384 | ~344 KB |
| `events` (ring buffer) | — | — | 16 MB |
| `diagnostics` (ring buffer) | — | — | 1 MB |
| `priority_events` (ring buffer) | — | — | 4 MB |
| `dead_processes` | 16 + 72 = 88 B | 4,096 | ~360 KB |
| `hook_latency` | 4 + 32 = 36 B | 16 | ~576 B (per-CPU) |
| `event_approver_inode` | 16 + 1 = 17 B | 4,096 | ~70 KB |
| `event_approver_path` | 256 + 1 = 257 B | 4,096 | ~1 MB |
| **Stats maps** | (per-CPU) | varies | ~2-8 MB |
| **Total (typical)** | | | **~32-37 MB** |

Note: Per-CPU maps multiply the value size by the number of CPUs. On a 16-CPU
system, a per-CPU array with 48-byte values uses 48 * 16 = 768 bytes per entry.
