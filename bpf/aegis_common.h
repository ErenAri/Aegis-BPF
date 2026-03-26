#pragma once
/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * This BPF program provides file access control using LSM hooks (when available)
 * or tracepoints (as fallback). It tracks process lineage, blocks access to
 * denied inodes/paths, and reports events via ring buffer.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno-base.h>

#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#define DENY_PATH_MAX 256
#ifndef MAY_EXEC
#define MAY_EXEC 0x01
#define MAY_WRITE 0x02
#define MAY_READ 0x04
#endif
#define SIGKILL_ESCALATION_THRESHOLD_DEFAULT 5
#define SIGKILL_ESCALATION_WINDOW_NS_DEFAULT (30ULL * 1000000000ULL)
#define RULE_FLAG_DENY_ALWAYS 1
#define RULE_FLAG_PROTECT_VERIFIED_EXEC 2
#define EXEC_IDENTITY_FLAG_ALLOWLIST_ENFORCE (1U << 0)
#define EXEC_IDENTITY_FLAG_PROTECT_CONNECT (1U << 1)
#define EXEC_IDENTITY_FLAG_PROTECT_FILES (1U << 2)
#define EXEC_IDENTITY_FLAG_TRUST_RUNTIME_DEPS (1U << 3)

#ifndef FS_VERITY_FL
#define FS_VERITY_FL 0x00100000
#endif
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif
#ifndef S_IWGRP
#define S_IWGRP 00020
#endif
#ifndef S_IWOTH
#define S_IWOTH 00002
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

/* BPF Map Size Constants */
#define MAX_PROCESS_TREE_ENTRIES 65536
#define MAX_ALLOW_CGROUP_ENTRIES 1024
#define MAX_SURVIVAL_ALLOWLIST_ENTRIES 256
#define MAX_DENY_INODE_ENTRIES 65536
#define MAX_DENY_PATH_ENTRIES 16384
#define MAX_DENY_CGROUP_STATS_ENTRIES 4096
#define MAX_DENY_PATH_STATS_ENTRIES 16384
#define MAX_DENY_INODE_STATS_ENTRIES 65536
#define RINGBUF_SIZE_BYTES (1 << 24)  /* 16MB default */
#define MAX_DEAD_PROCESS_ENTRIES 4096
#define DIAGNOSTICS_RINGBUF_SIZE (1 << 20) /* 1MB */
#define MAX_ARGV_SIZE 256
#define MAX_ARGV_ENTRIES 8
#define MAX_HOOK_LATENCY_ENTRIES 16
#define MAX_EVENT_APPROVER_ENTRIES 4096
#define PRIORITY_RINGBUF_SIZE (1 << 22) /* 4MB for high-priority security events */
#define MAX_FORENSIC_FDS 8
#define MAX_FORENSIC_PATH 64

/* Network Map Size Constants */
#define MAX_DENY_IPV4_ENTRIES 65536
#define MAX_DENY_IPV6_ENTRIES 65536
#define MAX_DENY_PORT_ENTRIES 4096
#define MAX_DENY_IP_PORT_V4_ENTRIES 4096
#define MAX_DENY_IP_PORT_V6_ENTRIES 4096
#define MAX_DENY_CIDR_V4_ENTRIES 16384
#define MAX_DENY_CIDR_V6_ENTRIES 16384
#define MAX_NET_IP_STATS_ENTRIES 16384
#define MAX_NET_PORT_STATS_ENTRIES 4096
#define MAX_ENFORCE_SIGNAL_STATE_ENTRIES 65536

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

enum event_type {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2,
    EVENT_EXEC_ARGV = 3,
    EVENT_FORENSIC_BLOCK = 4,
    EVENT_NET_CONNECT_BLOCK = 10,
    EVENT_NET_BIND_BLOCK = 11,
    EVENT_NET_LISTEN_BLOCK = 12,
    EVENT_NET_ACCEPT_BLOCK = 13,
    EVENT_NET_SENDMSG_BLOCK = 14,
};

/* Exec hook stages for multi-hook correlation */
enum exec_stage {
    EXEC_STAGE_NONE = 0,
    EXEC_STAGE_TRACEPOINT = 1,  /* sys_enter_execve fired */
    EXEC_STAGE_BPRM_CHECKED = 2, /* bprm_check_security completed */
    EXEC_STAGE_FULLY_VERIFIED = 3, /* file_mmap validated runtime deps */
};

/* Diagnostic event types (emitted to diagnostics ring buffer) */
enum diag_type {
    DIAG_MAP_PRESSURE = 1,
    DIAG_HOOK_ERROR = 2,
    DIAG_PROCESS_EVICTION = 3,
};

struct process_info {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
    __u8 verified_exec;            /* 1 if exec identity is VERIFIED_EXEC */
    __u8 exec_identity_known;      /* 1 if verified_exec has been computed for current image */
    __u8 pending_untrusted_args;   /* set on execve() entry for interpreter -c/-e style exec */
    __u8 env_shebang_active;       /* set when a script uses #!/usr/bin/env ... */
    __u8 env_shebang_script_ok;    /* script VERIFIED_EXEC result carried to next exec */
    __u8 exec_stage;               /* multi-hook correlation: see enum exec_stage */
    /* Binary identity captured at bprm_check for cross-hook correlation */
    __u64 exec_ino;                /* inode of the executed binary */
    __u32 exec_dev;                /* device of the executed binary */
    __u32 _pad;
};

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 cgid;
    char comm[16];
};

struct exec_argv_event {
    __u32 pid;
    __u32 _pad;
    __u64 start_time;
    __u16 argc;
    __u16 total_len;  /* total bytes written to argv[] including null separators */
    __u32 _pad2;
    char argv[MAX_ARGV_SIZE]; /* null-separated argument strings */
};

/* Dead process record for post-mortem correlation (LRU-evicted) */
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

/* Diagnostic event emitted to the diagnostics ring buffer */
struct diag_event {
    __u32 type;        /* enum diag_type */
    __u32 _pad;
    __u64 timestamp;
    __u32 data1;
    __u32 data2;
    char msg[64];
};

/* Hook latency tracking entry */
struct hook_latency_entry {
    __u64 total_ns;     /* cumulative latency */
    __u64 count;        /* invocation count */
    __u64 max_ns;       /* maximum single invocation */
    __u64 min_ns;       /* minimum single invocation */
};

/* Forensic event: enriched block event with extra process context */
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
    __u64 exec_ino;     /* binary that triggered the block */
    __u32 exec_dev;
    __u8 exec_stage;
    __u8 verified_exec;
    __u8 exec_identity_known;
    __u8 _pad3;
    char action[8];
};

struct block_event {
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
    __u32 pid;
    __u64 cgid;
    char comm[16];
    __u64 ino;
    __u32 dev;
    char path[DENY_PATH_MAX];
    char action[8];
};

struct net_block_event {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
    __u64 cgid;
    char comm[16];
    __u8 family;        /* AF_INET=2 or AF_INET6=10 */
    __u8 protocol;      /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
    __u16 local_port;
    __u16 remote_port;
    __u8 direction;     /* 0=egress (connect), 1=bind, 2=listen, 3=accept, 4=send */
    __u8 _pad;
    __be32 remote_ipv4;
    __u8 remote_ipv6[16];
    char action[8];     /* "AUDIT", "TERM", "KILL", or "BLOCK" */
    char rule_type[16]; /* "ip", "port", "cidr", "ip_port", "identity" */
};

struct event {
    __u32 type;
    union {
        struct exec_event exec;
        struct exec_argv_event exec_argv;
        struct block_event block;
        struct net_block_event net_block;
    };
};

struct inode_id {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};

struct path_key {
    char path[DENY_PATH_MAX];
};

struct agent_config {
    __u8 audit_only;
    __u8 deadman_enabled;
    __u8 break_glass_active;
    __u8 enforce_signal;  /* 0=none, 2=SIGINT, 9=SIGKILL, 15=SIGTERM */
    __u8 emergency_disable;  /* bypass enforcement (force AUDIT) when set */
    __u8 file_policy_empty;  /* optimization hint: no file deny rules loaded */
    __u8 net_policy_empty;   /* optimization hint: no network deny rules loaded */
    __u8 exec_identity_flags;  /* exec-identity policy + enforcement flags */
    __u64 deadman_deadline_ns;  /* ktime_get_boot_ns() deadline */
    __u32 deadman_ttl_seconds;
    __u32 event_sample_rate;
    __u32 sigkill_escalation_threshold;  /* SIGKILL after N denies in window */
    __u32 sigkill_escalation_window_seconds;  /* Escalation window size */
};

/* Agent config is stored as a BPF global so programs can read it without a
 * per-hook bpf_map_lookup_elem() helper call. Userspace updates the backing
 * map (and pins it at kAgentConfigPin).
 */
volatile struct agent_config agent_cfg = {
    .audit_only = 1,
    .deadman_enabled = 0,
    .break_glass_active = 0,
    .enforce_signal = SIGTERM,
    .emergency_disable = 0,
    .file_policy_empty = 0,
    .net_policy_empty = 0,
    .exec_identity_flags = 0,
    .deadman_deadline_ns = 0,
    .deadman_ttl_seconds = 0,
    .event_sample_rate = 1,
    .sigkill_escalation_threshold = SIGKILL_ESCALATION_THRESHOLD_DEFAULT,
    .sigkill_escalation_window_seconds = 30,
};

struct agent_meta {
    __u32 layout_version;
};

struct block_stats_entry {
    __u64 blocks;
    __u64 ringbuf_drops;
};

/* Key for process-specific maps that prevents PID reuse attacks */
struct process_key {
    __u32 pid;
    __u64 start_time;  /* task->start_time to uniquely identify process lifecycle */
};

struct signal_escalation_state {
    __u64 window_start_ns;
    __u32 strikes;
    __u32 _pad;
};

/* ============================================================================
 * BPF Maps
 * ============================================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESS_TREE_ENTRIES);
    __type(key, __u32);
    __type(value, struct process_info);
} process_tree SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOW_CGROUP_ENTRIES);
    __type(key, __u64);
    __type(value, __u8);
} allow_cgroup_map SEC(".maps");

/* Exec identity enforcement allowlist keyed by inode identity */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_INODE_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u8);
} allow_exec_inode_map SEC(".maps");

/* Exec identity mode toggle: key=0, value=0/1 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} exec_identity_mode_map SEC(".maps");

/* Survival allowlist - critical binaries that can NEVER be blocked */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SURVIVAL_ALLOWLIST_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u8);
} survival_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_meta);
} agent_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_INODE_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u8);
} deny_inode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_PATH_ENTRIES);
    __type(key, struct path_key);
    __type(value, __u8);
} deny_path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_DENY_CGROUP_STATS_ENTRIES);
    __type(key, __u64);
    __type(value, __u64);
} deny_cgroup_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_DENY_PATH_STATS_ENTRIES);
    __type(key, struct path_key);
    __type(value, __u64);
} deny_path_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_DENY_INODE_STATS_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u64);
} deny_inode_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct block_stats_entry);
} block_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_BYTES);
} events SEC(".maps");

/* Diagnostics ring buffer - separate from events for back-pressure isolation */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DIAGNOSTICS_RINGBUF_SIZE);
} diagnostics SEC(".maps");

/* Dead process cache - LRU retains recently exited processes for post-mortem */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DEAD_PROCESS_ENTRIES);
    __type(key, struct process_key);
    __type(value, struct dead_process_info);
} dead_processes SEC(".maps");

/* Per-hook latency tracking */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_HOOK_LATENCY_ENTRIES);
    __type(key, __u32);
    __type(value, struct hook_latency_entry);
} hook_latency SEC(".maps");

/* Event approver: inode allowlist for pre-filtering (skip event emission) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_APPROVER_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u8);
} event_approver_inode SEC(".maps");

/* Event approver: path allowlist for pre-filtering */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_APPROVER_ENTRIES);
    __type(key, struct path_key);
    __type(value, __u8);
} event_approver_path SEC(".maps");

/* Priority ring buffer for security-critical events (blocks, forensic) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PRIORITY_RINGBUF_SIZE);
} priority_events SEC(".maps");

/* ============================================================================
 * Network Maps
 * ============================================================================ */

/* IPv4 deny list - exact match */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_IPV4_ENTRIES);
    __type(key, __be32);
    __type(value, __u8);
} deny_ipv4 SEC(".maps");

/* IPv6 deny list - exact match */
struct ipv6_key {
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_IPV6_ENTRIES);
    __type(key, struct ipv6_key);
    __type(value, __u8);
} deny_ipv6 SEC(".maps");

/* Port deny key structure */
struct port_key {
    __u16 port;
    __u8 protocol;  /* 0=any, 6=tcp, 17=udp */
    __u8 direction; /* 0=egress, 1=bind, 2=both */
};

/* Port deny list */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_PORT_ENTRIES);
    __type(key, struct port_key);
    __type(value, __u8);
} deny_port SEC(".maps");

struct ip_port_key_v4 {
    __be32 addr;
    __u16 port;
    __u8 protocol; /* 0=any, 6=tcp, 17=udp */
    __u8 _pad;
};

struct ip_port_key_v6 {
    __u8 addr[16];
    __u16 port;
    __u8 protocol; /* 0=any, 6=tcp, 17=udp */
    __u8 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_IP_PORT_V4_ENTRIES);
    __type(key, struct ip_port_key_v4);
    __type(value, __u8);
} deny_ip_port_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_IP_PORT_V6_ENTRIES);
    __type(key, struct ip_port_key_v6);
    __type(value, __u8);
} deny_ip_port_v6 SEC(".maps");

/* IPv4 CIDR deny list - LPM trie for prefix matching */
struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_DENY_CIDR_V4_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} deny_cidr_v4 SEC(".maps");

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_DENY_CIDR_V6_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
} deny_cidr_v6 SEC(".maps");

/* Network block statistics */
struct net_stats_entry {
    __u64 connect_blocks;
    __u64 bind_blocks;
    __u64 listen_blocks;
    __u64 accept_blocks;
    __u64 sendmsg_blocks;
    __u64 ringbuf_drops;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_stats_entry);
} net_block_stats SEC(".maps");

/* Per-IP block statistics */
struct net_ip_key {
    __u8 family;  /* AF_INET=2, AF_INET6=10 */
    __u8 _pad[3];
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_NET_IP_STATS_ENTRIES);
    __type(key, struct net_ip_key);
    __type(value, __u64);
} net_ip_stats SEC(".maps");

/* Per-port block statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_NET_PORT_STATS_ENTRIES);
    __type(key, __u16);
    __type(value, __u64);
} net_port_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENFORCE_SIGNAL_STATE_ENTRIES);
    __type(key, struct process_key);
    __type(value, struct signal_escalation_state);
} enforce_signal_state SEC(".maps");

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static __always_inline void increment_block_stats(void)
{
    __u32 zero = 0;
    struct block_stats_entry *stats = bpf_map_lookup_elem(&block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->blocks, 1);
}

static __always_inline void increment_ringbuf_drops(void)
{
    __u32 zero = 0;
    struct block_stats_entry *stats = bpf_map_lookup_elem(&block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->ringbuf_drops, 1);
}

static __always_inline void increment_cgroup_stat(__u64 cgid)
{
    __u64 zero64 = 0;
    __u64 *cg_stat = bpf_map_lookup_elem(&deny_cgroup_stats, &cgid);
    if (!cg_stat) {
        bpf_map_update_elem(&deny_cgroup_stats, &cgid, &zero64, BPF_NOEXIST);
        cg_stat = bpf_map_lookup_elem(&deny_cgroup_stats, &cgid);
    }
    if (cg_stat)
        __sync_fetch_and_add(cg_stat, 1);
}

static __always_inline void increment_inode_stat(const struct inode_id *key)
{
    __u64 zero64 = 0;
    __u64 *ino_stat = bpf_map_lookup_elem(&deny_inode_stats, key);
    if (!ino_stat) {
        bpf_map_update_elem(&deny_inode_stats, key, &zero64, BPF_NOEXIST);
        ino_stat = bpf_map_lookup_elem(&deny_inode_stats, key);
    }
    if (ino_stat)
        __sync_fetch_and_add(ino_stat, 1);
}

static __always_inline void increment_path_stat(const struct path_key *key)
{
    __u64 zero64 = 0;
    __u64 *path_stat = bpf_map_lookup_elem(&deny_path_stats, key);
    if (!path_stat) {
        bpf_map_update_elem(&deny_path_stats, key, &zero64, BPF_NOEXIST);
        path_stat = bpf_map_lookup_elem(&deny_path_stats, key);
    }
    if (path_stat)
        __sync_fetch_and_add(path_stat, 1);
}

static __always_inline struct process_info *get_or_create_process_info(
    __u32 pid, struct task_struct *task)
{
    struct process_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    if (task) {
        if (!pi) {
            struct process_info info = {};
            info.pid = pid;
            info.ppid = BPF_CORE_READ(task, real_parent, tgid);
            info.start_time = BPF_CORE_READ(task, start_time);
            info.parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
            bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);
            pi = bpf_map_lookup_elem(&process_tree, &pid);
        } else if (pi->start_time == 0) {
            /* Ensure start_time is populated even for forked processes. */
            pi->start_time = BPF_CORE_READ(task, start_time);
            pi->parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
            pi->ppid = BPF_CORE_READ(task, real_parent, tgid);
            pi->pid = pid;
        }
    }
    return pi;
}

static __always_inline void fill_block_event_process_info(
    struct block_event *block, __u32 pid, struct task_struct *task)
{
    block->pid = pid;
    block->ppid = 0;
    block->start_time = 0;
    block->parent_start_time = 0;

    struct process_info *pi = get_or_create_process_info(pid, task);
    if (pi) {
        block->ppid = pi->ppid;
        block->start_time = pi->start_time;
        block->parent_start_time = pi->parent_start_time;
    }
}

static __always_inline __u8 current_verified_exec(__u32 pid, struct task_struct *task)
{
    struct process_info *pi = get_or_create_process_info(pid, task);
    if (!pi)
        return 0;
    if (!pi->exec_identity_known)
        return 0;
    return pi->verified_exec ? 1 : 0;
}

static __always_inline __u8 path_is_trusted_root(const char *path)
{
    if (!path)
        return 0;
    if (__builtin_memcmp(path, "/usr/", 5) == 0)
        return 1;
    if (__builtin_memcmp(path, "/bin/", 5) == 0)
        return 1;
    if (__builtin_memcmp(path, "/sbin/", 6) == 0)
        return 1;
    if (__builtin_memcmp(path, "/lib/", 5) == 0)
        return 1;
    if (__builtin_memcmp(path, "/lib64/", 7) == 0)
        return 1;
    return 0;
}

static __always_inline __u8 file_is_verified_exec_identity(const struct file *file)
{
    if (!file)
        return 0;

    const struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    __u32 magic = BPF_CORE_READ(inode, i_sb, s_magic);
    if (magic == OVERLAYFS_SUPER_MAGIC)
        return 0;

    __u32 uid = BPF_CORE_READ(inode, i_uid.val);
    if (uid != 0)
        return 0;

    __u16 mode = BPF_CORE_READ(inode, i_mode);
    if (mode & (S_IWGRP | S_IWOTH))
        return 0;

    __u32 iflags = BPF_CORE_READ(inode, i_flags);
    if (!(iflags & FS_VERITY_FL))
        return 0;

    char path[128] = {};
    long len = bpf_d_path((struct path *)&file->f_path, path, sizeof(path));
    if (len < 0)
        return 0;

    return path_is_trusted_root(path);
}

static __always_inline __u8 get_effective_audit_mode(void)
{
    const volatile struct agent_config *cfg = &agent_cfg;

    /* Emergency disable always forces audit-only (bypass enforcement). */
    if (cfg->emergency_disable)
        return 1;

    /* Break-glass mode always forces audit */
    if (cfg->break_glass_active)
        return 1;

    /* Explicit audit mode */
    if (cfg->audit_only)
        return 1;

    /* Deadman switch: if enabled and deadline passed, revert to audit */
    if (cfg->deadman_enabled) {
        __u64 now = bpf_ktime_get_boot_ns();
        if (now > cfg->deadman_deadline_ns)
            return 1;  /* Deadline passed - failsafe to audit */
    }

    return 0;  /* Enforce mode */
}

static __always_inline __u8 get_effective_enforce_signal(void)
{
    const volatile struct agent_config *cfg = &agent_cfg;

    if (cfg->enforce_signal == 0 || cfg->enforce_signal == SIGINT ||
        cfg->enforce_signal == SIGKILL || cfg->enforce_signal == SIGTERM)
        return cfg->enforce_signal;

    return SIGTERM;
}

static __always_inline void maybe_send_enforce_signal(__u8 signal)
{
    if (signal != 0)
        bpf_send_signal(signal);
}

static __always_inline int enforcement_result(void)
{
    __u8 audit = get_effective_audit_mode();
    if (audit)
        return 0;
    return -EPERM;
}

static __always_inline __u32 get_sigkill_escalation_threshold(void)
{
    const volatile struct agent_config *cfg = &agent_cfg;
    if (cfg->sigkill_escalation_threshold == 0)
        return SIGKILL_ESCALATION_THRESHOLD_DEFAULT;
    return cfg->sigkill_escalation_threshold;
}

static __always_inline __u64 get_sigkill_escalation_window_ns(void)
{
    const volatile struct agent_config *cfg = &agent_cfg;
    if (cfg->sigkill_escalation_window_seconds == 0)
        return SIGKILL_ESCALATION_WINDOW_NS_DEFAULT;
    return (__u64)cfg->sigkill_escalation_window_seconds * 1000000000ULL;
}

static __always_inline __u8 runtime_enforce_signal(
    __u8 configured_signal, __u32 pid, __u64 start_time, __u32 threshold, __u64 window_ns)
{
    if (configured_signal != SIGKILL)
        return configured_signal;
    if (threshold == 0)
        threshold = SIGKILL_ESCALATION_THRESHOLD_DEFAULT;
    if (window_ns == 0)
        window_ns = SIGKILL_ESCALATION_WINDOW_NS_DEFAULT;

    struct process_key key = {
        .pid = pid,
        .start_time = start_time,
    };

    __u64 now = bpf_ktime_get_boot_ns();
    struct signal_escalation_state *state =
        bpf_map_lookup_elem(&enforce_signal_state, &key);
    if (!state) {
        struct signal_escalation_state new_state = {
            .window_start_ns = now,
            .strikes = 1,
            ._pad = 0,
        };
        bpf_map_update_elem(&enforce_signal_state, &key, &new_state, BPF_ANY);
        if (threshold <= 1)
            return SIGKILL;
        return SIGTERM;
    }

    if (now < state->window_start_ns ||
        (now - state->window_start_ns) > window_ns) {
        state->window_start_ns = now;
        state->strikes = 1;
        if (threshold <= 1)
            return SIGKILL;
        return SIGTERM;
    }

    if (state->strikes < (__u32)-1)
        state->strikes++;

    if (state->strikes >= threshold)
        return SIGKILL;

    return SIGTERM;
}

static __always_inline void set_action_string(char action[8], __u8 audit, __u8 signal)
{
    if (audit) {
        __builtin_memcpy(action, "AUDIT", sizeof("AUDIT"));
        return;
    }
    if (signal == SIGKILL) {
        __builtin_memcpy(action, "KILL", sizeof("KILL"));
        return;
    }
    if (signal == SIGTERM) {
        __builtin_memcpy(action, "TERM", sizeof("TERM"));
        return;
    }
    if (signal == SIGINT) {
        __builtin_memcpy(action, "INT", sizeof("INT"));
        return;
    }
    __builtin_memcpy(action, "BLOCK", sizeof("BLOCK"));
}

static __always_inline __u32 get_event_sample_rate(void)
{
    const volatile struct agent_config *cfg = &agent_cfg;
    return cfg->event_sample_rate ? cfg->event_sample_rate : 1;
}

static __always_inline int should_emit_event(__u32 sample_rate)
{
    if (sample_rate <= 1)
        return 1;
    return (bpf_get_prandom_u32() % sample_rate) == 0;
}

static __always_inline int is_cgroup_allowed(__u64 cgid)
{
    return bpf_map_lookup_elem(&allow_cgroup_map, &cgid) != NULL;
}

/* ============================================================================
 * Diagnostic Helpers
 * ============================================================================ */

static __always_inline void emit_diag(__u32 type, __u32 d1, __u32 d2, const char *msg, int msg_len)
{
    struct diag_event *ev = bpf_ringbuf_reserve(&diagnostics, sizeof(*ev), BPF_RB_NO_WAKEUP);
    if (!ev)
        return;
    ev->type = type;
    ev->_pad = 0;
    ev->timestamp = bpf_ktime_get_boot_ns();
    ev->data1 = d1;
    ev->data2 = d2;
    __builtin_memset(ev->msg, 0, sizeof(ev->msg));
    if (msg && msg_len > 0) {
        if (msg_len > (int)sizeof(ev->msg))
            msg_len = (int)sizeof(ev->msg);
        bpf_probe_read_kernel(ev->msg, msg_len, msg);
    }
    bpf_ringbuf_submit(ev, BPF_RB_NO_WAKEUP);
}

/* Hook latency tracking helpers */
enum hook_id {
    HOOK_FILE_OPEN = 0,
    HOOK_INODE_PERMISSION = 1,
    HOOK_BPRM_CHECK = 2,
    HOOK_FILE_MMAP = 3,
    HOOK_SOCKET_CONNECT = 4,
    HOOK_SOCKET_BIND = 5,
    HOOK_SOCKET_LISTEN = 6,
    HOOK_SOCKET_ACCEPT = 7,
    HOOK_SOCKET_SENDMSG = 8,
    HOOK_EXECVE = 9,
};

static __always_inline void record_hook_latency(__u32 hook, __u64 start_ns)
{
    __u64 end_ns = bpf_ktime_get_ns();
    __u64 delta = end_ns - start_ns;
    struct hook_latency_entry *entry = bpf_map_lookup_elem(&hook_latency, &hook);
    if (entry) {
        __sync_fetch_and_add(&entry->total_ns, delta);
        __sync_fetch_and_add(&entry->count, 1);
        /* Atomic max/min: relaxed -- races are acceptable for profiling */
        if (delta > entry->max_ns)
            entry->max_ns = delta;
        if (entry->min_ns == 0 || delta < entry->min_ns)
            entry->min_ns = delta;
    }
}

/* Event pre-filtering: check if inode is in approver list (safe to skip event) */
static __always_inline int is_event_approved_inode(const struct inode_id *key)
{
    return bpf_map_lookup_elem(&event_approver_inode, key) != NULL;
}

/* Event pre-filtering: check if path is in approver list (safe to skip event) */
static __always_inline int is_event_approved_path(const struct path_key *key)
{
    return bpf_map_lookup_elem(&event_approver_path, key) != NULL;
}

/* Emit forensic event to the priority ring buffer */
static __always_inline void emit_forensic_block(
    __u32 pid, __u32 ppid, __u64 start_time, __u64 parent_start_time,
    __u64 cgid, __u64 ino, __u32 dev, const char action[8])
{
    struct forensic_event *fe = bpf_ringbuf_reserve(&priority_events, sizeof(*fe), 0);
    if (!fe)
        return;

    fe->type = EVENT_FORENSIC_BLOCK;
    fe->pid = pid;
    fe->ppid = ppid;
    fe->_pad = 0;
    fe->start_time = start_time;
    fe->parent_start_time = parent_start_time;
    fe->cgid = cgid;
    bpf_get_current_comm(fe->comm, sizeof(fe->comm));
    fe->ino = ino;
    fe->dev = dev;

    /* Enrich with UID/GID */
    __u64 uid_gid = bpf_get_current_uid_gid();
    fe->uid = (__u32)uid_gid;
    fe->gid = (__u32)(uid_gid >> 32);
    fe->_pad2 = 0;

    /* Enrich with exec identity from process tree */
    struct process_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    if (pi) {
        fe->exec_ino = pi->exec_ino;
        fe->exec_dev = pi->exec_dev;
        fe->exec_stage = pi->exec_stage;
        fe->verified_exec = pi->verified_exec;
        fe->exec_identity_known = pi->exec_identity_known;
    } else {
        fe->exec_ino = 0;
        fe->exec_dev = 0;
        fe->exec_stage = 0;
        fe->verified_exec = 0;
        fe->exec_identity_known = 0;
    }
    fe->_pad3 = 0;

    __builtin_memcpy(fe->action, action, 8);
    bpf_ringbuf_submit(fe, 0);
}

/* ============================================================================
 * Network Helper Functions
 * ============================================================================ */

static __always_inline void increment_net_connect_stats(void)
{
    __u32 zero = 0;
    struct net_stats_entry *stats = bpf_map_lookup_elem(&net_block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->connect_blocks, 1);
}

static __always_inline void increment_net_bind_stats(void)
{
    __u32 zero = 0;
    struct net_stats_entry *stats = bpf_map_lookup_elem(&net_block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->bind_blocks, 1);
}

static __always_inline void increment_net_listen_stats(void)
{
    __u32 zero = 0;
    struct net_stats_entry *stats = bpf_map_lookup_elem(&net_block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->listen_blocks, 1);
}

static __always_inline void increment_net_accept_stats(void)
{
    __u32 zero = 0;
    struct net_stats_entry *stats = bpf_map_lookup_elem(&net_block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->accept_blocks, 1);
}

static __always_inline void increment_net_sendmsg_stats(void)
{
    __u32 zero = 0;
    struct net_stats_entry *stats = bpf_map_lookup_elem(&net_block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->sendmsg_blocks, 1);
}

static __always_inline void increment_net_ringbuf_drops(void)
{
    __u32 zero = 0;
    struct net_stats_entry *stats = bpf_map_lookup_elem(&net_block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->ringbuf_drops, 1);
}

static __always_inline void increment_net_ip_stat_v4(__be32 ip)
{
    struct net_ip_key key = {
        .family = AF_INET,
        ._pad = {0, 0, 0},
        .addr = {0},
    };
    __builtin_memcpy(key.addr, &ip, sizeof(ip));

    __u64 zero64 = 0;
    __u64 *ip_stat = bpf_map_lookup_elem(&net_ip_stats, &key);
    if (!ip_stat) {
        bpf_map_update_elem(&net_ip_stats, &key, &zero64, BPF_NOEXIST);
        ip_stat = bpf_map_lookup_elem(&net_ip_stats, &key);
    }
    if (ip_stat)
        __sync_fetch_and_add(ip_stat, 1);
}

static __always_inline void increment_net_ip_stat_v6(const struct ipv6_key *ip)
{
    struct net_ip_key key = {
        .family = AF_INET6,
        ._pad = {0, 0, 0},
        .addr = {0},
    };
    __builtin_memcpy(key.addr, ip->addr, sizeof(key.addr));

    __u64 zero64 = 0;
    __u64 *ip_stat = bpf_map_lookup_elem(&net_ip_stats, &key);
    if (!ip_stat) {
        bpf_map_update_elem(&net_ip_stats, &key, &zero64, BPF_NOEXIST);
        ip_stat = bpf_map_lookup_elem(&net_ip_stats, &key);
    }
    if (ip_stat)
        __sync_fetch_and_add(ip_stat, 1);
}

static __always_inline void increment_net_port_stat(__u16 port)
{
    __u64 zero64 = 0;
    __u64 *port_stat = bpf_map_lookup_elem(&net_port_stats, &port);
    if (!port_stat) {
        bpf_map_update_elem(&net_port_stats, &port, &zero64, BPF_NOEXIST);
        port_stat = bpf_map_lookup_elem(&net_port_stats, &port);
    }
    if (port_stat)
        __sync_fetch_and_add(port_stat, 1);
}

static __always_inline void fill_net_block_event_process_info(
    struct net_block_event *ev, __u32 pid, struct task_struct *task)
{
    ev->pid = pid;
    ev->ppid = 0;
    ev->start_time = 0;
    ev->parent_start_time = 0;

    struct process_info *pi = get_or_create_process_info(pid, task);
    if (pi) {
        ev->ppid = pi->ppid;
        ev->start_time = pi->start_time;
        ev->parent_start_time = pi->parent_start_time;
    }
}

static __always_inline int port_rule_matches(__u16 port, __u8 protocol, __u8 direction)
{
    struct port_key key = {
        .port = port,
        .protocol = protocol,
        .direction = direction,
    };

    if (bpf_map_lookup_elem(&deny_port, &key))
        return 1;

    key.protocol = 0;  /* any protocol */
    if (bpf_map_lookup_elem(&deny_port, &key))
        return 1;

    key.direction = 2; /* both directions */
    key.protocol = protocol;
    if (bpf_map_lookup_elem(&deny_port, &key))
        return 1;

    key.protocol = 0;  /* both + any protocol */
    return bpf_map_lookup_elem(&deny_port, &key) != NULL;
}

static __always_inline int ip_port_rule_matches_v4(__be32 addr, __u16 port, __u8 protocol)
{
    struct ip_port_key_v4 key = {
        .addr = addr,
        .port = port,
        .protocol = protocol,
    };

    if (bpf_map_lookup_elem(&deny_ip_port_v4, &key))
        return 1;

    key.protocol = 0; /* any protocol */
    return bpf_map_lookup_elem(&deny_ip_port_v4, &key) != NULL;
}

static __always_inline int ip_port_rule_matches_v6(const struct ipv6_key *addr, __u16 port, __u8 protocol)
{
    struct ip_port_key_v6 key = {
        .port = port,
        .protocol = protocol,
    };
    __builtin_memcpy(key.addr, addr->addr, sizeof(key.addr));

    if (bpf_map_lookup_elem(&deny_ip_port_v6, &key))
        return 1;

    key.protocol = 0; /* any protocol */
    return bpf_map_lookup_elem(&deny_ip_port_v6, &key) != NULL;
}

/* ============================================================================
 * BPF Programs
 * ============================================================================ */

