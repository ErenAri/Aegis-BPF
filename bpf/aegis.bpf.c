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

/* BPF Map Size Constants */
#define MAX_PROCESS_TREE_ENTRIES 65536
#define MAX_ALLOW_CGROUP_ENTRIES 1024
#define MAX_SURVIVAL_ALLOWLIST_ENTRIES 256
#define MAX_DENY_BLOOM_ENTRIES 16384
#define MAX_DENY_EXACT_ENTRIES 65536
#define MAX_DENY_INODE_ENTRIES 65536
#define MAX_DENY_PATH_ENTRIES 16384
#define MAX_DENY_CGROUP_STATS_ENTRIES 4096
#define MAX_DENY_PATH_STATS_ENTRIES 16384
#define MAX_DENY_INODE_STATS_ENTRIES 65536
#define RINGBUF_SIZE_BYTES (1 << 24)  /* 16MB default */

/* Network Map Size Constants */
#define MAX_DENY_IPV4_ENTRIES 65536
#define MAX_DENY_IPV6_ENTRIES 65536
#define MAX_DENY_PORT_ENTRIES 4096
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
    EVENT_NET_CONNECT_BLOCK = 10,
    EVENT_NET_BIND_BLOCK = 11,
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
    __u8 _pad;
};

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 cgid;
    char comm[16];
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
    __u8 direction;     /* 0=egress (connect), 1=bind */
    __u8 _pad;
    __be32 remote_ipv4;
    __u8 remote_ipv6[16];
    char action[8];     /* "AUDIT", "TERM", "KILL", or "BLOCK" */
    char rule_type[16]; /* "ip", "port", "cidr" */
};

struct event {
    __u32 type;
    union {
        struct exec_event exec;
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
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, MAX_DENY_BLOOM_ENTRIES);
    __uint(key_size, 0);
    __uint(value_size, sizeof(__u64));
    __uint(map_extra, 5);
} deny_bloom SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_EXACT_ENTRIES);
    __type(key, __u64);
    __type(value, __u8);
} deny_exact SEC(".maps");

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

/* ============================================================================
 * BPF Programs
 * ============================================================================ */

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct task_struct *task = bpf_get_current_task_btf();

    /* Collect process info from task or existing entry */
    struct process_info info = {};
    struct process_info *existing = bpf_map_lookup_elem(&process_tree, &pid);
    if (existing) {
        info = *existing;
    }

    info.pid = pid;
    if (task) {
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
        __u64 start_time = BPF_CORE_READ(task, start_time);
        __u64 parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
        if (ppid)
            info.ppid = ppid;
        if (start_time)
            info.start_time = start_time;
        if (parent_start_time)
            info.parent_start_time = parent_start_time;
    }

    /* Track interpreter "-c"/"-e" execs as untrusted code execution. */
    info.pending_untrusted_args = 0;
    const char *filename_ptr = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];
    if (filename_ptr && argv) {
        char filename[64] = {};
        long fn_len = bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
        if (fn_len > 0) {
            int base_off = 0;
#pragma unroll
            for (int i = 0; i < (int)sizeof(filename); ++i) {
                if (filename[i] == '\0')
                    break;
                if (filename[i] == '/')
                    base_off = i + 1;
            }
            char *base = &filename[base_off];
            int rem = (int)sizeof(filename) - base_off;
            __u8 is_bash = (rem >= 5) && (__builtin_memcmp(base, "bash", 4) == 0) && (base[4] == '\0');
            __u8 is_dash = (rem >= 5) && (__builtin_memcmp(base, "dash", 4) == 0) && (base[4] == '\0');
            __u8 is_sh = (rem >= 3) && (__builtin_memcmp(base, "sh", 2) == 0) && (base[2] == '\0');
            __u8 is_shell = is_bash || is_dash || is_sh;
            __u8 is_python = (rem >= 6) && (__builtin_memcmp(base, "python", 6) == 0);
            __u8 is_node = (rem >= 5) && (__builtin_memcmp(base, "node", 4) == 0) && (base[4] == '\0');
            __u8 is_perl = (rem >= 5) && (__builtin_memcmp(base, "perl", 4) == 0) && (base[4] == '\0');
            __u8 is_ruby = (rem >= 5) && (__builtin_memcmp(base, "ruby", 4) == 0) && (base[4] == '\0');

            const char *arg1_ptr = NULL;
            bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &argv[1]);
            if (arg1_ptr) {
                char arg1[4] = {};
                long a1_len = bpf_probe_read_user_str(arg1, sizeof(arg1), arg1_ptr);
                if (a1_len > 0) {
                    if ((is_shell || is_python) &&
                        arg1[0] == '-' && arg1[1] == 'c' && arg1[2] == '\0') {
                        info.pending_untrusted_args = 1;
                    } else if ((is_node || is_perl || is_ruby) &&
                               arg1[0] == '-' && arg1[1] == 'e' && arg1[2] == '\0') {
                        info.pending_untrusted_args = 1;
                    }
                }
            }
        }
    }

    bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);

    /* Send exec event */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_EXEC;
    e->exec.pid = pid;
    e->exec.ppid = info.ppid;
    e->exec.start_time = info.start_time;
    e->exec.cgid = cgid;
    bpf_get_current_comm(e->exec.comm, sizeof(e->exec.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline __u8 exec_identity_mode_enabled(void)
{
    __u32 key = 0;
    __u8 *v = bpf_map_lookup_elem(&exec_identity_mode_map, &key);
    if (!v)
        return 0;
    return *v ? 1 : 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm_check_security, struct linux_binprm *bprm)
{
    if (!bprm)
        return 0;

    if (!exec_identity_mode_enabled())
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct task_struct *task = bpf_get_current_task_btf();
    struct process_info *pi = get_or_create_process_info(pid, task);

    struct file *file = BPF_CORE_READ(bprm, file);
    struct file *executable = BPF_CORE_READ(bprm, executable);
    struct file *interpreter = BPF_CORE_READ(bprm, interpreter);

    __u8 verified = 0;
    if (interpreter) {
        /* Script: require both the script file and interpreter binary to be VERIFIED_EXEC. */
        __u8 script_ok = file_is_verified_exec_identity(executable);
        __u8 interp_ok = file_is_verified_exec_identity(interpreter);
        verified = (script_ok && interp_ok) ? 1 : 0;

        /* Env shebangs: kernel can't attest the PATH-resolved final interpreter.
         * We carry the script VERIFIED_EXEC result to the next exec and require
         * both that script_ok and the final interpreter binary are VERIFIED_EXEC.
         */
        const char *interp = BPF_CORE_READ(bprm, interp);
        if (interp) {
            char interp_path[32] = {};
            long n = bpf_probe_read_kernel_str(interp_path, sizeof(interp_path), interp);
            if (n > 0 && __builtin_memcmp(interp_path, "/usr/bin/env", 12) == 0 &&
                interp_path[12] == '\0') {
                verified = 0;
                if (pi) {
                    pi->env_shebang_active = 1;
                    pi->env_shebang_script_ok = script_ok ? 1 : 0;
                }
            } else if (pi) {
                pi->env_shebang_active = 0;
                pi->env_shebang_script_ok = 0;
            }
        } else if (pi) {
            pi->env_shebang_active = 0;
            pi->env_shebang_script_ok = 0;
        }
    } else {
        verified = file_is_verified_exec_identity(file);
        if (pi && pi->env_shebang_active) {
            verified = verified && pi->env_shebang_script_ok;
            pi->env_shebang_active = 0;
            pi->env_shebang_script_ok = 0;
        }
    }

    if (pi) {
        if (pi->pending_untrusted_args)
            verified = 0;
        pi->verified_exec = verified ? 1 : 0;
        pi->exec_identity_known = 1;
        pi->pending_untrusted_args = 0;
    }

    /* Optional exec allowlist enforcement (version 3+ [allow_binary_hash]). */
    if (!(agent_cfg.exec_identity_flags & EXEC_IDENTITY_FLAG_ALLOWLIST_ENFORCE))
        return 0;

    if (!file)
        return 0;

    const struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Survival allowlist - never block critical binaries. */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    if (bpf_map_lookup_elem(&allow_exec_inode_map, &key))
        return 0;

    __u8 audit = get_effective_audit_mode();
    if (audit) {
        __u8 enforce_signal = 0;
        __u32 sample_rate = get_event_sample_rate();

        increment_block_stats();
        increment_cgroup_stat(cgid);
        increment_inode_stat(&key);

        if (!should_emit_event(sample_rate))
            return 0;

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_BLOCK;
            fill_block_event_process_info(&e->block, pid, task);
            e->block.cgid = cgid;
            bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
            e->block.ino = key.ino;
            e->block.dev = key.dev;
            __builtin_memset(e->block.path, 0, sizeof(e->block.path));
            set_action_string(e->block.action, 1, enforce_signal);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }
        return 0;
    }

    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = 0;
    __u8 configured_signal = get_effective_enforce_signal();
    if (configured_signal == SIGKILL) {
        __u32 kill_threshold = get_sigkill_escalation_threshold();
        __u64 kill_window_ns = get_sigkill_escalation_window_ns();
        enforce_signal = runtime_enforce_signal(configured_signal, pid, start_time, kill_threshold, kill_window_ns);
    } else {
        enforce_signal = configured_signal;
    }
    __u32 sample_rate = get_event_sample_rate();

    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    maybe_send_enforce_signal(enforce_signal);

    if (!should_emit_event(sample_rate))
        return -EPERM;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        set_action_string(e->block.action, 0, enforce_signal);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    if (!file)
        return 0;

    if (agent_cfg.file_policy_empty)
        return 0;

    /* Get inode info early for survival check */
    const struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Check if inode is in deny list */
    __u8 *rule = bpf_map_lookup_elem(&deny_inode_map, &key);
    if (!rule)
        return 0;
    const __u8 rule_flags = *rule;
    const __u8 protect_only = (rule_flags & RULE_FLAG_PROTECT_VERIFIED_EXEC) &&
                              !(rule_flags & RULE_FLAG_DENY_ALWAYS);

    /* Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    if (protect_only) {
        if (!(agent_cfg.exec_identity_flags & EXEC_IDENTITY_FLAG_PROTECT_FILES))
            return 0;
        if (current_verified_exec(pid, task))
            return 0;
    }

    __u8 audit = get_effective_audit_mode();
    if (audit) {
        __u8 enforce_signal = 0;
        __u32 sample_rate = get_event_sample_rate();

        /* Update statistics */
        increment_block_stats();
        increment_cgroup_stat(cgid);
        increment_inode_stat(&key);

        /* Send block event */
        if (!should_emit_event(sample_rate))
            return 0;
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_BLOCK;
            fill_block_event_process_info(&e->block, pid, task);
            e->block.cgid = cgid;
            bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
            e->block.ino = key.ino;
            e->block.dev = key.dev;
            __builtin_memset(e->block.path, 0, sizeof(e->block.path));
            set_action_string(e->block.action, 1, enforce_signal);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }

        return 0;
    }

    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;

    __u8 enforce_signal = 0;
    __u8 configured_signal = get_effective_enforce_signal();
    if (configured_signal == SIGKILL) {
        __u32 kill_threshold = get_sigkill_escalation_threshold();
        __u64 kill_window_ns = get_sigkill_escalation_window_ns();
        enforce_signal = runtime_enforce_signal(configured_signal, pid, start_time, kill_threshold, kill_window_ns);
    } else {
        enforce_signal = configured_signal;
    }
    __u32 sample_rate = get_event_sample_rate();

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    maybe_send_enforce_signal(enforce_signal);

    /* Send block event */
    if (!should_emit_event(sample_rate))
        return -EPERM;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        set_action_string(e->block.action, 0, enforce_signal);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    return -EPERM;
}

static __always_inline int handle_inode_permission_impl(struct inode *inode, int mask)
{
    if (!inode)
        return 0;
    (void)mask;

    if (agent_cfg.file_policy_empty)
        return 0;

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Check if inode is in deny list */
    __u8 *rule = bpf_map_lookup_elem(&deny_inode_map, &key);
    if (!rule)
        return 0;
    const __u8 rule_flags = *rule;
    const __u8 protect_only = (rule_flags & RULE_FLAG_PROTECT_VERIFIED_EXEC) &&
                              !(rule_flags & RULE_FLAG_DENY_ALWAYS);

    /* Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    if (protect_only) {
        if (!(agent_cfg.exec_identity_flags & EXEC_IDENTITY_FLAG_PROTECT_FILES))
            return 0;
        if (current_verified_exec(pid, task))
            return 0;
    }

    __u8 audit = get_effective_audit_mode();
    if (audit) {
        __u8 enforce_signal = 0;
        __u32 sample_rate = get_event_sample_rate();

        /* Update statistics */
        increment_block_stats();
        increment_cgroup_stat(cgid);
        increment_inode_stat(&key);

        /* Send block event */
        if (!should_emit_event(sample_rate))
            return 0;
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_BLOCK;
            fill_block_event_process_info(&e->block, pid, task);
            e->block.cgid = cgid;
            bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
            e->block.ino = key.ino;
            e->block.dev = key.dev;
            __builtin_memset(e->block.path, 0, sizeof(e->block.path));
            set_action_string(e->block.action, 1, enforce_signal);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }

        return 0;
    }

    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;

    __u8 enforce_signal = 0;
    __u8 configured_signal = get_effective_enforce_signal();
    if (configured_signal == SIGKILL) {
        __u32 kill_threshold = get_sigkill_escalation_threshold();
        __u64 kill_window_ns = get_sigkill_escalation_window_ns();
        enforce_signal = runtime_enforce_signal(configured_signal, pid, start_time, kill_threshold, kill_window_ns);
    } else {
        enforce_signal = configured_signal;
    }
    __u32 sample_rate = get_event_sample_rate();

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    maybe_send_enforce_signal(enforce_signal);

    /* Send block event */
    if (!should_emit_event(sample_rate))
        return -EPERM;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        set_action_string(e->block.action, 0, enforce_signal);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    return -EPERM;
}

SEC("lsm/inode_permission")
int BPF_PROG(handle_inode_permission, struct inode *inode, int mask)
{
    return handle_inode_permission_impl(inode, mask);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    if (!filename)
        return 0;

    if (agent_cfg.file_policy_empty)
        return 0;

    /* Read path from userspace */
    struct path_key key = {};
    long len = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);
    if (len <= 0)
        return 0;

    /* Check if path is in deny list */
    if (!bpf_map_lookup_elem(&deny_path_map, &key))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 sample_rate = get_event_sample_rate();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_path_stat(&key);

    /* Send block event (audit only - tracepoints can't block) */
    if (!should_emit_event(sample_rate))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = 0;
        e->block.dev = 0;
        __builtin_memcpy(e->block.path, key.path, sizeof(e->block.path));
        __builtin_memcpy(e->block.action, "AUDIT", sizeof("AUDIT"));
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 child_pid = ctx->child_pid;
    __u32 parent_pid = ctx->parent_pid;
    struct task_struct *task = bpf_get_current_task_btf();

    struct process_info info = {};
    info.pid = child_pid;
    info.ppid = parent_pid;
    info.start_time = 0;
    info.parent_start_time = task ? BPF_CORE_READ(task, start_time) : 0;

    /* Inherit exec identity status from parent; fork preserves the image. */
    struct process_info *parent = bpf_map_lookup_elem(&process_tree, &parent_pid);
    if (parent) {
        info.verified_exec = parent->verified_exec;
        info.exec_identity_known = parent->exec_identity_known;
        info.env_shebang_active = parent->env_shebang_active;
        info.env_shebang_script_ok = parent->env_shebang_script_ok;
    }

    bpf_map_update_elem(&process_tree, &child_pid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Get start_time before deleting process_tree entry */
    struct process_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    if (pi) {
        struct process_key key = {
            .pid = pid,
            .start_time = pi->start_time,
        };
        bpf_map_delete_elem(&enforce_signal_state, &key);
    }

    bpf_map_delete_elem(&process_tree, &pid);
    return 0;
}

/* ============================================================================
 * Network LSM Hooks
 * ============================================================================ */

SEC("lsm/socket_connect")
int BPF_PROG(handle_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!sock || !address)
        return 0;
    (void)addrlen;

    __u8 exec_flags = agent_cfg.exec_identity_flags;
    if (agent_cfg.net_policy_empty && !(exec_flags & EXEC_IDENTITY_FLAG_PROTECT_CONNECT))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family))
        return enforcement_result();

    if (family != AF_INET && family != AF_INET6)
        return 0;

    __be32 remote_ip_v4 = 0;
    struct ipv6_key remote_ip_v6 = {};
    __u16 remote_port = 0;
    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_kernel(&sin, sizeof(sin), address))
            return enforcement_result();
        remote_ip_v4 = sin.sin_addr.s_addr;
        remote_port = bpf_ntohs(sin.sin_port);
    } else {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
            return enforcement_result();
        remote_port = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(remote_ip_v6.addr, &sin6.sin6_addr, sizeof(remote_ip_v6.addr));
    }

    /* Get socket protocol */
    __u8 protocol = BPF_CORE_READ(sock, sk, sk_protocol);

    int matched = 0;
    char rule_type[16] = {};

    if ((exec_flags & EXEC_IDENTITY_FLAG_PROTECT_CONNECT)) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct task_struct *task = bpf_get_current_task_btf();
        struct process_info *pi = get_or_create_process_info(pid, task);
        __u8 verified = (pi && pi->exec_identity_known && pi->verified_exec) ? 1 : 0;
        if (!verified) {
            matched = 1;
            __builtin_memcpy(rule_type, "identity", sizeof("identity"));
        }
    }

    if (family == AF_INET) {
        /* Check 1: Exact IPv4 match */
        if (!matched && bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v4(remote_ip_v4);
        }

        /* Check 2: IPv4 CIDR match via LPM trie */
        if (!matched) {
            struct ipv4_lpm_key lpm_key = {
                .prefixlen = 32,
                .addr = remote_ip_v4,
            };
            if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v4(remote_ip_v4);
            }
        }
    } else {
        /* Check 1: Exact IPv6 match */
        if (!matched && bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v6(&remote_ip_v6);
        }

        /* Check 2: IPv6 CIDR match via LPM trie */
        if (!matched) {
            struct ipv6_lpm_key lpm_key = {
                .prefixlen = 128,
                .addr = {0},
            };
            __builtin_memcpy(lpm_key.addr, remote_ip_v6.addr, sizeof(lpm_key.addr));
            if (bpf_map_lookup_elem(&deny_cidr_v6, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v6(&remote_ip_v6);
            }
        }
    }

    /* Check 3: Port match (protocol/direction aware) */
    if (!matched) {
        if (port_rule_matches(remote_port, protocol, 0)) {
            matched = 1;
            __builtin_memcpy(rule_type, "port", 5);
            increment_net_port_stat(remote_port);
        }
    }

    if (!matched)
        return 0;

    /* Rule matched - process denial */
    __u8 audit = get_effective_audit_mode();
    if (audit) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u8 enforce_signal = 0;
        struct task_struct *task = bpf_get_current_task_btf();
        __u32 sample_rate = get_event_sample_rate();

        /* Update global network block stats */
        increment_net_connect_stats();
        increment_cgroup_stat(cgid);

        /* Emit event */
        if (!should_emit_event(sample_rate))
            return 0;

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_NET_CONNECT_BLOCK;
            fill_net_block_event_process_info(&e->net_block, pid, task);
            e->net_block.cgid = cgid;
            bpf_get_current_comm(e->net_block.comm, sizeof(e->net_block.comm));
            e->net_block.family = family;
            e->net_block.protocol = protocol;
            e->net_block.local_port = 0;
            e->net_block.remote_port = remote_port;
            e->net_block.direction = 0;  /* egress */
            e->net_block.remote_ipv4 = (family == AF_INET) ? remote_ip_v4 : 0;
            if (family == AF_INET6)
                __builtin_memcpy(e->net_block.remote_ipv6, remote_ip_v6.addr, sizeof(e->net_block.remote_ipv6));
            else
                __builtin_memset(e->net_block.remote_ipv6, 0, sizeof(e->net_block.remote_ipv6));
            set_action_string(e->net_block.action, 1, enforce_signal);
            __builtin_memcpy(e->net_block.rule_type, rule_type, sizeof(rule_type));
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_net_ringbuf_drops();
        }

        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;

    __u8 enforce_signal = 0;
    __u8 configured_signal = get_effective_enforce_signal();
    if (configured_signal == SIGKILL) {
        __u32 kill_threshold = get_sigkill_escalation_threshold();
        __u64 kill_window_ns = get_sigkill_escalation_window_ns();
        enforce_signal = runtime_enforce_signal(configured_signal, pid, start_time, kill_threshold, kill_window_ns);
    } else {
        enforce_signal = configured_signal;
    }
    __u32 sample_rate = get_event_sample_rate();

    /* Update global network block stats */
    increment_net_connect_stats();
    increment_cgroup_stat(cgid);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    maybe_send_enforce_signal(enforce_signal);

    /* Emit event */
    if (!should_emit_event(sample_rate))
        return -EPERM;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_NET_CONNECT_BLOCK;
        fill_net_block_event_process_info(&e->net_block, pid, task);
        e->net_block.cgid = cgid;
        bpf_get_current_comm(e->net_block.comm, sizeof(e->net_block.comm));
        e->net_block.family = family;
        e->net_block.protocol = protocol;
        e->net_block.local_port = 0;
        e->net_block.remote_port = remote_port;
        e->net_block.direction = 0;  /* egress */
        e->net_block.remote_ipv4 = (family == AF_INET) ? remote_ip_v4 : 0;
        if (family == AF_INET6)
            __builtin_memcpy(e->net_block.remote_ipv6, remote_ip_v6.addr, sizeof(e->net_block.remote_ipv6));
        else
            __builtin_memset(e->net_block.remote_ipv6, 0, sizeof(e->net_block.remote_ipv6));
        set_action_string(e->net_block.action, 0, enforce_signal);
        __builtin_memcpy(e->net_block.rule_type, rule_type, sizeof(rule_type));
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_net_ringbuf_drops();
    }

    return -EPERM;
}

SEC("lsm/socket_bind")
int BPF_PROG(handle_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!sock || !address)
        return 0;
    (void)addrlen;

    if (agent_cfg.net_policy_empty)
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family))
        return enforcement_result();

    if (family != AF_INET && family != AF_INET6)
        return 0;

    /* Extract bind port */
    __u16 bind_port = 0;
    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_kernel(&sin, sizeof(sin), address))
            return enforcement_result();
        bind_port = bpf_ntohs(sin.sin_port);
    } else {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
            return enforcement_result();
        bind_port = bpf_ntohs(sin6.sin6_port);
    }

    /* Get socket protocol */
    __u8 protocol = BPF_CORE_READ(sock, sk, sk_protocol);

    int matched = port_rule_matches(bind_port, protocol, 1);

    if (!matched)
        return 0;

    /* Rule matched - process denial */
    __u8 audit = get_effective_audit_mode();
    if (audit) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u8 enforce_signal = 0;
        struct task_struct *task = bpf_get_current_task_btf();
        __u32 sample_rate = get_event_sample_rate();

        /* Update statistics */
        increment_net_bind_stats();
        increment_cgroup_stat(cgid);
        increment_net_port_stat(bind_port);

        /* Emit event */
        if (!should_emit_event(sample_rate))
            return 0;

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_NET_BIND_BLOCK;
            fill_net_block_event_process_info(&e->net_block, pid, task);
            e->net_block.cgid = cgid;
            bpf_get_current_comm(e->net_block.comm, sizeof(e->net_block.comm));
            e->net_block.family = family;
            e->net_block.protocol = protocol;
            e->net_block.local_port = bind_port;
            e->net_block.remote_port = 0;
            e->net_block.direction = 1;  /* bind */
            e->net_block.remote_ipv4 = 0;
            __builtin_memset(e->net_block.remote_ipv6, 0, sizeof(e->net_block.remote_ipv6));
            set_action_string(e->net_block.action, 1, enforce_signal);
            __builtin_memcpy(e->net_block.rule_type, "port", 5);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_net_ringbuf_drops();
        }

        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;

    __u8 enforce_signal = 0;
    __u8 configured_signal = get_effective_enforce_signal();
    if (configured_signal == SIGKILL) {
        __u32 kill_threshold = get_sigkill_escalation_threshold();
        __u64 kill_window_ns = get_sigkill_escalation_window_ns();
        enforce_signal = runtime_enforce_signal(configured_signal, pid, start_time, kill_threshold, kill_window_ns);
    } else {
        enforce_signal = configured_signal;
    }
    __u32 sample_rate = get_event_sample_rate();

    /* Update statistics */
    increment_net_bind_stats();
    increment_cgroup_stat(cgid);
    increment_net_port_stat(bind_port);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    maybe_send_enforce_signal(enforce_signal);

    /* Emit event */
    if (!should_emit_event(sample_rate))
        return -EPERM;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_NET_BIND_BLOCK;
        fill_net_block_event_process_info(&e->net_block, pid, task);
        e->net_block.cgid = cgid;
        bpf_get_current_comm(e->net_block.comm, sizeof(e->net_block.comm));
        e->net_block.family = family;
        e->net_block.protocol = protocol;
        e->net_block.local_port = bind_port;
        e->net_block.remote_port = 0;
        e->net_block.direction = 1;  /* bind */
        e->net_block.remote_ipv4 = 0;
        __builtin_memset(e->net_block.remote_ipv6, 0, sizeof(e->net_block.remote_ipv6));
        set_action_string(e->net_block.action, 0, enforce_signal);
        __builtin_memcpy(e->net_block.rule_type, "port", 5);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_net_ringbuf_drops();
    }

    return -EPERM;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
