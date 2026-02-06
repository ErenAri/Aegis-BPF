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
    __u64 deadman_deadline_ns;  /* ktime_get_boot_ns() deadline */
    __u32 deadman_ttl_seconds;
    __u32 event_sample_rate;
    __u32 sigkill_escalation_threshold;  /* SIGKILL after N denies in window */
    __u32 sigkill_escalation_window_seconds;  /* Escalation window size */
};

struct agent_meta {
    __u32 layout_version;
};

struct block_stats_entry {
    __u64 blocks;
    __u64 ringbuf_drops;
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
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct process_info);
} process_tree SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} allow_cgroup_map SEC(".maps");

/* Survival allowlist - critical binaries that can NEVER be blocked */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct inode_id);
    __type(value, __u8);
} survival_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_config);
} agent_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_meta);
} agent_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 16384);
    __uint(key_size, 0);
    __uint(value_size, sizeof(__u64));
    __uint(map_extra, 5);
} deny_bloom SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} deny_exact SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct inode_id);
    __type(value, __u8);
} deny_inode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct path_key);
    __type(value, __u8);
} deny_path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} deny_cgroup_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct path_key);
    __type(value, __u64);
} deny_path_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
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
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* ============================================================================
 * Network Maps
 * ============================================================================ */

/* IPv4 deny list - exact match */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, __u8);
} deny_ipv4 SEC(".maps");

/* IPv6 deny list - exact match */
struct ipv6_key {
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
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
    __uint(max_entries, 4096);
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
    __uint(max_entries, 16384);
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
    __uint(max_entries, 16384);
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
    __uint(max_entries, 16384);
    __type(key, struct net_ip_key);
    __type(value, __u64);
} net_ip_stats SEC(".maps");

/* Per-port block statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, __u64);
} net_port_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
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
    if (!pi && task) {
        struct process_info info = {};
        info.pid = pid;
        info.ppid = BPF_CORE_READ(task, real_parent, tgid);
        info.start_time = BPF_CORE_READ(task, start_time);
        info.parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
        bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);
        pi = bpf_map_lookup_elem(&process_tree, &pid);
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

static __always_inline __u8 get_effective_audit_mode(void)
{
    __u32 zero = 0;
    struct agent_config *cfg = bpf_map_lookup_elem(&agent_config_map, &zero);
    if (!cfg)
        return 1;  /* Fail-open if no config */

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
    __u32 zero = 0;
    struct agent_config *cfg = bpf_map_lookup_elem(&agent_config_map, &zero);
    if (!cfg)
        return SIGTERM;  /* Safe default in enforce mode */

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
    __u32 zero = 0;
    struct agent_config *cfg = bpf_map_lookup_elem(&agent_config_map, &zero);
    if (!cfg || cfg->sigkill_escalation_threshold == 0)
        return SIGKILL_ESCALATION_THRESHOLD_DEFAULT;
    return cfg->sigkill_escalation_threshold;
}

static __always_inline __u64 get_sigkill_escalation_window_ns(void)
{
    __u32 zero = 0;
    struct agent_config *cfg = bpf_map_lookup_elem(&agent_config_map, &zero);
    if (!cfg || cfg->sigkill_escalation_window_seconds == 0)
        return SIGKILL_ESCALATION_WINDOW_NS_DEFAULT;
    return (__u64)cfg->sigkill_escalation_window_seconds * 1000000000ULL;
}

static __always_inline __u8 runtime_enforce_signal(
    __u8 configured_signal, __u32 pid, __u32 threshold, __u64 window_ns)
{
    if (configured_signal != SIGKILL)
        return configured_signal;
    if (threshold == 0)
        threshold = SIGKILL_ESCALATION_THRESHOLD_DEFAULT;
    if (window_ns == 0)
        window_ns = SIGKILL_ESCALATION_WINDOW_NS_DEFAULT;

    __u64 now = bpf_ktime_get_boot_ns();
    struct signal_escalation_state *state =
        bpf_map_lookup_elem(&enforce_signal_state, &pid);
    if (!state) {
        struct signal_escalation_state new_state = {
            .window_start_ns = now,
            .strikes = 1,
            ._pad = 0,
        };
        bpf_map_update_elem(&enforce_signal_state, &pid, &new_state, BPF_ANY);
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
    __u32 zero = 0;
    struct agent_config *cfg = bpf_map_lookup_elem(&agent_config_map, &zero);
    if (!cfg)
        return 1;  /* Default to no sampling if config missing */
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

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    if (!file)
        return 0;

    /* Get inode info early for survival check */
    const struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Check if inode is in deny list */
    if (!bpf_map_lookup_elem(&deny_inode_map, &key))
        return 0;

    /* Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    __u8 audit = get_effective_audit_mode();
    if (audit)
        audit = 1;
    else
        audit = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 enforce_signal = 0;
    if (!audit) {
        __u8 configured_signal = get_effective_enforce_signal();
        if (configured_signal == SIGKILL) {
            __u32 kill_threshold = get_sigkill_escalation_threshold();
            __u64 kill_window_ns = get_sigkill_escalation_window_ns();
            enforce_signal = runtime_enforce_signal(configured_signal, pid, kill_threshold, kill_window_ns);
        } else {
            enforce_signal = configured_signal;
        }
    }
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 sample_rate = get_event_sample_rate();

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    if (!audit)
        maybe_send_enforce_signal(enforce_signal);

    /* Send block event */
    if (!should_emit_event(sample_rate)) {
        if (audit)
            return 0;
        return -EPERM;
    }
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        set_action_string(e->block.action, audit, enforce_signal);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    if (audit)
        return 0;
    return -EPERM;
}

static __always_inline int handle_inode_permission_impl(struct inode *inode, int mask)
{
    if (!inode)
        return 0;
    (void)mask;

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Check if inode is in deny list */
    if (!bpf_map_lookup_elem(&deny_inode_map, &key))
        return 0;

    /* Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    __u8 audit = get_effective_audit_mode();
    if (audit)
        audit = 1;
    else
        audit = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 enforce_signal = 0;
    if (!audit) {
        __u8 configured_signal = get_effective_enforce_signal();
        if (configured_signal == SIGKILL) {
            __u32 kill_threshold = get_sigkill_escalation_threshold();
            __u64 kill_window_ns = get_sigkill_escalation_window_ns();
            enforce_signal = runtime_enforce_signal(configured_signal, pid, kill_threshold, kill_window_ns);
        } else {
            enforce_signal = configured_signal;
        }
    }
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 sample_rate = get_event_sample_rate();

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    if (!audit)
        maybe_send_enforce_signal(enforce_signal);

    /* Send block event */
    if (!should_emit_event(sample_rate)) {
        if (audit)
            return 0;
        return -EPERM;
    }
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        set_action_string(e->block.action, audit, enforce_signal);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    if (audit)
        return 0;
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

    struct process_info info = {
        .pid = child_pid,
        .ppid = parent_pid,
        .start_time = 0,
        .parent_start_time = task ? BPF_CORE_READ(task, start_time) : 0,
    };

    bpf_map_update_elem(&process_tree, &child_pid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&process_tree, &pid);
    bpf_map_delete_elem(&enforce_signal_state, &pid);
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
    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u8 protocol = sk ? BPF_CORE_READ(sk, sk_protocol) : 0;

    int matched = 0;
    char rule_type[16] = {};

    if (family == AF_INET) {
        /* Check 1: Exact IPv4 match */
        if (bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
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
        if (bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
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
    if (audit)
        audit = 1;
    else
        audit = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 enforce_signal = 0;
    if (!audit) {
        __u8 configured_signal = get_effective_enforce_signal();
        if (configured_signal == SIGKILL) {
            __u32 kill_threshold = get_sigkill_escalation_threshold();
            __u64 kill_window_ns = get_sigkill_escalation_window_ns();
            enforce_signal = runtime_enforce_signal(configured_signal, pid, kill_threshold, kill_window_ns);
        } else {
            enforce_signal = configured_signal;
        }
    }
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 sample_rate = get_event_sample_rate();

    /* Update global network block stats */
    increment_net_connect_stats();
    increment_cgroup_stat(cgid);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    if (!audit)
        maybe_send_enforce_signal(enforce_signal);

    /* Emit event */
    if (!should_emit_event(sample_rate)) {
        if (audit)
            return 0;
        return -EPERM;
    }

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
        set_action_string(e->net_block.action, audit, enforce_signal);
        __builtin_memcpy(e->net_block.rule_type, rule_type, sizeof(rule_type));
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_net_ringbuf_drops();
    }

    if (audit)
        return 0;
    return -EPERM;
}

SEC("lsm/socket_bind")
int BPF_PROG(handle_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!sock || !address)
        return 0;
    (void)addrlen;

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
    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u8 protocol = sk ? BPF_CORE_READ(sk, sk_protocol) : 0;

    int matched = port_rule_matches(bind_port, protocol, 1);

    if (!matched)
        return 0;

    /* Rule matched - process denial */
    __u8 audit = get_effective_audit_mode();
    if (audit)
        audit = 1;
    else
        audit = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 enforce_signal = 0;
    if (!audit) {
        __u8 configured_signal = get_effective_enforce_signal();
        if (configured_signal == SIGKILL) {
            __u32 kill_threshold = get_sigkill_escalation_threshold();
            __u64 kill_window_ns = get_sigkill_escalation_window_ns();
            enforce_signal = runtime_enforce_signal(configured_signal, pid, kill_threshold, kill_window_ns);
        } else {
            enforce_signal = configured_signal;
        }
    }
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 sample_rate = get_event_sample_rate();

    /* Update statistics */
    increment_net_bind_stats();
    increment_cgroup_stat(cgid);
    increment_net_port_stat(bind_port);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    if (!audit)
        maybe_send_enforce_signal(enforce_signal);

    /* Emit event */
    if (!should_emit_event(sample_rate)) {
        if (audit)
            return 0;
        return -EPERM;
    }

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
        set_action_string(e->net_block.action, audit, enforce_signal);
        __builtin_memcpy(e->net_block.rule_type, "port", 5);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_net_ringbuf_drops();
    }

    if (audit)
        return 0;
    return -EPERM;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
