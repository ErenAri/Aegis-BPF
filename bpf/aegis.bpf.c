/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * This BPF program provides file access control using LSM hooks (when available)
 * or tracepoints (as fallback). It tracks process lineage, blocks access to
 * denied inodes/paths, and reports events via ring buffer.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno-base.h>

#define SIGKILL 9
#define DENY_PATH_MAX 256
#ifndef MAY_EXEC
#define MAY_EXEC 0x01
#define MAY_WRITE 0x02
#define MAY_READ 0x04
#endif

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

enum event_type {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2,
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

struct event {
    __u32 type;
    union {
        struct exec_event exec;
        struct block_event block;
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
    __u8 _pad;
    __u64 deadman_deadline_ns;  /* ktime_get_boot_ns() deadline */
    __u32 deadman_ttl_seconds;
    __u32 _pad2;
};

struct agent_meta {
    __u32 layout_version;
};

struct block_stats_entry {
    __u64 blocks;
    __u64 ringbuf_drops;
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

static __always_inline int is_cgroup_allowed(__u64 cgid)
{
    return bpf_map_lookup_elem(&allow_cgroup_map, &cgid) != NULL;
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

    /* FIRST: Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct task_struct *task = bpf_get_current_task_btf();
    __u8 audit = get_effective_audit_mode();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    /* Check if inode is in deny list */
    if (!bpf_map_lookup_elem(&deny_inode_map, &key))
        return 0;

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    /* Send SIGKILL in enforce mode */
    if (!audit)
        bpf_send_signal(SIGKILL);

    /* Send block event */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        if (audit)
            __builtin_memcpy(e->block.action, "AUDIT", sizeof("AUDIT"));
        else
            __builtin_memcpy(e->block.action, "KILL", sizeof("KILL"));
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    return audit ? 0 : -EPERM;
}

static __always_inline int handle_inode_permission_impl(struct inode *inode, int mask)
{
    if (!inode)
        return 0;
    (void)mask;

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* FIRST: Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct task_struct *task = bpf_get_current_task_btf();
    __u8 audit = get_effective_audit_mode();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    /* Check if inode is in deny list */
    if (!bpf_map_lookup_elem(&deny_inode_map, &key))
        return 0;

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    /* Send SIGKILL in enforce mode */
    if (!audit)
        bpf_send_signal(SIGKILL);

    /* Send block event */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        fill_block_event_process_info(&e->block, pid, task);
        e->block.cgid = cgid;
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = key.ino;
        e->block.dev = key.dev;
        __builtin_memset(e->block.path, 0, sizeof(e->block.path));
        if (audit)
            __builtin_memcpy(e->block.action, "AUDIT", sizeof("AUDIT"));
        else
            __builtin_memcpy(e->block.action, "KILL", sizeof("KILL"));
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    return audit ? 0 : -EPERM;
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

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid))
        return 0;

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_path_stat(&key);

    /* Send block event (audit only - tracepoints can't block) */
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
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
