#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno-base.h>

#define SIGKILL 9
#define DENY_PATH_MAX 256

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

struct event {
    __u32 type;
    union {
        struct exec_event exec;
        struct {
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
        } block;
    };
};

struct inode_id {
    __u64 ino;
    __u32 dev;
};

struct path_key {
    char path[DENY_PATH_MAX];
};

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

struct agent_config {
    __u8 audit_only;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_config);
} agent_config_map SEC(".maps");

struct agent_meta {
    __u32 layout_version;
};

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
    __type(value, struct {
        __u64 blocks;
        __u64 ringbuf_drops;
    });
} block_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct process_info info = {};
    struct process_info *existing;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    __u64 start_time = 0;
    __u64 parent_start_time = 0;
    __u32 ppid = 0;
    struct task_struct *task = bpf_get_current_task_btf();

    if (task) {
        start_time = BPF_CORE_READ(task, start_time);
        parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
        ppid = BPF_CORE_READ(task, real_parent, tgid);
    }

    existing = bpf_map_lookup_elem(&process_tree, &pid);
    if (existing) {
        info.pid = existing->pid;
        info.ppid = existing->ppid;
        info.start_time = existing->start_time;
        info.parent_start_time = existing->parent_start_time;
    }

    info.pid = pid;
    if (ppid)
        info.ppid = ppid;
    if (start_time)
        info.start_time = start_time;
    if (parent_start_time)
        info.parent_start_time = parent_start_time;

    bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
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
    const struct inode *inode;
    struct inode_id key = {};
    __u8 *deny;
    __u32 zero = 0;
    struct agent_config *cfg;
    __u8 audit = 0;
    struct task_struct *task;
    __u32 pid;
    __u64 cgid;
    struct {
        __u64 blocks;
        __u64 ringbuf_drops;
    } *stats;
    __u64 *cg_stat;
    __u64 *ino_stat;
    __u64 zero64 = 0;

    if (!file)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    task = bpf_get_current_task_btf();
    cgid = bpf_get_current_cgroup_id();

    cfg = bpf_map_lookup_elem(&agent_config_map, &zero);
    if (cfg)
        audit = cfg->audit_only & 1;

    if (bpf_map_lookup_elem(&allow_cgroup_map, &cgid))
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    deny = bpf_map_lookup_elem(&deny_inode_map, &key);
    if (deny) {
        struct event *e;
        stats = bpf_map_lookup_elem(&block_stats, &zero);
        if (stats)
            __sync_fetch_and_add(&stats->blocks, 1);

        cg_stat = bpf_map_lookup_elem(&deny_cgroup_stats, &cgid);
        if (!cg_stat) {
            bpf_map_update_elem(&deny_cgroup_stats, &cgid, &zero64, BPF_NOEXIST);
            cg_stat = bpf_map_lookup_elem(&deny_cgroup_stats, &cgid);
        }
        if (cg_stat)
            __sync_fetch_and_add(cg_stat, 1);

        ino_stat = bpf_map_lookup_elem(&deny_inode_stats, &key);
        if (!ino_stat) {
            bpf_map_update_elem(&deny_inode_stats, &key, &zero64, BPF_NOEXIST);
            ino_stat = bpf_map_lookup_elem(&deny_inode_stats, &key);
        }
        if (ino_stat)
            __sync_fetch_and_add(ino_stat, 1);

        if (!audit)
            bpf_send_signal(SIGKILL);

        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_BLOCK;
            e->block.pid = pid;
            e->block.ppid = 0;
            e->block.start_time = 0;
            e->block.parent_start_time = 0;
            e->block.cgid = cgid;
            struct process_info *pi = bpf_map_lookup_elem(&process_tree, &e->block.pid);
            if (!pi && task) {
                struct process_info info = {};
                info.pid = pid;
                info.ppid = BPF_CORE_READ(task, real_parent, tgid);
                info.start_time = BPF_CORE_READ(task, start_time);
                info.parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
                bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);
                pi = bpf_map_lookup_elem(&process_tree, &pid);
            }
            if (pi) {
                e->block.ppid = pi->ppid;
                e->block.start_time = pi->start_time;
                e->block.parent_start_time = pi->parent_start_time;
            }
            bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
            e->block.ino = key.ino;
            e->block.dev = key.dev;
            __builtin_memset(e->block.path, 0, sizeof(e->block.path));
            if (audit)
                __builtin_memcpy(e->block.action, "AUDIT", sizeof("AUDIT"));
            else
                __builtin_memcpy(e->block.action, "KILL", sizeof("KILL"));
            bpf_ringbuf_submit(e, 0);
        } else if (stats) {
            __sync_fetch_and_add(&stats->ringbuf_drops, 1);
        }

        if (audit)
            goto out_audit;
        goto out_enforce;
    }

    return 0;

out_audit:
    return 0;
out_enforce:
    return -EPERM;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    struct path_key key = {};
    __u8 *deny;
    long len;
    __u32 pid;
    __u64 cgid;
    struct event *e;
    __u32 zero = 0;
    struct {
        __u64 blocks;
        __u64 ringbuf_drops;
    } *stats;
    __u64 *cg_stat;
    __u64 *path_stat;
    __u64 zero64 = 0;
    struct task_struct *task = bpf_get_current_task_btf();

    if (!filename)
        return 0;

    len = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);
    if (len <= 0)
        return 0;

    deny = bpf_map_lookup_elem(&deny_path_map, &key);
    if (!deny)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    cgid = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&allow_cgroup_map, &cgid))
        return 0;

    stats = bpf_map_lookup_elem(&block_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->blocks, 1);

    cg_stat = bpf_map_lookup_elem(&deny_cgroup_stats, &cgid);
    if (!cg_stat) {
        bpf_map_update_elem(&deny_cgroup_stats, &cgid, &zero64, BPF_NOEXIST);
        cg_stat = bpf_map_lookup_elem(&deny_cgroup_stats, &cgid);
    }
    if (cg_stat)
        __sync_fetch_and_add(cg_stat, 1);

    path_stat = bpf_map_lookup_elem(&deny_path_stats, &key);
    if (!path_stat) {
        bpf_map_update_elem(&deny_path_stats, &key, &zero64, BPF_NOEXIST);
        path_stat = bpf_map_lookup_elem(&deny_path_stats, &key);
    }
    if (path_stat)
        __sync_fetch_and_add(path_stat, 1);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_BLOCK;
        e->block.pid = pid;
        e->block.ppid = 0;
        e->block.start_time = 0;
        e->block.parent_start_time = 0;
        e->block.cgid = cgid;
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
        if (pi) {
            e->block.ppid = pi->ppid;
            e->block.start_time = pi->start_time;
            e->block.parent_start_time = pi->parent_start_time;
        }
        bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
        e->block.ino = 0;
        e->block.dev = 0;
        __builtin_memcpy(e->block.path, key.path, sizeof(e->block.path));
        __builtin_memcpy(e->block.action, "AUDIT", sizeof("AUDIT"));
        bpf_ringbuf_submit(e, 0);
    } else if (stats) {
        __sync_fetch_and_add(&stats->ringbuf_drops, 1);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_info info = {};
    __u32 child_pid = ctx->child_pid;
    __u32 parent_pid = ctx->parent_pid;
    struct task_struct *task = bpf_get_current_task_btf();

    info.pid = child_pid;
    info.ppid = parent_pid;
    if (task)
        info.parent_start_time = BPF_CORE_READ(task, start_time);

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
