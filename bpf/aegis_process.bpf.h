#pragma once
/*
 * AegisBPF - Process lifecycle hook implementations
 *
 * Tracepoint hooks for process tracking:
 *   - handle_fork (tracepoint)
 *   - handle_exit (tracepoint)
 */

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

        /* Transfer to dead process LRU for post-mortem correlation */
        struct dead_process_info dead = {};
        dead.pid = pi->pid;
        dead.ppid = pi->ppid;
        dead.start_time = pi->start_time;
        dead.parent_start_time = pi->parent_start_time;
        dead.exit_time = bpf_ktime_get_boot_ns();
        dead.verified_exec = pi->verified_exec;
        dead.exec_identity_known = pi->exec_identity_known;
        dead.exec_stage = pi->exec_stage;
        dead.exec_ino = pi->exec_ino;
        dead.exec_dev = pi->exec_dev;
        bpf_get_current_comm(dead.comm, sizeof(dead.comm));
        bpf_map_update_elem(&dead_processes, &key, &dead, BPF_ANY);

        bpf_map_delete_elem(&enforce_signal_state, &key);
    }

    bpf_map_delete_elem(&process_tree, &pid);
    return 0;
}
