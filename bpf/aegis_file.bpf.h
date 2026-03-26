#pragma once
/*
 * AegisBPF - File access hook implementations
 *
 * LSM and tracepoint hooks for file access control:
 *   - handle_file_open (LSM)
 *   - handle_inode_permission_impl (static inline helper)
 *   - handle_inode_permission (LSM)
 *   - handle_openat (tracepoint)
 */

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!file) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
        return 0;
    }

    if (agent_cfg.file_policy_empty) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
        return 0;
    }

    /* Get inode info early for survival check */
    const struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
        return 0;
    }

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Check if inode is in deny list */
    __u8 *rule = bpf_map_lookup_elem(&deny_inode_map, &key);
    if (!rule) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
        return 0;
    }
    const __u8 rule_flags = *rule;
    const __u8 protect_only = (rule_flags & RULE_FLAG_PROTECT_VERIFIED_EXEC) &&
                              !(rule_flags & RULE_FLAG_DENY_ALWAYS);

    /* Survival allowlist - always allow critical binaries */
    if (bpf_map_lookup_elem(&survival_allowlist, &key)) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();
    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    if (protect_only) {
        if (!(agent_cfg.exec_identity_flags & EXEC_IDENTITY_FLAG_PROTECT_FILES)) {
            record_hook_latency(HOOK_FILE_OPEN, _start_ns);
            return 0;
        }
        if (current_verified_exec(pid, task)) {
            record_hook_latency(HOOK_FILE_OPEN, _start_ns);
            return 0;
        }
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
        if (!should_emit_event(sample_rate)) {
            record_hook_latency(HOOK_FILE_OPEN, _start_ns);
            return 0;
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
            set_action_string(e->block.action, 1, enforce_signal);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }

        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
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
    if (!should_emit_event(sample_rate)) {
        record_hook_latency(HOOK_FILE_OPEN, _start_ns);
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
        set_action_string(e->block.action, 0, enforce_signal);
        bpf_ringbuf_submit(e, 0);
    } else {
        increment_ringbuf_drops();
    }

    record_hook_latency(HOOK_FILE_OPEN, _start_ns);
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
    __u64 _start_ns = bpf_ktime_get_ns();
    int ret = handle_inode_permission_impl(inode, mask);
    record_hook_latency(HOOK_INODE_PERMISSION, _start_ns);
    return ret;
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
