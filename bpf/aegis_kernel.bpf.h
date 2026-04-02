#pragma once
/*
 * AegisBPF - Kernel security hook implementations
 *
 * LSM hooks for kernel-level attack surface reduction (MITRE ATT&CK):
 *   - handle_ptrace_access_check (LSM) — T1055.008 Process Injection via ptrace
 *   - handle_kernel_module_request (LSM) — T1547.006 Kernel Module Persistence
 *   - handle_bpf (LSM) — T1562 Impair Defenses via malicious BPF
 */

/*
 * LSM hook: ptrace_access_check
 *
 * Called when a process attempts to ptrace another. Blocks the operation
 * when deny_ptrace is enabled in agent_config, preventing:
 *   - Memory inspection/modification of other processes
 *   - Process injection attacks
 *   - Credential harvesting from running processes
 *
 * MITRE ATT&CK: T1055.008 (Ptrace System Calls)
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(handle_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    __u64 _start_ns = bpf_ktime_get_ns();

    const volatile struct agent_config *cfg = &agent_cfg;
    if (!cfg->deny_ptrace) {
        record_hook_latency(HOOK_PTRACE, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups (e.g. aegis agent's own cgroup) */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_PTRACE, _start_ns);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();

    __u32 target_pid = 0;
    if (child)
        target_pid = BPF_CORE_READ(child, tgid);

    __u8 audit = get_effective_audit_mode();
    __u8 enforce_signal = 0;
    if (!audit) {
        enforce_signal = get_effective_enforce_signal();
    }

    /* Update statistics */
    increment_block_stats();
    increment_cgroup_stat(cgid);

    /* Send kernel block event */
    __u32 sample_rate = get_event_sample_rate();
    if (should_emit_event(sample_rate)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_KERNEL_PTRACE_BLOCK;
            e->kernel_block.pid = pid;
            e->kernel_block.ppid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
            e->kernel_block.start_time = task ? BPF_CORE_READ(task, start_time) : 0;
            e->kernel_block.parent_start_time = task ? BPF_CORE_READ(task, real_parent, start_time) : 0;
            e->kernel_block.cgid = cgid;
            bpf_get_current_comm(e->kernel_block.comm, sizeof(e->kernel_block.comm));
            e->kernel_block.target_pid = target_pid;
            e->kernel_block._pad = 0;
            set_action_string(e->kernel_block.action, audit, enforce_signal);
            __builtin_memcpy(e->kernel_block.rule_type, "ptrace\0\0\0\0\0\0\0\0\0", 16);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }
    }

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    record_hook_latency(HOOK_PTRACE, _start_ns);
    return audit ? 0 : -EPERM;
}

/*
 * LSM hook: locked_down
 *
 * Called when the kernel checks if an operation should be locked down.
 * We intercept LOCKDOWN_MODULE_SIGNATURE to block unsigned module loading
 * when deny_module_load is enabled.
 *
 * MITRE ATT&CK: T1547.006 (Kernel Modules and Extensions)
 */
SEC("lsm/locked_down")
int BPF_PROG(handle_locked_down, enum lockdown_reason what)
{
    __u64 _start_ns = bpf_ktime_get_ns();

    const volatile struct agent_config *cfg = &agent_cfg;
    if (!cfg->deny_module_load) {
        record_hook_latency(HOOK_MODULE_LOAD, _start_ns);
        return 0;
    }

    /* Only intercept module-related lockdown checks.
     * LOCKDOWN_MODULE_SIGNATURE = 1 in the kernel enum. */
    if (what != 1) {
        record_hook_latency(HOOK_MODULE_LOAD, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_MODULE_LOAD, _start_ns);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();

    __u8 audit = get_effective_audit_mode();
    __u8 enforce_signal = 0;
    if (!audit) {
        enforce_signal = get_effective_enforce_signal();
    }

    increment_block_stats();
    increment_cgroup_stat(cgid);

    __u32 sample_rate = get_event_sample_rate();
    if (should_emit_event(sample_rate)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_KERNEL_MODULE_BLOCK;
            e->kernel_block.pid = pid;
            e->kernel_block.ppid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
            e->kernel_block.start_time = task ? BPF_CORE_READ(task, start_time) : 0;
            e->kernel_block.parent_start_time = task ? BPF_CORE_READ(task, real_parent, start_time) : 0;
            e->kernel_block.cgid = cgid;
            bpf_get_current_comm(e->kernel_block.comm, sizeof(e->kernel_block.comm));
            e->kernel_block.target_pid = 0;
            e->kernel_block._pad = 0;
            set_action_string(e->kernel_block.action, audit, enforce_signal);
            __builtin_memcpy(e->kernel_block.rule_type, "module\0\0\0\0\0\0\0\0\0", 16);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }
    }

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    record_hook_latency(HOOK_MODULE_LOAD, _start_ns);
    return audit ? 0 : -EPERM;
}

/*
 * LSM hook: bpf
 *
 * Called when a process attempts to execute the bpf() syscall.
 * Blocks unauthorized BPF program loading when deny_bpf is enabled,
 * preventing an attacker from loading malicious BPF programs to:
 *   - Bypass security monitoring
 *   - Exfiltrate data via packet-level access
 *   - Escalate privileges via verifier exploits
 *
 * MITRE ATT&CK: T1562 (Impair Defenses)
 */
SEC("lsm/bpf")
int BPF_PROG(handle_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    __u64 _start_ns = bpf_ktime_get_ns();

    const volatile struct agent_config *cfg = &agent_cfg;
    if (!cfg->deny_bpf) {
        record_hook_latency(HOOK_BPF, _start_ns);
        return 0;
    }

    /* Only block program loading (BPF_PROG_LOAD = 5) and map creation
     * (BPF_MAP_CREATE = 0). Allow read-only operations like BPF_OBJ_GET,
     * BPF_MAP_LOOKUP_ELEM so existing programs continue to function. */
    if (cmd != 5 && cmd != 0) {
        record_hook_latency(HOOK_BPF, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Always allow the agent's own cgroup */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_BPF, _start_ns);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();

    __u8 audit = get_effective_audit_mode();
    __u8 enforce_signal = 0;
    if (!audit) {
        enforce_signal = get_effective_enforce_signal();
    }

    increment_block_stats();
    increment_cgroup_stat(cgid);

    __u32 sample_rate = get_event_sample_rate();
    if (should_emit_event(sample_rate)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_KERNEL_BPF_BLOCK;
            e->kernel_block.pid = pid;
            e->kernel_block.ppid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
            e->kernel_block.start_time = task ? BPF_CORE_READ(task, start_time) : 0;
            e->kernel_block.parent_start_time = task ? BPF_CORE_READ(task, real_parent, start_time) : 0;
            e->kernel_block.cgid = cgid;
            bpf_get_current_comm(e->kernel_block.comm, sizeof(e->kernel_block.comm));
            e->kernel_block.target_pid = 0;
            e->kernel_block._pad = 0;
            set_action_string(e->kernel_block.action, audit, enforce_signal);
            __builtin_memcpy(e->kernel_block.rule_type, "bpf\0\0\0\0\0\0\0\0\0\0\0\0", 16);
            bpf_ringbuf_submit(e, 0);
        } else {
            increment_ringbuf_drops();
        }
    }

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    record_hook_latency(HOOK_BPF, _start_ns);
    return audit ? 0 : -EPERM;
}
