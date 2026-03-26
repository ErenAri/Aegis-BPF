#pragma once
/*
 * AegisBPF - Exec hook implementations
 *
 * Tracepoint and LSM hooks for exec monitoring:
 *   - handle_execve (tracepoint)
 *   - exec_identity_mode_enabled
 *   - handle_bprm_check_security (LSM)
 *   - handle_file_mmap (LSM)
 */

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 _start_ns = bpf_ktime_get_ns();
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

    /* Multi-hook correlation: mark stage 1 (tracepoint), reset binary identity */
    info.exec_stage = EXEC_STAGE_TRACEPOINT;
    info.exec_ino = 0;
    info.exec_dev = 0;

    bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);

    /* Send exec event */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_hook_latency(HOOK_EXECVE, _start_ns);
        return 0;
    }

    e->type = EVENT_EXEC;
    e->exec.pid = pid;
    e->exec.ppid = info.ppid;
    e->exec.start_time = info.start_time;
    e->exec.cgid = cgid;
    bpf_get_current_comm(e->exec.comm, sizeof(e->exec.comm));
    bpf_ringbuf_submit(e, 0);

    /* Capture full argv into a separate event */
    struct event *ae = bpf_ringbuf_reserve(&events, sizeof(*ae), 0);
    if (!ae) {
        record_hook_latency(HOOK_EXECVE, _start_ns);
        return 0;
    }

    ae->type = EVENT_EXEC_ARGV;
    ae->exec_argv.pid = pid;
    ae->exec_argv._pad = 0;
    ae->exec_argv.start_time = info.start_time;
    ae->exec_argv._pad2 = 0;
    __builtin_memset(ae->exec_argv.argv, 0, sizeof(ae->exec_argv.argv));

    int offset = 0;
    int argc = 0;

    if (argv) {
#pragma unroll
        for (int i = 0; i < MAX_ARGV_ENTRIES; i++) {
            if (offset >= MAX_ARGV_SIZE - 1)
                break;
            const char *arg = NULL;
            bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
            if (!arg)
                break;
            int remaining = MAX_ARGV_SIZE - offset;
            if (remaining <= 0)
                break;
            long len = bpf_probe_read_user_str(
                &ae->exec_argv.argv[offset], remaining, arg);
            if (len <= 0)
                break;
            offset += len;
            argc++;
        }
    }

    ae->exec_argv.argc = (__u16)argc;
    ae->exec_argv.total_len = (__u16)offset;
    bpf_ringbuf_submit(ae, 0);

    record_hook_latency(HOOK_EXECVE, _start_ns);
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
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!bprm) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    if (!exec_identity_mode_enabled()) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct task_struct *task = bpf_get_current_task_btf();
    struct process_info *pi = get_or_create_process_info(pid, task);

    /* Direct field reads from the trusted bprm pointer preserve pointer typing
     * for verifier-sensitive helpers (e.g., bpf_d_path()).
     */
    struct file *file = bprm->file;
    struct file *executable = bprm->executable;
    struct file *interpreter = bprm->interpreter;

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
        const char *interp = bprm->interp;
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

        /* Multi-hook correlation: advance to stage 2, record binary identity */
        pi->exec_stage = EXEC_STAGE_BPRM_CHECKED;
        if (file) {
            const struct inode *bprm_inode = BPF_CORE_READ(file, f_inode);
            if (bprm_inode) {
                pi->exec_ino = BPF_CORE_READ(bprm_inode, i_ino);
                pi->exec_dev = (__u32)BPF_CORE_READ(bprm_inode, i_sb, s_dev);
            }
        }
    }

    /* Optional exec allowlist enforcement (version 3+ [allow_binary_hash]). */
    if (!(agent_cfg.exec_identity_flags & EXEC_IDENTITY_FLAG_ALLOWLIST_ENFORCE)) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    if (!file) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    const struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Survival allowlist - never block critical binaries. */
    if (bpf_map_lookup_elem(&survival_allowlist, &key)) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    if (bpf_map_lookup_elem(&allow_exec_inode_map, &key)) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
        return 0;
    }

    __u8 audit = get_effective_audit_mode();
    if (audit) {
        __u8 enforce_signal = 0;
        __u32 sample_rate = get_event_sample_rate();

        increment_block_stats();
        increment_cgroup_stat(cgid);
        increment_inode_stat(&key);

        if (!should_emit_event(sample_rate)) {
            record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
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
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
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

    if (!should_emit_event(sample_rate)) {
        record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
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

    record_hook_latency(HOOK_BPRM_CHECK, _start_ns);
    return -EPERM;
}

SEC("lsm/file_mmap")
int BPF_PROG(handle_file_mmap, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    (void)reqprot;
    (void)flags;

    if (!file) {
        record_hook_latency(HOOK_FILE_MMAP, _start_ns);
        return 0;
    }

    if (!(agent_cfg.exec_identity_flags & EXEC_IDENTITY_FLAG_TRUST_RUNTIME_DEPS)) {
        record_hook_latency(HOOK_FILE_MMAP, _start_ns);
        return 0;
    }

    if (!(prot & PROT_EXEC)) {
        record_hook_latency(HOOK_FILE_MMAP, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_FILE_MMAP, _start_ns);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    struct process_info *pi = get_or_create_process_info(pid, task);
    if (!pi || !pi->exec_identity_known || !pi->verified_exec) {
        record_hook_latency(HOOK_FILE_MMAP, _start_ns);
        return 0;
    }

    if (file_is_verified_exec_identity(file)) {
        /* Multi-hook correlation: all runtime deps verified, advance stage */
        if (pi->exec_stage == EXEC_STAGE_BPRM_CHECKED)
            pi->exec_stage = EXEC_STAGE_FULLY_VERIFIED;
        record_hook_latency(HOOK_FILE_MMAP, _start_ns);
        return 0;
    }

    /*
     * Keep mmap fail-open for compatibility; downgrade trust so protected
     * resource checks fail closed for this process afterward.
     */
    pi->verified_exec = 0;
    pi->exec_identity_known = 1;
    record_hook_latency(HOOK_FILE_MMAP, _start_ns);
    return 0;
}
