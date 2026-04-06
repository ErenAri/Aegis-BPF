#pragma once
/*
 * AegisBPF - IMA-based file integrity verification
 *
 * Optional LSM hook that uses bpf_ima_file_hash() (kernel 6.1+) to compute
 * the SHA-256 hash of a binary at exec time and verify it against a trusted
 * hash allowlist.  This provides cryptographic file integrity monitoring (FIM)
 * at the kernel level without requiring fs-verity setup on every binary.
 *
 * This program is compiled into the same BPF object but ONLY attached by
 * userspace when:
 *   1. Kernel version >= 6.1 (bpf_ima_file_hash available)
 *   2. CONFIG_IMA is enabled (IMA subsystem present)
 *   3. EXEC_IDENTITY_FLAG_USE_IMA_HASH is set in agent config
 *
 * On older kernels, this program is simply not attached and the existing
 * fs-verity verification path in handle_bprm_check_security continues to
 * operate unchanged.
 *
 * Multiple LSM programs on the same hook compose with "most restrictive wins":
 * if this program returns -EPERM, the exec is denied regardless of what the
 * other bprm_check_security program returns.
 */

SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm_ima_check, struct linux_binprm *bprm)
{
    __u64 _start_ns = bpf_ktime_get_ns();

    if (!bprm) {
        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0;
    }

    const volatile struct agent_config *cfg = &agent_cfg;
    __u8 flags = cfg->exec_identity_flags;

    /* Only active when IMA hash mode is explicitly enabled */
    if (!(flags & EXEC_IDENTITY_FLAG_USE_IMA_HASH)) {
        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0;
    }

    struct file *file = bprm->file;
    if (!file) {
        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0;
    }

    /* Compute the IMA hash of the binary being executed.
     * bpf_ima_file_hash returns the number of bytes written on success,
     * or a negative error code.  The hash algorithm depends on the IMA
     * policy (SHA-256 by default on most distributions). */
    struct exec_hash_key hash_key = {};
    long ret = bpf_ima_file_hash(file, hash_key.sha256, sizeof(hash_key.sha256));
    if (ret < 0) {
        /* IMA hash unavailable for this file (e.g., not yet appraised).
         * Fail-open: let the existing fs-verity path handle it. */
        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0;
    }

    /* Look up the computed hash in the trusted exec hash map */
    __u8 *trusted = bpf_map_lookup_elem(&trusted_exec_hash, &hash_key);
    if (trusted) {
        /* Hash found in trusted allowlist — allow execution */
        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0;
    }

    /* Hash NOT in trusted allowlist.
     * In audit mode: log but allow.
     * In enforce mode: deny with -EPERM. */
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (audit) {
        /* Emit a forensic event for the untrusted exec in audit mode.
         * Ring buffers are size-flexible, so we reserve a forensic_event
         * directly rather than going through the struct event union. */
        struct forensic_event *fe = bpf_ringbuf_reserve(&events, sizeof(*fe), 0);
        if (fe) {
            fe->type = EVENT_FORENSIC_BLOCK;
            struct task_struct *task = bpf_get_current_task_btf();
            fe->pid = pid;
            fe->ppid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
            fe->_pad = 0;
            fe->start_time = task ? BPF_CORE_READ(task, start_time) : 0;
            fe->parent_start_time = task ? BPF_CORE_READ(task, real_parent, start_time) : 0;
            fe->cgid = cgid;
            bpf_get_current_comm(fe->comm, sizeof(fe->comm));

            struct inode *inode = BPF_CORE_READ(file, f_inode);
            if (inode) {
                fe->ino = BPF_CORE_READ(inode, i_ino);
                fe->dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
                fe->uid = BPF_CORE_READ(inode, i_uid.val);
                fe->gid = BPF_CORE_READ(inode, i_gid.val);
            }
            fe->exec_stage = EXEC_STAGE_BPRM_CHECKED;
            fe->verified_exec = 0;
            fe->exec_identity_known = 1;
            __builtin_memcpy(fe->action, "AUDIT\0\0\0", 8);
            bpf_ringbuf_submit(fe, 0);
        }

        record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
        return 0; /* audit: allow */
    }

    /* Enforce mode: deny execution of untrusted binary */
    struct forensic_event *fe = bpf_ringbuf_reserve(&priority_events, sizeof(*fe), 0);
    if (fe) {
        fe->type = EVENT_FORENSIC_BLOCK;
        struct task_struct *task = bpf_get_current_task_btf();
        fe->pid = pid;
        fe->ppid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
        fe->_pad = 0;
        fe->start_time = task ? BPF_CORE_READ(task, start_time) : 0;
        fe->parent_start_time = task ? BPF_CORE_READ(task, real_parent, start_time) : 0;
        fe->cgid = cgid;
        bpf_get_current_comm(fe->comm, sizeof(fe->comm));

        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            fe->ino = BPF_CORE_READ(inode, i_ino);
            fe->dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
            fe->uid = BPF_CORE_READ(inode, i_uid.val);
            fe->gid = BPF_CORE_READ(inode, i_gid.val);
        }
        fe->exec_stage = EXEC_STAGE_BPRM_CHECKED;
        fe->verified_exec = 0;
        fe->exec_identity_known = 1;
        __builtin_memcpy(fe->action, "BLOCK\0\0\0", 8);
        bpf_ringbuf_submit(fe, 0);
        bp_record_priority_submit();
    } else {
        bp_record_priority_drop();
    }

    record_hook_latency(HOOK_BPRM_IMA_CHECK, _start_ns);
    return -EPERM;
}
