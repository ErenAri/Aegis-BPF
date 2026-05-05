#pragma once
/*
 * AegisBPF - OverlayFS copy-up hook implementation
 *
 * The kernel calls security_inode_copy_up before copying a file from
 * the overlay lower layer to the upper layer. The upper-layer copy
 * receives a fresh inode that is not in deny_inode_map; without this
 * hook, an inode-based deny rule on a lower-layer file would be
 * silently bypassed the moment a containerised workload modifies the
 * file (the canonical container-escape pattern that motivates this
 * mitigation).
 *
 * Two enforcement strategies coexist, selected by the source rule's
 * flag bits:
 *
 *   * RULE_FLAG_DENY_ALWAYS -- race-free in-kernel deny. We return
 *     -EPERM directly from the hook so the upper-layer inode is never
 *     created. This closes the TOCTOU window that exists when the
 *     decision is punted to userspace (between the copy-up returning
 *     and the daemon stat()-and-propagate path completing, the
 *     upper-layer file would otherwise be fully accessible). An
 *     EVENT_BLOCK is emitted with action set per the standard
 *     audit/enforce_signal logic so SIEM pipelines see overlay denies
 *     in the same shape as file_open denies.
 *
 *   * RULE_FLAG_PROTECT_VERIFIED_EXEC (without DENY_ALWAYS) -- keep
 *     the existing event-based propagation. The verified-exec workflow
 *     needs the new upper-layer inode to be reachable so userspace can
 *     stamp identity onto it; denying copy-up here would prevent
 *     legitimate updates of allowed-but-tracked binaries. We emit an
 *     EVENT_OVERLAY_COPY_UP priority event and let
 *     on_overlay_copy_up_propagate() add the upper-layer inode to the
 *     deny map.
 *
 * Audit-only mode (agent_cfg.audit_only or get_effective_audit_mode())
 * downgrades the deny path to observation: the BLOCK event is still
 * emitted, but the hook returns 0 so the syscall succeeds.
 */

SEC("lsm/inode_copy_up")
int BPF_PROG(handle_inode_copy_up, struct dentry *src, struct cred **new_cred)
{
    __u64 _start_ns = bpf_ktime_get_ns();

    if (!src) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    if (agent_cfg.file_policy_empty) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(src, d_inode);
    if (!inode) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    struct inode_id key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

    /* Only the source (lower-layer) inode is checked here. The upper
     * inode does not exist yet at copy-up time; the kernel decides
     * whether to allocate it based on this hook's return value. */
    __u8 *rule = bpf_map_lookup_elem(&deny_inode_map, &key);
    if (!rule) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    const __u8 rule_flags = *rule;

    /* Survival allowlist - never block critical binaries. Symmetric
     * with file_open: if a misconfigured rule lands on init/systemd,
     * the agent must not break the host. */
    if (bpf_map_lookup_elem(&survival_allowlist, &key)) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Allowed cgroups bypass the global deny (per-workload allowlist
     * still applies to cgroup-scoped rules, but those use the
     * cgroup_inode_denied map; copy-up only consults global rules). */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    const __u8 deny_always = rule_flags & RULE_FLAG_DENY_ALWAYS;
    const __u8 protect_only = (rule_flags & RULE_FLAG_PROTECT_VERIFIED_EXEC) && !deny_always;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (protect_only) {
        /* Verified-exec-only rules: allow the copy-up to proceed and
         * let userspace propagate the deny rule to the new upper-layer
         * inode via on_overlay_copy_up_propagate(). The window between
         * copy-up completion and propagation is acceptable for this
         * rule class because verified-exec checks happen at exec time
         * (lsm/bprm_check_security), not at file_open time, and the
         * propagation typically completes before any exec attempt. */
        struct event *e = priority_event_reserve();
        if (e) {
            e->type = EVENT_OVERLAY_COPY_UP;
            e->overlay_copy_up.pid = pid;
            e->overlay_copy_up._pad = 0;
            e->overlay_copy_up.cgid = cgid;
            e->overlay_copy_up.src_ino = key.ino;
            e->overlay_copy_up.src_dev = key.dev;
            e->overlay_copy_up._pad3 = 0;
            e->overlay_copy_up.deny_flags = rule_flags;
            __builtin_memset(e->overlay_copy_up._pad2, 0, sizeof(e->overlay_copy_up._pad2));
            bpf_ringbuf_submit(e, 0);
            bp_record_priority_submit();
        } else {
            bp_record_priority_drop();
        }
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    /* DENY_ALWAYS rule: race-free in-kernel deny of the copy-up. */
    const __u8 audit = get_effective_audit_mode();
    const __u8 enforce_signal = audit ? 0 : get_effective_enforce_signal();

    increment_block_stats();
    increment_cgroup_stat(cgid);
    increment_inode_stat(&key);

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    const __u32 sample_rate = get_event_sample_rate();
    if (should_emit_event(sample_rate)) {
        struct task_struct *task = bpf_get_current_task_btf();
        struct event *e = priority_event_reserve();
        int used_priority = (e != NULL);
        if (!e) {
            e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        }
        if (e) {
            e->type = EVENT_BLOCK;
            fill_block_event_process_info(&e->block, pid, task);
            e->block.cgid = cgid;
            bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
            e->block.ino = key.ino;
            e->block.dev = key.dev;
            /* No race-free path resolution for copy-up: the file's
             * path in the merged overlay view requires bpf_d_path on
             * the dentry the kernel is materialising, which doesn't
             * exist yet at this hook. Userspace can correlate via
             * (ino, dev). */
            __builtin_memset(e->block.path, 0, sizeof(e->block.path));
            set_action_string(e->block.action, audit, enforce_signal);
            bpf_ringbuf_submit(e, 0);
            if (used_priority) {
                bp_record_priority_submit();
            }
        } else {
            increment_ringbuf_drops();
            bp_record_priority_drop();
        }
    }

    record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
    return audit ? 0 : -EPERM;
}
