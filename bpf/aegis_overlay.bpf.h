#pragma once
/*
 * AegisBPF - OverlayFS copy-up hook implementation
 *
 * LSM hook for detecting when a denied inode is copied from the
 * overlay lower layer to the upper layer.  When this happens, the
 * kernel allocates a new inode in the upper layer, breaking any
 * inode-based deny rules that targeted the lower-layer inode.
 *
 * This hook emits a priority event so userspace can re-resolve the
 * file path to the new upper-layer inode and propagate the deny rule.
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

    /* Check if the source (lower-layer) inode has a deny rule */
    __u8 *rule = bpf_map_lookup_elem(&deny_inode_map, &key);
    if (!rule) {
        record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
        return 0;
    }

    __u8 rule_flags = *rule;

    /* Denied inode is being copied up — emit priority event for userspace */
    __u64 cgid = bpf_get_current_cgroup_id();
    struct event *e = priority_event_reserve();
    if (e) {
        e->type = EVENT_OVERLAY_COPY_UP;
        e->overlay_copy_up.pid = bpf_get_current_pid_tgid() >> 32;
        e->overlay_copy_up._pad = 0;
        e->overlay_copy_up.cgid = cgid;
        e->overlay_copy_up.src_ino = key.ino;
        e->overlay_copy_up.src_dev = key.dev;
        e->overlay_copy_up._pad3 = 0;
        e->overlay_copy_up.deny_flags = rule_flags;
        __builtin_memset(e->overlay_copy_up._pad2, 0,
                         sizeof(e->overlay_copy_up._pad2));
        bpf_ringbuf_submit(e, 0);
        bp_record_priority_submit();
    } else {
        bp_record_priority_drop();
    }

    record_hook_latency(HOOK_INODE_COPY_UP, _start_ns);
    return 0; /* allow copy-up; deny is handled via the new inode */
}
