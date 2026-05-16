// SPDX-License-Identifier: GPL-2.0
//
// aegis-next: ringbuf-only provenance for kernels < 6.9.
//
// Fallback BPF program that sends full events through a ringbuf instead
// of writing to a BPF arena map. Used when BPF_MAP_TYPE_ARENA is not
// available (kernels older than 6.9). Same 9 LSM hooks, same policy
// enforcement, same quarantine bridge — just a different event transport.
//
// Key differences from arena mode (provenance.bpf.c):
//   - No BPF arena map, no arena globals, no arena hash table.
//   - No path/net slabs — path and 5-tuple are inlined in each event.
//   - Events are ~372 bytes (vs 16-byte alert + 80-byte arena node).
//   - No catch-up scan (userspace graph starts empty).
//   - No in-kernel GC timer (userspace manages its own graph).
//   - Lineage is built in userspace from PID/PPID, not arena backlinks.
//
// Minimum kernel: ~5.11 (BPF LSM, ringbuf, bpf_get_current_task_btf).

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "prov_types.h"

// ---- ringbuf event struct (must match prov_arena_types.h) --------

struct net_flow {
    __u8  family;
    __u8  proto;
    __u16 src_port;
    __u16 dst_port;
    __u16 _pad;
    __u32 src_v4;
    __u32 dst_v4;
    __u8  src_v6[16];
    __u8  dst_v6[16];
};

struct prov_ringbuf_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 tgid;
    __u32 uid;
    __u64 cgid;
    __u64 object_id;
    __u8  kind;
    __u8  flags;
    __u16 extra;
    char  comm[12];
    __u32 mnt_ns;
    __u32 pid_ns;
    __u16 path_len;     // 0 = no path
    __u8  has_net;      // 0 = no flow, 1 = flow present
    __u8  _pad2;
    char  path[PATH_SLAB_SLOT_SZ]; // 256 bytes inline
    struct net_flow net;            // 48 bytes inline
};

// ---- maps (same names as arena version for pin-path compat) ------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, AEGIS_RINGBUF_PAGES * 4096);
} aegis_next_ringbuf SEC(".maps");

struct policy_key {
    __u8  hook;
    __u8  match_type;
    __u16 _pad;
    __u32 match_val;
};

struct policy_val {
    __u8  action;
    __u8  flags;
    __u16 _pad;
    __u32 _reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_key);
    __type(value, struct policy_val);
    __uint(max_entries, 1024);
} aegis_next_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 4096);
} aegis_next_quarantine SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[PATH_SLAB_SLOT_SZ]);
    __uint(max_entries, 1);
} aegis_next_path_scratch SEC(".maps");

// ---- shared helpers (same logic as arena version) ----------------

static __always_inline __u32 fnv1a_hash(const char *s, int maxlen)
{
    __u32 h = 0x811c9dc5u;
    #pragma unroll
    for (int i = 0; i < maxlen; i++) {
        char c = s[i];
        if (c == 0)
            break;
        h ^= (__u32)(unsigned char)c;
        h *= 0x01000193u;
    }
    return h;
}

static __always_inline void
apply_verdict(struct policy_val *val, __u64 cgid, int *deny)
{
    if (!val)
        return;
    if (val->action == POLICY_ACTION_DENY) {
        *deny = 1;
        if (val->flags & POLICY_FLAG_KILL)
            bpf_send_signal(9);
    } else if (val->action == POLICY_ACTION_QUARANTINE && cgid) {
        __u32 level = 1;
        bpf_map_update_elem(&aegis_next_quarantine, &cgid, &level, BPF_ANY);
    }
}

static __always_inline int
evaluate_policy(__u8 hook, const char *comm, __u16 port, __u64 cgid)
{
    struct policy_key key = {};
    struct policy_val *val;
    int deny = 0;

    key.hook = hook;

    key.match_type = POLICY_MATCH_COMM;
    key.match_val = fnv1a_hash(comm, 12);
    val = bpf_map_lookup_elem(&aegis_next_policy, &key);
    apply_verdict(val, cgid, &deny);

    if (port && !deny) {
        key.match_type = POLICY_MATCH_PORT;
        key.match_val = port;
        val = bpf_map_lookup_elem(&aegis_next_policy, &key);
        apply_verdict(val, cgid, &deny);
    }

    if (cgid && !deny) {
        key.match_type = POLICY_MATCH_CGROUP;
        key.match_val = (__u32)cgid;
        val = bpf_map_lookup_elem(&aegis_next_policy, &key);
        apply_verdict(val, cgid, &deny);
    }

    return deny ? -1 : 0;
}

// ---- event helpers -----------------------------------------------

// Fill common fields in a ringbuf event from a task_struct.
static __always_inline void
fill_common(struct prov_ringbuf_event *evt, struct task_struct *task,
            __u8 kind, __u64 object_id, __u16 extra)
{
    evt->ts_ns     = bpf_ktime_get_ns();
    evt->pid       = BPF_CORE_READ(task, pid);
    evt->tgid      = BPF_CORE_READ(task, tgid);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    evt->ppid      = parent ? BPF_CORE_READ(parent, tgid) : 0;
    evt->uid       = bpf_get_current_uid_gid() & 0xffffffff;
    evt->cgid      = bpf_get_current_cgroup_id();
    evt->object_id = object_id;
    evt->kind      = kind;
    evt->flags     = 0;
    evt->extra     = extra;

    char tmp[16];
    bpf_probe_read_kernel(tmp, sizeof(tmp), &task->comm);
    #pragma unroll
    for (int i = 0; i < 12; i++)
        evt->comm[i] = tmp[i];

    evt->mnt_ns = 0;
    evt->pid_ns = 0;
    {
        struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
        if (ns) {
            struct mnt_namespace *mnt = BPF_CORE_READ(ns, mnt_ns);
            if (mnt)
                evt->mnt_ns = BPF_CORE_READ(mnt, ns.inum);
            struct pid_namespace *pidns = BPF_CORE_READ(ns, pid_ns_for_children);
            if (pidns)
                evt->pid_ns = BPF_CORE_READ(pidns, ns.inum);
        }
    }

    evt->path_len = 0;
    evt->has_net  = 0;
    evt->_pad2    = 0;
    // Path and net fields left uninitialized; userspace checks
    // path_len and has_net before accessing them.
}

// Resolve a file path into the event's inline path field.
static __always_inline void
resolve_path_inline(struct prov_ringbuf_event *evt, struct path *p)
{
    __u32 zero = 0;
    char *scratch = bpf_map_lookup_elem(&aegis_next_path_scratch, &zero);
    if (!scratch)
        return;

    long len = bpf_d_path(p, scratch, PATH_SLAB_SLOT_SZ);
    if (len <= 0)
        return;

    // Copy from per-CPU scratch to ringbuf event (u64 at a time).
    __u64 *src = (__u64 *)scratch;
    __u64 *dst = (__u64 *)evt->path;
    #pragma unroll
    for (int i = 0; i < (PATH_SLAB_SLOT_SZ / 8); i++)
        dst[i] = src[i];

    evt->path_len = (__u16)(len > PATH_SLAB_SLOT_SZ
                            ? PATH_SLAB_SLOT_SZ : len);
}

// Fill inline net flow fields in the event.
static __always_inline void
fill_net_flow(struct prov_ringbuf_event *evt,
              __u8 family, __u8 proto,
              __u32 src_v4, __u16 src_port,
              __u32 dst_v4, __u16 dst_port,
              const __u8 *src_v6, const __u8 *dst_v6)
{
    evt->has_net       = 1;
    evt->net.family    = family;
    evt->net.proto     = proto;
    evt->net.src_port  = src_port;
    evt->net.dst_port  = dst_port;
    evt->net._pad      = 0;
    evt->net.src_v4    = src_v4;
    evt->net.dst_v4    = dst_v4;

    if (src_v6) {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            evt->net.src_v6[i] = src_v6[i];
    } else {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            evt->net.src_v6[i] = 0;
    }

    if (dst_v6) {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            evt->net.dst_v6[i] = dst_v6[i];
    } else {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            evt->net.dst_v6[i] = 0;
    }
}

// ---- LSM hooks ---------------------------------------------------

SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_legacy_on_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    __u64 exec_inode = 0;
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct inode *ino = BPF_CORE_READ(file, f_inode);
        if (ino)
            exec_inode = BPF_CORE_READ(ino, i_ino);
    }

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_EXEC, exec_inode, 0);

        struct file *bfile = bprm->file;
        if (bfile)
            resolve_path_inline(evt, &bfile->f_path);

        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_EXEC, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(aegis_legacy_on_file_open, struct file *file)
{
    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    __u16 open_flags = (__u16)(BPF_CORE_READ(file, f_flags) & 0xFFFF);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_FILE_OPEN, inode, open_flags);
        resolve_path_inline(evt, &file->f_path);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_FILE_OPEN, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(aegis_legacy_on_socket_connect,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u16 family = BPF_CORE_READ(address, sa_family);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u8  proto    = BPF_CORE_READ(sk, sk_protocol);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 src_v4   = 0, dst_v4 = 0;
    __u16 dst_port = 0;
    __u8  src_v6[16] = {}, dst_v6[16] = {};
    __u64 object_id = 0;

    if (family == 2 && addrlen >= 8) {
        src_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&dst_port, 2, (const char *)address + 2);
        dst_port = __builtin_bswap16(dst_port);
        bpf_probe_read_kernel(&dst_v4, 4, (const char *)address + 4);
        object_id = ((__u64)dst_port << 32) | dst_v4;
    } else if (family == 10 && addrlen >= 28) {
        bpf_probe_read_kernel(&dst_port, 2, (const char *)address + 2);
        dst_port = __builtin_bswap16(dst_port);
        bpf_probe_read_kernel(dst_v6, 16, (const char *)address + 8);
        bpf_probe_read_kernel(src_v6, 16,
                              &sk->__sk_common.skc_v6_rcv_saddr);
        __u32 addr_low = 0;
        bpf_probe_read_kernel(&addr_low, 4, (const char *)address + 24);
        object_id = ((__u64)dst_port << 32) | addr_low;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_SOCKET_CONNECT, object_id, family);
        fill_net_flow(evt, (__u8)family, proto, src_v4, src_port,
                      dst_v4, dst_port,
                      (family == 10) ? src_v6 : (void *)0,
                      (family == 10) ? dst_v6 : (void *)0);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_SOCKET_CONNECT, comm, dst_port, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(aegis_legacy_on_socket_bind,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u16 family = BPF_CORE_READ(address, sa_family);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u8  proto     = BPF_CORE_READ(sk, sk_protocol);
    __u32 bind_v4   = 0;
    __u16 bind_port = 0;
    __u8  bind_v6[16] = {};
    __u64 object_id = 0;

    if (family == 2 && addrlen >= 8) {
        bpf_probe_read_kernel(&bind_port, 2, (const char *)address + 2);
        bind_port = __builtin_bswap16(bind_port);
        bpf_probe_read_kernel(&bind_v4, 4, (const char *)address + 4);
        object_id = ((__u64)bind_port << 32) | bind_v4;
    } else if (family == 10 && addrlen >= 28) {
        bpf_probe_read_kernel(&bind_port, 2, (const char *)address + 2);
        bind_port = __builtin_bswap16(bind_port);
        bpf_probe_read_kernel(bind_v6, 16, (const char *)address + 8);
        __u32 addr_low = 0;
        bpf_probe_read_kernel(&addr_low, 4, (const char *)address + 24);
        object_id = ((__u64)bind_port << 32) | addr_low;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_SOCKET_BIND, object_id, family);
        fill_net_flow(evt, (__u8)family, proto, bind_v4, bind_port, 0, 0,
                      (family == 10) ? bind_v6 : (void *)0,
                      (void *)0);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_SOCKET_BIND, comm, bind_port, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(aegis_legacy_on_socket_listen,
             struct socket *sock, int backlog)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u16 family   = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8  proto    = BPF_CORE_READ(sk, sk_protocol);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 src_v4   = 0;
    __u8  src_v6[16] = {};
    __u64 object_id = 0;

    if (family == 2) {
        src_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        object_id = ((__u64)src_port << 32) | src_v4;
    } else if (family == 10) {
        bpf_probe_read_kernel(src_v6, 16,
                              &sk->__sk_common.skc_v6_rcv_saddr);
        __u32 addr_low = 0;
        __builtin_memcpy(&addr_low, &src_v6[12], 4);
        object_id = ((__u64)src_port << 32) | addr_low;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_SOCKET_LISTEN, object_id, family);
        fill_net_flow(evt, (__u8)family, proto, src_v4, src_port, 0, 0,
                      (family == 10) ? src_v6 : (void *)0,
                      (void *)0);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_SOCKET_LISTEN, comm, src_port, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(aegis_legacy_on_file_perm, struct file *file, int mask)
{
    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_FILE_PERM, inode,
                    (__u16)(mask & 0xFFFF));
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_FILE_PERM, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(aegis_legacy_on_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    if (!file)
        return 0;

    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    __u16 prot_flags = (__u16)(prot & 0xFFFF);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_MMAP_FILE, inode, prot_flags);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_MMAP_FILE, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(aegis_legacy_on_task_alloc, struct task_struct *task,
             unsigned long clone_flags)
{
    struct task_struct *current = (struct task_struct *)bpf_get_current_task_btf();

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, current, PROV_KIND_TASK_ALLOC, clone_flags, 0);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &current->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_TASK_ALLOC, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(aegis_legacy_on_kmod_req, char *kmod_name)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);

    __u32 name_hash = fnv1a_hash(comm, 12);

    struct prov_ringbuf_event *evt = bpf_ringbuf_reserve(
        &aegis_next_ringbuf, sizeof(*evt), 0);
    if (evt) {
        fill_common(evt, task, PROV_KIND_KMOD_REQ, name_hash, 0);
        bpf_ringbuf_submit(evt, 0);
    }

    {
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_KMOD_REQ, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
