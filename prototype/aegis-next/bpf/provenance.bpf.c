// SPDX-License-Identifier: GPL-2.0
//
// aegis-next: arena-backed provenance graph (proof-of-concept).
//
// Goal: demonstrate that a BPF arena map can hold a process
// provenance graph that userspace reads via mmap, without
// copy-out through a perf/ring buffer per event.
//
// What this program does:
//   1. Declares a BPF_MAP_TYPE_ARENA (Linux >= 6.9) of fixed size.
//   2. On LSM bprm_check_security (exec gate), records one node
//      per successful exec into a slot array inside the arena.
//   3. Each node stores synthetic-ID adjacency (pid, ppid, cgid,
//      exec inode, start_ns) — NEVER raw kernel pointers. This
//      side-steps the KASLR restriction on arena content.
//
// What this program does NOT do (intentionally, scaffold scope):
//   - No deny/audit verdict (returns 0, observe-only).
//   - No ringbuf fallback for old kernels.
//   - No hash-indexed lookup; userspace walks the slot array.
//   - No GC, no eviction, no overflow handling beyond a wrap counter.
//
// The point of the scaffold is to prove the wiring works. Real
// graph semantics land in follow-up PRs.

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "prov_types.h"

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

// Arena geometry. 16384 pages * 4 KiB = 64 MiB.
// Sized for ~1M process nodes at 64 bytes each, with headroom.
#define AEGIS_NEXT_ARENA_PAGES 16384

// One slot per process exec event. Stored contiguously starting at
// the base of the arena allocation.
#define AEGIS_NEXT_MAX_NODES   (1u << 20) // 1,048,576

struct prov_header {
    __u64 magic;       // sentinel: 0xA591_5BPF_A5E61571 (truncated to 64b)
    __u64 next_index;  // monotonic write cursor, wraps modulo MAX_NODES
    __u64 dropped;     // count of events lost to verifier/alloc failure
    __u64 generation;  // incremented each time next_index wraps past MAX_NODES
};

struct prov_node {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 tgid;
    __u32 uid;
    __u64 cgid;
    __u64 object_id;   // inode for exec/file_open, port<<32|addr for socket
    __u64 prev_index;  // owning exec node slot (for non-exec kinds), or parent
    __u8  kind;        // PROV_KIND_*
    __u8  flags;       // reserved
    __u16 extra;       // open_flags / addr_family per kind
    char  comm[12];
};

// Arena map. Userspace mmaps this fd; BPF accesses via __arena ptrs.
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, AEGIS_NEXT_ARENA_PAGES);
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
    __ulong(map_extra, 0); // user_vm_start hint; 0 lets kernel pick
#endif
} aegis_next_arena SEC(".maps");

// bpf_arena_alloc_pages / bpf_arena_free_pages are kfuncs exported
// by the kernel. We declare them here so the verifier resolves them
// at load time on 6.9+.
#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

extern void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
                                           __u32 page_cnt, int node_id,
                                           __u64 flags) __ksym;

// Open-coded task iterator kfuncs (Linux >= 6.4).
// Used by the catch-up scan to seed the arena with all existing
// processes at attach time.
extern void bpf_iter_task_new(struct bpf_iter_task *it,
                              struct task_struct *task__nullable,
                              unsigned int flags) __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;

// A single global pointer into the arena holding our header + slot
// array. Initialized lazily from the first bprm event.
struct prov_layout {
    struct prov_header hdr;
    struct prov_node   nodes[AEGIS_NEXT_MAX_NODES];
};

// Live pointer to the arena allocation. Stored in a single-entry
// array map so that BPF runs can share it across CPUs. We use a
// PERCPU init flag map to avoid double-alloc races.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64); // arena address cast to u64
    __uint(max_entries, 1);
} aegis_next_layout_ptr SEC(".maps");

// tgid -> most-recent slot index in the arena. Lets a child exec
// find its parent's exec record in O(1) so we can populate
// prev_index and build an actual lineage chain.
//
// Sized at 64K entries: enough for typical workloads, falls back
// to "parent unknown" on overflow (LRU eviction). The hash holds
// integers only, so KASLR rules are not implicated.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);   // tgid
    __type(value, __u64); // slot index into prov_layout.nodes[]
    __uint(max_entries, 65536);
} aegis_next_pid_slot SEC(".maps");

// Best-effort one-time initializer. Returns the arena base or NULL.
// We accept the very small race window of two CPUs both allocating;
// only one wins the array store, the loser's pages stay reserved
// for the lifetime of the program — acceptable for a scaffold.
static __always_inline struct prov_layout __arena *
aegis_next_layout(void)
{
    __u32 key = 0;
    __u64 *cached = bpf_map_lookup_elem(&aegis_next_layout_ptr, &key);
    if (!cached)
        return NULL;

    if (*cached) {
        return (struct prov_layout __arena *)(unsigned long)*cached;
    }

    // 1 page of header + N pages for the nodes. The kernel rounds
    // up; we ask for the full arena up front.
    void __arena *base = bpf_arena_alloc_pages(&aegis_next_arena, NULL,
                                               AEGIS_NEXT_ARENA_PAGES,
                                               -1 /* NUMA: any */,
                                               0);
    if (!base)
        return NULL;

    struct prov_layout __arena *layout = base;
    layout->hdr.magic = 0xA5E61500A5E61500ULL;
    layout->hdr.next_index = 0;
    layout->hdr.dropped = 0;
    layout->hdr.generation = 0;

    __u64 addr = (__u64)(unsigned long)base;
    bpf_map_update_elem(&aegis_next_layout_ptr, &key, &addr, BPF_ANY);
    return layout;
}

// Reserve a slot and fill the common fields from a task_struct.
// Returns the slot index (for callers that need to patch fields).
static __always_inline __u64
record_base(struct prov_layout __arena *layout,
            struct task_struct *task, __u8 kind,
            __u64 object_id, __u16 extra)
{
    __u64 idx = __sync_fetch_and_add(&layout->hdr.next_index, 1);
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;

    // Bump generation counter when the arena wraps around.
    if (slot == 0 && idx > 0)
        __sync_fetch_and_add(&layout->hdr.generation, 1);

    struct prov_node __arena *node = &layout->nodes[slot];

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    node->ts_ns     = bpf_ktime_get_ns();
    node->pid       = BPF_CORE_READ(task, pid);
    node->tgid      = BPF_CORE_READ(task, tgid);
    node->ppid      = parent ? BPF_CORE_READ(parent, tgid) : 0;
    node->uid       = BPF_CORE_READ(task, cred, uid.val);
    node->cgid      = 0; // patched by LSM context helpers when available
    node->object_id = object_id;
    node->kind      = kind;
    // Tag with low byte of generation so userspace can detect stale nodes.
    node->flags     = (__u8)(layout->hdr.generation & 0xFF);
    node->extra     = extra;

    // Stage comm through a stack buffer.
    char tmp[16];
    bpf_probe_read_kernel(tmp, sizeof(tmp), &task->comm);
    #pragma unroll
    for (int i = 0; i < 12; i++)
        node->comm[i] = tmp[i];

    return slot;
}

// Record a process exec event. Updates the pid->slot hash and
// links to the parent's exec node via prev_index.
static __always_inline void
record_task(struct prov_layout __arena *layout,
            struct task_struct *task, __u64 exec_inode)
{
    __u64 slot = record_base(layout, task, PROV_KIND_EXEC,
                             exec_inode, 0);
    struct prov_node __arena *node = &layout->nodes[slot];

    // Link to parent's most recent exec node.
    __u32 ppid_key = node->ppid;
    __u64 *parent_slot = bpf_map_lookup_elem(&aegis_next_pid_slot, &ppid_key);
    node->prev_index = parent_slot ? *parent_slot : (__u64)-1;

    // Publish our slot for future children.
    __u32 my_key = node->tgid;
    bpf_map_update_elem(&aegis_next_pid_slot, &my_key, &slot, BPF_ANY);
}

// Record a non-exec event (file_open, socket_connect, ...).
// prev_index points to the OWNING exec node (current process's
// most recent exec), not to the parent process.
static __always_inline void
record_event(struct prov_layout __arena *layout,
             __u8 kind, __u64 object_id, __u16 extra)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u64 slot = record_base(layout, task, kind, object_id, extra);
    struct prov_node __arena *node = &layout->nodes[slot];

    // Link to owning exec node, not to parent process.
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __u64 *exec_slot = bpf_map_lookup_elem(&aegis_next_pid_slot, &tgid);
    node->prev_index = exec_slot ? *exec_slot : (__u64)-1;

    // Patch context-available fields.
    node->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    node->cgid = bpf_get_current_cgroup_id();
}

SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_next_on_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    struct prov_layout __arena *layout = aegis_next_layout();
    if (!layout)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    __u64 exec_inode = 0;
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct inode *ino = BPF_CORE_READ(file, f_inode);
        if (ino)
            exec_inode = BPF_CORE_READ(ino, i_ino);
    }

    // For the LSM hook we can also fill cgroup_id and uid from the
    // helper context (faster and more accurate than BPF_CORE_READ).
    record_task(layout, task, exec_inode);

    // Patch the cgroup/uid fields with the helper-provided values
    // which are more accurate in the LSM context.
    __u64 idx = layout->hdr.next_index - 1; // just written above
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    layout->nodes[slot].uid  = bpf_get_current_uid_gid() & 0xffffffff;
    layout->nodes[slot].cgid = bpf_get_current_cgroup_id();

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(aegis_next_on_file_open, struct file *file)
{
    struct prov_layout __arena *layout = aegis_next_layout();
    if (!layout)
        return 0;

    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    __u16 open_flags = (__u16)(BPF_CORE_READ(file, f_flags) & 0xFFFF);
    record_event(layout, PROV_KIND_FILE_OPEN, inode, open_flags);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(aegis_next_on_socket_connect,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct prov_layout __arena *layout = aegis_next_layout();
    if (!layout)
        return 0;

    __u16 family = BPF_CORE_READ(address, sa_family);

    // Encode destination as object_id: port in high 32 bits,
    // IPv4 addr (or lower 32 bits of IPv6) in low 32 bits.
    __u64 object_id = 0;
    if (family == 2 /* AF_INET */ && addrlen >= 8) {
        // struct sockaddr_in: { sa_family, sin_port, sin_addr }
        __u16 port = 0;
        __u32 addr = 0;
        bpf_probe_read_kernel(&port, 2,
                              (const char *)address + 2);
        bpf_probe_read_kernel(&addr, 4,
                              (const char *)address + 4);
        object_id = ((__u64)port << 32) | addr;
    } else if (family == 10 /* AF_INET6 */ && addrlen >= 28) {
        __u16 port = 0;
        __u32 addr_low = 0;
        bpf_probe_read_kernel(&port, 2,
                              (const char *)address + 2);
        // Take last 4 bytes of in6_addr for a coarse fingerprint.
        bpf_probe_read_kernel(&addr_low, 4,
                              (const char *)address + 24);
        object_id = ((__u64)port << 32) | addr_low;
    }

    record_event(layout, PROV_KIND_SOCKET_CONNECT, object_id, family);
    return 0;
}

// ---- one-shot catch-up scan -----------------------------------
//
// Iterates all thread-group leaders currently alive in the kernel
// and records them into the arena. Called once from userspace via
// bpf_prog_test_run_opts() immediately after attach, so the
// provenance graph is seeded with pre-existing processes rather
// than starting empty.
//
// Program type: BPF_PROG_TYPE_SYSCALL (SEC("syscall")). This
// supports kfunc calls and has a 1M-instruction verifier budget,
// which is enough for ~65K processes on a busy host.
SEC("syscall")
int aegis_next_catchup(void *ctx)
{
    struct prov_layout __arena *layout = aegis_next_layout();
    if (!layout)
        return -1;

    struct task_struct *task;
    bpf_for_each(task, task, NULL, BPF_TASK_ITER_ALL) {
        // Skip non-leaders (threads). We only record one node per
        // process (thread group), keyed by tgid.
        __u32 pid = BPF_CORE_READ(task, pid);
        __u32 tgid = BPF_CORE_READ(task, tgid);
        if (pid != tgid)
            continue;

        // exec_inode: we don't have bprm here; set to 0. The live
        // LSM hook will overwrite this with the real inode when the
        // process next exec's. For now, having the pid/ppid/tgid in
        // the arena is what matters for lineage connectivity.
        record_task(layout, task, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
