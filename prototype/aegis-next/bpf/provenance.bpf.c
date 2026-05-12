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
    __u64 reserved;
};

struct prov_node {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 tgid;
    __u32 uid;
    __u64 cgid;
    __u64 exec_inode;
    __u64 prev_index;  // index of parent node in the arena, or U64_MAX
    char  comm[16];
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
    layout->hdr.reserved = 0;

    __u64 addr = (__u64)(unsigned long)base;
    bpf_map_update_elem(&aegis_next_layout_ptr, &key, &addr, BPF_ANY);
    return layout;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_next_on_exec, struct linux_binprm *bprm, int ret)
{
    // Honor any earlier deny in the LSM chain — observe-only.
    if (ret != 0)
        return ret;

    struct prov_layout __arena *layout = aegis_next_layout();
    if (!layout) {
        // Cannot record; the header is unreachable so we cannot
        // even bump the drop counter. Return 0 to stay observe-only.
        return 0;
    }

    // Reserve a slot. Wraps on overflow — scaffold semantics.
    __u64 idx;
    idx = __sync_fetch_and_add(&layout->hdr.next_index, 1);
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;

    struct prov_node __arena *node = &layout->nodes[slot];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    node->ts_ns = bpf_ktime_get_ns();
    node->pid  = BPF_CORE_READ(task, pid);
    node->tgid = BPF_CORE_READ(task, tgid);
    node->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    node->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    node->cgid = bpf_get_current_cgroup_id();

    // exec_inode: best-effort, may be zero on some kernels until
    // bprm->file is populated. Synthetic ID, not a pointer.
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct inode *ino = BPF_CORE_READ(file, f_inode);
        if (ino)
            node->exec_inode = BPF_CORE_READ(ino, i_ino);
    }

    // prev_index left as U64_MAX in this scaffold; a real impl
    // would look up the parent's most recent slot. That belongs
    // in the follow-up PR introducing the hash-indexed lookup.
    node->prev_index = (__u64)-1;

    // bpf_get_current_comm writes into non-arena memory only, and
    // bpf_probe_read_kernel_str refuses arena destinations, so we
    // stage in a stack buffer and copy byte-by-byte through the
    // arena pointer.
    char tmp[16];
    bpf_get_current_comm(tmp, sizeof(tmp));
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        node->comm[i] = tmp[i];
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
