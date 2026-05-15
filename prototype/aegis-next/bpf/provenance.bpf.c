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

// Arena geometry.
// Node array:  1M × 64B = 64 MiB  = 16384 pages
// Header+flag: 36B                 ~     1 page
// Hash table:  64K × 16B = 1 MiB  =   256 pages
// Total:                           = 16641 pages
#define AEGIS_NEXT_ARENA_PAGES 16641

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

#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

// Open-coded task iterator kfuncs (Linux >= 6.7).
// Used by the catch-up scan to seed the arena with all existing
// processes at attach time.
// NOTE: bpf_iter_task_new always returned int (since introduction in 6.7).
// Our original void declaration was incorrect.
extern int bpf_iter_task_new(struct bpf_iter_task *it,
                             struct task_struct *task__nullable,
                             unsigned int flags) __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;

// RCU kfuncs — required by kernel 6.17 verifier for task iteration
// in SEC("syscall") programs.
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

// NOTE: prov_layout is still defined in aegis_next_prov.hpp for
// userspace mmap access. BPF code uses arena globals directly.

// Workaround for kernel 6.17 verifier + clang-19: when accessing an
// arena global through a pointer, clang may hoist the pre-cast
// (address-space-0) base address into a register and reuse it for
// multiple field writes, skipping addr_space_cast on subsequent
// accesses. The verifier then rejects the write as "R? invalid mem
// access 'scalar'".
//
// This macro takes a pointer to an arena object, runs it through an
// inline asm barrier so clang cannot merge it with any prior register
// holding the uncasted base.
#define ARENA_PTR(ptr)                                     \
    ({                                                     \
        typeof(ptr) __p = (ptr);                           \
        asm volatile("" : "+r"(__p));                      \
        __p;                                               \
    })

#include "arena_htable.h"

// Arena-resident layout: header + node array + hash table live
// directly in the arena address space. Using both __arena (for clang
// type checking) and SEC(".addr_space.1") (for libbpf 1.5.0 section
// placement). libbpf >= 1.6.0 would auto-relocate __arena globals.
// The kernel allocates arena pages on demand (fault-in).
struct prov_header __arena arena_hdr SEC(".addr_space.1");
struct prov_node __arena arena_nodes[AEGIS_NEXT_MAX_NODES] SEC(".addr_space.1");
int __arena arena_ready SEC(".addr_space.1");
struct arena_ht_entry __arena arena_ht[ARENA_HT_BUCKETS] SEC(".addr_space.1");

// Legacy pid->slot LRU hash, kept alongside the arena hash table
// during transition. The GC timer sweeps this map; once the arena
// hash is proven reliable, this map can be removed.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);   // tgid
    __type(value, __u64); // slot index into prov_layout.nodes[]
    __uint(max_entries, 65536);
} aegis_next_pid_slot SEC(".maps");

// Check if arena has been initialized.
static __always_inline bool aegis_is_ready(void)
{
    return *(ARENA_PTR(&arena_ready)) != 0;
}

// Initialize arena header. Called from aegis_next_catchup()
// (SEC("syscall"), sleepable context) before LSM hooks attach.
static __always_inline void aegis_next_arena_init(void)
{
    ARENA_PTR(&arena_hdr)->magic = 0xA5E61500A5E61500ULL;
    ARENA_PTR(&arena_hdr)->next_index = 0;
    ARENA_PTR(&arena_hdr)->dropped = 0;
    ARENA_PTR(&arena_hdr)->generation = 0;
    *(ARENA_PTR(&arena_ready)) = 1;
}

// Reserve a slot and fill the common fields from a task_struct.
// Returns the slot index (for callers that need to patch fields).
//
// Each store to the arena node goes through ARENA_PTR() to force
// clang to emit a fresh addr_space_cast per access. Without this,
// clang's register allocator may hold the uncasted arena_nodes base
// in a spare register and reuse it for some stores, causing the
// kernel 6.17 verifier to reject the program.
static __always_inline __u64
record_base(struct task_struct *task, __u8 kind,
            __u64 object_id, __u16 extra)
{
    __u64 idx = __sync_fetch_and_add(&arena_hdr.next_index, 1);
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;

    // Bump generation counter when the arena wraps around.
    if (slot == 0 && idx > 0)
        __sync_fetch_and_add(&arena_hdr.generation, 1);

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    ARENA_PTR(&arena_nodes[slot])->ts_ns     = bpf_ktime_get_ns();
    ARENA_PTR(&arena_nodes[slot])->pid       = BPF_CORE_READ(task, pid);
    ARENA_PTR(&arena_nodes[slot])->tgid      = BPF_CORE_READ(task, tgid);
    ARENA_PTR(&arena_nodes[slot])->ppid      = parent ? BPF_CORE_READ(parent, tgid) : 0;
    ARENA_PTR(&arena_nodes[slot])->uid       = BPF_CORE_READ(task, cred, uid.val);
    ARENA_PTR(&arena_nodes[slot])->cgid      = 0;
    ARENA_PTR(&arena_nodes[slot])->object_id = object_id;
    ARENA_PTR(&arena_nodes[slot])->kind      = kind;
    ARENA_PTR(&arena_nodes[slot])->flags     = (__u8)(ARENA_PTR(&arena_hdr)->generation & 0xFF);
    ARENA_PTR(&arena_nodes[slot])->extra     = extra;

    char tmp[16];
    bpf_probe_read_kernel(tmp, sizeof(tmp), &task->comm);
    #pragma unroll
    for (int i = 0; i < 12; i++)
        ARENA_PTR(&arena_nodes[slot])->comm[i] = tmp[i];

    return slot;
}

// Record a process exec event. Updates the arena hash table and
// links to the parent's exec node via prev_index.
static __always_inline void
record_task(struct task_struct *task, __u64 exec_inode)
{
    __u64 slot = record_base(task, PROV_KIND_EXEC, exec_inode, 0);

    // Look up parent's exec slot via arena hash table.
    __u32 ppid = ARENA_PTR(&arena_nodes[slot])->ppid;
    __u64 parent_key = arena_ht_make_key(PROV_KIND_EXEC, ppid);
    __u64 parent_slot = arena_ht_lookup(arena_ht, parent_key);
    ARENA_PTR(&arena_nodes[slot])->prev_index = parent_slot;

    // Index this exec in the arena hash table.
    __u32 tgid = ARENA_PTR(&arena_nodes[slot])->tgid;
    __u64 my_key = arena_ht_make_key(PROV_KIND_EXEC, tgid);
    arena_ht_insert(arena_ht, my_key, slot);

    // Also maintain the legacy pid_slot LRU (GC still sweeps it).
    bpf_map_update_elem(&aegis_next_pid_slot, &tgid, &slot, BPF_ANY);
}

static __always_inline void
record_event(__u8 kind, __u64 object_id, __u16 extra)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u64 slot = record_base(task, kind, object_id, extra);

    // Link this event to the process's exec node via arena hash.
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __u64 exec_key = arena_ht_make_key(PROV_KIND_EXEC, tgid);
    __u64 exec_slot = arena_ht_lookup(arena_ht, exec_key);
    ARENA_PTR(&arena_nodes[slot])->prev_index = exec_slot;

    // Also index this event by (kind, object_id) for future lookups
    // (e.g. find all opens of a specific inode).
    __u64 evt_key = arena_ht_make_key(kind, object_id);
    arena_ht_insert(arena_ht, evt_key, slot);

    ARENA_PTR(&arena_nodes[slot])->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    ARENA_PTR(&arena_nodes[slot])->cgid = bpf_get_current_cgroup_id();
}

SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_next_on_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;
    if (!aegis_is_ready())
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    __u64 exec_inode = 0;
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct inode *ino = BPF_CORE_READ(file, f_inode);
        if (ino)
            exec_inode = BPF_CORE_READ(ino, i_ino);
    }

    record_task(task, exec_inode);

    // Patch cgroup/uid with helper-provided values (more accurate in LSM context).
    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    ARENA_PTR(&arena_nodes[slot])->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    ARENA_PTR(&arena_nodes[slot])->cgid = bpf_get_current_cgroup_id();

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(aegis_next_on_file_open, struct file *file)
{
    if (!aegis_is_ready())
        return 0;

    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    __u16 open_flags = (__u16)(BPF_CORE_READ(file, f_flags) & 0xFFFF);
    record_event(PROV_KIND_FILE_OPEN, inode, open_flags);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(aegis_next_on_socket_connect,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!aegis_is_ready())
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

    record_event(PROV_KIND_SOCKET_CONNECT, object_id, family);
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
    aegis_next_arena_init();

    struct task_struct *task;
    bpf_rcu_read_lock();
    bpf_for_each(task, task, NULL, BPF_TASK_ITER_ALL) {
        __u32 pid = BPF_CORE_READ(task, pid);
        __u32 tgid = BPF_CORE_READ(task, tgid);
        if (pid != tgid)
            continue;
        record_task(task, 0);
    }
    bpf_rcu_read_unlock();

    return 0;
}

// ---- in-kernel GC (timer-based pid_slot sweep) ----------------
//
// A BPF timer fires every GC_INTERVAL_NS nanoseconds, iterates the
// pid_slot LRU hash, and deletes entries whose referenced arena
// slot has been overwritten (generation tag mismatch). This keeps
// pid_slot accurate after arena wrap, preventing lineage lookups
// from following stale pointers.
//
// The timer lives inside a single-entry array map so the verifier
// can associate it with a map lifetime.

#define GC_INTERVAL_NS (30ULL * 1000 * 1000 * 1000) // 30 seconds

struct gc_state {
    struct bpf_timer timer;
    __u64 runs;       // number of GC passes completed
    __u64 evicted;    // total pid_slot entries evicted
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct gc_state);
    __uint(max_entries, 1);
} aegis_next_gc_state SEC(".maps");

// Context passed to the bpf_for_each_map_elem callback.
struct gc_ctx {
    __u8  current_gen_tag;
    __u64 evicted;
};

// Callback: check one pid_slot entry for staleness.
static long gc_check_entry(struct bpf_map *map, const __u32 *key,
                           __u64 *value, struct gc_ctx *ctx)
{
    __u64 slot = *value % AEGIS_NEXT_MAX_NODES;
    struct prov_node __arena *node = ARENA_PTR(&arena_nodes[slot]);

    if (node->flags != ctx->current_gen_tag) {
        bpf_map_delete_elem(map, key);
        ctx->evicted++;
    }
    return 0;
}

// Timer callback: runs the GC sweep.
static int gc_timer_cb(void *map, __u32 *key, struct gc_state *state)
{
    if (!aegis_is_ready())
        goto reschedule;

    struct gc_ctx ctx = {
        .current_gen_tag = (__u8)(ARENA_PTR(&arena_hdr)->generation & 0xFF),
        .evicted = 0,
    };

    bpf_for_each_map_elem(&aegis_next_pid_slot, gc_check_entry, &ctx, 0);

    state->runs++;
    state->evicted += ctx.evicted;

reschedule:
    bpf_timer_start(&state->timer, GC_INTERVAL_NS, 0);
    return 0;
}

// Arm the GC timer. Called once from userspace via
// bpf_prog_test_run_opts() after attach.
SEC("syscall")
int aegis_next_gc_start(void *ctx)
{
    __u32 key = 0;
    struct gc_state *state = bpf_map_lookup_elem(&aegis_next_gc_state, &key);
    if (!state)
        return -1;

    bpf_timer_init(&state->timer, &aegis_next_gc_state, 0 /* CLOCK_MONOTONIC */);
    bpf_timer_set_callback(&state->timer, gc_timer_cb);
    bpf_timer_start(&state->timer, GC_INTERVAL_NS, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
