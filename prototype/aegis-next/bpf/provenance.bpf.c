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
// What this program implements (beyond the initial scaffold):
//   - Arena hash table (64K buckets, 8-step linear probe) for O(1) lookup
//   - Policy-driven enforcement: deny/quarantine/kill via evaluate_policy()
//   - In-kernel rate limiting with automatic quarantine bridge
//   - Ringbuf alerts for sub-ms detection latency
//   - Path resolution via bpf_d_path() + arena path slab (4K × 256B)
//   - Network 5-tuple recording via arena net slab (4K × 48B)
//   - Namespace awareness (mnt_ns, pid_ns in prov_node)
//   - user_ringbuf for zero-copy policy hot-reload
//   - File security labeling via bpf_set_dentry_xattr (6.13+)
//   - Targeted signal delivery via bpf_send_signal_task (6.13+)
//   - In-kernel GC via BPF timer (pid_slot sweep every 30s)
//   - Catch-up scan seeding via open-coded task iterator
//   - See provenance_legacy.bpf.c for ringbuf fallback (kernel < 6.9)

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "prov_types.h"

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

// Arena geometry (80-byte nodes):
// arena_hdr(32) + arena_nodes(80*1M) + arena_ready(4) + pad(4)
// + arena_ht(16*64K) + path_slab_next(8) + path_slab(256*4K)
// + net_slab_next(8) + net_slab(48*4K)
// = 86,179,896 bytes → 21041 pages
#define AEGIS_NEXT_ARENA_PAGES 21041

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
    __u8  flags;       // generation tag
    __u16 extra;       // open_flags / addr_family per kind
    __u32 path_slab_idx; // index into path_slab[], 0 = no path
    char  comm[12];
    __u32 net_slab_idx; // 1-based index into net_slab[], 0 = no flow
    __u32 mnt_ns;       // mount namespace inum
    __u32 pid_ns;       // PID namespace inum
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

// ---- Phase 4 kfuncs (weak — absent at runtime is OK) ----

// bpf_send_signal_task: send a signal to a specific task (6.13+).
// More precise than bpf_send_signal() which targets current task only.
extern int bpf_send_signal_task(struct task_struct *task,
                                 int sig, enum pid_type type,
                                 __u64 value) __ksym __weak;

// bpf_task_from_vpid: resolve a virtual PID to a task_struct (6.5+).
// Namespace-aware — resolves within the caller's PID namespace.
extern struct task_struct *bpf_task_from_vpid(pid_t vpid) __ksym __weak;
extern void bpf_task_release(struct task_struct *p) __ksym __weak;

// xattr kfuncs for file security labeling (6.8+ / 6.13+).
extern int bpf_get_file_xattr(struct file *file, const char *name__str,
                               struct bpf_dynptr *value_p) __ksym __weak;
extern int bpf_set_dentry_xattr(struct dentry *dentry, const char *name__str,
                                 const struct bpf_dynptr *value_p,
                                 int flags) __ksym __weak;

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

// Path slab: fixed 256-byte slots for resolved file paths.
// Allocated via atomic bump pointer with wrap-around.
#define PATH_SLAB_SLOTS   (1u << 12)  // 4096
#define PATH_SLAB_SLOT_SZ 256

struct path_slab_entry {
    __u64 data[PATH_SLAB_SLOT_SZ / 8]; // 32 × u64 = 256 bytes
};

// Network flow entry — 48-byte 5-tuple for socket events.
struct net_flow {
    __u8  family;       // AF_INET=2, AF_INET6=10
    __u8  proto;        // IPPROTO_TCP=6, IPPROTO_UDP=17, etc.
    __u16 src_port;     // host byte order
    __u16 dst_port;     // host byte order
    __u16 _pad;
    __u32 src_v4;       // network byte order; 0 for IPv6
    __u32 dst_v4;       // network byte order; 0 for IPv6
    __u8  src_v6[16];   // full IPv6 src; zeroed for IPv4
    __u8  dst_v6[16];   // full IPv6 dst; zeroed for IPv4
};

// Arena-resident layout: header + node array + hash table + path slab
// + net slab live directly in the arena address space.
struct prov_header __arena arena_hdr SEC(".addr_space.1");
struct prov_node __arena arena_nodes[AEGIS_NEXT_MAX_NODES] SEC(".addr_space.1");
int __arena arena_ready SEC(".addr_space.1");
struct arena_ht_entry __arena arena_ht[ARENA_HT_BUCKETS] SEC(".addr_space.1");
__u64 __arena path_slab_next SEC(".addr_space.1");
struct path_slab_entry __arena path_slab[PATH_SLAB_SLOTS] SEC(".addr_space.1");
__u64 __arena net_slab_next SEC(".addr_space.1");
struct net_flow __arena net_slab[NET_SLAB_SLOTS] SEC(".addr_space.1");

// Per-CPU scratch buffer for bpf_d_path(). Stack is too small (512B)
// for a 256-byte path + other locals, so we use a per-CPU array.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[PATH_SLAB_SLOT_SZ]);
    __uint(max_entries, 1);
} aegis_next_path_scratch SEC(".maps");

// Ringbuf alert struct — compact notification per LSM event.
struct aegis_alert {
    __u64 slot;    // arena node slot index
    __u32 pid;     // process tgid
    __u8  kind;    // PROV_KIND_*
    __u8  _pad[3];
};

// Ringbuf for real-time event alerts. Userspace polls this instead
// of sleeping; the arena remains the source of truth.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, AEGIS_RINGBUF_PAGES * 4096);
} aegis_next_ringbuf SEC(".maps");

// Policy map — BPF_MAP_TYPE_HASH for fast O(1) rule lookup.
// Userspace loads rules via bpf_map_update_elem.
struct policy_key {
    __u8  hook;        // PROV_KIND_*
    __u8  match_type;  // POLICY_MATCH_*
    __u16 _pad;
    __u32 match_val;   // FNV hash of comm/path, port number, or cgid low bits
};

struct policy_val {
    __u8  action;      // POLICY_ACTION_*
    __u8  flags;       // POLICY_FLAG_*
    __u16 _pad;
    __u32 _reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_key);
    __type(value, struct policy_val);
    __uint(max_entries, 1024);
} aegis_next_policy SEC(".maps");

// Quarantine map — shared with quarantine.bpf.c (sched_ext scheduler).
// When a policy rule has action=QUARANTINE, evaluate_policy() writes
// the offending cgroup id here directly from BPF — no userspace
// round-trip. The sched_ext enqueue path reads this same map.
// At load time, userspace reuses the pinned map FD so both BPF
// programs share the same underlying map instance.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // cgroup id
    __type(value, __u32); // quarantine level
    __uint(max_entries, 4096);
} aegis_next_quarantine SEC(".maps");

// ---- Phase 4: user_ringbuf for zero-copy policy hot-reload ----
//
// Instead of calling bpf_map_update_elem() per policy rule (which
// takes a syscall per rule and serializes on the map lock), userspace
// writes a batch of policy_msg structs into a user_ringbuf. A BPF
// callback processes them in-kernel with zero copies and no syscall
// overhead. This enables sub-microsecond policy reloads.
//
// No competitor uses user_ringbuf for policy delivery.

struct policy_msg {
    __u8  msg_type;    // POLICY_MSG_ADD / DELETE / FLUSH
    __u8  _pad[3];
    struct policy_key key;
    struct policy_val val;
};

struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 262144);  // 256KB
} aegis_policy_ringbuf SEC(".maps");

// ---- Phase 4: in-kernel rate limiter ----------------------------
//
// Per-cgroup event rate tracking with sliding window. When the rate
// exceeds a configurable threshold, the offending cgroup is
// automatically quarantined (written to quarantine map).
//
// This catches fork bombs, connection floods, and file scan storms
// entirely in-kernel — no userspace round-trip.

struct rate_key {
    __u64 cgid;        // cgroup ID
    __u8  kind;        // PROV_KIND_* being rate-limited
    __u8  _pad[7];
};

struct rate_val {
    __u64 window_start_ns;  // start of current window
    __u32 count;            // events in current window
    __u32 max_rate;         // threshold (0 = use default)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct rate_key);
    __type(value, struct rate_val);
    __uint(max_entries, 8192);
} aegis_rate_limits SEC(".maps");

// Rate limit configuration: per-kind max rates.
// [PROV_KIND_TASK_ALLOC] = fork limit, [PROV_KIND_SOCKET_CONNECT] = conn limit
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 16);
} aegis_rate_config SEC(".maps");

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

// FNV-1a hash of a null-terminated string (bounded to 16 bytes).
// Used to hash comm names for policy key lookups.
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

// ---- Phase 4: targeted enforcement with bpf_send_signal_task ----
//
// When bpf_send_signal_task is available (6.13+), use it to send
// SIGKILL to a specific task by reference instead of just the
// current task. Falls back to bpf_send_signal() on older kernels.
static __always_inline void
send_kill(struct task_struct *task)
{
    if (bpf_send_signal_task) {
        bpf_send_signal_task(task, 9 /* SIGKILL */, PIDTYPE_TGID, 0);
    } else {
        bpf_send_signal(9 /* SIGKILL */);
    }
}

// Apply a single policy match result. Updates deny flag, handles
// QUARANTINE (in-kernel bridge to sched_ext) and KILL flag.
static __always_inline void
apply_verdict(struct policy_val *val, __u64 cgid, int *deny)
{
    if (!val)
        return;
    if (val->action == POLICY_ACTION_DENY) {
        *deny = 1;
        if (val->flags & POLICY_FLAG_KILL) {
            struct task_struct *t =
                (struct task_struct *)bpf_get_current_task_btf();
            send_kill(t);
        }
    } else if (val->action == POLICY_ACTION_QUARANTINE && cgid) {
        // P2.3: In-kernel enforcement bridge — write cgroup directly
        // to the quarantine map. The sched_ext scheduler reads this
        // map on enqueue, throttling the offending cgroup immediately.
        __u32 level = 1; // QUARANTINE_THROTTLE
        bpf_map_update_elem(&aegis_next_quarantine, &cgid, &level, BPF_ANY);
    }
}

// Evaluate policy for a given hook. Returns 0 (allow) or -1 (deny).
// Performs up to 3 map lookups: comm, port, cgroup.
// On QUARANTINE action, writes cgroup to quarantine map from BPF.
// On DENY + KILL flag, sends SIGKILL.
static __always_inline int
evaluate_policy(__u8 hook, const char *comm, __u16 port, __u64 cgid)
{
    struct policy_key key = {};
    struct policy_val *val;
    int deny = 0;

    key.hook = hook;

    // 1. Match by comm hash.
    key.match_type = POLICY_MATCH_COMM;
    key.match_val = fnv1a_hash(comm, 12);
    val = bpf_map_lookup_elem(&aegis_next_policy, &key);
    apply_verdict(val, cgid, &deny);

    // 2. Match by port (socket hooks only).
    if (port && !deny) {
        key.match_type = POLICY_MATCH_PORT;
        key.match_val = port;
        val = bpf_map_lookup_elem(&aegis_next_policy, &key);
        apply_verdict(val, cgid, &deny);
    }

    // 3. Match by cgroup (container-scoped rules).
    if (cgid && !deny) {
        key.match_type = POLICY_MATCH_CGROUP;
        key.match_val = (__u32)cgid;
        val = bpf_map_lookup_elem(&aegis_next_policy, &key);
        apply_verdict(val, cgid, &deny);
    }

    // 4. Match by path prefix hash (file/exec hooks only).
    // Caller passes path_hash = 0 when no path is available.
    // Path hash is computed from the resolved bpf_d_path string.

    return deny ? -1 : 0;
}

// Evaluate a path-prefix policy match. Separated from evaluate_policy
// because only hooks that resolve a path can provide a hash.
static __always_inline int
evaluate_policy_path(__u8 hook, __u32 path_hash, __u64 cgid)
{
    if (path_hash == 0)
        return 0;

    struct policy_key key = {};
    key.hook = hook;
    key.match_type = POLICY_MATCH_PATH;
    key.match_val = path_hash;

    struct policy_val *val = bpf_map_lookup_elem(&aegis_next_policy, &key);
    int deny = 0;
    apply_verdict(val, cgid, &deny);
    return deny ? -1 : 0;
}

// Compute FNV-1a hash on a path buffer (for POLICY_MATCH_PATH lookups).
static __always_inline __u32
path_prefix_hash(const char *path, int maxlen)
{
    return fnv1a_hash(path, maxlen);
}

// Resolve a file path via bpf_d_path, allocate a path slab slot, and
// copy the resolved string into the arena. Returns the 1-based slab
// index (0 = no path / resolution failed).
static __always_inline __u32
resolve_path(struct path *p)
{
    __u32 zero = 0;
    char *scratch = bpf_map_lookup_elem(&aegis_next_path_scratch, &zero);
    if (!scratch)
        return 0;

    long len = bpf_d_path(p, scratch, PATH_SLAB_SLOT_SZ);
    if (len <= 0)
        return 0;

    // Allocate a slab slot (1-based index so 0 means "no path").
    __u64 raw = __sync_fetch_and_add(ARENA_PTR(&path_slab_next), 1);
    __u32 slab_idx = ((__u32)(raw % PATH_SLAB_SLOTS)) + 1;
    __u32 slab_slot = slab_idx - 1;

    // Copy path from per-CPU scratch to arena slab (u64 at a time).
    __u64 *src = (__u64 *)scratch;
    #pragma unroll
    for (int i = 0; i < (PATH_SLAB_SLOT_SZ / 8); i++)
        ARENA_PTR(&path_slab[slab_slot])->data[i] = src[i];

    return slab_idx;
}

// Allocate a net slab slot and write a 5-tuple flow record.
// Returns the 1-based slab index (0 = allocation failed).
static __always_inline __u32
record_net_flow(__u8 family, __u8 proto,
                __u32 src_v4, __u16 src_port,
                __u32 dst_v4, __u16 dst_port,
                const __u8 *src_v6, const __u8 *dst_v6)
{
    __u64 raw = __sync_fetch_and_add(ARENA_PTR(&net_slab_next), 1);
    __u32 slab_idx = ((__u32)(raw % NET_SLAB_SLOTS)) + 1;
    __u32 slot = slab_idx - 1;

    ARENA_PTR(&net_slab[slot])->family   = family;
    ARENA_PTR(&net_slab[slot])->proto    = proto;
    ARENA_PTR(&net_slab[slot])->src_port = src_port;
    ARENA_PTR(&net_slab[slot])->dst_port = dst_port;
    ARENA_PTR(&net_slab[slot])->_pad     = 0;
    ARENA_PTR(&net_slab[slot])->src_v4   = src_v4;
    ARENA_PTR(&net_slab[slot])->dst_v4   = dst_v4;

    if (src_v6) {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            ARENA_PTR(&net_slab[slot])->src_v6[i] = src_v6[i];
    } else {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            ARENA_PTR(&net_slab[slot])->src_v6[i] = 0;
    }

    if (dst_v6) {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            ARENA_PTR(&net_slab[slot])->dst_v6[i] = dst_v6[i];
    } else {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            ARENA_PTR(&net_slab[slot])->dst_v6[i] = 0;
    }

    return slab_idx;
}

// Push a compact alert to the ringbuf. Best-effort: drops are
// counted by the ringbuf's internal counter (not fatal).
static __always_inline void
emit_alert(__u64 slot, __u32 pid, __u8 kind)
{
    struct aegis_alert *alert;
    alert = bpf_ringbuf_reserve(&aegis_next_ringbuf,
                                sizeof(*alert), 0);
    if (!alert)
        return;
    alert->slot = slot;
    alert->pid  = pid;
    alert->kind = kind;
    alert->_pad[0] = 0;
    alert->_pad[1] = 0;
    alert->_pad[2] = 0;
    bpf_ringbuf_submit(alert, 0);
}

// ---- Phase 4: in-kernel rate limiter ----------------------------
//
// Check and update the rate counter for (cgid, kind). Returns true if
// the rate limit has been exceeded (caller should quarantine/deny).
static __always_inline bool
check_rate_limit(__u64 cgid, __u8 kind)
{
    if (!cgid)
        return false;

    struct rate_key rk = { .cgid = cgid, .kind = kind };
    struct rate_val *rv = bpf_map_lookup_elem(&aegis_rate_limits, &rk);
    __u64 now = bpf_ktime_get_ns();

    if (!rv) {
        // First event for this (cgid, kind) pair — initialize.
        struct rate_val new_rv = {
            .window_start_ns = now,
            .count = 1,
            .max_rate = 0,
        };
        bpf_map_update_elem(&aegis_rate_limits, &rk, &new_rv, BPF_NOEXIST);
        return false;
    }

    // Check if we're still in the same window.
    if (now - rv->window_start_ns >= RATE_LIMIT_WINDOW_NS) {
        // Window expired — reset.
        rv->window_start_ns = now;
        rv->count = 1;
        return false;
    }

    rv->count++;

    // Determine threshold: per-kind config map, or hardcoded default.
    __u32 max_rate = rv->max_rate;
    if (max_rate == 0) {
        __u32 kind_u32 = kind;
        __u32 *configured = bpf_map_lookup_elem(&aegis_rate_config, &kind_u32);
        if (configured && *configured > 0)
            max_rate = *configured;
        else if (kind == PROV_KIND_TASK_ALLOC)
            max_rate = RATE_LIMIT_FORK_MAX;
        else if (kind == PROV_KIND_SOCKET_CONNECT)
            max_rate = RATE_LIMIT_CONN_MAX;
        else
            max_rate = 200; // generous default
    }

    if (rv->count > max_rate) {
        // Rate exceeded — quarantine the cgroup.
        __u32 level = 1; // QUARANTINE_THROTTLE
        bpf_map_update_elem(&aegis_next_quarantine, &cgid, &level, BPF_ANY);
        return true;
    }

    return false;
}

// ---- Phase 4: user_ringbuf policy callback ----------------------
//
// Called when userspace writes policy update messages to the
// user_ringbuf. Processes adds, deletes, and flushes in bulk.
static long
policy_ringbuf_cb(struct bpf_dynptr *dynptr, void *ctx)
{
    struct policy_msg msg;
    long ret = bpf_dynptr_read(&msg, sizeof(msg), dynptr, 0, 0);
    if (ret < 0)
        return 0; // skip malformed entry

    switch (msg.msg_type) {
    case POLICY_MSG_ADD:
        bpf_map_update_elem(&aegis_next_policy, &msg.key, &msg.val, BPF_ANY);
        break;
    case POLICY_MSG_DELETE:
        bpf_map_delete_elem(&aegis_next_policy, &msg.key);
        break;
    case POLICY_MSG_FLUSH:
        // Flush is handled by userspace deleting all keys before
        // sending new ones. This message type is a no-op marker.
        break;
    }

    return 0;
}

// Drain the user_ringbuf. Called periodically from a BPF timer or
// explicitly from a syscall program.
SEC("syscall")
int aegis_next_drain_policy(void *ctx)
{
    bpf_user_ringbuf_drain(&aegis_policy_ringbuf, policy_ringbuf_cb, NULL, 0);
    return 0;
}

// ---- Phase 4: file security labeling ----------------------------
//
// After recording a file_open event, write a "last seen by aegis"
// marker into the file's xattr. This enables:
// - Tracking which files were accessed under aegis supervision
// - Fast cache lookups for binary authorization
// - Forensic evidence that survives process exit
static __always_inline void
label_file_xattr(struct file *file, __u8 kind)
{
    if (!bpf_set_dentry_xattr)
        return;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return;

    // Write a single byte: the kind of access that was observed.
    struct bpf_dynptr val;
    bpf_dynptr_from_mem(&kind, sizeof(kind), 0, &val);
    bpf_set_dentry_xattr(dentry, "security.aegis.seen", &val, 0);
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
    ARENA_PTR(&arena_nodes[slot])->kind          = kind;
    ARENA_PTR(&arena_nodes[slot])->flags         = (__u8)(ARENA_PTR(&arena_hdr)->generation & 0xFF);
    ARENA_PTR(&arena_nodes[slot])->extra         = extra;
    ARENA_PTR(&arena_nodes[slot])->path_slab_idx = 0;
    ARENA_PTR(&arena_nodes[slot])->net_slab_idx  = 0;

    // Extract mount and PID namespace inums from task->nsproxy.
    {
        __u32 mnt_inum = 0;
        __u32 pid_inum = 0;
        struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
        if (ns) {
            struct mnt_namespace *mnt = BPF_CORE_READ(ns, mnt_ns);
            if (mnt)
                mnt_inum = BPF_CORE_READ(mnt, ns.inum);
            struct pid_namespace *pidns = BPF_CORE_READ(ns, pid_ns_for_children);
            if (pidns)
                pid_inum = BPF_CORE_READ(pidns, ns.inum);
        }
        ARENA_PTR(&arena_nodes[slot])->mnt_ns = mnt_inum;
        ARENA_PTR(&arena_nodes[slot])->pid_ns = pid_inum;
    }

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

// Record a non-exec event. Returns true if the per-cgroup rate limit
// was exceeded — LSM hook callers check this and return -1 to deny.
static __always_inline bool
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
    __u64 cgid = bpf_get_current_cgroup_id();
    ARENA_PTR(&arena_nodes[slot])->cgid = cgid;

    // Phase 4: in-kernel rate limiting check.
    if (check_rate_limit(cgid, kind)) {
        // Rate exceeded — emit a rate-limit alert and signal caller to deny.
        emit_alert(slot, BPF_CORE_READ(task, tgid), PROV_KIND_RATE_LIMIT);
        return true;
    }
    return false;
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

    // Resolve the executable's file path into the path slab.
    // We must access bprm->file directly (BTF-aware) rather than
    // through the stack-copied `file` pointer, because bpf_d_path
    // requires a trusted_ptr to struct path.
    {
        struct file *bfile = bprm->file;
        if (bfile) {
            __u32 path_idx = resolve_path(&bfile->f_path);
            ARENA_PTR(&arena_nodes[slot])->path_slab_idx = path_idx;
        }
    }

    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_EXEC);

    // Rate-limit check for exec events (fork bomb / exec storm detection).
    {
        __u64 cgid = bpf_get_current_cgroup_id();
        if (check_rate_limit(cgid, PROV_KIND_EXEC)) {
            emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_RATE_LIMIT);
            return -1; /* -EPERM */
        }
    }

    // Evaluate policy — may deny the exec.
    {
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_EXEC, comm, 0, cgid) < 0)
            return -1; /* -EPERM */

        // Path-prefix policy check (scratch buffer still has resolved path).
        __u32 pzero = 0;
        char *pscratch = bpf_map_lookup_elem(&aegis_next_path_scratch, &pzero);
        if (pscratch) {
            __u32 phash = path_prefix_hash(pscratch, 64);
            if (evaluate_policy_path(PROV_KIND_EXEC, phash, cgid) < 0)
                return -1;
        }
    }
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
    bool rate_exceeded = record_event(PROV_KIND_FILE_OPEN, inode, open_flags);

    // Resolve the opened file's path into the path slab.
    // `file` is the direct BTF-typed LSM hook argument, so
    // &file->f_path gives a trusted pointer for bpf_d_path.
    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    __u32 path_idx = resolve_path(&file->f_path);
    ARENA_PTR(&arena_nodes[slot])->path_slab_idx = path_idx;

    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_FILE_OPEN);

    // Phase 4: label the file with a security xattr.
    label_file_xattr(file, PROV_KIND_FILE_OPEN);

    // Deny if rate limit exceeded for this cgroup.
    if (rate_exceeded)
        return -1; /* -EACCES */

    // Evaluate policy — may deny the file open.
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_FILE_OPEN, comm, 0, cgid) < 0)
            return -1; /* -EACCES */

        __u32 pzero = 0;
        char *pscratch = bpf_map_lookup_elem(&aegis_next_path_scratch, &pzero);
        if (pscratch) {
            __u32 phash = path_prefix_hash(pscratch, 64);
            if (evaluate_policy_path(PROV_KIND_FILE_OPEN, phash, cgid) < 0)
                return -1;
        }
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(aegis_next_on_socket_connect,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!aegis_is_ready())
        return 0;

    __u16 family = BPF_CORE_READ(address, sa_family);

    // Extract destination from sockaddr, source from sock->sk.
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u8  proto    = BPF_CORE_READ(sk, sk_protocol);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 src_v4   = 0;
    __u32 dst_v4   = 0;
    __u16 dst_port = 0;
    __u8  src_v6_buf[16] = {};
    __u8  dst_v6_buf[16] = {};
    __u64 object_id = 0;

    if (family == 2 /* AF_INET */ && addrlen >= 8) {
        src_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&dst_port, 2,
                              (const char *)address + 2);
        dst_port = __builtin_bswap16(dst_port);
        bpf_probe_read_kernel(&dst_v4, 4,
                              (const char *)address + 4);
        object_id = ((__u64)dst_port << 32) | dst_v4;
    } else if (family == 10 /* AF_INET6 */ && addrlen >= 28) {
        bpf_probe_read_kernel(&dst_port, 2,
                              (const char *)address + 2);
        dst_port = __builtin_bswap16(dst_port);
        bpf_probe_read_kernel(dst_v6_buf, 16,
                              (const char *)address + 8);
        // Read source IPv6 from socket.
        bpf_probe_read_kernel(src_v6_buf, 16,
                              &sk->__sk_common.skc_v6_rcv_saddr);
        // Coarse fingerprint for object_id: last 4 bytes of dst.
        __u32 addr_low = 0;
        bpf_probe_read_kernel(&addr_low, 4,
                              (const char *)address + 24);
        object_id = ((__u64)dst_port << 32) | addr_low;
    }

    bool rate_exceeded = record_event(PROV_KIND_SOCKET_CONNECT, object_id, family);

    // Store full 5-tuple in net slab.
    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    __u32 nidx = record_net_flow(
        (__u8)family, proto, src_v4, src_port, dst_v4, dst_port,
        (family == 10) ? src_v6_buf : (void *)0,
        (family == 10) ? dst_v6_buf : (void *)0);
    ARENA_PTR(&arena_nodes[slot])->net_slab_idx = nidx;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_SOCKET_CONNECT);

    if (rate_exceeded)
        return -1; /* -EACCES */

    // Evaluate policy — may deny the connect.
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_SOCKET_CONNECT, comm, dst_port, cgid) < 0)
            return -1; /* -EACCES */
    }
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(aegis_next_on_socket_bind,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!aegis_is_ready())
        return 0;

    __u16 family = BPF_CORE_READ(address, sa_family);

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u8  proto    = BPF_CORE_READ(sk, sk_protocol);
    __u32 bind_v4  = 0;
    __u16 bind_port = 0;
    __u8  bind_v6_buf[16] = {};
    __u64 object_id = 0;

    if (family == 2 /* AF_INET */ && addrlen >= 8) {
        bpf_probe_read_kernel(&bind_port, 2,
                              (const char *)address + 2);
        bind_port = __builtin_bswap16(bind_port);
        bpf_probe_read_kernel(&bind_v4, 4,
                              (const char *)address + 4);
        object_id = ((__u64)bind_port << 32) | bind_v4;
    } else if (family == 10 /* AF_INET6 */ && addrlen >= 28) {
        bpf_probe_read_kernel(&bind_port, 2,
                              (const char *)address + 2);
        bind_port = __builtin_bswap16(bind_port);
        bpf_probe_read_kernel(bind_v6_buf, 16,
                              (const char *)address + 8);
        __u32 addr_low = 0;
        bpf_probe_read_kernel(&addr_low, 4,
                              (const char *)address + 24);
        object_id = ((__u64)bind_port << 32) | addr_low;
    }

    bool rate_exceeded = record_event(PROV_KIND_SOCKET_BIND, object_id, family);

    // Store bind address in net slab (src = bind addr, dst = 0).
    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    __u32 nidx = record_net_flow(
        (__u8)family, proto, bind_v4, bind_port, 0, 0,
        (family == 10) ? bind_v6_buf : (void *)0,
        (void *)0);
    ARENA_PTR(&arena_nodes[slot])->net_slab_idx = nidx;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_SOCKET_BIND);

    if (rate_exceeded)
        return -1;

    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_SOCKET_BIND, comm, bind_port, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(aegis_next_on_socket_listen,
             struct socket *sock, int backlog)
{
    if (!aegis_is_ready())
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u16 family   = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8  proto    = BPF_CORE_READ(sk, sk_protocol);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 src_v4   = 0;
    __u8  src_v6_buf[16] = {};
    __u64 object_id = 0;

    if (family == 2 /* AF_INET */) {
        src_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        object_id = ((__u64)src_port << 32) | src_v4;
    } else if (family == 10 /* AF_INET6 */) {
        bpf_probe_read_kernel(src_v6_buf, 16,
                              &sk->__sk_common.skc_v6_rcv_saddr);
        __u32 addr_low = 0;
        __builtin_memcpy(&addr_low, &src_v6_buf[12], 4);
        object_id = ((__u64)src_port << 32) | addr_low;
    }

    bool rate_exceeded = record_event(PROV_KIND_SOCKET_LISTEN, object_id, family);

    // Store listen address in net slab (src = listen addr, dst = 0).
    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    __u32 nidx = record_net_flow(
        (__u8)family, proto, src_v4, src_port, 0, 0,
        (family == 10) ? src_v6_buf : (void *)0,
        (void *)0);
    ARENA_PTR(&arena_nodes[slot])->net_slab_idx = nidx;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_SOCKET_LISTEN);

    if (rate_exceeded)
        return -1;

    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_SOCKET_LISTEN, comm, src_port, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(aegis_next_on_file_perm, struct file *file, int mask)
{
    if (!aegis_is_ready())
        return 0;

    // mask: MAY_READ=4, MAY_WRITE=2, MAY_EXEC=1, MAY_APPEND=8
    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    bool rate_exceeded = record_event(PROV_KIND_FILE_PERM, inode, (__u16)(mask & 0xFFFF));

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_FILE_PERM);

    if (rate_exceeded)
        return -1;

    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_FILE_PERM, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(aegis_next_on_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    if (!aegis_is_ready())
        return 0;
    if (!file)
        return 0;

    // Detect W+X: writable AND executable mmap (fileless malware indicator).
    // prot bits: PROT_EXEC=4, PROT_WRITE=2.
    __u16 prot_flags = (__u16)(prot & 0xFFFF);

    __u64 inode = 0;
    struct inode *ino = BPF_CORE_READ(file, f_inode);
    if (ino)
        inode = BPF_CORE_READ(ino, i_ino);

    bool rate_exceeded = record_event(PROV_KIND_MMAP_FILE, inode, prot_flags);

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_MMAP_FILE);

    if (rate_exceeded)
        return -1;

    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        char comm[12];
        bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_MMAP_FILE, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(aegis_next_on_task_alloc, struct task_struct *task,
             unsigned long clone_flags)
{
    if (!aegis_is_ready())
        return 0;

    // Record fork/clone events for fork bomb detection.
    struct task_struct *current = (struct task_struct *)bpf_get_current_task_btf();
    __u64 object_id = clone_flags;
    bool rate_exceeded = record_event(PROV_KIND_TASK_ALLOC, object_id, 0);

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_TASK_ALLOC);

    if (rate_exceeded)
        return -1;

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
int BPF_PROG(aegis_next_on_kmod_req, char *kmod_name)
{
    if (!aegis_is_ready())
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);

    // Use comm hash as object_id for module request events.
    __u32 name_hash = fnv1a_hash(comm, 12);
    bool rate_exceeded = record_event(PROV_KIND_KMOD_REQ, name_hash, 0);

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_KMOD_REQ);

    if (rate_exceeded)
        return -1;

    {
        __u64 cgid = bpf_get_current_cgroup_id();
        if (evaluate_policy(PROV_KIND_KMOD_REQ, comm, 0, cgid) < 0)
            return -1;
    }
    return 0;
}

// ---- Phase 5: expanded hook coverage ----------------------------

// Detect debugger attachment (anti-tampering, privilege escalation).
SEC("lsm/ptrace_access_check")
int BPF_PROG(aegis_next_on_ptrace, struct task_struct *child, unsigned int mode)
{
    if (!aegis_is_ready())
        return 0;

    __u32 child_pid = BPF_CORE_READ(child, tgid);
    bool rate_exceeded = record_event(PROV_KIND_PTRACE, child_pid, (__u16)(mode & 0xFFFF));

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_PTRACE);

    if (rate_exceeded)
        return -1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
    __u64 cgid = bpf_get_current_cgroup_id();
    if (evaluate_policy(PROV_KIND_PTRACE, comm, 0, cgid) < 0)
        return -1;
    return 0;
}

// Detect setuid/setgid transitions (privilege escalation detection).
SEC("lsm/task_fix_setuid")
int BPF_PROG(aegis_next_on_setuid, struct cred *new_cred,
             const struct cred *old_cred, int flags)
{
    if (!aegis_is_ready())
        return 0;

    __u32 old_uid = BPF_CORE_READ(old_cred, uid.val);
    __u32 new_uid = BPF_CORE_READ(new_cred, uid.val);

    // Only record transitions (uid actually changing).
    if (old_uid == new_uid)
        return 0;

    bool rate_exceeded = record_event(PROV_KIND_SETUID, new_uid, (__u16)(old_uid & 0xFFFF));

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_SETUID);

    if (rate_exceeded)
        return -1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
    __u64 cgid = bpf_get_current_cgroup_id();
    if (evaluate_policy(PROV_KIND_SETUID, comm, 0, cgid) < 0)
        return -1;
    return 0;
}

// Detect file renames (lateral movement, evidence tampering).
SEC("lsm/path_rename")
int BPF_PROG(aegis_next_on_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
    if (!aegis_is_ready())
        return 0;

    __u64 ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    bool rate_exceeded = record_event(PROV_KIND_RENAME, ino, 0);

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_RENAME);

    if (rate_exceeded)
        return -1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
    __u64 cgid = bpf_get_current_cgroup_id();
    if (evaluate_policy(PROV_KIND_RENAME, comm, 0, cgid) < 0)
        return -1;
    return 0;
}

// Detect file deletions (evidence destruction, log tampering).
SEC("lsm/path_unlink")
int BPF_PROG(aegis_next_on_unlink, const struct path *dir,
             struct dentry *dentry)
{
    if (!aegis_is_ready())
        return 0;

    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    bool rate_exceeded = record_event(PROV_KIND_UNLINK, ino, 0);

    __u64 idx = ARENA_PTR(&arena_hdr)->next_index - 1;
    __u64 slot = idx % AEGIS_NEXT_MAX_NODES;
    emit_alert(slot, ARENA_PTR(&arena_nodes[slot])->tgid, PROV_KIND_UNLINK);

    if (rate_exceeded)
        return -1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
    __u64 cgid = bpf_get_current_cgroup_id();
    if (evaluate_policy(PROV_KIND_UNLINK, comm, 0, cgid) < 0)
        return -1;
    return 0;
}

// Track network data egress (data exfiltration detection).
SEC("lsm/socket_sendmsg")
int BPF_PROG(aegis_next_on_sendmsg, struct socket *sock,
             struct msghdr *msg, int size)
{
    if (!aegis_is_ready())
        return 0;

    // Record message size in extra field (capped to u16).
    __u16 sz = (size > 0xFFFF) ? 0xFFFF : (__u16)size;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 dst_port = 0;
    if (sk)
        dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dst_port = __builtin_bswap16(dst_port);

    bool rate_exceeded = record_event(PROV_KIND_SENDMSG, dst_port, sz);

    if (rate_exceeded)
        return -1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    char comm[12];
    bpf_probe_read_kernel(comm, sizeof(comm), &task->comm);
    __u64 cgid = bpf_get_current_cgroup_id();
    if (evaluate_policy(PROV_KIND_SENDMSG, comm, dst_port, cgid) < 0)
        return -1;
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
