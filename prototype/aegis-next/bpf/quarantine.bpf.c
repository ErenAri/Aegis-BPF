// SPDX-License-Identifier: GPL-2.0
//
// aegis-next: sched_ext scheduler with tiered quarantine enforcement.
//
// P2.5 of the prototype roadmap. Reads a quarantine map (cgroup id →
// level) shared with the LSM provenance program (P2.3 bridge).
//
// Quarantine levels:
//   0 (NONE):     normal scheduling — default 5ms slice, global DSQ
//   1 (THROTTLE): reduced time slice (1ms), global DSQ
//   2 (PIN):      1ms slice, pinned to CPU 0 only (cache isolation)
//   3 (STARVE):   100μs slice, pinned to CPU 0 (effective starvation)
//
// The LSM side sends SIGKILL for DENY+KILL policy; STARVE-level
// quarantine ensures the task cannot make progress before delivery.
//
// Note: we use raw SEC("struct_ops/...") annotations instead of
// BPF_STRUCT_OPS() macros because the latter are not available in
// libbpf <= 1.5. The verifier matches callback signatures via BTF.

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

// Default time slice: 5ms in nanoseconds.
#define AEGIS_NEXT_DEFAULT_SLICE_NS  (5ULL * 1000 * 1000)
// Throttled slice for quarantined tasks: 1ms.
#define AEGIS_NEXT_THROTTLE_SLICE_NS (1ULL * 1000 * 1000)
// Starvation slice: 100μs — just enough to avoid sched_ext watchdog.
#define AEGIS_NEXT_STARVE_SLICE_NS   (100ULL * 1000)

// Quarantine levels stored in the map value.
#define QUARANTINE_NONE     0
#define QUARANTINE_THROTTLE 1  // reduced time slice
#define QUARANTINE_PIN      2  // pin to CPU 0 + throttle
#define QUARANTINE_STARVE   3  // pin to CPU 0 + minimal slice

// Jail CPU for PIN and STARVE levels.
#define QUARANTINE_JAIL_CPU 0

// Quarantine map: cgroup id -> quarantine level.
// Written by LSM evaluate_policy() (P2.3 bridge) or userspace CLI.
// Read by the sched_ext enqueue path on every scheduling decision.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // cgroup id
    __type(value, __u32); // quarantine level
    __uint(max_entries, 4096);
} aegis_next_quarantine SEC(".maps");

// Stats counters for observability.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // [0]=throttle, [1]=pin, [2]=starve, [3]=normal
} aegis_next_sched_stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&aegis_next_sched_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

// kfuncs for sched_ext dispatch.
extern void scx_bpf_dsq_insert(struct task_struct *p, __u64 dsq_id,
                                __u64 slice, __u64 enq_flags) __ksym;
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu,
                                   u64 wake_flags, bool *is_idle) __ksym;

// ---- struct_ops callbacks -------------------------------------

SEC("struct_ops/aegis_next_select_cpu")
s32 aegis_next_select_cpu(struct task_struct *p, s32 prev_cpu,
                          u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle)
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, AEGIS_NEXT_DEFAULT_SLICE_NS, 0);
    return cpu;
}

SEC("struct_ops/aegis_next_enqueue")
void aegis_next_enqueue(struct task_struct *p, u64 enq_flags)
{
    __u64 slice = AEGIS_NEXT_DEFAULT_SLICE_NS;
    __u64 dsq = SCX_DSQ_GLOBAL;
    __u32 stat_idx = 3; // normal

    // Look up quarantine level by cgroup id.
    __u64 cgid = bpf_get_current_cgroup_id();
    if (cgid) {
        __u32 *level = bpf_map_lookup_elem(&aegis_next_quarantine, &cgid);
        if (level) {
            __u32 lv = *level;
            if (lv >= QUARANTINE_STARVE) {
                // STARVE: 100μs on jail CPU — effective starvation.
                slice = AEGIS_NEXT_STARVE_SLICE_NS;
                dsq = SCX_DSQ_LOCAL_ON | QUARANTINE_JAIL_CPU;
                stat_idx = 2;
            } else if (lv >= QUARANTINE_PIN) {
                // PIN: 1ms on jail CPU — isolated + throttled.
                slice = AEGIS_NEXT_THROTTLE_SLICE_NS;
                dsq = SCX_DSQ_LOCAL_ON | QUARANTINE_JAIL_CPU;
                stat_idx = 1;
            } else if (lv >= QUARANTINE_THROTTLE) {
                // THROTTLE: 1ms on global — reduced priority.
                slice = AEGIS_NEXT_THROTTLE_SLICE_NS;
                stat_idx = 0;
            }
        }
    }

    bump_stat(stat_idx);
    scx_bpf_dsq_insert(p, dsq, slice, enq_flags);
}

SEC("struct_ops.s/aegis_next_init")
s32 aegis_next_init(void)
{
    return 0;
}

SEC("struct_ops/aegis_next_exit")
void aegis_next_exit(struct scx_exit_info *ei)
{
    // Nothing to clean up.
}

// ---- struct_ops registration ----------------------------------

SEC(".struct_ops.link")
struct sched_ext_ops aegis_next_sched = {
    .select_cpu   = (void *)aegis_next_select_cpu,
    .enqueue      = (void *)aegis_next_enqueue,
    .init         = (void *)aegis_next_init,
    .exit         = (void *)aegis_next_exit,
    .name         = "aegis_next",
};

char LICENSE[] SEC("license") = "GPL";
