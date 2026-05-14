// SPDX-License-Identifier: GPL-2.0
//
// aegis-next: minimal sched_ext scheduler with quarantine map.
//
// F2.1 of the prototype roadmap. This is NOT a production
// scheduler. It is the smallest possible struct_ops scheduler
// that loads, attaches, dispatches everything to SCX_DSQ_GLOBAL,
// and reads a quarantine map — proving the wiring works.
//
// What the scheduler does:
//   .enqueue():
//     1. Look up the task's cgroup id in the quarantine map.
//     2. If quarantined (level > 0), reduce the time slice.
//     3. Dispatch to SCX_DSQ_GLOBAL (the kernel's default queue).
//
// What it does NOT do (yet):
//   - CPU pinning or isolation of quarantined tasks.
//   - Integration with the provenance graph (F2.3).
//   - Configurable policy beyond the quarantine map.
//   - Any optimization (fair vtime, load balancing, NUMA).
//
// The point is to prove sched_ext + struct_ops loads, attaches,
// and can read from a shared map. F2.2-F2.4 build on this.
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

// Quarantine levels stored in the map value.
#define QUARANTINE_NONE     0
#define QUARANTINE_THROTTLE 1  // reduced time slice
#define QUARANTINE_PIN      2  // reserved for future: pin to single CPU

// Quarantine map: cgroup id -> quarantine level.
// Written by userspace (or future LSM verdict bridge).
// Read by the sched_ext enqueue path.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // cgroup id
    __type(value, __u32); // quarantine level
    __uint(max_entries, 4096);
} aegis_next_quarantine SEC(".maps");

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

    // Look up quarantine level by cgroup id.
    __u64 cgid = bpf_get_current_cgroup_id();
    if (cgid) {
        __u32 *level = bpf_map_lookup_elem(&aegis_next_quarantine, &cgid);
        if (level && *level >= QUARANTINE_THROTTLE) {
            slice = AEGIS_NEXT_THROTTLE_SLICE_NS;
        }
    }

    scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice, enq_flags);
}

SEC("struct_ops.s/aegis_next_init")
s32 aegis_next_init(void)
{
    return 0;
}

SEC("struct_ops/aegis_next_exit")
void aegis_next_exit(struct scx_exit_info *ei)
{
    // Nothing to clean up in the minimal scheduler.
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
