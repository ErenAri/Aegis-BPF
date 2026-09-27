/* Measure what one ARRAY_OF_MAPS update costs.
 *
 * The kernel matrix showed the leak phase taking many minutes inside a VM
 * whose CPUs were saturated by the stress workers, which looked like a hang.
 * It is not: bpf_map_update_elem() on a map-in-map calls synchronize_rcu(),
 * so every inner-map install waits a full RCU grace period. A policy commit
 * stages 16 inner maps and retires 16 more, so it pays ~32 of them, and a
 * grace period stretches when every CPU is busy.
 *
 * This isolates that cost from Aegis entirely: no agent, no policy, no
 * enforcement -- just an outer map, an inner map, and a timed loop. Compare
 * the per-update figure on an idle machine against one under load to see the
 * amplification that produced the apparent stall.
 *
 * Usage: mapinmap_cost [updates]        (default 32, one commit's worth)
 * Exit: 0 on success, 1 if the maps cannot be created.
 */
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    int updates = argc > 1 ? atoi(argv[1]) : 32;
    if (updates < 1) updates = 1;

    LIBBPF_OPTS(bpf_map_create_opts, iopts);
    int inner = bpf_map_create(BPF_MAP_TYPE_HASH, "cost_inner",
                               sizeof(__u32), sizeof(__u32), 64, &iopts);
    if (inner < 0) {
        fprintf(stderr, "inner map: %s\n", strerror(-inner));
        return 1;
    }

    LIBBPF_OPTS(bpf_map_create_opts, oopts, .inner_map_fd = inner);
    int outer = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "cost_outer",
                               sizeof(__u32), sizeof(__u32), 2, &oopts);
    if (outer < 0) {
        fprintf(stderr, "outer map: %s\n", strerror(-outer));
        return 1;
    }

    /* One untimed update first: the initial install can pull in allocations
     * that later iterations do not repeat, and that would flatter or inflate
     * the average depending on which way it lands. */
    __u32 key = 0, val = inner;
    if (bpf_map_update_elem(outer, &key, &val, BPF_ANY) < 0) {
        fprintf(stderr, "warmup update: %s\n", strerror(errno));
        return 1;
    }

    double slowest = 0.0, start = now_s();
    for (int i = 0; i < updates; i++) {
        key = (__u32)(i % 2);
        double t0 = now_s();
        if (bpf_map_update_elem(outer, &key, &val, BPF_ANY) < 0) {
            fprintf(stderr, "update %d: %s\n", i, strerror(errno));
            return 1;
        }
        double dt = now_s() - t0;
        if (dt > slowest) slowest = dt;
    }
    double total = now_s() - start;

    printf("updates=%d\n", updates);
    printf("total_seconds=%.3f\n", total);
    printf("mean_ms_per_update=%.3f\n", total * 1000.0 / updates);
    printf("slowest_ms=%.3f\n", slowest * 1000.0);
    printf("commit_equivalent_seconds=%.3f\n", total * 32.0 / updates);
    close(outer);
    close(inner);
    return 0;
}
