/* EXPERIMENT (#323 phase 2): loader + flow-summary exporter.
 *
 * Export model: userspace walks the map periodically (option A of the four
 * considered). BPF timers would be tidier but need 5.15+, and Aegis supports
 * 5.14 per docs/SUPPORT_POLICY.md, so using them would trade real kernel
 * coverage for elegance. A plain map walk works everywhere the hook does.
 *
 * Lifecycle: kernel updates counters -> userspace sweeps -> a flow idle longer
 * than the threshold is emitted as a final summary and deleted. No TCP state
 * machine, no conntrack.
 *
 * Usage:
 *   flow_probe <cgroup> [--seconds N] [--idle MS] [--sweep MS]
 *              [--shadow 0|1] [--json out.jsonl] [--quiet]
 *   flow_probe --check
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

enum { CNT_INGRESS_PKT, CNT_EGRESS_PKT, CNT_NEW_FLOW, CNT_UPDATE,
       CNT_PARSE_ERR, CNT_MAP_FULL, CNT_TUPLE5_NEW, CNT_MAX };

struct flow_key {
    __u64 cgroup_id;
    __u8  remote_addr[16];
    __u16 remote_port;
    __u8  direction, family, protocol, _pad[3];
};
struct flow_value {
    __u64 packets, bytes, syn_count, rst_count, fin_count;
    __u64 first_seen_ns, last_seen_ns, parse_errors;
};

static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

static unsigned long long g_summaries, g_peak_occupancy, g_sweeps;
static FILE *g_json;

static __u64 now_ns(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void addr_str(const __u8 *a, __u8 fam, char *out, size_t n)
{
    if (fam == 4) inet_ntop(AF_INET, a, out, n);
    else if (fam == 6) inet_ntop(AF_INET6, a, out, n);
    else snprintf(out, n, "-");
}

static void emit(const struct flow_key *k, const struct flow_value *v, const char *reason)
{
    g_summaries++;
    if (!g_json) return;
    char ip[64]; addr_str(k->remote_addr, k->family, ip, sizeof(ip));
    fprintf(g_json,
        "{\"cgroup_id\":%" PRIu64 ",\"dir\":\"%s\",\"family\":%u,\"proto\":%u,"
        "\"remote\":\"%s\",\"remote_port\":%u,\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 ","
        "\"syn\":%" PRIu64 ",\"rst\":%" PRIu64 ",\"fin\":%" PRIu64 ","
        "\"duration_ms\":%" PRIu64 ",\"parse_errors\":%" PRIu64 ",\"reason\":\"%s\"}\n",
        k->cgroup_id, k->direction ? "egress" : "ingress", k->family, k->protocol,
        ip, k->remote_port, v->packets, v->bytes, v->syn_count, v->rst_count, v->fin_count,
        (v->last_seen_ns - v->first_seen_ns) / 1000000ull, v->parse_errors, reason);
}

/* One sweep: count occupancy, expire idle flows, emit their summaries. */
static unsigned sweep(int map_fd, __u64 idle_ns, int final_flush)
{
    struct flow_key key, next;
    struct flow_value val;
    unsigned live = 0, expired = 0;
    __u64 now = now_ns();
    int have = (bpf_map_get_next_key(map_fd, NULL, &next) == 0);

    /* Collect first, delete second: deleting during iteration is defined for
     * LRU hash but collecting keeps the walk simple and the counts exact. */
    static struct flow_key doomed[65536];
    static struct flow_value doomed_v[65536];
    unsigned ndoomed = 0;

    while (have) {
        key = next;
        have = (bpf_map_get_next_key(map_fd, &key, &next) == 0);
        if (bpf_map_lookup_elem(map_fd, &key, &val))
            continue;
        live++;
        if (final_flush || (now > val.last_seen_ns && now - val.last_seen_ns > idle_ns)) {
            if (ndoomed < 65536) { doomed[ndoomed] = key; doomed_v[ndoomed] = val; ndoomed++; }
        }
    }
    for (unsigned i = 0; i < ndoomed; i++) {
        emit(&doomed[i], &doomed_v[i], final_flush ? "final_flush" : "idle_timeout");
        bpf_map_delete_elem(map_fd, &doomed[i]);
        expired++;
    }
    if (live > g_peak_occupancy) g_peak_occupancy = live;
    g_sweeps++;
    (void)expired;
    return live;
}

int main(int argc, char **argv)
{
    const char *cg_path = NULL, *json_path = NULL;
    int seconds = 15, idle_ms = 2000, sweep_ms = 500, shadow = 0, check = 0, quiet = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--check")) check = 1;
        else if (!strcmp(argv[i], "--seconds") && i+1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--idle") && i+1 < argc) idle_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sweep") && i+1 < argc) sweep_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--shadow") && i+1 < argc) shadow = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json") && i+1 < argc) json_path = argv[++i];
        else if (!strcmp(argv[i], "--quiet")) quiet = 1;
        else cg_path = argv[i];
    }
    if (!check && !cg_path) {
        fprintf(stderr, "usage: flow_probe <cgroup> [--seconds N] [--idle MS] [--sweep MS]"
                        " [--shadow 0|1] [--json f] [--quiet]\n       flow_probe --check\n");
        return 1;
    }

    libbpf_set_print(NULL);
    struct bpf_object *obj = bpf_object__open_file("aegis_flow.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open failed\n"); return 1; }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed: %s -- cgroup_skb/LRU unsupported or verifier rejected\n",
                strerror(errno));
        bpf_object__close(obj); return 77;
    }
    if (check) {
        printf("ok: programs verified, maps created (LRU_HASH flows, PERCPU counters)\n");
        bpf_object__close(obj); return 0;
    }

    int flows_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "flows"));
    int cnt_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "counters"));
    int cfg_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "cfg"));
    int t5_fd    = bpf_map__fd(bpf_object__find_map_by_name(obj, "tuple5_shadow"));
    __u32 zero = 0, sv = (__u32)shadow;
    bpf_map_update_elem(cfg_fd, &zero, &sv, BPF_ANY);

    int cg_fd = open(cg_path, O_RDONLY);
    if (cg_fd < 0) { fprintf(stderr, "open cgroup %s: %s\n", cg_path, strerror(errno));
                     bpf_object__close(obj); return 1; }

    int ing = bpf_program__fd(bpf_object__find_program_by_name(obj, "aegis_flow_ingress"));
    int egr = bpf_program__fd(bpf_object__find_program_by_name(obj, "aegis_flow_egress"));
    if (bpf_prog_attach(ing, cg_fd, BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attach ingress: %s\n", strerror(errno));
        close(cg_fd); bpf_object__close(obj); return 1;
    }
    if (bpf_prog_attach(egr, cg_fd, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attach egress: %s\n", strerror(errno));
        bpf_prog_detach2(ing, cg_fd, BPF_CGROUP_INET_INGRESS);
        close(cg_fd); bpf_object__close(obj); return 1;
    }
    if (!quiet) printf("attached to %s (ALLOW_MULTI) idle=%dms sweep=%dms shadow=%d\n",
                       cg_path, idle_ms, sweep_ms, shadow);

    if (json_path) { g_json = fopen(json_path, "w"); if (!g_json) fprintf(stderr, "warn: %s\n", json_path); }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    __u64 idle_ns = (__u64)idle_ms * 1000000ull;
    time_t deadline = time(NULL) + seconds;
    unsigned last_live = 0;
    while (!g_stop && time(NULL) < deadline) {
        usleep(sweep_ms * 1000);
        last_live = sweep(flows_fd, idle_ns, 0);
    }
    last_live = sweep(flows_fd, idle_ns, 1);   /* final flush */

    int ncpu = libbpf_num_possible_cpus();
    unsigned long long tot[CNT_MAX] = {0};
    for (__u32 i = 0; i < CNT_MAX; i++) {
        __u64 per[1024] = {0};
        if (!bpf_map_lookup_elem(cnt_fd, &i, per))
            for (int c = 0; c < ncpu && c < 1024; c++) tot[i] += per[c];
    }
    unsigned long long pkts = tot[CNT_INGRESS_PKT] + tot[CNT_EGRESS_PKT];

    printf("\n=== flow aggregation results ===\n");
    printf("packets observed        : %llu  (ingress %llu / egress %llu)\n",
           pkts, tot[CNT_INGRESS_PKT], tot[CNT_EGRESS_PKT]);
    printf("flow keys created       : %llu\n", tot[CNT_NEW_FLOW]);
    printf("flow updates (hits)     : %llu\n", tot[CNT_UPDATE]);
    printf("summaries exported      : %llu\n", g_summaries);
    printf("peak map occupancy      : %llu\n", g_peak_occupancy);
    printf("live at exit            : %u\n", last_live);
    printf("map-full (insert fail)  : %llu\n", tot[CNT_MAP_FULL]);
    /* LRU evictions are INVISIBLE to the program: BPF's LRU hash has no
     * eviction callback, and an insert into a full LRU succeeds by evicting
     * somebody else, so CNT_MAP_FULL stays zero no matter how much is thrown
     * away. The count has to be derived, and it has to be reported -- a
     * telemetry layer that silently discards what it was asked to observe is
     * worse than one that admits it cannot keep up. */
    {
        long long evicted = (long long)tot[CNT_NEW_FLOW] - (long long)g_summaries;
        if (evicted < 0) evicted = 0;
        printf("evicted, inferred       : %lld%s\n", evicted,
               evicted ? "   <- LRU discarded these; no summary was ever emitted" : "");
        if (tot[CNT_NEW_FLOW])
            printf("observation loss        : %.1f%% of flows never reported\n",
                   100.0 * (double)evicted / (double)tot[CNT_NEW_FLOW]);
    }
    printf("parse errors            : %llu\n", tot[CNT_PARSE_ERR]);
    printf("sweeps                  : %llu\n", g_sweeps);
    if (shadow)
        printf("5-tuple keys (shadow)   : %llu   <- cardinality a 5-tuple key would cost\n",
               tot[CNT_TUPLE5_NEW]);
    if (g_summaries)
        printf("REDUCTION               : %.1fx  (%llu packets -> %llu summaries)\n",
               (double)pkts / (double)g_summaries, pkts, g_summaries);

    if (g_json) fclose(g_json);
    bpf_prog_detach2(egr, cg_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach2(ing, cg_fd, BPF_CGROUP_INET_INGRESS);
    close(cg_fd);
    bpf_object__close(obj);
    (void)t5_fd;
    if (!quiet) printf("detached cleanly\n");
    return 0;
}
