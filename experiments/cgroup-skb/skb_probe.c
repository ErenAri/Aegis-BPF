/* EXPERIMENT (#323): loader/harness for the audit-only cgroup_skb prototype.
 *
 * Attaches ONLY to the cgroup named on the command line. There is no
 * host-global attach path here on purpose: a cgroup_skb program attached to
 * the root cgroup would observe every packet on the machine, which is not a
 * thing an experiment should be able to do by accident.
 *
 * Usage:
 *   skb_probe <cgroup-path> [--seconds N] [--emit 0|1] [--json out.json]
 *   skb_probe --check           capability probe only, attaches nothing
 *
 * Exit: 0 ok, 1 error, 77 cgroup_skb unsupported on this kernel.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { CNT_INGRESS = 0, CNT_EGRESS, CNT_EMITTED, CNT_UNPARSED, CNT_DROPPED, CNT_MAX };

static const char *kParse[] = {"ok", "unsup_l3", "unsup_l4", "truncated", "fragment", "v6_ext_chain"};

struct aegis_skb_event {
    __u64 ts_ns, skb_cgid, current_cgid;
    __u32 ifindex, len;
    __u8 direction, family, protocol, parse_status;
    __u16 sport, dport;
    __u8 saddr[16], daddr[16];
};

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

static unsigned long long g_seen, g_id_match, g_id_mismatch, g_current_zero;
static unsigned long long g_by_status[6];
static FILE *g_jsonl;

static void ip_str(const __u8 *a, __u8 family, char *out, size_t n)
{
    if (family == 4)
        snprintf(out, n, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    else if (family == 6)
        snprintf(out, n, "%02x%02x:%02x%02x:...:%02x%02x", a[0], a[1], a[2], a[3], a[14], a[15]);
    else
        snprintf(out, n, "-");
}

static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct aegis_skb_event))
        return 0;
    const struct aegis_skb_event *e = data;
    g_seen++;
    if (e->parse_status < 6)
        g_by_status[e->parse_status]++;

    /* The identity question, measured rather than assumed. */
    if (e->current_cgid == 0)
        g_current_zero++;
    else if (e->skb_cgid == e->current_cgid)
        g_id_match++;
    else
        g_id_mismatch++;

    if (g_jsonl) {
        char s[64], d[64];
        ip_str(e->saddr, e->family, s, sizeof(s));
        ip_str(e->daddr, e->family, d, sizeof(d));
        fprintf(g_jsonl,
                "{\"dir\":\"%s\",\"skb_cgid\":%llu,\"current_cgid\":%llu,\"family\":%u,"
                "\"proto\":%u,\"src\":\"%s\",\"sport\":%u,\"dst\":\"%s\",\"dport\":%u,"
                "\"len\":%u,\"ifindex\":%u,\"parse\":\"%s\"}\n",
                e->direction ? "egress" : "ingress", (unsigned long long)e->skb_cgid,
                (unsigned long long)e->current_cgid, e->family, e->protocol, s, e->sport, d,
                e->dport, e->len, e->ifindex, kParse[e->parse_status < 6 ? e->parse_status : 0]);
    }
    return 0;
}

/* Capability probe: load only, attach nothing. Reports unsupported rather than
 * falling back to a different hook -- a silent fallback would make the
 * experiment's conclusions meaningless. */
static int probe_only(struct bpf_object *obj)
{
    struct bpf_program *p = bpf_object__find_program_by_name(obj, "aegis_skb_ingress");
    if (!p) {
        fprintf(stderr, "ingress program missing from object\n");
        return 1;
    }
    printf("cgroup_skb: loadable (verifier accepted both programs)\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *cgroup_path = NULL, *json_path = NULL;
    int seconds = 10, emit = 1, check_only = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--check")) check_only = 1;
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--emit") && i + 1 < argc) emit = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
        else cgroup_path = argv[i];
    }
    if (!check_only && !cgroup_path) {
        fprintf(stderr, "usage: skb_probe <cgroup-path> [--seconds N] [--emit 0|1] [--json f]\n"
                        "       skb_probe --check\n");
        return 1;
    }

    libbpf_set_print(NULL);
    struct bpf_object *obj = bpf_object__open_file("aegis_cgroup_skb.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "open object failed: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed (%s) -- cgroup_skb unsupported or verifier rejected\n",
                strerror(errno));
        bpf_object__close(obj);
        return 77;
    }
    if (check_only) {
        int rc = probe_only(obj);
        bpf_object__close(obj);
        return rc;
    }

    int cg_fd = open(cgroup_path, O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "open cgroup %s: %s\n", cgroup_path, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    int cfg_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "skb_cfg"));
    __u32 k = 0, v = (__u32)emit;
    bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY);

    /* BPF_F_ALLOW_MULTI via the prog_attach API rather than a bpf_link.
     *
     * A link attaches exclusively unless the whole chain agrees, and an
     * experiment that evicts a CNI's cgroup program would be far worse than one
     * that fails to attach. ALLOW_MULTI is also what makes the coexistence
     * question (B9) answerable at all: it is the mode real cgroup BPF users
     * (systemd, Cilium) attach with. */
    int ing_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "aegis_skb_ingress"));
    int egr_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "aegis_skb_egress"));
    if (bpf_prog_attach(ing_fd, cg_fd, BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attach ingress failed: %s\n", strerror(errno));
        close(cg_fd); bpf_object__close(obj); return 1;
    }
    if (bpf_prog_attach(egr_fd, cg_fd, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attach egress failed: %s\n", strerror(errno));
        bpf_prog_detach2(ing_fd, cg_fd, BPF_CGROUP_INET_INGRESS);
        close(cg_fd); bpf_object__close(obj); return 1;
    }
    printf("attached to %s (ALLOW_MULTI), emit=%d, %ds\n", cgroup_path, emit, seconds);

    if (json_path) {
        g_jsonl = fopen(json_path, "w");
        if (!g_jsonl) fprintf(stderr, "warning: cannot write %s\n", json_path);
    }

    struct ring_buffer *rb = NULL;
    if (emit) {
        rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "skb_events")),
                              on_event, NULL, NULL);
        if (!rb) fprintf(stderr, "warning: ring buffer unavailable\n");
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    time_t deadline = time(NULL) + seconds;
    while (!g_stop && time(NULL) < deadline) {
        if (rb) ring_buffer__poll(rb, 200);
        else usleep(200000);
    }

    /* Counters survive emission being off, which is how hook cost is measured
     * separately from observability cost. */
    int cnt_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "skb_counters"));
    int ncpu = libbpf_num_possible_cpus();
    unsigned long long totals[CNT_MAX] = {0};
    for (__u32 i = 0; i < CNT_MAX; i++) {
        __u64 per[1024] = {0};
        if (!bpf_map_lookup_elem(cnt_fd, &i, per))
            for (int c = 0; c < ncpu && c < 1024; c++) totals[i] += per[c];
    }

    printf("\n=== cgroup_skb audit results ===\n");
    printf("ingress packets observed : %llu\n", totals[CNT_INGRESS]);
    printf("egress  packets observed : %llu\n", totals[CNT_EGRESS]);
    printf("events emitted           : %llu\n", totals[CNT_EMITTED]);
    printf("unparsed packets         : %llu\n", totals[CNT_UNPARSED]);
    printf("ringbuf drops            : %llu\n", totals[CNT_DROPPED]);
    printf("events read by userspace : %llu\n", g_seen);
    printf("\n--- identity (the question this experiment exists for) ---\n");
    printf("skb_cgid == current_cgid : %llu\n", g_id_match);
    printf("skb_cgid != current_cgid : %llu\n", g_id_mismatch);
    printf("current_cgid == 0        : %llu\n", g_current_zero);
    printf("\n--- parse outcomes ---\n");
    for (int i = 0; i < 6; i++)
        if (g_by_status[i]) printf("%-14s : %llu\n", kParse[i], g_by_status[i]);

    if (g_jsonl) fclose(g_jsonl);
    if (rb) ring_buffer__free(rb);
    /* Explicit detach: prog_attach outlives the process, unlike a link. Leaving
     * a cgroup program behind after an experiment exits is exactly the kind of
     * surprise B8 is about. */
    bpf_prog_detach2(egr_fd, cg_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach2(ing_fd, cg_fd, BPF_CGROUP_INET_INGRESS);
    close(cg_fd);
    bpf_object__close(obj);
    printf("\ndetached cleanly\n");
    return 0;
}
