/* Per-program BPF verifier complexity, in veristat's units.
 *
 * veristat lives in the kernel tree (tools/testing/selftests/bpf) and is not
 * packaged on any distro Aegis supports, so this reads the same numbers from
 * the verifier's own log: the "processed N insns ... total_states N
 * peak_states N" summary each program emits at log_level=1.
 *
 * Output is CSV so two branches can be diffed directly:
 *     program,processed_insns,total_states,peak_states
 *
 * Needs root (it loads the programs). Build:
 *     cc -O2 -o verifier_stats tools/verifier_stats.c -lbpf
 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define MAXP 64
#define LOGSZ (4 * 1024 * 1024)

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <aegis.bpf.o>\n", argv[0]); return 2; }
    printf("program,processed_insns,total_states,peak_states\n");
    struct bpf_object *obj = bpf_object__open(argv[1]);
    if (!obj) { fprintf(stderr, "open failed\n"); return 1; }

    struct bpf_program *progs[MAXP]; char *bufs[MAXP]; int n = 0;
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        if (n >= MAXP) break;
        bufs[n] = calloc(1, LOGSZ);
        bpf_program__set_log_buf(p, bufs[n], LOGSZ);
        bpf_program__set_log_level(p, 1);
        progs[n++] = p;
    }
    if (bpf_object__load(obj))
        fprintf(stderr, "note: load reported: %s\n", strerror(errno));

    long ti = 0, tp = 0; int got = 0;
    for (int i = 0; i < n; i++) {
        char *last = NULL, *cur = bufs[i];
        while ((cur = strstr(cur, "processed ")) != NULL) { last = cur; cur += 10; }
        if (!last) continue;
        long insns = 0, peak = 0, states = 0;
        sscanf(last, "processed %ld insns", &insns);
        char *pk = strstr(last, "peak_states ");
        if (pk) sscanf(pk, "peak_states %ld", &peak);
        char *ms = strstr(last, "total_states ");
        if (ms) sscanf(ms, "total_states %ld", &states);
        printf("%s,%ld,%ld,%ld\n", bpf_program__name(progs[i]), insns, states, peak);
        ti += insns; tp += peak; got++;
    }
    printf("TOTAL,%ld,,%ld\n", ti, tp);
    fprintf(stderr, "programs with verifier data: %d\n", got);
    return 0;
}
