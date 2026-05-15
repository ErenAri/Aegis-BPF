/* SPDX-License-Identifier: GPL-2.0 */
/*
 * C-compatible struct definitions for the BPF arena globals.
 * These must match provenance.bpf.c byte-for-byte.
 * Included by C++ code before the skeleton header so bpftool's
 * generated struct provenance_bpf__arena can resolve the types.
 */
#ifndef AEGIS_NEXT_PROV_ARENA_TYPES_H
#define AEGIS_NEXT_PROV_ARENA_TYPES_H

#include <stdint.h>

struct prov_header {
    uint64_t magic;
    uint64_t next_index;
    uint64_t dropped;
    uint64_t generation;
};

struct prov_node {
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t ppid;
    uint32_t tgid;
    uint32_t uid;
    uint64_t cgid;
    uint64_t object_id;
    uint64_t prev_index;
    uint8_t  kind;
    uint8_t  flags;
    uint16_t extra;
    char     comm[12];
};

/* Arena hash table entry — matches arena_htable.h on the BPF side. */
struct arena_ht_entry {
    uint64_t key;    /* 0 = empty, else (kind << 56) | id */
    uint64_t value;  /* slot index into arena_nodes[] */
};

#define ARENA_HT_BUCKETS      (1u << 16)  /* 64K — must match BPF side */
#define ARENA_HT_MAX_PROBE    8
#define ARENA_HT_EMPTY_KEY    0ULL

#endif /* AEGIS_NEXT_PROV_ARENA_TYPES_H */
