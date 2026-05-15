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
    uint32_t path_slab_idx; /* 1-based index into path_slab[], 0 = no path */
    char     comm[12];
    uint32_t net_slab_idx;  /* 1-based index into net_slab[], 0 = no flow */
    uint32_t mnt_ns;        /* mount namespace inum */
    uint32_t pid_ns;        /* PID namespace inum */
};

/* Arena hash table entry — matches arena_htable.h on the BPF side. */
struct arena_ht_entry {
    uint64_t key;    /* 0 = empty, else (kind << 56) | id */
    uint64_t value;  /* slot index into arena_nodes[] */
};

/* Path slab entry — 256-byte slot for resolved file paths. */
struct path_slab_entry {
    uint64_t data[32]; /* 256 bytes as 32 × u64 */
};

/* Network flow entry — 48-byte 5-tuple for socket events. */
struct net_flow {
    uint8_t  family;       /* AF_INET=2, AF_INET6=10 */
    uint8_t  proto;        /* IPPROTO_TCP=6, IPPROTO_UDP=17, etc. */
    uint16_t src_port;     /* host byte order */
    uint16_t dst_port;     /* host byte order */
    uint16_t _pad;
    uint32_t src_v4;       /* network byte order; 0 for IPv6 */
    uint32_t dst_v4;       /* network byte order; 0 for IPv6 */
    uint8_t  src_v6[16];   /* full IPv6 src; zeroed for IPv4 */
    uint8_t  dst_v6[16];   /* full IPv6 dst; zeroed for IPv4 */
};

#define ARENA_HT_BUCKETS      (1u << 16)  /* 64K — must match BPF side */
#define ARENA_HT_MAX_PROBE    8
#define ARENA_HT_EMPTY_KEY    0ULL
#define PATH_SLAB_SLOTS       (1u << 12)  /* 4K — must match BPF side */
#define PATH_SLAB_SLOT_SZ     256
#define NET_SLAB_SLOTS        (1u << 12)  /* 4K — must match BPF side */
#define NET_SLAB_SLOT_SZ      48

/* Ringbuf alert — compact notification per LSM event.
 * Must match struct aegis_alert in provenance.bpf.c. */
struct aegis_alert {
    uint64_t slot;    /* arena node slot index */
    uint32_t pid;     /* process tgid */
    uint8_t  kind;    /* PROV_KIND_* */
    uint8_t  _pad[3];
};

#endif /* AEGIS_NEXT_PROV_ARENA_TYPES_H */
