/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arena_htable.h — Open-addressing hash table inside a BPF arena.
 *
 * Keys are 64-bit composites: (kind << 56) | id.
 * Values are 64-bit slot indices into the arena node array.
 *
 * Design constraints:
 *   - Every arena access goes through ARENA_PTR() to work around
 *     the kernel 6.17 verifier + clang-19 addr_space_cast issue.
 *   - Probe loop is bounded to ARENA_HT_MAX_PROBE steps and fully
 *     unrolled (#pragma unroll) so the verifier sees a fixed trip count.
 *   - ~40 instructions per lookup, well within the 1M limit.
 *
 * This header is BPF-only (not included by userspace C++).
 */

#ifndef AEGIS_NEXT_ARENA_HTABLE_H
#define AEGIS_NEXT_ARENA_HTABLE_H

/* Number of buckets — must be a power of two. */
#define ARENA_HT_BUCKETS      (1u << 16)  /* 64K */
#define ARENA_HT_BUCKET_MASK  (ARENA_HT_BUCKETS - 1)

/* Max linear-probe steps before giving up. */
#define ARENA_HT_MAX_PROBE    8

/* Sentinel: key == 0 means empty bucket. */
#define ARENA_HT_EMPTY_KEY    0ULL

struct arena_ht_entry {
    __u64 key;    /* 0 = empty, else (kind << 56) | id */
    __u64 value;  /* slot index into arena_nodes[] */
};

/* Ensure ARENA_PTR is available. If the includer already defined it,
 * this is a no-op. Otherwise provide the standard definition. */
#ifndef ARENA_PTR
#define ARENA_PTR(ptr)                                     \
    ({                                                     \
        typeof(ptr) __p = (ptr);                           \
        asm volatile("" : "+r"(__p));                      \
        __p;                                               \
    })
#endif

/* Build a composite key from (kind, id).
 * kind occupies bits [63:56], id occupies bits [55:0]. */
static __always_inline __u64 arena_ht_make_key(__u8 kind, __u64 id)
{
    return ((__u64)kind << 56) | (id & 0x00FFFFFFFFFFFFFFULL);
}

/* FNV-1a-inspired multiplicative hash → bucket index. */
static __always_inline __u32 arena_ht_hash(__u64 key)
{
    /* Fibonacci hashing: multiply by golden-ratio constant, take
     * high bits. Distributes sequential keys well. */
    return (__u32)((key * 0x9E3779B97F4A7C15ULL) >> 48) & ARENA_HT_BUCKET_MASK;
}

/*
 * Insert (key, value) into the arena hash table.
 *
 * Overwrites an existing entry with the same key.
 * Returns 0 on success, -1 if all probe slots are occupied
 * by different keys (caller should treat as non-fatal).
 */
static __always_inline int
arena_ht_insert(struct arena_ht_entry __arena *table,
                __u64 key, __u64 value)
{
    __u32 idx = arena_ht_hash(key);

    #pragma unroll
    for (int i = 0; i < ARENA_HT_MAX_PROBE; i++) {
        __u32 probe = (idx + i) & ARENA_HT_BUCKET_MASK;
        __u64 existing = ARENA_PTR(&table[probe])->key;

        if (existing == ARENA_HT_EMPTY_KEY || existing == key) {
            ARENA_PTR(&table[probe])->key   = key;
            ARENA_PTR(&table[probe])->value = value;
            return 0;
        }
    }
    return -1; /* probe chain full */
}

/*
 * Look up a key in the arena hash table.
 *
 * Returns the associated slot index, or (__u64)-1 on miss.
 * Stops probing on the first empty bucket (linear probing invariant).
 */
static __always_inline __u64
arena_ht_lookup(struct arena_ht_entry __arena *table, __u64 key)
{
    __u32 idx = arena_ht_hash(key);

    #pragma unroll
    for (int i = 0; i < ARENA_HT_MAX_PROBE; i++) {
        __u32 probe = (idx + i) & ARENA_HT_BUCKET_MASK;
        __u64 existing = ARENA_PTR(&table[probe])->key;

        if (existing == key)
            return ARENA_PTR(&table[probe])->value;
        if (existing == ARENA_HT_EMPTY_KEY)
            return (__u64)-1;
    }
    return (__u64)-1; /* probed all steps, no match */
}

#endif /* AEGIS_NEXT_ARENA_HTABLE_H */
