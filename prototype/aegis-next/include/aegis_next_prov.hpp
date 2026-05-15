// SPDX-License-Identifier: GPL-2.0
//
// Shared layout types for the aegis-next arena provenance graph.
//
// These structs MUST match prototype/aegis-next/bpf/provenance.bpf.c
// byte-for-byte. The userspace tool mmaps the BPF arena directly,
// so any drift here is a memory-corruption bug, not a portability
// issue. The static_asserts at the bottom of this header catch
// the obvious layout breakage at compile time.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Event-kind constants shared with BPF side.
#include "../bpf/prov_types.h"

namespace aegis_next {

// ----- arena geometry (matches BPF side) -----

// Arena: nodes(80*1M) + hdr(32) + ready(4+pad4) + ht(16*64K)
//        + path_slab_next(8) + path_slab(256*4K)
//        + net_slab_next(8) + net_slab(48*4K) = ~82MB
inline constexpr std::size_t kArenaPages     = 21041;
inline constexpr std::size_t kArenaBytes     = kArenaPages * 4096ULL;
inline constexpr std::size_t kMaxNodes       = 1ULL << 20;
inline constexpr std::size_t kHtBuckets      = 1ULL << 16;  // 64K
inline constexpr int         kHtMaxProbe     = 8;
inline constexpr std::size_t kPathSlabSlots  = 1ULL << 12;  // 4K
inline constexpr std::size_t kPathSlabSlotSz = 256;
inline constexpr std::size_t kNetSlabSlots   = 1ULL << 12;  // 4K
inline constexpr std::size_t kNetSlabSlotSz  = 48;

inline constexpr std::uint64_t kRootSentinel =
    static_cast<std::uint64_t>(-1);

inline constexpr int kMaxLineageDepth = 64;

// ----- on-arena layout (matches BPF side) -----

struct ProvHeader {
    std::uint64_t magic;
    std::uint64_t next_index;
    std::uint64_t dropped;
    std::uint64_t generation;
};

struct ProvNode {
    std::uint64_t ts_ns;
    std::uint32_t pid;
    std::uint32_t ppid;
    std::uint32_t tgid;
    std::uint32_t uid;
    std::uint64_t cgid;
    std::uint64_t object_id;
    std::uint64_t prev_index;
    std::uint8_t  kind;
    std::uint8_t  flags;
    std::uint16_t extra;
    std::uint32_t path_slab_idx;  // 1-based index into path slab, 0 = no path
    char          comm[12];
    std::uint32_t net_slab_idx;   // 1-based index into net slab, 0 = no flow
    std::uint32_t mnt_ns;         // mount namespace inum
    std::uint32_t pid_ns;         // PID namespace inum
};

struct ProvLayout {
    ProvHeader hdr;
    ProvNode   nodes[kMaxNodes];
};

static_assert(sizeof(ProvHeader) == 32,
              "ProvHeader layout drift — must match BPF side");
static_assert(sizeof(ProvNode) == 80,
              "ProvNode layout drift — must match BPF side");
static_assert(offsetof(ProvNode, prev_index) == 40,
              "ProvNode.prev_index offset drift");
static_assert(offsetof(ProvNode, kind) == 48,
              "ProvNode.kind offset drift");
static_assert(offsetof(ProvNode, path_slab_idx) == 52,
              "ProvNode.path_slab_idx offset drift");
static_assert(offsetof(ProvNode, comm) == 56,
              "ProvNode.comm offset drift");

// ----- arena hash table helpers (userspace, reads mmap'd arena) -----

struct HtEntry {
    std::uint64_t key;
    std::uint64_t value;
};

inline std::uint64_t ht_make_key(std::uint8_t kind, std::uint64_t id)
{
    return (static_cast<std::uint64_t>(kind) << 56) |
           (id & 0x00FFFFFFFFFFFFFFULL);
}

inline std::uint32_t ht_hash(std::uint64_t key)
{
    return static_cast<std::uint32_t>(
        (key * 0x9E3779B97F4A7C15ULL) >> 48) & (kHtBuckets - 1);
}

inline std::uint64_t ht_lookup(const HtEntry* table, std::uint64_t key)
{
    std::uint32_t idx = ht_hash(key);
    for (int i = 0; i < kHtMaxProbe; ++i) {
        std::uint32_t probe = (idx + i) & (kHtBuckets - 1);
        if (table[probe].key == key)
            return table[probe].value;
        if (table[probe].key == 0)
            return kRootSentinel;
    }
    return kRootSentinel;
}

// Byte offset of the arena hash table from the arena mmap base.
// Verified at compile time in main.cpp via skeleton offsetof.
inline constexpr std::size_t kHtOffset =
    sizeof(ProvHeader) + sizeof(ProvNode) * kMaxNodes + 8;

inline const HtEntry* arena_ht_from_mmap(const void* arena_base)
{
    return reinterpret_cast<const HtEntry*>(
        static_cast<const char*>(arena_base) + kHtOffset);
}

// ----- path slab helpers -----

struct PathSlabEntry {
    std::uint64_t data[kPathSlabSlotSz / 8]; // 256 bytes
};

// Get the null-terminated path string from a path slab entry.
// Returns empty string if idx == 0 (no path).
inline const char* path_from_slab(const PathSlabEntry* slab,
                                   std::uint32_t idx)
{
    if (idx == 0)
        return "";
    return reinterpret_cast<const char*>(&slab[idx - 1]);
}

// ----- network flow slab helpers -----

struct NetFlow {
    std::uint8_t  family;       // AF_INET=2, AF_INET6=10
    std::uint8_t  proto;        // IPPROTO_TCP=6, IPPROTO_UDP=17
    std::uint16_t src_port;     // host byte order
    std::uint16_t dst_port;     // host byte order
    std::uint16_t _pad;
    std::uint32_t src_v4;       // network byte order; 0 for IPv6
    std::uint32_t dst_v4;       // network byte order; 0 for IPv6
    std::uint8_t  src_v6[16];   // full IPv6 src; zeroed for IPv4
    std::uint8_t  dst_v6[16];   // full IPv6 dst; zeroed for IPv4
};

static_assert(sizeof(NetFlow) == 48,
              "NetFlow layout drift — must match BPF side");

// Get a pointer to the net flow for a given 1-based slab index.
// Returns nullptr if idx == 0 (no flow).
inline const NetFlow* net_from_slab(const NetFlow* slab, std::uint32_t idx)
{
    if (idx == 0)
        return nullptr;
    return &slab[idx - 1];
}

// ----- node helpers -----

inline bool is_node_stale(const ProvNode& node, std::uint64_t current_generation)
{
    return node.flags != static_cast<std::uint8_t>(current_generation & 0xFF);
}

inline const char* kind_name(std::uint8_t kind)
{
    switch (kind) {
    case PROV_KIND_EXEC:           return "exec";
    case PROV_KIND_FILE_OPEN:      return "file";
    case PROV_KIND_SOCKET_CONNECT: return "conn";
    case PROV_KIND_SOCKET_BIND:    return "bind";
    case PROV_KIND_SOCKET_LISTEN:  return "listen";
    default:                       return "???";
    }
}

// ----- policy helpers -----

// FNV-1a hash matching the BPF side (must produce identical values).
inline std::uint32_t fnv1a(const char* s, std::size_t maxlen = 12)
{
    std::uint32_t h = 0x811c9dc5u;
    for (std::size_t i = 0; i < maxlen && s[i] != '\0'; ++i) {
        h ^= static_cast<std::uint32_t>(static_cast<unsigned char>(s[i]));
        h *= 0x01000193u;
    }
    return h;
}

} // namespace aegis_next
