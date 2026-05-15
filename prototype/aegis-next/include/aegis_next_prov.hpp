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

// Event-kind constants shared with BPF side.
#include "../bpf/prov_types.h"

namespace aegis_next {

// ----- arena geometry (matches BPF side) -----

// Arena geometry: nodes (16384p) + header/flag (1p) + hash table (256p)
inline constexpr std::size_t kArenaPages   = 16641;
inline constexpr std::size_t kArenaBytes   = kArenaPages * 4096ULL;
inline constexpr std::size_t kMaxNodes     = 1ULL << 20;
inline constexpr std::size_t kHtBuckets    = 1ULL << 16;  // 64K
inline constexpr int         kHtMaxProbe   = 8;

inline constexpr std::uint64_t kRootSentinel =
    static_cast<std::uint64_t>(-1);

inline constexpr int kMaxLineageDepth = 64;

// ----- on-arena layout (matches BPF side) -----

struct ProvHeader {
    std::uint64_t magic;
    std::uint64_t next_index;
    std::uint64_t dropped;
    std::uint64_t generation;  // incremented each time next_index wraps past kMaxNodes
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
    char          comm[12];
};

struct ProvLayout {
    ProvHeader hdr;
    ProvNode   nodes[kMaxNodes];
};

static_assert(sizeof(ProvHeader) == 32,
              "ProvHeader layout drift — must match BPF side");
static_assert(sizeof(ProvNode) == 64,
              "ProvNode layout drift — must match BPF side");
static_assert(offsetof(ProvNode, prev_index) == 40,
              "ProvNode.prev_index offset drift");
static_assert(offsetof(ProvNode, kind) == 48,
              "ProvNode.kind offset drift");
static_assert(offsetof(ProvNode, comm) == 52,
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

// O(1) lookup in the mmap'd arena hash table.
// Returns the slot index, or kRootSentinel on miss.
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
// Layout: arena_hdr(32) + arena_nodes(64M) + arena_ready(int,4) + pad(4)
// The pad aligns arena_ht to 8 bytes (arena_ht_entry contains u64).
// Verified at compile time in main.cpp via skeleton offsetof.
inline constexpr std::size_t kHtOffset =
    sizeof(ProvHeader) + sizeof(ProvNode) * kMaxNodes + 8;

// Get the arena hash table from a raw mmap'd arena pointer.
inline const HtEntry* arena_ht_from_mmap(const void* arena_base)
{
    return reinterpret_cast<const HtEntry*>(
        static_cast<const char*>(arena_base) + kHtOffset);
}

// A node is "stale" if its generation tag (flags byte) doesn't match
// the current generation's low byte. This catches overwrites after
// the arena wraps. False negatives occur every 256 wraps (~256M nodes).
inline bool is_node_stale(const ProvNode& node, std::uint64_t current_generation)
{
    return node.flags != static_cast<std::uint8_t>(current_generation & 0xFF);
}

inline const char* kind_name(std::uint8_t kind)
{
    switch (kind) {
    case PROV_KIND_EXEC:           return "exec";
    case PROV_KIND_FILE_OPEN:      return "file";
    case PROV_KIND_SOCKET_CONNECT: return "sock";
    default:                       return "???";
    }
}

} // namespace aegis_next
