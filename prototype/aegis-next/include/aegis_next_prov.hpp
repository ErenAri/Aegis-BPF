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

namespace aegis_next {

// ----- arena geometry (matches BPF side) -----

inline constexpr std::size_t kArenaPages = 16384;
inline constexpr std::size_t kArenaBytes = kArenaPages * 4096ULL;
inline constexpr std::size_t kMaxNodes   = 1ULL << 20;

inline constexpr std::uint64_t kRootSentinel =
    static_cast<std::uint64_t>(-1);

inline constexpr int kMaxLineageDepth = 64;

// ----- on-arena layout (matches BPF side) -----

struct ProvHeader {
    std::uint64_t magic;
    std::uint64_t next_index;
    std::uint64_t dropped;
    std::uint64_t reserved;
};

struct ProvNode {
    std::uint64_t ts_ns;
    std::uint32_t pid;
    std::uint32_t ppid;
    std::uint32_t tgid;
    std::uint32_t uid;
    std::uint64_t cgid;
    std::uint64_t exec_inode;
    std::uint64_t prev_index;
    char          comm[16];
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

} // namespace aegis_next
