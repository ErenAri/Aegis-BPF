// SPDX-License-Identifier: GPL-2.0
//
// Lineage walking for the aegis-next arena provenance graph.
//
// Pure userspace; no BPF dependency. The traversal is decoupled
// from the concrete arena pointer via a SlotReader callback so
// tests can drive it against a synthetic in-memory store without
// allocating a 64 MiB ProvLayout.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

#include "aegis_next_prov.hpp"

namespace aegis_next {

struct LineageEntry {
    int           depth;
    std::uint64_t slot;
    ProvNode      node;
    bool          stale = false;  // true if generation tag mismatches
};

using SlotReader = std::function<ProvNode(std::uint64_t)>;
using LineageVisitor = std::function<void(const LineageEntry&)>;

// Walks backwards from start_slot following prev_index, modulo
// slot_modulus, invoking `visit` for each visited node. Stops at
// the first node whose prev_index == kRootSentinel, OR when
// kMaxLineageDepth would be exceeded, whichever comes first.
//
// Returns the number of entries visited (1 + the final depth).
// Callers that want to know whether the walk terminated cleanly
// can compare the return value to kMaxLineageDepth.
//
// The function intentionally does NOT detect cycles by tracking
// visited slots: the depth cap is the cycle defense. A malicious
// or corrupted arena that loops back on itself just truncates at
// depth 64, which is the same behavior as legitimate deep chains.
// When generation != kRootSentinel, each visited node is tagged as
// stale if its flags byte doesn't match the generation's low byte.
// The walk still continues through stale nodes (callers decide how
// to render them), but stops if it would follow a stale prev_index.
std::size_t walk_lineage(std::uint64_t        start_slot,
                         std::uint64_t        slot_modulus,
                         const SlotReader&    read_slot,
                         const LineageVisitor& visit,
                         std::uint64_t        generation = kRootSentinel);

// O(1) lookup via the arena hash table. Returns the slot index
// for the most recent exec of `target_pid`, or kRootSentinel on miss.
// The hash table pointer comes from arena_ht_from_mmap() or the
// skeleton's skel->arena->arena_ht.
std::uint64_t find_slot_by_pid_ht(std::uint32_t        target_pid,
                                   const HtEntry*       ht,
                                   std::uint64_t        slot_modulus,
                                   const SlotReader&    read_slot);

// Linear scan fallback. Scans backwards from `total_nodes - 1` to
// find the most recent arena slot whose tgid matches `target_pid`.
// Returns the slot index, or kRootSentinel if no match is found.
std::uint64_t find_slot_by_pid(std::uint32_t        target_pid,
                                std::uint64_t        total_nodes,
                                std::uint64_t        slot_modulus,
                                const SlotReader&    read_slot,
                                std::uint64_t        scan_limit = 0);

} // namespace aegis_next
