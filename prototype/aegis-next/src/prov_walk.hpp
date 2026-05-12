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
std::size_t walk_lineage(std::uint64_t        start_slot,
                         std::uint64_t        slot_modulus,
                         const SlotReader&    read_slot,
                         const LineageVisitor& visit);

} // namespace aegis_next
