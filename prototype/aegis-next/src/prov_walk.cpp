// SPDX-License-Identifier: GPL-2.0

#include "prov_walk.hpp"

namespace aegis_next {

std::size_t walk_lineage(std::uint64_t         start_slot,
                         std::uint64_t         slot_modulus,
                         const SlotReader&     read_slot,
                         const LineageVisitor& visit)
{
    if (slot_modulus == 0) {
        return 0;
    }

    std::uint64_t cursor = start_slot % slot_modulus;
    int depth = 0;
    while (depth < kMaxLineageDepth) {
        LineageEntry entry{};
        entry.depth = depth;
        entry.slot  = cursor;
        entry.node  = read_slot(cursor);
        visit(entry);

        if (entry.node.prev_index == kRootSentinel) {
            return static_cast<std::size_t>(depth + 1);
        }
        cursor = entry.node.prev_index % slot_modulus;
        ++depth;
    }
    return static_cast<std::size_t>(kMaxLineageDepth);
}

} // namespace aegis_next
