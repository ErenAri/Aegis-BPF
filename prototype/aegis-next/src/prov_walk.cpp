// SPDX-License-Identifier: GPL-2.0

#include "prov_walk.hpp"

namespace aegis_next {

std::size_t walk_lineage(std::uint64_t         start_slot,
                         std::uint64_t         slot_modulus,
                         const SlotReader&     read_slot,
                         const LineageVisitor& visit,
                         std::uint64_t         generation)
{
    if (slot_modulus == 0) {
        return 0;
    }

    const bool check_gen = (generation != kRootSentinel);

    std::uint64_t cursor = start_slot % slot_modulus;
    int depth = 0;
    while (depth < kMaxLineageDepth) {
        LineageEntry entry{};
        entry.depth = depth;
        entry.slot  = cursor;
        entry.node  = read_slot(cursor);
        entry.stale = check_gen && is_node_stale(entry.node, generation);
        visit(entry);

        if (entry.node.prev_index == kRootSentinel) {
            return static_cast<std::size_t>(depth + 1);
        }
        // Stop following prev_index if this node is stale —
        // the pointer likely points to overwritten data.
        if (entry.stale) {
            return static_cast<std::size_t>(depth + 1);
        }
        cursor = entry.node.prev_index % slot_modulus;
        ++depth;
    }
    return static_cast<std::size_t>(kMaxLineageDepth);
}

std::uint64_t find_slot_by_pid(std::uint32_t     target_pid,
                                std::uint64_t     total_nodes,
                                std::uint64_t     slot_modulus,
                                const SlotReader& read_slot,
                                std::uint64_t     scan_limit)
{
    if (slot_modulus == 0 || total_nodes == 0) {
        return kRootSentinel;
    }
    // Default: scan the entire populated range (capped at modulus).
    const std::uint64_t effective_total =
        (total_nodes < slot_modulus) ? total_nodes : slot_modulus;
    const std::uint64_t limit =
        (scan_limit > 0 && scan_limit < effective_total)
            ? scan_limit
            : effective_total;

    // Walk backwards from the most recent entry so we find the
    // freshest exec for this pid.
    for (std::uint64_t i = 0; i < limit; ++i) {
        const std::uint64_t idx = (total_nodes - 1 - i) % slot_modulus;
        ProvNode node = read_slot(idx);
        if (node.tgid == target_pid) {
            return idx;
        }
    }
    return kRootSentinel;
}

} // namespace aegis_next
