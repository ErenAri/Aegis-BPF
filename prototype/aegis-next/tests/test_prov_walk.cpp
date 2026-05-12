// SPDX-License-Identifier: GPL-2.0
//
// Selftest harness for the aegis-next userspace lineage walker.
//
// These tests run without root, without a 6.9+ kernel, and
// without loading any BPF program. The lineage-walk logic is
// driven against a synthetic in-memory store via SlotReader, so
// CI can run it on any Linux runner.
//
// What is NOT covered here (intentional — needs a 6.9+ vmtest):
//   - BPF arena map load/attach/mmap roundtrip
//   - LSM bprm_check_security firing
//   - LRU_HASH eviction behaviour under load
//
// Those belong in a separate kernel-side test target gated on
// runtime kernel detection (see F0.3 in the prototype roadmap).

// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "aegis_next_prov.hpp"
#include "prov_walk.hpp"

namespace aegis_next {
namespace {

// Build a synthetic chain of N nodes where node[i].prev_index = i-1
// and node[0].prev_index = kRootSentinel. Tail is node[N-1].
std::vector<ProvNode> make_chain(std::size_t n)
{
    std::vector<ProvNode> chain(n);
    for (std::size_t i = 0; i < n; ++i) {
        chain[i] = ProvNode{};
        chain[i].pid = static_cast<std::uint32_t>(1000 + i);
        chain[i].tgid = chain[i].pid;
        chain[i].ppid = (i == 0)
            ? 0u
            : static_cast<std::uint32_t>(1000 + i - 1);
        chain[i].prev_index = (i == 0)
            ? kRootSentinel
            : static_cast<std::uint64_t>(i - 1);
        // Truncate to avoid format-truncation warnings: the slot
        // index, not the comm field, is the identity in tests.
        const unsigned bounded = static_cast<unsigned>(i % 10000u);
        std::snprintf(chain[i].comm, sizeof(chain[i].comm), "p%u", bounded);
    }
    return chain;
}

// ----- layout invariants ----------------------------------------

TEST(AegisNextLayout, HeaderSizeMatchesBpfSide)
{
    // 4 x u64 = 32 bytes. BPF side encodes the same layout; drift
    // here is a memory-corruption bug, not a portability issue.
    EXPECT_EQ(sizeof(ProvHeader), 32u);
}

TEST(AegisNextLayout, NodeSizeMatchesBpfSide)
{
    // ts_ns(8) + pid(4) + ppid(4) + tgid(4) + uid(4)
    //   + cgid(8) + exec_inode(8) + prev_index(8) + comm[16]
    //   = 64 bytes, no padding.
    EXPECT_EQ(sizeof(ProvNode), 64u);
}

TEST(AegisNextLayout, PrevIndexOffsetMatchesBpfSide)
{
    EXPECT_EQ(offsetof(ProvNode, prev_index), 40u);
}

// ----- walk_lineage --------------------------------------------

TEST(WalkLineage, ZeroModulusReturnsZero)
{
    std::size_t visits = 0;
    const std::size_t depth = walk_lineage(
        0, 0,
        [](std::uint64_t) { return ProvNode{}; },
        [&](const LineageEntry&) { ++visits; });
    EXPECT_EQ(depth, 0u);
    EXPECT_EQ(visits, 0u);
}

TEST(WalkLineage, SingleNodeChainTerminatesAtRoot)
{
    auto chain = make_chain(1);
    std::vector<LineageEntry> visited;
    const std::size_t depth = walk_lineage(
        0, chain.size(),
        [&](std::uint64_t slot) { return chain[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); });

    ASSERT_EQ(depth, 1u);
    ASSERT_EQ(visited.size(), 1u);
    EXPECT_EQ(visited[0].depth, 0);
    EXPECT_EQ(visited[0].node.pid, 1000u);
    EXPECT_EQ(visited[0].node.prev_index, kRootSentinel);
}

TEST(WalkLineage, FiveNodeChainVisitsAllAndStopsAtRoot)
{
    auto chain = make_chain(5);
    std::vector<LineageEntry> visited;
    const std::size_t depth = walk_lineage(
        4, chain.size(),
        [&](std::uint64_t slot) { return chain[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); });

    ASSERT_EQ(depth, 5u);
    ASSERT_EQ(visited.size(), 5u);
    // Walk goes tail -> root, so depth 0 = last exec, depth 4 = root.
    EXPECT_EQ(visited[0].node.pid, 1004u);
    EXPECT_EQ(visited[0].slot, 4u);
    EXPECT_EQ(visited[0].depth, 0);
    EXPECT_EQ(visited[4].node.pid, 1000u);
    EXPECT_EQ(visited[4].depth, 4);
    EXPECT_EQ(visited[4].node.prev_index, kRootSentinel);
}

TEST(WalkLineage, DepthCapTruncatesPathologicallyLongChain)
{
    // Build a chain LONGER than the cap. We don't actually need
    // the chain stored linearly — just need every prev_index to
    // resolve to a node whose prev_index is also non-sentinel.
    // Simulate a 1000-deep chain.
    constexpr std::size_t kLen = 1000;
    auto chain = make_chain(kLen);

    std::vector<LineageEntry> visited;
    const std::size_t depth = walk_lineage(
        kLen - 1, chain.size(),
        [&](std::uint64_t slot) { return chain[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); });

    EXPECT_EQ(depth, static_cast<std::size_t>(kMaxLineageDepth));
    EXPECT_EQ(visited.size(), static_cast<std::size_t>(kMaxLineageDepth));
    // Even though chain[0] is the real root, we stopped before
    // reaching it.
    EXPECT_NE(visited.back().node.prev_index, kRootSentinel);
}

TEST(WalkLineage, CyclicArenaTerminatesAtDepthCap)
{
    // A corrupted or malicious arena could form a cycle.
    // walk_lineage has no visited-set tracking by design (it
    // would cost memory on every event); the depth cap is the
    // defense. Verify it actually defends.
    std::vector<ProvNode> cycle(3);
    for (std::size_t i = 0; i < cycle.size(); ++i) {
        cycle[i] = ProvNode{};
        cycle[i].pid = static_cast<std::uint32_t>(2000 + i);
        cycle[i].prev_index = (i + cycle.size() - 1) % cycle.size();
    }

    std::size_t visit_count = 0;
    const std::size_t depth = walk_lineage(
        0, cycle.size(),
        [&](std::uint64_t slot) { return cycle[slot]; },
        [&](const LineageEntry&) { ++visit_count; });

    EXPECT_EQ(depth, static_cast<std::size_t>(kMaxLineageDepth));
    EXPECT_EQ(visit_count, static_cast<std::size_t>(kMaxLineageDepth));
}

TEST(WalkLineage, StartSlotIsTakenModuloSlotModulus)
{
    // walk_lineage applies `% slot_modulus` to start_slot so that
    // callers can pass a raw monotonic next_index - 1 without
    // having to do the wrap themselves.
    auto chain = make_chain(3);
    std::vector<LineageEntry> visited;
    walk_lineage(
        chain.size() + 1, // wraps to slot 1
        chain.size(),
        [&](std::uint64_t slot) { return chain[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); });

    ASSERT_GE(visited.size(), 1u);
    EXPECT_EQ(visited[0].slot, 1u);
    EXPECT_EQ(visited[0].node.pid, 1001u);
}

TEST(WalkLineage, RootSentinelStopsTraversalImmediately)
{
    std::vector<ProvNode> nodes(2);
    nodes[0] = ProvNode{};
    nodes[0].pid = 1;
    nodes[0].prev_index = kRootSentinel;
    nodes[1] = ProvNode{};
    nodes[1].pid = 2;
    nodes[1].prev_index = 0;

    std::vector<LineageEntry> visited;
    const std::size_t depth = walk_lineage(
        0, nodes.size(),
        [&](std::uint64_t slot) { return nodes[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); });

    EXPECT_EQ(depth, 1u);
    ASSERT_EQ(visited.size(), 1u);
    EXPECT_EQ(visited[0].node.pid, 1u);
}

} // namespace
} // namespace aegis_next
