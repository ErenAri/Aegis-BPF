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
    //   + cgid(8) + object_id(8) + prev_index(8)
    //   + kind(1) + flags(1) + extra(2) + path_slab_idx(4)
    //   + comm[12] + net_slab_idx(4) = 72 bytes.
    EXPECT_EQ(sizeof(ProvNode), 72u);
}

TEST(AegisNextLayout, PrevIndexOffsetMatchesBpfSide)
{
    EXPECT_EQ(offsetof(ProvNode, prev_index), 40u);
}

TEST(AegisNextLayout, KindOffsetMatchesBpfSide)
{
    EXPECT_EQ(offsetof(ProvNode, kind), 48u);
}

TEST(AegisNextLayout, PathSlabIdxOffsetMatchesBpfSide)
{
    EXPECT_EQ(offsetof(ProvNode, path_slab_idx), 52u);
}

TEST(AegisNextLayout, NetSlabIdxOffsetMatchesBpfSide)
{
    EXPECT_EQ(offsetof(ProvNode, net_slab_idx), 68u);
}

TEST(AegisNextLayout, NetFlowSizeMatchesBpfSide)
{
    EXPECT_EQ(sizeof(aegis_next::NetFlow), 48u);
}

TEST(AegisNextLayout, CommOffsetMatchesBpfSide)
{
    EXPECT_EQ(offsetof(ProvNode, comm), 56u);
}

TEST(AegisNextLayout, KindNameReturnsExpected)
{
    EXPECT_STREQ(kind_name(PROV_KIND_EXEC), "exec");
    EXPECT_STREQ(kind_name(PROV_KIND_FILE_OPEN), "file");
    EXPECT_STREQ(kind_name(PROV_KIND_SOCKET_CONNECT), "conn");
    EXPECT_STREQ(kind_name(PROV_KIND_SOCKET_BIND), "bind");
    EXPECT_STREQ(kind_name(PROV_KIND_SOCKET_LISTEN), "listen");
    EXPECT_STREQ(kind_name(255), "???");
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

// ----- find_slot_by_pid ----------------------------------------

TEST(FindSlotByPid, ReturnsRootSentinelOnEmptyArena)
{
    EXPECT_EQ(find_slot_by_pid(1000, 0, 8,
                               [](std::uint64_t) { return ProvNode{}; }),
              kRootSentinel);
}

TEST(FindSlotByPid, ReturnsRootSentinelOnZeroModulus)
{
    EXPECT_EQ(find_slot_by_pid(1000, 5, 0,
                               [](std::uint64_t) { return ProvNode{}; }),
              kRootSentinel);
}

TEST(FindSlotByPid, FindsSingleNodeByTgid)
{
    std::vector<ProvNode> nodes(1);
    nodes[0].tgid = 42;
    EXPECT_EQ(find_slot_by_pid(42, 1, nodes.size(),
                               [&](std::uint64_t s) { return nodes[s]; }),
              0u);
}

TEST(FindSlotByPid, FindsMostRecentExecWhenDuplicatePids)
{
    // Two execs from the same pid: slot 0 is older, slot 1 is newer.
    // find_slot_by_pid scans backwards and must return slot 1.
    std::vector<ProvNode> nodes(2);
    nodes[0].tgid = 99;
    nodes[0].ts_ns = 100;
    nodes[1].tgid = 99;
    nodes[1].ts_ns = 200;

    EXPECT_EQ(find_slot_by_pid(99, 2, nodes.size(),
                               [&](std::uint64_t s) { return nodes[s]; }),
              1u);
}

TEST(FindSlotByPid, ReturnsRootSentinelWhenPidNotPresent)
{
    auto chain = make_chain(5);
    EXPECT_EQ(find_slot_by_pid(9999, 5, chain.size(),
                               [&](std::uint64_t s) { return chain[s]; }),
              kRootSentinel);
}

TEST(FindSlotByPid, RespectsScanLimit)
{
    // Place target at slot 0, but limit scan to last 2 of 5 nodes.
    // The scanner only sees slots 4 and 3, never slot 0.
    std::vector<ProvNode> nodes(5);
    nodes[0].tgid = 42;
    for (std::size_t i = 1; i < 5; ++i) {
        nodes[i].tgid = static_cast<std::uint32_t>(100 + i);
    }

    EXPECT_EQ(find_slot_by_pid(42, 5, nodes.size(),
                               [&](std::uint64_t s) { return nodes[s]; },
                               2),
              kRootSentinel);
}

TEST(FindSlotByPid, WrapsAroundModulus)
{
    // total_nodes > slot_modulus simulates wrap. With modulus 3 and
    // total 5, the most recent entry is at (5-1)%3 = slot 1.
    std::vector<ProvNode> nodes(3);
    nodes[0].tgid = 10;
    nodes[1].tgid = 42; // this is the most recent write (total=5 -> slot 1)
    nodes[2].tgid = 20;

    EXPECT_EQ(find_slot_by_pid(42, 5, nodes.size(),
                               [&](std::uint64_t s) { return nodes[s]; }),
              1u);
}

// ----- generation / stale detection ----------------------------

TEST(Generation, IsNodeStaleMatchesCurrentGeneration)
{
    ProvNode node{};
    node.flags = 3;
    EXPECT_FALSE(is_node_stale(node, 3));
    EXPECT_FALSE(is_node_stale(node, 259)); // 259 & 0xFF == 3
    EXPECT_TRUE(is_node_stale(node, 4));
    EXPECT_TRUE(is_node_stale(node, 0));
}

TEST(Generation, WalkLineageStopsAtStaleNode)
{
    // Build a 3-node chain. Node 0 has generation 0 (stale),
    // nodes 1 and 2 have generation 1 (current).
    std::vector<ProvNode> chain(3);
    for (std::size_t i = 0; i < 3; ++i) {
        chain[i] = ProvNode{};
        chain[i].pid = static_cast<std::uint32_t>(100 + i);
        chain[i].tgid = chain[i].pid;
        chain[i].prev_index = (i == 0)
            ? kRootSentinel
            : static_cast<std::uint64_t>(i - 1);
        chain[i].flags = 1; // current generation
    }
    // Make node 0 stale (different generation tag).
    chain[0].flags = 0;

    std::vector<LineageEntry> visited;
    const std::size_t depth = walk_lineage(
        2, chain.size(),
        [&](std::uint64_t slot) { return chain[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); },
        1 /* current generation */);

    // Should visit node 2 (fresh), node 1 (fresh, prev=0 which is
    // stale), then stop. Node 1 follows prev_index to node 0 but
    // walk_lineage should visit node 1 and then node 0 is stale.
    // Actually: walk visits 2 (fresh), follows to 1 (fresh),
    // follows to 0 (stale, visited but walk stops after).
    ASSERT_EQ(visited.size(), 3u);
    EXPECT_FALSE(visited[0].stale); // node 2
    EXPECT_FALSE(visited[1].stale); // node 1
    EXPECT_TRUE(visited[2].stale);  // node 0 (stale)
    EXPECT_EQ(depth, 3u);
}

TEST(Generation, WalkLineageNoGenerationCheckWhenSentinel)
{
    // When generation == kRootSentinel, no stale checking occurs.
    std::vector<ProvNode> chain(2);
    chain[0] = ProvNode{};
    chain[0].pid = 1;
    chain[0].flags = 99; // different from any generation
    chain[0].prev_index = kRootSentinel;
    chain[1] = ProvNode{};
    chain[1].pid = 2;
    chain[1].flags = 0;
    chain[1].prev_index = 0;

    std::vector<LineageEntry> visited;
    walk_lineage(
        1, chain.size(),
        [&](std::uint64_t slot) { return chain[slot]; },
        [&](const LineageEntry& e) { visited.push_back(e); },
        kRootSentinel /* no generation check */);

    ASSERT_EQ(visited.size(), 2u);
    EXPECT_FALSE(visited[0].stale);
    EXPECT_FALSE(visited[1].stale);
}

} // namespace
} // namespace aegis_next
