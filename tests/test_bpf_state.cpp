// Move-semantics regression test for BpfState.
//
// BpfState's map handles + reuse/attach flags live in the trivially-copyable
// BpfMapState base, so a move copies them wholesale — a newly-added map or flag
// can never be silently dropped from the move path (the footgun behind the
// policy_generation / deny_comm unpinned-map regressions). This test pins that
// invariant: a move transfers the state and resets the source.
//
// Map handles are borrowed (owned by BpfState::obj, which stays null here), so
// the sentinel pointers below are never dereferenced or freed.

#include <gtest/gtest.h>

#include "bpf_ops.hpp"

using namespace aegis;

namespace {
bpf_map* fake(uintptr_t n)
{
    return reinterpret_cast<bpf_map*>(n);
}
} // namespace

TEST(BpfStateMove, MoveConstructTransfersStateAndResetsSource)
{
    BpfState a;
    a.deny_path = fake(0x1001);
    a.deny_comm = fake(0x1002);
    a.policy_generation_map = fake(0x1003);
    a.net_block_stats = fake(0x1004);
    a.deny_comm_reused = true;
    a.policy_generation_reused = true;
    a.ima_hook_attached = true;
    a.file_hooks_attached = 3;

    BpfState b = std::move(a);

    // Destination carries every field.
    EXPECT_EQ(b.deny_path, fake(0x1001));
    EXPECT_EQ(b.deny_comm, fake(0x1002));
    EXPECT_EQ(b.policy_generation_map, fake(0x1003));
    EXPECT_EQ(b.net_block_stats, fake(0x1004));
    EXPECT_TRUE(b.deny_comm_reused);
    EXPECT_TRUE(b.policy_generation_reused);
    EXPECT_TRUE(b.ima_hook_attached);
    EXPECT_EQ(b.file_hooks_attached, 3);

    // Source is reset — no dangling handles or stale flags.
    EXPECT_EQ(a.deny_path, nullptr); // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(a.deny_comm, nullptr);
    EXPECT_EQ(a.policy_generation_map, nullptr);
    EXPECT_FALSE(a.deny_comm_reused);
    EXPECT_FALSE(a.policy_generation_reused);
    EXPECT_EQ(a.file_hooks_attached, 0);
}

TEST(BpfStateMove, MoveAssignTransfersStateAndResetsSource)
{
    BpfState a;
    a.deny_ipv4 = fake(0x2001);
    a.deny_cidr_v6 = fake(0x2002);
    a.deny_ipv4_reused = true;
    a.socket_connect_hook_attached = true;

    BpfState b;
    b = std::move(a);

    EXPECT_EQ(b.deny_ipv4, fake(0x2001));
    EXPECT_EQ(b.deny_cidr_v6, fake(0x2002));
    EXPECT_TRUE(b.deny_ipv4_reused);
    EXPECT_TRUE(b.socket_connect_hook_attached);

    EXPECT_EQ(a.deny_ipv4, nullptr); // NOLINT(bugprone-use-after-move)
    EXPECT_FALSE(a.deny_ipv4_reused);
    EXPECT_FALSE(a.socket_connect_hook_attached);
}
