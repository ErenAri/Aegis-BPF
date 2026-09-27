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

#include <bpf/bpf.h>

#include <gtest/gtest.h>
#include <unistd.h>

#include "bpf_map_compat.hpp"
#include "bpf_maps.hpp"
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
    a.deny_path.outer = fake(0x1001);
    a.deny_comm.outer = fake(0x1002);
    a.policy_generation_map = fake(0x1003);
    a.net_block_stats = fake(0x1004);
    a.deny_comm_reused = true;
    a.policy_generation_reused = true;
    a.ima_hook_attached = true;
    a.file_hooks_attached = 3;

    BpfState b = std::move(a);

    // Destination carries every field.
    EXPECT_EQ(b.deny_path.outer, fake(0x1001));
    EXPECT_EQ(b.deny_comm.outer, fake(0x1002));
    EXPECT_EQ(b.policy_generation_map, fake(0x1003));
    EXPECT_EQ(b.net_block_stats, fake(0x1004));
    EXPECT_TRUE(b.deny_comm_reused);
    EXPECT_TRUE(b.policy_generation_reused);
    EXPECT_TRUE(b.ima_hook_attached);
    EXPECT_EQ(b.file_hooks_attached, 3);

    // Source is reset — no dangling handles or stale flags.
    EXPECT_EQ(a.deny_path.outer, nullptr); // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(a.deny_comm.outer, nullptr);
    EXPECT_EQ(a.policy_generation_map, nullptr);
    EXPECT_FALSE(a.deny_comm_reused);
    EXPECT_FALSE(a.policy_generation_reused);
    EXPECT_EQ(a.file_hooks_attached, 0);
}

TEST(BpfStateMove, MoveAssignTransfersStateAndResetsSource)
{
    BpfState a;
    a.deny_ipv4.outer = fake(0x2001);
    a.deny_cidr_v6.outer = fake(0x2002);
    a.deny_ipv4_reused = true;
    a.socket_connect_hook_attached = true;

    BpfState b;
    b = std::move(a);

    EXPECT_EQ(b.deny_ipv4.outer, fake(0x2001));
    EXPECT_EQ(b.deny_cidr_v6.outer, fake(0x2002));
    EXPECT_TRUE(b.deny_ipv4_reused);
    EXPECT_TRUE(b.socket_connect_hook_attached);

    EXPECT_EQ(a.deny_ipv4.outer, nullptr); // NOLINT(bugprone-use-after-move)
    EXPECT_FALSE(a.deny_ipv4_reused);
    EXPECT_FALSE(a.socket_connect_hook_attached);
}

// Probes whether this kernel accepts an inner map whose max_entries differs
// from the outer map's template (relaxed in 5.11). The answer decides whether
// policy inner maps can be right-sized; the probe must be stable and cached.
TEST(BpfMapProbe, VariableInnerMaxEntriesIsStableAndCached)
{
    const bool first = aegis::supports_variable_inner_max_entries();
    const bool second = aegis::supports_variable_inner_max_entries();
    EXPECT_EQ(first, second);

    // Unprivileged runs cannot create BPF maps at all, so the probe reports
    // false for want of CAP_BPF rather than for want of kernel support. Only
    // a privileged run can assert the real answer -- without this skip the
    // test would pass trivially and never exercise the probe.
    if (geteuid() != 0) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }
    EXPECT_TRUE(first) << "kernel " << "5.11+ should accept variable-size inner maps";
}

// Right-sizing contract: a non-zero override shrinks the clone when the kernel
// allows it, and is ignored (falling back to the source size) when it does not.
TEST(ShadowMap, HonoursMaxEntriesOverride)
{
    if (geteuid() != 0) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }

    int live = aegis::map_create(BPF_MAP_TYPE_HASH, "aegis_live", 4, 1, 4096);
    ASSERT_GE(live, 0);

    auto shadow = aegis::create_shadow_map_from_fd(live, 64);
    ASSERT_TRUE(static_cast<bool>(shadow));

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    ASSERT_EQ(bpf_obj_get_info_by_fd(shadow->fd(), &info, &len), 0);

    if (aegis::supports_variable_inner_max_entries()) {
        EXPECT_EQ(info.max_entries, 64u);
    } else {
        EXPECT_EQ(info.max_entries, 4096u);
    }
    close(live);
}

// A zero override means "clone the source size", which is what every existing
// create_shadow_map call site relies on.
TEST(ShadowMap, ZeroOverrideClonesSourceSize)
{
    if (geteuid() != 0) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }

    int live = aegis::map_create(BPF_MAP_TYPE_HASH, "aegis_live2", 4, 1, 512);
    ASSERT_GE(live, 0);

    auto shadow = aegis::create_shadow_map_from_fd(live, 0);
    ASSERT_TRUE(static_cast<bool>(shadow));

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    ASSERT_EQ(bpf_obj_get_info_by_fd(shadow->fd(), &info, &len), 0);
    EXPECT_EQ(info.max_entries, 512u);
    close(live);
}
