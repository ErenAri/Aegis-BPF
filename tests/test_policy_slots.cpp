// Tests for the slotted-policy accessor and commit machinery.
//
// These need CAP_BPF to create maps, so they skip rather than fail when run
// unprivileged -- a silent pass there would never exercise the code.
// cppcheck-suppress-file missingIncludeSystem
#include <bpf/bpf.h>

#include <gtest/gtest.h>
#include <unistd.h>

#include "policy_slots.hpp"

namespace aegis {
namespace {

bool needs_root()
{
    return geteuid() != 0;
}

int make_hash_map(uint32_t entries)
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    return bpf_map_create(BPF_MAP_TYPE_HASH, "t_inner", 4, 1, entries, &opts);
}

int make_outer(int tmpl_fd)
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.inner_map_fd = static_cast<__u32>(tmpl_fd);
    return bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "t_outer", 4, 4, 2, &opts);
}

int make_active_slot()
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    return bpf_map_create(BPF_MAP_TYPE_ARRAY, "t_slot", 4, 4, 1, &opts);
}

} // namespace

// The accessor must reach the inner map that active_slot currently names, not
// slot 0 unconditionally -- otherwise every read would target a stale
// generation the moment the slot flips.
TEST(PolicySlots, ResolvesTheLiveInnerMap)
{
    if (needs_root()) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }

    const int tmpl = make_hash_map(64);
    ASSERT_GE(tmpl, 0);
    const int outer = make_outer(tmpl);
    ASSERT_GE(outer, 0);
    const int slot_fd = make_active_slot();
    ASSERT_GE(slot_fd, 0);

    // Put a distinct inner map in each slot, marked by the value it holds.
    for (uint32_t slot = 0; slot < 2; ++slot) {
        const int inner = make_hash_map(64);
        ASSERT_GE(inner, 0);
        uint32_t key = 1;
        uint8_t marker = static_cast<uint8_t>(10 + slot);
        ASSERT_EQ(bpf_map_update_elem(inner, &key, &marker, BPF_ANY), 0);
        uint32_t inner_value = static_cast<uint32_t>(inner);
        ASSERT_EQ(bpf_map_update_elem(outer, &slot, &inner_value, BPF_ANY), 0);
        close(inner);
    }

    // Slot 0 is live: we must read slot 0's marker.
    auto live0 = live_policy_map_from_fds(outer, slot_fd);
    ASSERT_TRUE(static_cast<bool>(live0));
    uint32_t key = 1;
    uint8_t got = 0;
    ASSERT_EQ(bpf_map_lookup_elem(live0->fd(), &key, &got), 0);
    EXPECT_EQ(got, 10);

    // Flip to slot 1; the accessor must now follow it.
    uint32_t zero = 0;
    uint32_t one = 1;
    ASSERT_EQ(bpf_map_update_elem(slot_fd, &zero, &one, BPF_ANY), 0);

    auto live1 = live_policy_map_from_fds(outer, slot_fd);
    ASSERT_TRUE(static_cast<bool>(live1));
    got = 0;
    ASSERT_EQ(bpf_map_lookup_elem(live1->fd(), &key, &got), 0);
    EXPECT_EQ(got, 11);

    close(slot_fd);
    close(outer);
    close(tmpl);
}

// An unpopulated slot must surface as an error, never as a silently empty map
// that a caller could mistake for "no rules".
TEST(PolicySlots, UnpopulatedSlotIsAnError)
{
    if (needs_root()) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }

    const int tmpl = make_hash_map(64);
    ASSERT_GE(tmpl, 0);
    const int outer = make_outer(tmpl);
    ASSERT_GE(outer, 0);
    const int slot_fd = make_active_slot();
    ASSERT_GE(slot_fd, 0);

    EXPECT_FALSE(static_cast<bool>(live_policy_map_from_fds(outer, slot_fd)));

    close(slot_fd);
    close(outer);
    close(tmpl);
}

} // namespace aegis
