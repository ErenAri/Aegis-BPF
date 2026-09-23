// Tests for the slotted-policy accessor and commit machinery.
//
// These need CAP_BPF to create maps, so they skip rather than fail when run
// unprivileged -- a silent pass there would never exercise the code.
// cppcheck-suppress-file missingIncludeSystem
#include <bpf/bpf.h>

#include <gtest/gtest.h>
#include <unistd.h>

#include <sys/stat.h>

#include <fstream>
#include <string>
#include <vector>

#include "policy_slots.hpp"
#include "utils.hpp"

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

// A pin left behind by a different agent version can have a different map type
// entirely. bpf_map__reuse_fd() does NOT reject that, so the mismatch surfaces
// much later as an opaque verifier error ("R1 type=map_value expected=map_ptr").
// The layout check exists to catch it at reuse time instead.
TEST(PinCompat, DetectsLayoutMismatch)
{
    if (needs_root()) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }

    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    const int hash = bpf_map_create(BPF_MAP_TYPE_HASH, "t_hash", 16, 1, 64, &opts);
    ASSERT_GE(hash, 0);

    // Same layout: compatible.
    EXPECT_TRUE(pinned_map_layout_matches(hash, BPF_MAP_TYPE_HASH, 16, 1));

    // The real upgrade case: a HASH pin where an ARRAY_OF_MAPS is now declared.
    EXPECT_FALSE(pinned_map_layout_matches(hash, BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 4));

    // Same type but a different key width is also incompatible.
    EXPECT_FALSE(pinned_map_layout_matches(hash, BPF_MAP_TYPE_HASH, 8, 1));

    close(hash);
}

// max_entries legitimately varies (try_set_max tuning, right-sized inner maps),
// so it must NOT be part of the compatibility decision.
TEST(PinCompat, IgnoresMaxEntries)
{
    if (needs_root()) {
        GTEST_SKIP() << "requires privileges to create BPF maps";
    }

    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    const int small = bpf_map_create(BPF_MAP_TYPE_HASH, "t_small", 16, 1, 64, &opts);
    ASSERT_GE(small, 0);
    EXPECT_TRUE(pinned_map_layout_matches(small, BPF_MAP_TYPE_HASH, 16, 1));
    close(small);
}

} // namespace aegis

using aegis::DenyEntries;
using aegis::encode_dev;
using aegis::InodeId;
using aegis::prune_stale_runtime_rules;

// --- runtime-rule carry-forward -------------------------------------------
//
// A reload builds a brand new generation, so a rule added with
// `aegis block add` only survives if it is deliberately re-installed. These
// cover the validation that decides which rules are worth re-installing.

namespace {

InodeId inode_of(const std::string& path)
{
    struct stat st{};
    EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
    InodeId id{};
    id.ino = st.st_ino;
    id.dev = encode_dev(st.st_dev);
    return id;
}

std::string make_temp_file(const std::string& name)
{
    std::string path = std::string(::getenv("TMPDIR") ? ::getenv("TMPDIR") : "/tmp") + "/" + name;
    std::ofstream out(path);
    out << "x";
    out.close();
    return path;
}

} // namespace

TEST(RuntimeRuleCarryForward, KeepsRuleWhosePathStillResolvesToTheSameInode)
{
    const std::string path = make_temp_file("aegis_rr_live");
    DenyEntries rules{{inode_of(path), path}};

    size_t dropped = 0;
    auto kept = prune_stale_runtime_rules(rules, dropped, nullptr);

    EXPECT_EQ(dropped, 0u);
    ASSERT_EQ(kept.size(), 1u);
    EXPECT_EQ(kept.begin()->second, path);
    ::unlink(path.c_str());
}

TEST(RuntimeRuleCarryForward, DropsRuleWhosePathNoLongerExists)
{
    const std::string path = make_temp_file("aegis_rr_vanish");
    DenyEntries rules{{inode_of(path), path}};
    ::unlink(path.c_str());

    std::vector<std::string> reasons;
    size_t dropped = 0;
    auto kept = prune_stale_runtime_rules(rules, dropped,
                                          [&](const std::string&, const std::string& why) { reasons.push_back(why); });

    EXPECT_EQ(dropped, 1u);
    EXPECT_TRUE(kept.empty());
    ASSERT_EQ(reasons.size(), 1u);
    EXPECT_NE(reasons[0].find("no longer exists"), std::string::npos);
}

TEST(RuntimeRuleCarryForward, DropsRuleWhosePathNowNamesADifferentInode)
{
    // The dangerous case: the path exists, so a naive existence check would
    // re-install the rule -- against whatever object has since taken that
    // path. The recorded inode is set explicitly rather than by deleting and
    // recreating the file, because a filesystem is free to hand the same inode
    // number straight back, which would silently make this test vacuous.
    const std::string path = make_temp_file("aegis_rr_replaced");
    InodeId recorded = inode_of(path);
    recorded.ino += 1; // the path now names a different object than recorded
    DenyEntries rules{{recorded, path}};
    ASSERT_NE(inode_of(path).ino, recorded.ino);

    std::vector<std::string> reasons;
    size_t dropped = 0;
    auto kept = prune_stale_runtime_rules(rules, dropped,
                                          [&](const std::string&, const std::string& why) { reasons.push_back(why); });

    EXPECT_EQ(dropped, 1u);
    EXPECT_TRUE(kept.empty()) << "a recycled inode must not inherit someone else's deny rule";
    ASSERT_EQ(reasons.size(), 1u);
    EXPECT_NE(reasons[0].find("different inode"), std::string::npos);
    ::unlink(path.c_str());
}

TEST(RuntimeRuleCarryForward, PartitionsAMixedSet)
{
    const std::string live = make_temp_file("aegis_rr_mixed_live");
    const std::string gone = make_temp_file("aegis_rr_mixed_gone");
    DenyEntries rules{{inode_of(live), live}, {inode_of(gone), gone}};
    ::unlink(gone.c_str());

    size_t dropped = 0;
    auto kept = prune_stale_runtime_rules(rules, dropped, nullptr);

    EXPECT_EQ(dropped, 1u);
    ASSERT_EQ(kept.size(), 1u);
    EXPECT_EQ(kept.begin()->second, live);
    ::unlink(live.c_str());
}
