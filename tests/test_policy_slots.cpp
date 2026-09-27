// Tests for the slotted-policy accessor and commit machinery.
//
// These need CAP_BPF to create maps, so they skip rather than fail when run
// unprivileged -- a silent pass there would never exercise the code.
// cppcheck-suppress-file missingIncludeSystem
#include <bpf/bpf.h>

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "bpf_map_compat.hpp"
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
    return aegis::map_create(BPF_MAP_TYPE_HASH, "t_inner", 4, 1, entries);
}

int make_outer(int tmpl_fd)
{
    return aegis::map_create_in_map(BPF_MAP_TYPE_ARRAY_OF_MAPS, "t_outer", 4, tmpl_fd, 2);
}

int make_active_slot()
{
    return aegis::map_create(BPF_MAP_TYPE_ARRAY, "t_slot", 4, 4, 1);
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

    const int hash = aegis::map_create(BPF_MAP_TYPE_HASH, "t_hash", 16, 1, 64);
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

    const int small = aegis::map_create(BPF_MAP_TYPE_HASH, "t_small", 16, 1, 64);
    ASSERT_GE(small, 0);
    EXPECT_TRUE(pinned_map_layout_matches(small, BPF_MAP_TYPE_HASH, 16, 1));
    close(small);
}

} // namespace aegis

using aegis::DenyEntries;
using aegis::encode_dev;
using aegis::InodeId;
using aegis::migrate_legacy_runtime_rules;
using aegis::prune_stale_runtime_rules;

// --- runtime-rule carry-forward -------------------------------------------
//
// A reload builds a brand new generation, so a rule added with
// `aegis block add` only survives if it is deliberately re-installed. These
// cover the validation that decides which rules are worth re-installing.

namespace {

InodeId inode_of(const std::string& path)
{
    struct stat st {};
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

// --- legacy deny.db migration ---------------------------------------------
//
// An installation predating the runtime-rule registry recorded hand-added
// blocks only in deny.db, mixed with policy-derived rules and with no
// provenance. Adopting all of them resurrects policy rules the operator
// already removed; adopting none silently drops every manual block. These
// cover the partition, the cases where it cannot be trusted, and the
// idempotence/crash properties.

namespace {

using aegis::RuntimeRuleMigrationPaths;

struct MigrationFixture {
    std::string dir;
    RuntimeRuleMigrationPaths paths;

    explicit MigrationFixture(const std::string& name)
    {
        dir = std::string(::getenv("TMPDIR") ? ::getenv("TMPDIR") : "/tmp") + "/aegis_mig_" + name;
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
        paths = {dir + "/deny.db", dir + "/runtime_rules.db", dir + "/migrated", dir + "/quarantine",
                 dir + "/policy.applied"};
    }
    ~MigrationFixture() { std::filesystem::remove_all(dir); }

    void write(const std::string& path, const std::string& body) const
    {
        std::ofstream out(path);
        out << body;
    }
    std::string file(const std::string& name) const { return dir + "/" + name; }
    bool exists(const std::string& path) const { return std::filesystem::exists(path); }
};

std::string deny_line(const std::string& path)
{
    struct stat st {};
    EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
    return std::to_string(aegis::encode_dev(st.st_dev)) + " " + std::to_string(st.st_ino) + " " + path + "\n";
}

} // namespace

TEST(RuntimeRuleMigration, SeparatesPolicyDerivedEntriesFromHandAddedOnes)
{
    MigrationFixture f("partition");
    const std::string policy_file = f.file("from_policy");
    const std::string manual_file = f.file("added_by_hand");
    f.write(policy_file, "p");
    f.write(manual_file, "m");

    f.write(f.paths.deny_db, deny_line(policy_file) + deny_line(manual_file));
    f.write(f.paths.applied_policy, "version=6\n\n[deny_path]\n" + policy_file + "\n");

    auto r = migrate_legacy_runtime_rules(f.paths);

    EXPECT_TRUE(r.ran);
    EXPECT_EQ(r.policy_derived, 1u) << "the policy's own rule must not become a sticky runtime rule";
    EXPECT_EQ(r.migrated, 1u);
    EXPECT_EQ(r.quarantined, 0u);

    auto adopted = aegis::read_deny_entries_file_for_test(f.paths.runtime_rules);
    ASSERT_EQ(adopted.size(), 1u);
    EXPECT_EQ(adopted.begin()->second, manual_file);
}

TEST(RuntimeRuleMigration, QuarantinesEverythingWhenNoAppliedPolicyIsOnRecord)
{
    MigrationFixture f("noapplied");
    const std::string some_file = f.file("blocked");
    f.write(some_file, "x");
    f.write(f.paths.deny_db, deny_line(some_file));
    // no applied_policy written

    auto r = migrate_legacy_runtime_rules(f.paths);

    EXPECT_TRUE(r.ran);
    EXPECT_EQ(r.quarantined, 1u);
    EXPECT_EQ(r.migrated, 0u) << "nothing may be enforced on a guess";
    EXPECT_TRUE(f.exists(f.paths.quarantine));
    EXPECT_NE(r.reason.find("no applied policy"), std::string::npos);
}

TEST(RuntimeRuleMigration, QuarantinesWhenThePolicyExpandedBinaryHashes)
{
    // [deny_binary_hash] expands by scanning the filesystem for matching
    // contents. That expansion cannot be replayed from the policy text, so the
    // subtraction would leave policy-derived inodes behind and resurrect them.
    MigrationFixture f("binhash");
    const std::string some_file = f.file("blocked");
    f.write(some_file, "x");
    f.write(f.paths.deny_db, deny_line(some_file));
    f.write(f.paths.applied_policy, "version=6\n\n[deny_path]\n/nonexistent\n\n[deny_binary_hash]\n"
                                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");

    auto r = migrate_legacy_runtime_rules(f.paths);

    EXPECT_EQ(r.quarantined, 1u);
    EXPECT_EQ(r.migrated, 0u);
    EXPECT_NE(r.reason.find("binary-hash"), std::string::npos);
}

TEST(RuntimeRuleMigration, RunsExactlyOnce)
{
    MigrationFixture f("once");
    const std::string manual_file = f.file("added_by_hand");
    f.write(manual_file, "m");
    f.write(f.paths.deny_db, deny_line(manual_file));
    f.write(f.paths.applied_policy, "version=6\n");

    auto first = migrate_legacy_runtime_rules(f.paths);
    EXPECT_TRUE(first.ran);
    EXPECT_EQ(first.migrated, 1u);

    // A second run must not re-adopt, even if deny.db still holds the entry.
    auto second = migrate_legacy_runtime_rules(f.paths);
    EXPECT_FALSE(second.ran) << "migration must be idempotent";
    EXPECT_EQ(second.migrated, 0u);
}

TEST(RuntimeRuleMigration, InterruptedRunRepeatsInsteadOfHalfApplying)
{
    // The marker is written last, so a crash between the registry write and
    // the marker leaves the migration pending. Re-running must converge on the
    // same result rather than double-adopting or skipping.
    MigrationFixture f("crash");
    const std::string manual_file = f.file("added_by_hand");
    f.write(manual_file, "m");
    f.write(f.paths.deny_db, deny_line(manual_file));
    f.write(f.paths.applied_policy, "version=6\n");

    auto first = migrate_legacy_runtime_rules(f.paths);
    ASSERT_TRUE(first.ran);
    ASSERT_TRUE(f.exists(f.paths.migrated_marker));

    // Simulate the crash: marker never landed.
    std::filesystem::remove(f.paths.migrated_marker);
    std::filesystem::remove(f.paths.runtime_rules);

    auto retry = migrate_legacy_runtime_rules(f.paths);
    EXPECT_TRUE(retry.ran);
    EXPECT_EQ(retry.migrated, first.migrated);
    auto adopted = aegis::read_deny_entries_file_for_test(f.paths.runtime_rules);
    EXPECT_EQ(adopted.size(), 1u);
}

TEST(RuntimeRuleMigration, LeavesTheLegacyDenyDatabaseUntouched)
{
    // Downgrade safety: an older binary reads deny.db and knows nothing about
    // the registry, so the migration must not modify or remove it.
    MigrationFixture f("nodestroy");
    const std::string manual_file = f.file("added_by_hand");
    f.write(manual_file, "m");
    const std::string original = deny_line(manual_file);
    f.write(f.paths.deny_db, original);
    f.write(f.paths.applied_policy, "version=6\n");

    (void)migrate_legacy_runtime_rules(f.paths);

    std::ifstream in(f.paths.deny_db);
    std::string after((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(after, original) << "deny.db must remain readable by an older Aegis";
}
