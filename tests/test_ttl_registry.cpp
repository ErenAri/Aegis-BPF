// Unit tests for the TTL registry used by the control-API auto-expiry reaper.
// All helpers here are kernel-free, so these run anywhere.
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "ttl_registry.hpp"

using namespace aegis;

namespace {

std::string temp_db_path(const char* name)
{
    return (std::filesystem::temp_directory_path() / name).string();
}

} // namespace

TEST(TtlRegistry, ParseTtlSuffixBasic)
{
    std::string arg = "/usr/bin/evil ttl=300";
    auto ttl = parse_ttl_suffix(arg);
    ASSERT_TRUE(ttl.has_value());
    EXPECT_EQ(ttl.value_or(0), 300u);
    EXPECT_EQ(arg, "/usr/bin/evil");
}

TEST(TtlRegistry, ParseTtlSuffixPreservesPathsWithSpaces)
{
    std::string arg = "/var/tmp/a b c ttl=60";
    auto ttl = parse_ttl_suffix(arg);
    ASSERT_TRUE(ttl.has_value());
    EXPECT_EQ(ttl.value_or(0), 60u);
    EXPECT_EQ(arg, "/var/tmp/a b c");
}

TEST(TtlRegistry, ParseTtlSuffixAbsentLeavesArgUntouched)
{
    std::string arg = "/usr/bin/evil";
    auto ttl = parse_ttl_suffix(arg);
    EXPECT_FALSE(ttl.has_value());
    EXPECT_EQ(arg, "/usr/bin/evil");
}

TEST(TtlRegistry, ParseTtlSuffixRejectsMalformed)
{
    for (const char* raw : {"/p ttl=", "/p ttl=abc", "/p ttl=0", "/p ttl=-5", "/p ttl=12x"}) {
        std::string arg = raw;
        std::string before = arg;
        auto ttl = parse_ttl_suffix(arg);
        EXPECT_FALSE(ttl.has_value()) << "for " << raw;
        EXPECT_EQ(arg, before) << "arg mutated for " << raw;
    }
}

TEST(TtlRegistry, PartitionExpiredSplitsByDeadline)
{
    std::vector<TtlEntry> entries = {
        {100, "/block/add", "/a"},
        {200, "/block/add", "/b"},
        {300, "/network/deny/ip", "203.0.113.7"},
    };
    auto part = partition_expired(entries, 200); // <=200 expired
    ASSERT_EQ(part.expired.size(), 2u);
    ASSERT_EQ(part.live.size(), 1u);
    EXPECT_EQ(part.live[0].arg, "203.0.113.7");
}

TEST(TtlRegistry, UpsertReplacesExistingExpiry)
{
    std::vector<TtlEntry> entries;
    upsert_ttl_entry(entries, 100, "/block/add", "/a");
    upsert_ttl_entry(entries, 500, "/block/add", "/a"); // extend, not duplicate
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].expiry_epoch, 500u);
}

TEST(TtlRegistry, RemoveEntryAndByVerb)
{
    std::vector<TtlEntry> entries = {
        {100, "/block/add", "/a"},
        {100, "/block/add", "/b"},
        {100, "/network/deny/ip", "203.0.113.7"},
    };
    remove_ttl_entry(entries, "/block/add", "/a");
    EXPECT_EQ(entries.size(), 2u);
    remove_ttl_entries_by_verb(entries, "/block/add");
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].verb, "/network/deny/ip");
}

TEST(TtlRegistry, DbRoundTripPreservesSpacesInArg)
{
    const std::string path = temp_db_path("aegis_ttl_roundtrip.db");
    std::filesystem::remove(path);
    std::vector<TtlEntry> entries = {
        {1000, "/block/add", "/var/tmp/a b"},
        {2000, "/network/deny/cidr", "10.0.0.0/8"},
    };
    ASSERT_TRUE(write_ttl_db(entries, path));
    auto read = read_ttl_db(path);
    ASSERT_EQ(read.size(), 2u);
    EXPECT_EQ(read[0].expiry_epoch, 1000u);
    EXPECT_EQ(read[0].verb, "/block/add");
    EXPECT_EQ(read[0].arg, "/var/tmp/a b");
    EXPECT_EQ(read[1].arg, "10.0.0.0/8");
    std::filesystem::remove(path);
}

TEST(TtlRegistry, ReadMissingFileIsEmpty)
{
    auto read = read_ttl_db(temp_db_path("aegis_ttl_does_not_exist.db"));
    EXPECT_TRUE(read.empty());
}

TEST(TtlRegistry, ReapInvokesDelForExpiredAndPersistsLive)
{
    const std::string path = temp_db_path("aegis_ttl_reap.db");
    std::filesystem::remove(path);
    std::vector<TtlEntry> entries = {
        {100, "/block/add", "/expired"},
        {5000, "/block/add", "/live"},
    };
    ASSERT_TRUE(write_ttl_db(entries, path));

    std::vector<std::pair<std::string, std::string>> deleted;
    size_t n = reap_expired_ttls(
        200, [&](const std::string& verb, const std::string& arg) { deleted.emplace_back(verb, arg); }, path);

    EXPECT_EQ(n, 1u);
    ASSERT_EQ(deleted.size(), 1u);
    EXPECT_EQ(deleted[0].second, "/expired");

    auto remaining = read_ttl_db(path);
    ASSERT_EQ(remaining.size(), 1u);
    EXPECT_EQ(remaining[0].arg, "/live");
    std::filesystem::remove(path);
}

TEST(TtlRegistry, ReapNoExpiredLeavesFileUntouched)
{
    const std::string path = temp_db_path("aegis_ttl_noexpiry.db");
    std::filesystem::remove(path);
    std::vector<TtlEntry> entries = {{5000, "/block/add", "/live"}};
    ASSERT_TRUE(write_ttl_db(entries, path));

    int calls = 0;
    size_t n = reap_expired_ttls(200, [&](const std::string&, const std::string&) { ++calls; }, path);
    EXPECT_EQ(n, 0u);
    EXPECT_EQ(calls, 0);
    EXPECT_EQ(read_ttl_db(path).size(), 1u);
    std::filesystem::remove(path);
}
