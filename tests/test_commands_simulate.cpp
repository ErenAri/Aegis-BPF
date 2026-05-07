// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include <string>

#include "commands_simulate.hpp"
#include "policy.hpp"

namespace aegis {
namespace {

Policy build_policy(const std::vector<std::string>& deny_paths, const std::vector<std::string>& allow_cgroup_paths,
                    const std::vector<uint64_t>& allow_cgroup_ids = {})
{
    Policy p{};
    p.deny_paths = deny_paths;
    p.allow_cgroup_paths = allow_cgroup_paths;
    p.allow_cgroup_ids = allow_cgroup_ids;
    return p;
}

std::string make_block_event(const std::string& path, const std::string& cgroup_path = std::string(),
                             uint64_t cgid = 0)
{
    std::ostringstream oss;
    oss << "{\"type\":\"block\",\"path\":\"" << path << "\"";
    if (!cgroup_path.empty()) {
        oss << ",\"cgroup_path\":\"" << cgroup_path << "\",\"cgid\":" << cgid;
    }
    oss << ",\"action\":\"AUDIT\"}";
    return oss.str();
}

TEST(SimulateOneEvent, DenyPathMatchCountedAsWouldBlock)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev = make_block_event("/etc/shadow");

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.block_events, 1u);
    EXPECT_EQ(summary.would_block, 1u);
    EXPECT_EQ(summary.would_block_path, 1u);
    EXPECT_EQ(summary.would_block_inode, 0u);
    EXPECT_EQ(summary.would_allow, 0u);
    EXPECT_EQ(summary.no_match, 0u);
    EXPECT_EQ(rec.simulated_rule, "deny_path");
    EXPECT_TRUE(rec.deny_path_match);
    EXPECT_FALSE(rec.allow_match);
}

TEST(SimulateOneEvent, AllowCgroupPathOverridesDenyPath)
{
    const Policy policy = build_policy({"/etc/shadow"}, {"/system.slice/aegisbpfd.service"});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev = make_block_event("/etc/shadow", "/system.slice/aegisbpfd.service", 4242);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.would_allow, 1u);
    EXPECT_EQ(summary.would_block, 0u);
    EXPECT_EQ(rec.simulated_rule, "allow_cgroup");
    EXPECT_TRUE(rec.allow_match);
    // Allow takes precedence in the inferred-rule classification, but the
    // raw deny-path match flag should still be visible to operators
    // looking at per-event detail.
    EXPECT_TRUE(rec.deny_path_match);
}

TEST(SimulateOneEvent, AllowCgroupIdMatchesNumericCgid)
{
    const Policy policy = build_policy({"/etc/shadow"}, {}, {4242});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev = make_block_event("/etc/shadow", "/some/path", 4242);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.would_allow, 1u);
    EXPECT_EQ(rec.simulated_rule, "allow_cgroup");
}

TEST(SimulateOneEvent, NoMatchCounted)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    const std::string ev = make_block_event("/tmp/unrelated");

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr));
    EXPECT_EQ(summary.no_match, 1u);
    EXPECT_EQ(summary.would_block, 0u);
}

TEST(SimulateOneEvent, ResolvedPathFallsBackWhenRawPathMissesDenyList)
{
    // The agent emits `path` as the raw user-provided path and
    // `resolved_path` as the post-symlink resolution. A deny rule
    // targeting the resolved path must still match.
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev =
        R"({"type":"block","path":"/etc/sh","resolved_path":"/etc/shadow","action":"AUDIT"})";

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.would_block, 1u);
    EXPECT_EQ(rec.simulated_rule, "deny_path");
}

TEST(SimulateOneEvent, NonBlockEventSkipped)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    const std::string ev = R"({"type":"exec","path":"/etc/shadow","action":"AUDIT"})";

    EXPECT_FALSE(simulate_one_event(ev, policy, summary, nullptr));
    EXPECT_EQ(summary.skipped_non_block, 1u);
    EXPECT_EQ(summary.block_events, 0u);
}

TEST(SimulateOneEvent, NonJsonLineSkipped)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};

    EXPECT_FALSE(simulate_one_event("not json", policy, summary, nullptr));
    EXPECT_EQ(summary.skipped_non_json, 1u);
    EXPECT_EQ(summary.block_events, 0u);
}

TEST(SimulateOneEvent, EmptyLineSkippedAsNonJson)
{
    const Policy policy = build_policy({}, {});
    SimulateSummary summary{};

    EXPECT_FALSE(simulate_one_event("", policy, summary, nullptr));
    EXPECT_EQ(summary.skipped_non_json, 1u);
}

TEST(SimulateOneEvent, MalformedJsonMissingTypeIsParseError)
{
    const Policy policy = build_policy({}, {});
    SimulateSummary summary{};

    EXPECT_FALSE(simulate_one_event(R"({"path":"/etc/shadow"})", policy, summary, nullptr));
    EXPECT_EQ(summary.parse_errors, 1u);
    EXPECT_EQ(summary.skipped_non_json, 0u);
}

TEST(SimulateOneEvent, CountersPartitionBlockEvents)
{
    const Policy policy = build_policy({"/etc/shadow"}, {"/system.slice/agent.service"});
    SimulateSummary summary{};

    simulate_one_event(make_block_event("/etc/shadow"), policy, summary, nullptr);                 // would_block
    simulate_one_event(make_block_event("/etc/shadow", "/system.slice/agent.service", 1), policy,
                       summary, nullptr);                                                          // would_allow
    simulate_one_event(make_block_event("/tmp/x"), policy, summary, nullptr);                      // no_match
    simulate_one_event(R"({"type":"exec"})", policy, summary, nullptr);                            // skipped_non_block
    simulate_one_event("garbage", policy, summary, nullptr);                                       // skipped_non_json

    EXPECT_EQ(summary.total_lines, 5u);
    EXPECT_EQ(summary.block_events, 3u);
    // The four counters MUST partition block_events exactly. This is the
    // guarantee documented in `SimulateSummary` and the property
    // operators rely on when reading the dry-run report.
    EXPECT_EQ(summary.would_block + summary.would_allow + summary.no_match, summary.block_events);
}

} // namespace
} // namespace aegis
