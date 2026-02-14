// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "policy.hpp"

namespace aegis {
namespace {

std::string resolve_fixture(const std::string& name)
{
    // Try relative to build directory
    std::string path = "../tests/fixtures/golden/" + name;
    if (std::filesystem::exists(path)) {
        return path;
    }
    // Try from source root
    path = (std::filesystem::current_path().parent_path() / "tests/fixtures/golden" / name).string();
    if (std::filesystem::exists(path)) {
        return path;
    }
    return "../tests/fixtures/golden/" + name;
}

struct GoldenTestCase {
    std::string fixture_name;
    int expected_version;
    size_t expected_deny_paths;
    size_t expected_deny_inodes;
    size_t expected_allow_cgroup_paths;
    size_t expected_allow_cgroup_ids;
    bool expected_network_enabled;
    size_t expected_deny_ips;
    size_t expected_deny_cidrs;
    size_t expected_deny_ports;
};

class PolicyGoldenTest : public ::testing::TestWithParam<GoldenTestCase> {};

TEST_P(PolicyGoldenTest, MatchesExpectedEntries)
{
    const auto& tc = GetParam();
    std::string path = resolve_fixture(tc.fixture_name);
    ASSERT_TRUE(std::filesystem::exists(path)) << "Golden fixture not found: " << path;

    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    ASSERT_TRUE(result) << "Parse failed: " << (issues.has_errors() ? issues.errors[0] : "unknown");
    EXPECT_FALSE(issues.has_errors());

    const Policy& policy = *result;
    EXPECT_EQ(policy.version, tc.expected_version);
    EXPECT_EQ(policy.deny_paths.size(), tc.expected_deny_paths);
    EXPECT_EQ(policy.deny_inodes.size(), tc.expected_deny_inodes);
    EXPECT_EQ(policy.allow_cgroup_paths.size(), tc.expected_allow_cgroup_paths);
    EXPECT_EQ(policy.allow_cgroup_ids.size(), tc.expected_allow_cgroup_ids);
    EXPECT_EQ(policy.network.enabled, tc.expected_network_enabled);
    EXPECT_EQ(policy.network.deny_ips.size(), tc.expected_deny_ips);
    EXPECT_EQ(policy.network.deny_cidrs.size(), tc.expected_deny_cidrs);
    EXPECT_EQ(policy.network.deny_ports.size(), tc.expected_deny_ports);
}

INSTANTIATE_TEST_SUITE_P(
    GoldenVectors, PolicyGoldenTest,
    ::testing::Values(
        GoldenTestCase{"deny_path_basic.conf", 1, 3, 0, 0, 0, false, 0, 0, 0},
        GoldenTestCase{"deny_inode_basic.conf", 1, 0, 3, 0, 0, false, 0, 0, 0},
        GoldenTestCase{"network_ipv4_deny.conf", 2, 0, 0, 0, 0, true, 2, 0, 0},
        GoldenTestCase{"network_cidr_deny.conf", 2, 0, 0, 0, 0, true, 0, 2, 0},
        GoldenTestCase{"allow_cgroup.conf", 1, 0, 0, 2, 1, false, 0, 0, 0},
        GoldenTestCase{"network_mixed.conf", 2, 0, 0, 0, 0, true, 3, 2, 3},
        GoldenTestCase{"version_2_full.conf", 2, 2, 2, 1, 1, true, 2, 2, 2}),
    [](const ::testing::TestParamInfo<GoldenTestCase>& info) {
        // Generate readable test name from fixture name
        std::string name = info.param.fixture_name;
        // Remove .conf extension
        auto pos = name.rfind('.');
        if (pos != std::string::npos) {
            name = name.substr(0, pos);
        }
        return name;
    });

} // namespace
} // namespace aegis
