#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include "policy.hpp"
#include "utils.hpp"

namespace aegis {
namespace {

class PolicyTest : public ::testing::Test {
  protected:
    void SetUp() override
    {
        test_dir_ = std::filesystem::temp_directory_path() / "aegisbpf_test";
        std::filesystem::create_directories(test_dir_);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(test_dir_);
    }

    std::string CreateTestPolicy(const std::string& content)
    {
        std::string path = test_dir_ / "test_policy.conf";
        std::ofstream out(path);
        out << content;
        return path;
    }

    std::filesystem::path test_dir_;
};

TEST_F(PolicyTest, ParseValidPolicy)
{
    std::string content = R"(
version=1

[deny_path]
/usr/bin/dangerous
/opt/malware

[allow_cgroup]
/sys/fs/cgroup/user.slice
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_FALSE(issues.has_errors());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->deny_paths.size(), 2u);
    EXPECT_EQ(result->deny_paths[0], "/usr/bin/dangerous");
    EXPECT_EQ(result->deny_paths[1], "/opt/malware");
    EXPECT_EQ(result->allow_cgroup_paths.size(), 1u);
}

TEST_F(PolicyTest, ParsePolicyWithInodes)
{
    std::string content = R"(
version=1

[deny_inode]
259:12345
260:67890
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_EQ(result->deny_inodes.size(), 2u);
    EXPECT_EQ(result->deny_inodes[0].dev, 259u);
    EXPECT_EQ(result->deny_inodes[0].ino, 12345u);
}

TEST_F(PolicyTest, ParsePolicyWithCgid)
{
    std::string content = R"(
version=1

[allow_cgroup]
cgid:1234567
/sys/fs/cgroup/system.slice
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_EQ(result->allow_cgroup_ids.size(), 1u);
    EXPECT_EQ(result->allow_cgroup_ids[0], 1234567u);
    EXPECT_EQ(result->allow_cgroup_paths.size(), 1u);
}

TEST_F(PolicyTest, MissingVersion)
{
    std::string content = R"(
[deny_path]
/usr/bin/test
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_FALSE(result);
    EXPECT_TRUE(issues.has_errors());
}

TEST_F(PolicyTest, InvalidVersion)
{
    std::string content = R"(
version=99

[deny_path]
/usr/bin/test
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_FALSE(result);
    EXPECT_TRUE(issues.has_errors());
}

TEST_F(PolicyTest, UnknownSection)
{
    std::string content = R"(
version=1

[unknown_section]
something
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_FALSE(result);
    EXPECT_TRUE(issues.has_errors());
}

TEST_F(PolicyTest, CommentsIgnored)
{
    std::string content = R"(
# This is a comment
version=1
# Another comment

[deny_path]
# Path to block
/usr/bin/test
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_EQ(result->deny_paths.size(), 1u);
}

TEST_F(PolicyTest, EmptyLinesIgnored)
{
    std::string content = R"(
version=1



[deny_path]

/usr/bin/test

)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_EQ(result->deny_paths.size(), 1u);
}

TEST_F(PolicyTest, DuplicatePathsDeduped)
{
    std::string content = R"(
version=1

[deny_path]
/usr/bin/test
/usr/bin/test
/usr/bin/other
/usr/bin/test
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_EQ(result->deny_paths.size(), 2u);
}

TEST_F(PolicyTest, RelativePathWarning)
{
    std::string content = R"(
version=1

[deny_path]
relative/path/test
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_TRUE(issues.has_warnings());
}

TEST_F(PolicyTest, InvalidInodeFormat)
{
    std::string content = R"(
version=1

[deny_inode]
notanumber:12345
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_FALSE(result);
    EXPECT_TRUE(issues.has_errors());
}

TEST_F(PolicyTest, NonexistentFile)
{
    PolicyIssues issues;
    auto result = parse_policy_file("/nonexistent/path/policy.conf", issues);

    EXPECT_FALSE(result);
    EXPECT_TRUE(issues.has_errors());
}

}  // namespace
}  // namespace aegis
