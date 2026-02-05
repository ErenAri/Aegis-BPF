// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>
#include <unistd.h>
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

TEST_F(PolicyTest, ParsePolicyWithIpv6NetworkRules)
{
    std::string content = R"(
version=2

[deny_ip]
2001:db8::1

[deny_cidr]
2001:db8:abcd::/48

[deny_port]
443:tcp:egress
)";
    std::string path = CreateTestPolicy(content);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);

    EXPECT_TRUE(result);
    EXPECT_FALSE(issues.has_errors());
    EXPECT_TRUE(result->network.enabled);
    EXPECT_EQ(result->network.deny_ips.size(), 1u);
    EXPECT_EQ(result->network.deny_cidrs.size(), 1u);
    EXPECT_EQ(result->network.deny_ports.size(), 1u);
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

TEST_F(PolicyTest, ApplyRejectsConflictingHashOptions)
{
    auto result = policy_apply("/tmp/does-not-matter.policy",
                               false,
                               std::string(64, 'a'),
                               "/tmp/policy.sha256",
                               true);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidArgument);
}

class ScopedEnvVar {
  public:
    ScopedEnvVar(const char* key, const std::string& value) : key_(key)
    {
        const char* existing = std::getenv(key_);
        if (existing) {
            had_previous_ = true;
            previous_ = existing;
        }
        ::setenv(key_, value.c_str(), 1);
    }

    ~ScopedEnvVar()
    {
        if (had_previous_) {
            ::setenv(key_, previous_.c_str(), 1);
        }
        else {
            ::unsetenv(key_);
        }
    }

  private:
    const char* key_;
    bool had_previous_ = false;
    std::string previous_;
};

struct ApplyCall {
    std::string path;
    std::string hash;
    bool reset = false;
    bool record = false;
};

std::vector<ApplyCall> g_apply_calls;
bool g_fail_first_apply_call = true;
bool g_fail_second_apply_call = false;
Error g_first_apply_error(ErrorCode::PolicyApplyFailed, "Injected apply failure");
Error g_second_apply_error(ErrorCode::PolicyApplyFailed, "Injected rollback failure");

Result<void> fake_apply_policy_internal(const std::string& path,
                                        const std::string& computed_hash,
                                        bool reset,
                                        bool record)
{
    g_apply_calls.push_back(ApplyCall{path, computed_hash, reset, record});
    if (g_fail_first_apply_call && g_apply_calls.size() == 1) {
        return g_first_apply_error;
    }
    if (g_fail_second_apply_call && g_apply_calls.size() == 2) {
        return g_second_apply_error;
    }
    return {};
}

class PolicyRollbackTest : public ::testing::Test {
  protected:
    void SetUp() override
    {
        static uint64_t counter = 0;
        test_dir_ = std::filesystem::temp_directory_path() /
                    ("aegisbpf_policy_rollback_test_" + std::to_string(getpid()) + "_" +
                     std::to_string(counter++));
        std::filesystem::create_directories(test_dir_);
        g_apply_calls.clear();
        g_fail_first_apply_call = true;
        g_fail_second_apply_call = false;
        g_first_apply_error = Error(ErrorCode::PolicyApplyFailed, "Injected apply failure");
        g_second_apply_error = Error(ErrorCode::PolicyApplyFailed, "Injected rollback failure");
        set_apply_policy_internal_for_test(fake_apply_policy_internal);
    }

    void TearDown() override
    {
        reset_apply_policy_internal_for_test();
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::string WritePolicy(const std::string& name, const std::string& content)
    {
        std::filesystem::path file = test_dir_ / name;
        std::ofstream out(file);
        out << content;
        std::error_code ec;
        std::filesystem::permissions(file,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace,
                                     ec);
        EXPECT_FALSE(ec);
        return file.string();
    }

    std::filesystem::path test_dir_;
};

TEST_F(PolicyRollbackTest, ApplyFailureTriggersRollbackWhenEnabled)
{
    std::string requested_policy = WritePolicy("requested.conf", "version=1\n");
    std::string applied_policy = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar applied_env("AEGIS_POLICY_APPLIED_PATH", applied_policy);

    auto result = policy_apply(requested_policy, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PolicyApplyFailed);
    ASSERT_EQ(g_apply_calls.size(), 2u);
    EXPECT_EQ(g_apply_calls[0].path, requested_policy);
    EXPECT_EQ(g_apply_calls[1].path, applied_policy);
    EXPECT_TRUE(g_apply_calls[1].reset);
    EXPECT_FALSE(g_apply_calls[1].record);
}

TEST_F(PolicyRollbackTest, ApplyFailureSkipsRollbackWhenDisabled)
{
    std::string requested_policy = WritePolicy("requested.conf", "version=1\n");
    std::string applied_policy = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar applied_env("AEGIS_POLICY_APPLIED_PATH", applied_policy);

    auto result = policy_apply(requested_policy, false, "", "", false);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PolicyApplyFailed);
    ASSERT_EQ(g_apply_calls.size(), 1u);
    EXPECT_EQ(g_apply_calls[0].path, requested_policy);
}

TEST_F(PolicyRollbackTest, ApplyFailureSkipsRollbackWhenNoAppliedPolicyExists)
{
    std::string requested_policy = WritePolicy("requested.conf", "version=1\n");
    std::string missing_applied_policy = (test_dir_ / "missing-applied.conf").string();
    ScopedEnvVar applied_env("AEGIS_POLICY_APPLIED_PATH", missing_applied_policy);

    auto result = policy_apply(requested_policy, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PolicyApplyFailed);
    ASSERT_EQ(g_apply_calls.size(), 1u);
    EXPECT_EQ(g_apply_calls[0].path, requested_policy);
}

TEST_F(PolicyRollbackTest, MapFullFailureTriggersRollbackAttemptWhenEnabled)
{
    std::string requested_policy = WritePolicy("requested.conf", "version=1\n");
    std::string applied_policy = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar applied_env("AEGIS_POLICY_APPLIED_PATH", applied_policy);

    g_first_apply_error = Error(ErrorCode::BpfMapOperationFailed, "Injected map full");

    auto result = policy_apply(requested_policy, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::BpfMapOperationFailed);
    ASSERT_EQ(g_apply_calls.size(), 2u);
    EXPECT_EQ(g_apply_calls[0].path, requested_policy);
    EXPECT_EQ(g_apply_calls[1].path, applied_policy);
    EXPECT_TRUE(g_apply_calls[1].reset);
    EXPECT_FALSE(g_apply_calls[1].record);
}

TEST_F(PolicyRollbackTest, RollbackFailureStillReturnsOriginalApplyError)
{
    std::string requested_policy = WritePolicy("requested.conf", "version=1\n");
    std::string applied_policy = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar applied_env("AEGIS_POLICY_APPLIED_PATH", applied_policy);

    g_fail_second_apply_call = true;
    g_second_apply_error = Error(ErrorCode::BpfMapOperationFailed, "Injected rollback map failure");

    auto result = policy_apply(requested_policy, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PolicyApplyFailed);
    ASSERT_EQ(g_apply_calls.size(), 2u);
    EXPECT_EQ(g_apply_calls[0].path, requested_policy);
    EXPECT_EQ(g_apply_calls[1].path, applied_policy);
}

TEST_F(PolicyRollbackTest, RollbackControlPathCompletesWithinFiveSecondsUnderLoad)
{
    std::string requested_policy = WritePolicy("requested.conf", "version=1\n");
    std::string applied_policy = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar applied_env("AEGIS_POLICY_APPLIED_PATH", applied_policy);

    constexpr int kAttempts = 1000;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kAttempts; ++i) {
        g_apply_calls.clear();
        g_fail_first_apply_call = true;
        g_fail_second_apply_call = false;

        auto result = policy_apply(requested_policy, false, "", "", true);
        ASSERT_FALSE(result);
        ASSERT_EQ(g_apply_calls.size(), 2u);
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    EXPECT_LT(elapsed.count(), 5000) << "rollback control path exceeded 5s target: "
                                     << elapsed.count() << "ms";
}

}  // namespace
}  // namespace aegis
