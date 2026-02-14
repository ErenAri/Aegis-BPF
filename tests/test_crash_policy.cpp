// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>

#include "policy.hpp"
#include "sha256.hpp"
#include "utils.hpp"

namespace aegis {
namespace {

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
        } else {
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

// Global state for crash injection
static std::vector<ApplyCall> g_crash_apply_calls;
static int g_crash_at_call = -1; // Fail at this call number (0-indexed)
static Error g_crash_error(ErrorCode::BpfMapOperationFailed, "Simulated crash during map population");

Result<void> crash_inject_apply_internal(const std::string& path, const std::string& computed_hash, bool reset,
                                         bool record)
{
    int call_idx = static_cast<int>(g_crash_apply_calls.size());
    g_crash_apply_calls.push_back(ApplyCall{path, computed_hash, reset, record});
    if (call_idx == g_crash_at_call) {
        return g_crash_error;
    }
    return {};
}

class CrashPolicyTest : public ::testing::Test {
  protected:
    void SetUp() override
    {
        static uint64_t counter = 0;
        test_dir_ = std::filesystem::temp_directory_path() /
                    ("aegisbpf_crash_policy_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++));
        std::filesystem::create_directories(test_dir_);

        g_crash_apply_calls.clear();
        g_crash_at_call = -1;
        g_crash_error = Error(ErrorCode::BpfMapOperationFailed, "Simulated crash during map population");
        set_apply_policy_internal_for_test(crash_inject_apply_internal);
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
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                         std::filesystem::perms::group_read | std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace, ec);
        EXPECT_FALSE(ec);
        return file.string();
    }

    std::filesystem::path test_dir_;
};

// Test: Crash on first apply triggers rollback attempt
TEST_F(CrashPolicyTest, CrashOnApplyTriggersRollback)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", (test_dir_ / "applied.sha256").string());

    g_crash_at_call = 0; // Crash on the first apply call

    auto result = policy_apply(policy_path, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::BpfMapOperationFailed);

    // Should have attempted initial apply + rollback
    ASSERT_GE(g_crash_apply_calls.size(), 2u);
    EXPECT_EQ(g_crash_apply_calls[0].path, policy_path);
    EXPECT_EQ(g_crash_apply_calls[1].path, applied_path);
    EXPECT_TRUE(g_crash_apply_calls[1].reset);
}

// Test: Crash on both apply AND rollback returns original error
TEST_F(CrashPolicyTest, CrashOnBothApplyAndRollbackReturnsOriginalError)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", (test_dir_ / "applied.sha256").string());

    // Both calls will fail: apply at call 0, rollback at call 1
    g_crash_at_call = -1; // Don't use single-call crash

    set_apply_policy_internal_for_test(
        [](const std::string& path, const std::string& computed_hash, bool reset, bool record) -> Result<void> {
            g_crash_apply_calls.push_back(ApplyCall{path, computed_hash, reset, record});
            // All calls fail
            return Error(ErrorCode::BpfMapOperationFailed, "Total failure");
        });

    auto result = policy_apply(policy_path, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::BpfMapOperationFailed);
}

// Test: No crash (success) doesn't trigger rollback
TEST_F(CrashPolicyTest, SuccessfulApplyNoRollback)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", (test_dir_ / "applied.sha256").string());

    // No crash
    g_crash_at_call = -1;

    auto result = policy_apply(policy_path, false, "", "", true);
    EXPECT_TRUE(result);
    EXPECT_EQ(g_crash_apply_calls.size(), 1u);
}

// Test: Crash with corrupted applied hash skips file rollback, attempts in-memory
TEST_F(CrashPolicyTest, CorruptedAppliedHashTriggersInMemoryFallback)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");

    // Write a hash that won't match the applied policy
    std::string hash_path = (test_dir_ / "applied.sha256").string();
    {
        std::ofstream hash_out(hash_path);
        hash_out << "0000000000000000000000000000000000000000000000000000000000000000\n";
    }

    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", hash_path);

    g_crash_at_call = 0; // Crash on first apply

    auto result = policy_apply(policy_path, false, "", "", true);
    ASSERT_FALSE(result);
    // File-based rollback should be skipped (hash mismatch), so only 1 apply call
    EXPECT_EQ(g_crash_apply_calls.size(), 1u);
}

// Test: Multiple rapid crash-and-rollback cycles complete within time budget
TEST_F(CrashPolicyTest, RapidCrashRollbackCyclesCompleteWithinTimeBudget)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", (test_dir_ / "applied.sha256").string());

    constexpr int kCycles = 500;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kCycles; ++i) {
        g_crash_apply_calls.clear();
        g_crash_at_call = 0;

        auto result = policy_apply(policy_path, false, "", "", true);
        ASSERT_FALSE(result);
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    EXPECT_LT(elapsed.count(), 5000) << "Crash-rollback cycles exceeded 5s budget: " << elapsed.count() << "ms";
}

// Test: Crash with BpfLoadFailed error type
TEST_F(CrashPolicyTest, BpfLoadFailureCrashTriggersRollback)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", (test_dir_ / "applied.sha256").string());

    g_crash_at_call = 0;
    g_crash_error = Error(ErrorCode::BpfLoadFailed, "Simulated BPF load failure");

    auto result = policy_apply(policy_path, false, "", "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::BpfLoadFailed);
    ASSERT_GE(g_crash_apply_calls.size(), 2u);
}

// Test: PolicyHashMismatch error propagates correctly
TEST_F(CrashPolicyTest, PolicyHashMismatchDoesNotTriggerRollback)
{
    std::string policy_path = WritePolicy("policy.conf", "version=1\n[deny_path]\n/tmp/test\n");
    std::string applied_path = WritePolicy("applied.conf", "version=1\n");
    ScopedEnvVar env_applied("AEGIS_POLICY_APPLIED_PATH", applied_path);
    ScopedEnvVar env_prev("AEGIS_POLICY_APPLIED_PREV_PATH", (test_dir_ / "prev.conf").string());
    ScopedEnvVar env_hash("AEGIS_POLICY_APPLIED_HASH_PATH", (test_dir_ / "applied.sha256").string());

    // Provide wrong hash - should fail before reaching apply_policy_internal
    auto result = policy_apply(policy_path, false, std::string(64, '0'), "", true);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PolicyHashMismatch);
    // apply_policy_internal should not have been called
    EXPECT_EQ(g_crash_apply_calls.size(), 0u);
}

} // namespace
} // namespace aegis
