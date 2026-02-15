// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

#include "exec_identity.hpp"

namespace aegis {
namespace {

class ExecIdentityTest : public ::testing::Test {
  protected:
    void SetUp() override
    {
        test_dir_ =
            std::filesystem::temp_directory_path() / ("aegisbpf_exec_identity_test_" + std::to_string(getpid()));
        std::filesystem::create_directories(test_dir_);
    }

    void TearDown() override { std::filesystem::remove_all(test_dir_); }

    std::string WritePolicy(const std::string& content)
    {
        auto path = test_dir_ / "policy.conf";
        std::ofstream out(path);
        out << content;
        return path.string();
    }

    std::filesystem::path test_dir_;
};

TEST_F(ExecIdentityTest, LoadAllowBinaryHashesFromPolicy)
{
    const std::string path = WritePolicy(R"(
version=3

[allow_binary_hash]
sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)");

    auto result = load_allow_binary_hashes_from_policy(path);
    ASSERT_TRUE(result);
    ASSERT_EQ(result->size(), 1u);
    EXPECT_EQ((*result)[0], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

TEST_F(ExecIdentityTest, LoadAllowBinaryHashesRejectsInvalidPolicy)
{
    const std::string path = WritePolicy(R"(
version=2

[allow_binary_hash]
sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)");

    auto result = load_allow_binary_hashes_from_policy(path);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PolicyParseFailed);
}

TEST(ExecIdentityEnforcerTest, EnabledReflectsAllowlist)
{
    ExecIdentityEnforcer enabled({"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, true, true,
                                 kEnforceSignalTerm);
    ExecIdentityEnforcer disabled({}, true, true, kEnforceSignalTerm);

    EXPECT_TRUE(enabled.enabled());
    EXPECT_EQ(enabled.allowlist_size(), 1u);
    EXPECT_FALSE(disabled.enabled());
}

TEST(ExecIdentityEnforcerTest, IgnoresSelfExecEvent)
{
    ExecIdentityEnforcer enforcer({"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, false, false,
                                  kEnforceSignalKill);

    ExecEvent ev{};
    ev.pid = static_cast<uint32_t>(::getpid());
    ev.ppid = static_cast<uint32_t>(::getppid());
    std::snprintf(ev.comm, sizeof(ev.comm), "self");

    // Must not self-signal even when configured for strict enforcement.
    enforcer.on_exec(ev);
    SUCCEED();
}

} // namespace
} // namespace aegis
