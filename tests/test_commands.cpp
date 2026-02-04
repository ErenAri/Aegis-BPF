// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
#include <gtest/gtest.h>

#include "commands.hpp"
#include "crypto.hpp"
#include "logging.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace aegis {
namespace {

class TempDir {
  public:
    TempDir()
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_cmd_test_" + std::to_string(getpid()) + "_" +
                 std::to_string(counter++) + "_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(path_);
    }

    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

  private:
    std::filesystem::path path_;
};

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

class ScopedJsonLogCapture {
  public:
    ScopedJsonLogCapture()
    {
        logger().set_output(&output_);
        logger().set_json_format(true);
    }

    ~ScopedJsonLogCapture()
    {
        logger().set_output(&std::cerr);
        logger().set_json_format(false);
    }

    [[nodiscard]] std::string str() const { return output_.str(); }

  private:
    std::ostringstream output_;
};

std::string secret_key_hex(const SecretKey& key)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(key.size() * 2);
    for (uint8_t b : key) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

TEST(CmdPolicySignTest, CreatesSignedBundle)
{
    auto keypair_result = generate_keypair();
    ASSERT_TRUE(keypair_result);
    const auto& [public_key, secret_key] = *keypair_result;

    TempDir temp_dir;
    auto policy_path = temp_dir.path() / "policy.conf";
    auto key_path = temp_dir.path() / "private.key";
    auto output_path = temp_dir.path() / "policy.signed";
    auto version_counter_path = temp_dir.path() / "version_counter";

    {
        std::ofstream policy_out(policy_path);
        ASSERT_TRUE(policy_out.is_open());
        policy_out << "version=1\n\n[deny_path]\n/etc/passwd\n";
    }
    ASSERT_EQ(::chmod(policy_path.c_str(), 0644), 0);

    {
        std::ofstream key_out(key_path);
        ASSERT_TRUE(key_out.is_open());
        key_out << secret_key_hex(secret_key) << "\n";
    }
    ASSERT_EQ(::chmod(key_path.c_str(), 0644), 0);

    ScopedEnvVar counter_env("AEGIS_VERSION_COUNTER_PATH", version_counter_path.string());

    EXPECT_EQ(cmd_policy_sign(policy_path.string(), key_path.string(), output_path.string()), 0);

    std::ifstream bundle_in(output_path);
    ASSERT_TRUE(bundle_in.is_open());
    std::stringstream ss;
    ss << bundle_in.rdbuf();
    auto parse_result = parse_signed_bundle(ss.str());
    ASSERT_TRUE(parse_result);
    EXPECT_EQ(parse_result->format_version, 1u);
    EXPECT_EQ(parse_result->signer_key, public_key);
    EXPECT_EQ(parse_result->policy_content, "version=1\n\n[deny_path]\n/etc/passwd\n");
}

TEST(CmdPolicySignTest, RejectsInvalidKeyEncoding)
{
    TempDir temp_dir;
    auto policy_path = temp_dir.path() / "policy.conf";
    auto key_path = temp_dir.path() / "private.key";
    auto output_path = temp_dir.path() / "policy.signed";

    {
        std::ofstream policy_out(policy_path);
        ASSERT_TRUE(policy_out.is_open());
        policy_out << "version=1\n";
    }
    ASSERT_EQ(::chmod(policy_path.c_str(), 0644), 0);

    {
        std::ofstream key_out(key_path);
        ASSERT_TRUE(key_out.is_open());
        key_out << std::string(128, 'g') << "\n";
    }
    ASSERT_EQ(::chmod(key_path.c_str(), 0644), 0);

    EXPECT_EQ(cmd_policy_sign(policy_path.string(), key_path.string(), output_path.string()), 1);
}

TEST(CmdPolicyApplySignedTest, RequireSignatureRejectsUnsignedPolicy)
{
    TempDir temp_dir;
    auto policy_path = temp_dir.path() / "policy.conf";
    {
        std::ofstream policy_out(policy_path);
        ASSERT_TRUE(policy_out.is_open());
        policy_out << "version=1\n";
    }
    ASSERT_EQ(::chmod(policy_path.c_str(), 0644), 0);

    EXPECT_EQ(cmd_policy_apply_signed(policy_path.string(), true), 1);
}

TEST(CmdPolicyApplySignedTest, RejectsWorldWritableBundle)
{
    TempDir temp_dir;
    auto bundle_path = temp_dir.path() / "policy.signed";
    {
        std::ofstream bundle_out(bundle_path);
        ASSERT_TRUE(bundle_out.is_open());
        bundle_out << "version=1\n";
    }
    ASSERT_EQ(::chmod(bundle_path.c_str(), 0666), 0);
    EXPECT_EQ(cmd_policy_apply_signed(bundle_path.string(), false), 1);
}

TEST(CmdNetworkDenyDelPortTest, RejectsInvalidProtocolAndDirection)
{
    EXPECT_EQ(cmd_network_deny_del_port(443, "invalid", "both"), 1);
    EXPECT_EQ(cmd_network_deny_del_port(443, "tcp", "invalid"), 1);
}

TEST(CmdPolicyApplySignedTest, RejectsRollbackBundleVersion)
{
    auto keypair_result = generate_keypair();
    ASSERT_TRUE(keypair_result);
    const auto& [public_key, secret_key] = *keypair_result;

    TempDir temp_dir;
    auto keys_dir = temp_dir.path() / "keys";
    auto version_counter_path = temp_dir.path() / "version_counter";
    auto bundle_path = temp_dir.path() / "policy.signed";

    ASSERT_TRUE(std::filesystem::create_directories(keys_dir));
    {
        std::ofstream key_out(keys_dir / "trusted.pub");
        ASSERT_TRUE(key_out.is_open());
        key_out << encode_hex(public_key) << "\n";
    }
    ASSERT_EQ(::chmod((keys_dir / "trusted.pub").c_str(), 0644), 0);

    auto bundle_result = create_signed_bundle("version=1\n", secret_key, 5, 0);
    ASSERT_TRUE(bundle_result);
    {
        std::ofstream bundle_out(bundle_path);
        ASSERT_TRUE(bundle_out.is_open());
        bundle_out << *bundle_result;
    }
    ASSERT_EQ(::chmod(bundle_path.c_str(), 0644), 0);

    ScopedEnvVar keys_env("AEGIS_KEYS_DIR", keys_dir.string());
    ScopedEnvVar counter_env("AEGIS_VERSION_COUNTER_PATH", version_counter_path.string());
    ASSERT_TRUE(write_version_counter(10));

    EXPECT_EQ(cmd_policy_apply_signed(bundle_path.string(), true), 1);
}

TEST(CmdKeysAddTest, RejectsWorldWritableKeyFile)
{
    TempDir temp_dir;
    auto key_path = temp_dir.path() / "test.pub";
    {
        std::ofstream key_out(key_path);
        ASSERT_TRUE(key_out.is_open());
        key_out << std::string(64, 'a') << "\n";
    }
    ASSERT_EQ(::chmod(key_path.c_str(), 0666), 0);
    EXPECT_EQ(cmd_keys_add(key_path.string()), 1);
}

TEST(CmdTracingTest, PolicySignEmitsRootSpanOnSuccess)
{
    auto keypair_result = generate_keypair();
    ASSERT_TRUE(keypair_result);
    const SecretKey secret_key = keypair_result->second;

    TempDir temp_dir;
    auto policy_path = temp_dir.path() / "policy.conf";
    auto key_path = temp_dir.path() / "private.key";
    auto output_path = temp_dir.path() / "policy.signed";

    {
        std::ofstream policy_out(policy_path);
        ASSERT_TRUE(policy_out.is_open());
        policy_out << "version=1\n";
    }
    ASSERT_EQ(::chmod(policy_path.c_str(), 0644), 0);

    {
        std::ofstream key_out(key_path);
        ASSERT_TRUE(key_out.is_open());
        key_out << secret_key_hex(secret_key) << "\n";
    }
    ASSERT_EQ(::chmod(key_path.c_str(), 0644), 0);

    ScopedEnvVar spans_env("AEGIS_OTEL_SPANS", "1");
    ScopedJsonLogCapture logs;

    EXPECT_EQ(cmd_policy_sign(policy_path.string(), key_path.string(), output_path.string()), 0);

    const std::string log = logs.str();
    EXPECT_NE(log.find("\"message\":\"otel_span_start\""), std::string::npos);
    EXPECT_NE(log.find("\"message\":\"otel_span_end\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"cli.policy_sign\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"ok\""), std::string::npos);
}

TEST(CmdTracingTest, PolicySignMarksSpanErrorOnFailure)
{
    TempDir temp_dir;
    auto policy_path = temp_dir.path() / "policy.conf";
    auto key_path = temp_dir.path() / "private.key";
    auto output_path = temp_dir.path() / "policy.signed";

    {
        std::ofstream policy_out(policy_path);
        ASSERT_TRUE(policy_out.is_open());
        policy_out << "version=1\n";
    }
    ASSERT_EQ(::chmod(policy_path.c_str(), 0644), 0);

    {
        std::ofstream key_out(key_path);
        ASSERT_TRUE(key_out.is_open());
        key_out << std::string(128, 'g') << "\n";
    }
    ASSERT_EQ(::chmod(key_path.c_str(), 0644), 0);

    ScopedEnvVar spans_env("AEGIS_OTEL_SPANS", "1");
    ScopedJsonLogCapture logs;

    EXPECT_EQ(cmd_policy_sign(policy_path.string(), key_path.string(), output_path.string()), 1);

    const std::string log = logs.str();
    EXPECT_NE(log.find("\"span_name\":\"cli.policy_sign\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
}

TEST(CmdTracingTest, NetworkDenyDelPortMarksSpanErrorOnInvalidProtocol)
{
    ScopedEnvVar spans_env("AEGIS_OTEL_SPANS", "1");
    ScopedJsonLogCapture logs;

    EXPECT_EQ(cmd_network_deny_del_port(443, "invalid", "both"), 1);

    const std::string log = logs.str();
    EXPECT_NE(log.find("\"span_name\":\"cli.network_deny_del_port\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
}

TEST(CmdTracingTest, StatsCommandEmitsNestedLoadBpfSpan)
{
    ScopedEnvVar spans_env("AEGIS_OTEL_SPANS", "1");
    ScopedJsonLogCapture logs;

    (void)cmd_stats(false);

    const std::string log = logs.str();
    EXPECT_NE(log.find("\"span_name\":\"cli.stats\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"bpf.load\""), std::string::npos);
    EXPECT_NE(log.find("\"parent_span_id\":\"span-"), std::string::npos);
}

}  // namespace
}  // namespace aegis
