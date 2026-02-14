// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "bpf_ops.hpp"
#include "sha256.hpp"

namespace aegis {
namespace {

class TempDir {
  public:
    TempDir()
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_integrity_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) + "_" +
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
        if (existing != nullptr) {
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

TEST(BpfIntegrityTest, VerifiesMatchingHashWhenRequired)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    const auto hash_path = temp_dir.path() / "aegis.bpf.sha256";

    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    std::string obj_hash;
    ASSERT_TRUE(sha256_file_hex(obj_path.string(), obj_hash));
    {
        std::ofstream out(hash_path);
        ASSERT_TRUE(out.is_open());
        out << obj_hash << "\n";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", hash_path.string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing.sha256").string());

    auto result = evaluate_bpf_integrity(true, false);
    ASSERT_TRUE(result);
    EXPECT_TRUE(result->object_exists);
    EXPECT_TRUE(result->hash_exists);
    EXPECT_TRUE(result->hash_verified);
    EXPECT_TRUE(result->reason.empty());
}

TEST(BpfIntegrityTest, FailsWhenHashIsMissingAndRequired)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", (temp_dir.path() / "missing.sha256").string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing2.sha256").string());

    auto result = evaluate_bpf_integrity(true, false);
    EXPECT_FALSE(result);
}

TEST(BpfIntegrityTest, AllowsMissingHashWithBreakGlass)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", (temp_dir.path() / "missing.sha256").string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing2.sha256").string());

    auto result = evaluate_bpf_integrity(true, true);
    ASSERT_TRUE(result);
    EXPECT_TRUE(result->object_exists);
    EXPECT_FALSE(result->hash_exists);
    EXPECT_FALSE(result->hash_verified);
    EXPECT_EQ(result->reason, "bpf_hash_missing");
}

TEST(BpfIntegrityTest, AllowsMismatchWithBreakGlass)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    const auto hash_path = temp_dir.path() / "aegis.bpf.sha256";

    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }
    {
        std::ofstream out(hash_path);
        ASSERT_TRUE(out.is_open());
        out << std::string(64, 'a') << "\n";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", hash_path.string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing.sha256").string());

    auto strict_result = evaluate_bpf_integrity(true, false);
    EXPECT_FALSE(strict_result);

    auto break_glass_result = evaluate_bpf_integrity(true, true);
    ASSERT_TRUE(break_glass_result);
    EXPECT_TRUE(break_glass_result->hash_exists);
    EXPECT_FALSE(break_glass_result->hash_verified);
    EXPECT_EQ(break_glass_result->reason, "bpf_hash_mismatch");
}

TEST(BpfIntegrityTest, ParsesUnsignedBpfEnvFlag)
{
    ScopedEnvVar env("AEGIS_ALLOW_UNSIGNED_BPF", "yes");
    EXPECT_TRUE(allow_unsigned_bpf_enabled());
}

TEST(BpfIntegrityTest, ParsesRequireHashEnvFlag)
{
    ScopedEnvVar env("AEGIS_REQUIRE_BPF_HASH", "true");
    EXPECT_TRUE(require_bpf_hash_enabled());
}

} // namespace
} // namespace aegis
