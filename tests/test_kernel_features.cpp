// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include "kernel_features.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace aegis {
namespace {

class ScopedEnvVar {
  public:
    ScopedEnvVar(const char* key, const std::string& value) : key_(key)
    {
        const char* current = std::getenv(key_);
        if (current != nullptr) {
            had_previous_ = true;
            previous_ = current;
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
    bool had_previous_{false};
    std::string previous_;
};

class TempDir {
  public:
    TempDir()
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_kernel_features_test_" + std::to_string(getpid()) + "_" +
                 std::to_string(counter++));
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

TEST(KernelFeaturesTest, ParseKernelVersionHandlesStandardAndTaggedReleases)
{
    int major = 0;
    int minor = 0;
    int patch = 0;

    EXPECT_TRUE(parse_kernel_version("6.8.12", major, minor, patch));
    EXPECT_EQ(major, 6);
    EXPECT_EQ(minor, 8);
    EXPECT_EQ(patch, 12);

    EXPECT_TRUE(parse_kernel_version("5.15.0-113-generic", major, minor, patch));
    EXPECT_EQ(major, 5);
    EXPECT_EQ(minor, 15);
    EXPECT_EQ(patch, 0);
}

TEST(KernelFeaturesTest, ParseKernelVersionRejectsEmptyInput)
{
    int major = 0;
    int minor = 0;
    int patch = 0;
    EXPECT_FALSE(parse_kernel_version("", major, minor, patch));
}

TEST(KernelFeaturesTest, DetermineCapabilityCoversFullAuditAndDisabledModes)
{
    KernelFeatures full{};
    full.bpf_lsm = true;
    full.ringbuf = true;
    full.cgroup_v2 = true;
    full.btf = true;
    full.bpf_syscall = true;
    full.tracepoints = true;
    EXPECT_EQ(determine_capability(full), EnforcementCapability::Full);

    KernelFeatures audit = full;
    audit.bpf_lsm = false;
    EXPECT_EQ(determine_capability(audit), EnforcementCapability::AuditOnly);

    KernelFeatures disabled = audit;
    disabled.cgroup_v2 = false;
    EXPECT_EQ(determine_capability(disabled), EnforcementCapability::Disabled);
}

TEST(KernelFeaturesTest, FeatureChecksHonorPathOverrides)
{
    TempDir temp;
    const auto lsm_path = temp.path() / "lsm";
    const auto cgroup_path = temp.path() / "cgroup.controllers";
    const auto btf_path = temp.path() / "vmlinux";
    const auto bpffs_path = temp.path() / "bpffs";

    {
        std::ofstream out(lsm_path);
        out << "lockdown,yama,bpf,integrity\n";
    }
    {
        std::ofstream out(cgroup_path);
        out << "memory cpu io\n";
    }
    {
        std::ofstream out(btf_path);
        out << "btf";
    }
    std::filesystem::create_directories(bpffs_path);

    ScopedEnvVar lsm_env("AEGIS_LSM_PATH", lsm_path.string());
    ScopedEnvVar cgroup_env("AEGIS_CGROUP_CONTROLLERS_PATH", cgroup_path.string());
    ScopedEnvVar btf_env("AEGIS_BTF_VMLINUX_PATH", btf_path.string());
    ScopedEnvVar bpffs_env("AEGIS_BPFFS_PATH", bpffs_path.string());

    EXPECT_TRUE(check_bpf_lsm_enabled());
    EXPECT_TRUE(check_cgroup_v2());
    EXPECT_TRUE(check_btf_available());
    EXPECT_TRUE(check_bpffs_mounted());

    {
        std::ofstream out(lsm_path, std::ios::trunc);
        out << "lockdown,yama,integrity\n";
    }
    std::filesystem::remove(cgroup_path);
    std::filesystem::remove(btf_path);
    std::filesystem::remove_all(bpffs_path);

    EXPECT_FALSE(check_bpf_lsm_enabled());
    EXPECT_FALSE(check_cgroup_v2());
    EXPECT_FALSE(check_btf_available());
    EXPECT_FALSE(check_bpffs_mounted());
}

}  // namespace
}  // namespace aegis
