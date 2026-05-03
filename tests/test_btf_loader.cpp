// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "btf_loader.hpp"

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
        } else {
            ::unsetenv(key_);
        }
    }

  private:
    const char* key_;
    bool had_previous_{false};
    std::string previous_;
};

// Drop a deterministic temp BTF blob and return its path. The
// content doesn't have to be a valid BTF — we're only exercising
// access(2) lookups here.
std::string write_temp_blob(const std::string& name)
{
    auto path = std::filesystem::temp_directory_path() /
                ("aegis_btfloader_" + std::to_string(::getpid()) + "_" + name);
    std::ofstream(path) << "fake-btf";
    return path.string();
}

} // namespace

TEST(BtfLoaderTest, EnvOverrideUnsetReturnsEmpty)
{
    ::unsetenv("AEGIS_BTF_PATH");
    EXPECT_EQ(btf_path_env_override(), "");
}

TEST(BtfLoaderTest, EnvOverridePicksUpFromEnvironment)
{
    ScopedEnvVar env("AEGIS_BTF_PATH", "/tmp/explicit.btf");
    EXPECT_EQ(btf_path_env_override(), "/tmp/explicit.btf");
}

TEST(BtfLoaderTest, ReadableOverrideWins)
{
    const auto blob = write_temp_blob("override.btf");
    auto cleanup = std::filesystem::path(blob);
    auto res = resolve_btf_path("5.4.0-test", blob);
    EXPECT_EQ(res.path, blob);
    EXPECT_EQ(res.source, "override");
    std::filesystem::remove(cleanup);
}

TEST(BtfLoaderTest, UnreadableOverrideReportedExplicitly)
{
    // /nonexistent_xxx must not exist on a sane system; the resolver
    // must surface this to the caller rather than silently falling
    // through to a possibly-mismatched kernel BTF.
    auto res = resolve_btf_path("5.4.0-test", "/nonexistent_aegis_btf_xxx_yyy.btf");
    EXPECT_TRUE(res.path.empty());
    EXPECT_EQ(res.source, "override-missing");
}

TEST(BtfLoaderTest, KernelBuiltinSourceWhenAvailable)
{
    // If /sys/kernel/btf/vmlinux is readable on the host, the
    // resolver should prefer it (path stays empty so libbpf uses
    // the kernel one automatically). On hosts without it, source
    // is "none" — both outcomes are valid for this test, we just
    // assert the contract.
    auto res = resolve_btf_path("5.4.0-test", "");
    if (::access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        EXPECT_EQ(res.source, "kernel");
        EXPECT_TRUE(res.path.empty());
    } else {
        // Fallbacks may or may not exist on the test runner.
        EXPECT_TRUE(res.source == "none" || res.source == "modules" || res.source == "var-lib" ||
                    res.source == "usr-lib" || res.source == "etc");
    }
}

TEST(BtfLoaderTest, EmptyKernelReleaseProducesNoneWhenNoKernelBtf)
{
    // Without /sys/kernel/btf/vmlinux and without a kernel release,
    // there's no way to construct fallback paths — must report
    // "none" rather than building bogus "/lib/modules//btf/vmlinux".
    auto res = resolve_btf_path("", "");
    if (::access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        // Test runner has built-in BTF; that's fine.
        EXPECT_EQ(res.source, "kernel");
    } else {
        EXPECT_EQ(res.source, "none");
        EXPECT_TRUE(res.searched.empty());
    }
}

TEST(BtfLoaderTest, SearchedListPopulatedWhenFallingThrough)
{
    // Force the fallback path by pointing AEGIS_BTF_PATH at an
    // unreadable file — that makes the function return early with
    // source="override-missing" and `searched` containing exactly
    // the override path.
    auto res = resolve_btf_path("5.4.0-test", "/nonexistent_aegis_btf.btf");
    ASSERT_FALSE(res.searched.empty());
    EXPECT_EQ(res.searched.front(), "/nonexistent_aegis_btf.btf");
}

} // namespace aegis
