// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "landlock.hpp"

namespace aegis {
namespace {

class TempDir {
  public:
    TempDir()
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_landlock_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) + "_" +
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

void write_file(const std::filesystem::path& p, const std::string& contents)
{
    std::ofstream f(p);
    f << contents;
}

} // namespace

TEST(LandlockSandboxTest, AbiVersionIsNonNegativeOrUnsupported)
{
    const int abi = landlock_abi_version();
    // Either Landlock is unsupported (-1) or the kernel reports ABI >= 1.
    EXPECT_TRUE(abi == -1 || abi >= 1);
    EXPECT_EQ(landlock_available(), abi >= 1);
}

TEST(LandlockSandboxTest, DefaultConfigContainsCoreDirectories)
{
    auto cfg = default_landlock_config();
    bool has_var_lib = false;
    bool has_etc = false;
    bool has_proc = false;
    bool has_bpf_fs = false;
    for (const auto& p : cfg.paths) {
        if (p.path == "/var/lib/aegisbpf") {
            has_var_lib = true;
            EXPECT_TRUE(p.writable);
        }
        if (p.path == "/etc/aegisbpf") {
            has_etc = true;
            EXPECT_FALSE(p.writable);
        }
        if (p.path == "/proc") {
            has_proc = true;
            EXPECT_FALSE(p.writable);
        }
        if (p.path == "/sys/fs/bpf") {
            has_bpf_fs = true;
            EXPECT_TRUE(p.writable);
        }
    }
    EXPECT_TRUE(has_var_lib);
    EXPECT_TRUE(has_etc);
    EXPECT_TRUE(has_proc);
    EXPECT_TRUE(has_bpf_fs);
}

TEST(LandlockSandboxTest, DefaultConfigPicksUpAegisKeysDirEnv)
{
    ::setenv("AEGIS_KEYS_DIR", "/tmp/aegisbpf-test-keys", 1);
    auto cfg = default_landlock_config();
    bool found = false;
    for (const auto& p : cfg.paths) {
        if (p.path == "/tmp/aegisbpf-test-keys") {
            found = true;
            EXPECT_FALSE(p.writable);
        }
    }
    EXPECT_TRUE(found);
    ::unsetenv("AEGIS_KEYS_DIR");
}

TEST(LandlockSandboxTest, ApplySucceedsWithMissingPaths)
{
    if (!landlock_available()) {
        GTEST_SKIP() << "Landlock unsupported by running kernel";
    }

    // Run inside a child so the sandbox doesn't leak into the rest of
    // the test binary. We pass only paths that don't exist; the sandbox
    // module should silently skip them.
    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        LandlockConfig cfg;
        cfg.paths.push_back({"/tmp/aegisbpf-nonexistent-xyz-123", false});
        auto res = apply_landlock_sandbox(cfg);
        _exit(res ? 0 : 1);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(LandlockSandboxTest, SandboxBlocksUnlistedDirectoryAndAllowsListedOne)
{
    if (!landlock_available()) {
        GTEST_SKIP() << "Landlock unsupported by running kernel";
    }

    TempDir allowed;
    TempDir denied;
    write_file(allowed.path() / "ok.txt", "ok");
    write_file(denied.path() / "blocked.txt", "blocked");

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        LandlockConfig cfg;
        cfg.paths.push_back({allowed.path().string(), false});
        auto res = apply_landlock_sandbox(cfg);
        if (!res) {
            _exit(10);
        }

        // Reading the allowed file should still succeed.
        const int ok_fd = ::open((allowed.path() / "ok.txt").c_str(), O_RDONLY | O_CLOEXEC);
        if (ok_fd < 0) {
            _exit(20);
        }
        ::close(ok_fd);

        // Reading from a directory that wasn't on the allowlist must fail with EACCES.
        const int denied_fd = ::open((denied.path() / "blocked.txt").c_str(), O_RDONLY | O_CLOEXEC);
        if (denied_fd >= 0) {
            ::close(denied_fd);
            _exit(30);
        }
        if (errno != EACCES) {
            _exit(40);
        }
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status)) << "child terminated abnormally";
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child exited with sentinel " << WEXITSTATUS(status)
        << " (10=apply_failed, 20=allowed_open_failed, 30=denied_open_succeeded, 40=wrong_errno)";
}

TEST(LandlockSandboxTest, WritableFlagAllowsCreatingFiles)
{
    if (!landlock_available()) {
        GTEST_SKIP() << "Landlock unsupported by running kernel";
    }

    TempDir rw;

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        LandlockConfig cfg;
        cfg.paths.push_back({rw.path().string(), true});
        auto res = apply_landlock_sandbox(cfg);
        if (!res) {
            _exit(10);
        }

        const int fd = ::open((rw.path() / "new.txt").c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) {
            _exit(20);
        }
        ::close(fd);
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

} // namespace aegis
