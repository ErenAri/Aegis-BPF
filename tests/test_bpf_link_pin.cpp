// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include "bpf_link_pin.hpp"
#include "bpf_ops.hpp"

namespace aegis {
namespace {

// Build a unique scratch directory under TMPDIR (or /tmp) for the test
// instance. We use this to exercise filesystem-side helpers without
// touching the real bpffs (which requires root + mounted /sys/fs/bpf).
std::string make_scratch_dir(const char* name)
{
    const char* tmp = std::getenv("TMPDIR");
    if (tmp == nullptr || tmp[0] == '\0') {
        tmp = "/tmp";
    }
    std::string dir = std::string(tmp) + "/aegisbpf_test_" + name + "_" + std::to_string(::getpid());
    (void)::mkdir(dir.c_str(), 0700);
    return dir;
}

void rm_rf(const std::string& path)
{
    // Test-only helper; recursive deletion via shell since we never
    // build nested trees in these tests, only flat directories.
    const std::string cmd = "rm -rf '" + path + "'";
    int rc = std::system(cmd.c_str());
    (void)rc;
}

void touch(const std::string& path)
{
    std::ofstream f(path);
    f << "test";
}

TEST(BpfLinkPin, IsBpffsMountedRejectsTmp)
{
    // /tmp is not a bpf filesystem; probe must return false.
    EXPECT_FALSE(is_bpffs_mounted("/tmp"));
}

TEST(BpfLinkPin, IsBpffsMountedRejectsMissingPath)
{
    EXPECT_FALSE(is_bpffs_mounted("/this/path/does/not/exist/aegis"));
}

TEST(BpfLinkPin, EnsurePinRootCreatesDirectory)
{
    std::string scratch = make_scratch_dir("ensure_create");
    rm_rf(scratch);

    auto result = ensure_pin_root(scratch);
    ASSERT_TRUE(result.ok()) << "ensure_pin_root failed: " << result.error().to_string();

    struct stat st {};
    ASSERT_EQ(::stat(scratch.c_str(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));

    rm_rf(scratch);
}

TEST(BpfLinkPin, EnsurePinRootIdempotentOnExistingDir)
{
    std::string scratch = make_scratch_dir("ensure_idempotent");
    rm_rf(scratch);
    ASSERT_EQ(::mkdir(scratch.c_str(), 0700), 0);

    auto result = ensure_pin_root(scratch);
    EXPECT_TRUE(result.ok());

    rm_rf(scratch);
}

TEST(BpfLinkPin, EnsurePinRootFailsWhenPathIsRegularFile)
{
    std::string scratch = make_scratch_dir("ensure_isfile");
    rm_rf(scratch);
    touch(scratch);

    auto result = ensure_pin_root(scratch);
    EXPECT_FALSE(result.ok());

    rm_rf(scratch);
}

TEST(BpfLinkPin, CountExistingPinsZeroOnEmptyDir)
{
    std::string scratch = make_scratch_dir("count_empty");
    rm_rf(scratch);
    ASSERT_EQ(::mkdir(scratch.c_str(), 0700), 0);

    EXPECT_EQ(count_existing_pins(scratch), 0u);

    rm_rf(scratch);
}

TEST(BpfLinkPin, CountExistingPinsMatchesFileCount)
{
    std::string scratch = make_scratch_dir("count_three");
    rm_rf(scratch);
    ASSERT_EQ(::mkdir(scratch.c_str(), 0700), 0);

    touch(scratch + "/handle_inode_permission");
    touch(scratch + "/handle_file_open");
    touch(scratch + "/handle_execve");

    EXPECT_EQ(count_existing_pins(scratch), 3u);

    rm_rf(scratch);
}

TEST(BpfLinkPin, CountExistingPinsIgnoresDotEntries)
{
    std::string scratch = make_scratch_dir("count_dots");
    rm_rf(scratch);
    ASSERT_EQ(::mkdir(scratch.c_str(), 0700), 0);

    touch(scratch + "/real");

    // "." and ".." are always present in a directory and must not count.
    EXPECT_EQ(count_existing_pins(scratch), 1u);

    rm_rf(scratch);
}

TEST(BpfLinkPin, CountExistingPinsReturnsZeroOnMissingDir)
{
    EXPECT_EQ(count_existing_pins("/this/path/does/not/exist/aegis_pins"), 0u);
}

TEST(BpfLinkPin, PinAttachedLinkRejectsNullLink)
{
    BpfState state;
    state.pin_root = "/tmp";
    auto result = pin_attached_link("handle_execve", nullptr, state.pin_root, state);
    EXPECT_FALSE(result.ok());
    EXPECT_TRUE(state.pinned_hooks.empty());
}

TEST(BpfLinkPin, PinAttachedLinkRejectsEmptyName)
{
    BpfState state;
    // Use a sentinel non-null pointer; we never actually call into libbpf
    // because the name validation rejects empty names before bpf_link__pin.
    auto* sentinel = reinterpret_cast<bpf_link*>(uintptr_t{0xDEAD});
    auto result = pin_attached_link("", sentinel, "/tmp", state);
    EXPECT_FALSE(result.ok());
    EXPECT_TRUE(state.pinned_hooks.empty());
}

TEST(BpfLinkPin, PinAttachedLinkRejectsPathTraversalName)
{
    BpfState state;
    auto* sentinel = reinterpret_cast<bpf_link*>(uintptr_t{0xDEAD});
    auto result = pin_attached_link("../etc/passwd", sentinel, "/tmp", state);
    EXPECT_FALSE(result.ok());
    EXPECT_TRUE(state.pinned_hooks.empty());
}

TEST(BpfLinkPin, PinAttachedLinkRejectsSlashInName)
{
    BpfState state;
    auto* sentinel = reinterpret_cast<bpf_link*>(uintptr_t{0xDEAD});
    auto result = pin_attached_link("handle/execve", sentinel, "/tmp", state);
    EXPECT_FALSE(result.ok());
    EXPECT_TRUE(state.pinned_hooks.empty());
}

TEST(BpfLinkPin, VerifyPinnedHooksReportsZeroOnHealthy)
{
    std::string scratch = make_scratch_dir("verify_healthy");
    rm_rf(scratch);
    ASSERT_EQ(::mkdir(scratch.c_str(), 0700), 0);

    BpfState state;
    PinnedHook hook;
    hook.program_name = "handle_execve";
    hook.link = nullptr; // verify_pinned_hooks only stat()s the path
    hook.pin_path = scratch + "/handle_execve";
    touch(hook.pin_path);
    state.pinned_hooks.push_back(hook);

    EXPECT_EQ(verify_pinned_hooks(state), 0u);

    rm_rf(scratch);
}

TEST(BpfLinkPin, VerifyPinnedHooksCountsMissing)
{
    std::string scratch = make_scratch_dir("verify_missing");
    rm_rf(scratch);
    ASSERT_EQ(::mkdir(scratch.c_str(), 0700), 0);

    BpfState state;
    PinnedHook present;
    present.program_name = "handle_execve";
    present.pin_path = scratch + "/handle_execve";
    touch(present.pin_path);
    state.pinned_hooks.push_back(present);

    PinnedHook missing;
    missing.program_name = "handle_file_open";
    missing.pin_path = scratch + "/handle_file_open";
    // Intentionally do not create the file.
    state.pinned_hooks.push_back(missing);

    EXPECT_EQ(verify_pinned_hooks(state), 1u);

    rm_rf(scratch);
}

} // namespace
} // namespace aegis
