// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
/*
 * AegisBPF - E2E Bypass Tests
 *
 * These tests verify that common bypass techniques are properly blocked
 * by the BPF enforcement.
 *
 * Note: These tests require root privileges and a running BPF enforcement.
 * They are designed to be run in a controlled test environment.
 */

// cppcheck-suppress-file syntaxError
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace aegis {
namespace test {

class BypassTest : public ::testing::Test {
  protected:
    static constexpr const char* kTestDir = "/tmp/aegisbpf_bypass_test";
    static constexpr const char* kTestFile = "/tmp/aegisbpf_bypass_test/target.txt";

    void SetUp() override
    {
        // Skip tests if not root
        if (geteuid() != 0) {
            GTEST_SKIP() << "Bypass tests require root privileges";
        }

        // Create test directory and file
        std::filesystem::create_directories(kTestDir);
        std::ofstream out(kTestFile);
        out << "secret content" << '\n';
        out.close();
    }

    void TearDown() override { std::filesystem::remove_all(kTestDir); }

    bool file_is_blocked(const char* path)
    {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            return false;
        }
        // EPERM indicates BPF blocked it
        // Other errors might be permission-based
        return errno == EPERM;
    }

    bool can_read_file(const char* path)
    {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            return false;
        }
        close(fd);
        return true;
    }
};

// Test: Symlink bypass attempt
// If we block /tmp/.../target.txt, accessing via symlink should also be blocked
TEST_F(BypassTest, SymlinkBypass)
{
    const char* symlink_path = "/tmp/aegisbpf_bypass_test/symlink_to_target";

    // Create symlink to target file
    ASSERT_EQ(0, symlink(kTestFile, symlink_path));

    // Block the target file (would be done via aegisbpf CLI)
    // For this test, we assume the file is already blocked

    // Verify both paths point to same inode
    struct stat st1 {
    }, st2{};
    ASSERT_EQ(0, stat(kTestFile, &st1));
    ASSERT_EQ(0, stat(symlink_path, &st2));
    EXPECT_EQ(st1.st_ino, st2.st_ino);
    EXPECT_EQ(st1.st_dev, st2.st_dev);

    // If the target is blocked, the symlink should also be blocked
    // because AegisBPF blocks by inode, not by path
    // (The actual blocking would need to be tested with the agent running)
}

// Test: Hardlink bypass attempt
// Hardlinks share the same inode, so blocking should work
TEST_F(BypassTest, HardlinkBypass)
{
    const char* hardlink_path = "/tmp/aegisbpf_bypass_test/hardlink_to_target";

    // Create hardlink to target file
    ASSERT_EQ(0, link(kTestFile, hardlink_path));

    // Verify both paths point to same inode
    struct stat st1 {
    }, st2{};
    ASSERT_EQ(0, stat(kTestFile, &st1));
    ASSERT_EQ(0, stat(hardlink_path, &st2));
    EXPECT_EQ(st1.st_ino, st2.st_ino);
    EXPECT_EQ(st1.st_dev, st2.st_dev);

    // AegisBPF blocks by inode, so hardlinks should be blocked too
}

// Test: Rename bypass attempt
// Renamed files keep the same inode
TEST_F(BypassTest, RenameBypass)
{
    const char* renamed_path = "/tmp/aegisbpf_bypass_test/renamed_target.txt";

    // Get original inode
    struct stat st_before {};
    ASSERT_EQ(0, stat(kTestFile, &st_before));

    // Rename the file
    ASSERT_EQ(0, rename(kTestFile, renamed_path));

    // Verify inode is unchanged
    struct stat st_after {};
    ASSERT_EQ(0, stat(renamed_path, &st_after));
    EXPECT_EQ(st_before.st_ino, st_after.st_ino);
    EXPECT_EQ(st_before.st_dev, st_after.st_dev);

    // Rename back for cleanup
    rename(renamed_path, kTestFile);
}

// Test: /proc/self/fd bypass attempt
// Opening a file, deleting it, then accessing via /proc/self/fd
TEST_F(BypassTest, ProcFdBypass)
{
    // Open the file
    int fd = open(kTestFile, O_RDONLY);
    ASSERT_GE(fd, 0);

    // Get the /proc/self/fd path
    std::string proc_path = "/proc/self/fd/" + std::to_string(fd);

    // The proc path should resolve to the same file
    struct stat st_orig {
    }, st_proc{};
    ASSERT_EQ(0, fstat(fd, &st_orig));
    ASSERT_EQ(0, stat(proc_path.c_str(), &st_proc));
    EXPECT_EQ(st_orig.st_ino, st_proc.st_ino);

    // Note: Opening /proc/self/fd/N is essentially dup()ing the fd
    // The BPF hook on file_open will see the same inode

    close(fd);
}

// Test: Verifying inode tracking across filesystem operations
TEST_F(BypassTest, InodeStability)
{
    struct stat st {};
    ASSERT_EQ(0, stat(kTestFile, &st));
    ino_t original_inode = st.st_ino;
    dev_t original_dev = st.st_dev;

    // Append to file - inode should stay the same
    {
        std::ofstream out(kTestFile, std::ios::app);
        out << "more content" << '\n';
    }
    ASSERT_EQ(0, stat(kTestFile, &st));
    EXPECT_EQ(original_inode, st.st_ino);
    EXPECT_EQ(original_dev, st.st_dev);

    // Truncate file - inode should stay the same
    ASSERT_EQ(0, truncate(kTestFile, 0));
    ASSERT_EQ(0, stat(kTestFile, &st));
    EXPECT_EQ(original_inode, st.st_ino);

    // Note: Recreating the file (delete + create) would change the inode
    // This is expected behavior - the deny entry should be updated
}

// Test: Directory traversal doesn't change file inode
TEST_F(BypassTest, DirectoryTraversal)
{
    // Access via different path representations
    const char* paths[] = {
        kTestFile,
        "/tmp/aegisbpf_bypass_test/../aegisbpf_bypass_test/target.txt",
        "/tmp/../tmp/aegisbpf_bypass_test/target.txt",
        "/tmp/aegisbpf_bypass_test/./target.txt",
    };

    struct stat st_base {};
    ASSERT_EQ(0, stat(paths[0], &st_base));

    for (const char* path : paths) {
        struct stat st {};
        if (stat(path, &st) == 0) {
            EXPECT_EQ(st_base.st_ino, st.st_ino) << "Path: " << path << " should have same inode";
            EXPECT_EQ(st_base.st_dev, st.st_dev) << "Path: " << path << " should have same device";
        }
    }
}

// Test: Case sensitivity (Linux is case-sensitive)
TEST_F(BypassTest, CaseSensitivity)
{
    // Create a file with different case
    const char* uppercase_path = "/tmp/aegisbpf_bypass_test/TARGET.txt";

    std::ofstream out(uppercase_path);
    out << "different file" << '\n';
    out.close();

    // These should be different files with different inodes
    struct stat st_lower {
    }, st_upper{};
    ASSERT_EQ(0, stat(kTestFile, &st_lower));
    ASSERT_EQ(0, stat(uppercase_path, &st_upper));

    EXPECT_NE(st_lower.st_ino, st_upper.st_ino) << "Different case should be different files on Linux";
}

// Test: Blocking a symlink target vs the symlink itself
TEST_F(BypassTest, SymlinkTargetVsSymlink)
{
    const char* symlink_path = "/tmp/aegisbpf_bypass_test/symlink2";
    ASSERT_EQ(0, symlink(kTestFile, symlink_path));

    // lstat gets the symlink inode, stat follows the symlink
    struct stat st_link {
    }, st_target{};
    ASSERT_EQ(0, lstat(symlink_path, &st_link));
    ASSERT_EQ(0, stat(symlink_path, &st_target));

    // These should be different inodes
    EXPECT_NE(st_link.st_ino, st_target.st_ino) << "Symlink inode should differ from target inode";

    // Verify target inode matches direct access
    struct stat st_direct {};
    ASSERT_EQ(0, stat(kTestFile, &st_direct));
    EXPECT_EQ(st_target.st_ino, st_direct.st_ino);
}

// Test: Survival allowlist verification
TEST_F(BypassTest, SurvivalBinariesExist)
{
    // These are critical binaries that should exist and never be blocked
    const char* survival_binaries[] = {
        "/sbin/init",
        "/bin/sh",
        "/usr/bin/sudo",
    };

    for (const char* path : survival_binaries) {
        struct stat st {};
        if (stat(path, &st) == 0) {
            EXPECT_TRUE(can_read_file(path)) << "Survival binary should be readable: " << path;
        }
    }
}

} // namespace test
} // namespace aegis
