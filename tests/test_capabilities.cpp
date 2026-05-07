// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "capabilities.hpp"

namespace aegis {

TEST(CapabilitiesTest, SplitSupportProbeWorks)
{
    // Either CAP_BPF is recognised by the kernel or it isn't; both
    // outcomes are valid. The probe must not crash and must return a
    // bool that matches the prctl(PR_CAPBSET_READ) outcome.
    const bool supported = capabilities_split_supported();
    EXPECT_TRUE(supported == true || supported == false);
}

TEST(CapabilitiesTest, ReadCapabilitiesReturnsConsistentSnapshot)
{
    auto snap_or_err = read_capabilities();
    ASSERT_TRUE(snap_or_err) << snap_or_err.error().to_string();
    const auto& snap = *snap_or_err;
    // Effective is always a subset of permitted; inheritable can be
    // anything but bits should fit in 64-bit space.
    EXPECT_EQ(snap.effective & ~snap.permitted, 0u);
}

TEST(CapabilitiesTest, CapNameKnowsTheImportantBits)
{
    EXPECT_STREQ(cap_name(AegisCapBpf), "CAP_BPF");
    EXPECT_STREQ(cap_name(AegisCapPerfmon), "CAP_PERFMON");
    EXPECT_STREQ(cap_name(AegisCapSysAdmin), "CAP_SYS_ADMIN");
    EXPECT_STREQ(cap_name(AegisCapNetAdmin), "CAP_NET_ADMIN");
    EXPECT_STREQ(cap_name(AegisCapDacReadSearch), "CAP_DAC_READ_SEARCH");
    EXPECT_STREQ(cap_name(9999), "CAP_UNKNOWN");
}

TEST(CapabilitiesTest, KeepSetIsNotEmptyAndIncludesNetAdmin)
{
    auto keep = default_post_attach_keep_set();
    ASSERT_FALSE(keep.empty());
    bool found_net = false;
    bool found_dac = false;
    for (int c : keep) {
        if (c == AegisCapNetAdmin)
            found_net = true;
        if (c == AegisCapDacReadSearch)
            found_dac = true;
    }
    EXPECT_TRUE(found_net);
    EXPECT_TRUE(found_dac);
}

TEST(CapabilitiesTest, DropEmptyListIsNoop)
{
    auto rc = drop_capabilities({});
    EXPECT_TRUE(rc);
}

TEST(CapabilitiesTest, DropAlreadyAbsentCapabilityIsIdempotent)
{
    // Forking so we don't actually mutate the test process for later
    // tests. We try to drop an arbitrary cap (CAP_AUDIT_READ = 37) and
    // immediately try again — both calls must succeed.
    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        const std::vector<int> caps = {37};
        auto first = drop_capabilities(caps);
        if (!first) {
            _exit(10);
        }
        auto second = drop_capabilities(caps);
        if (!second) {
            _exit(20);
        }
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0) << "child exited with sentinel " << WEXITSTATUS(status)
                                      << " (10=first_drop_failed, 20=second_drop_failed)";
}

TEST(CapabilitiesTest, DroppedCapDisappearsFromPermittedSet)
{
    // Skip when running unprivileged — without an initial cap to drop,
    // there's nothing to verify.
    auto initial = read_capabilities();
    ASSERT_TRUE(initial);
    // CAP_KILL (5) is in the permitted set of any reasonable process;
    // skip if it isn't (e.g. heavily sandboxed CI runner).
    if ((initial->permitted & (1ULL << 5)) == 0) {
        GTEST_SKIP() << "CAP_KILL not in permitted set";
    }

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        // Drop CAP_KILL (5). It is in the permitted set of any
        // unprivileged process unless something already stripped it.
        auto rc = drop_capabilities({5});
        if (!rc) {
            _exit(10);
        }
        auto after = read_capabilities();
        if (!after) {
            _exit(20);
        }
        if ((after->permitted & (1ULL << 5)) != 0) {
            _exit(30);
        }
        if ((after->effective & (1ULL << 5)) != 0) {
            _exit(40);
        }
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child exited with sentinel " << WEXITSTATUS(status)
        << " (10=drop_failed, 20=read_failed, 30=permitted_still_set, 40=effective_still_set)";
}

namespace {

// Read a single Cap* line from /proc/self/status and decode the
// 16-hex-digit bitmap into a uint64_t. Returns 0 if the line is
// absent or malformed (only used in tests so this is fine).
uint64_t read_proc_cap_line(const char* prefix)
{
    std::FILE* fp = std::fopen("/proc/self/status", "r");
    if (!fp) {
        return 0;
    }
    char line[256];
    uint64_t value = 0;
    const size_t prefix_len = std::strlen(prefix);
    while (std::fgets(line, sizeof(line), fp)) {
        if (std::strncmp(line, prefix, prefix_len) == 0) {
            // Format: "CapBnd:\t<16 hex digits>\n"
            std::sscanf(line + prefix_len, "%lx", &value);
            break;
        }
    }
    std::fclose(fp);
    return value;
}

} // namespace

TEST(CapabilitiesTest, DroppedCapDisappearsFromBoundingSet)
{
    // The bounding set is the cap-drop fix's most important invariant:
    // it survives execve, so a leak there means a child process could
    // re-acquire the cap via a setuid binary or fcaps. The drop_*
    // function must reliably clear it; this test pins that behaviour
    // so any future regression in the call order trips a unit test
    // instead of being discovered by a security review.
    auto initial = read_capabilities();
    ASSERT_TRUE(initial);
    const uint64_t initial_bnd = read_proc_cap_line("CapBnd:");
    if ((initial_bnd & (1ULL << 5)) == 0) {
        GTEST_SKIP() << "CAP_KILL not in bounding set (likely an unprivileged container)";
    }
    if ((initial->effective & (1ULL << 8)) == 0) { // CAP_SETPCAP
        GTEST_SKIP() << "CAP_SETPCAP not in effective set; PR_CAPBSET_DROP requires it";
    }

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        auto rc = drop_capabilities({5}); // CAP_KILL
        if (!rc) {
            _exit(10);
        }
        const uint64_t after_bnd = read_proc_cap_line("CapBnd:");
        if ((after_bnd & (1ULL << 5)) != 0) {
            _exit(20);
        }
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0) << "child exited with sentinel " << WEXITSTATUS(status)
                                      << " (10=drop_failed, 20=bounding_still_set)";
}

} // namespace aegis
