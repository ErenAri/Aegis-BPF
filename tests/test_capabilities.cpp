// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>

#include "capabilities.hpp"

namespace aegis {
namespace {

constexpr uint64_t cap_bit(int c) noexcept
{
    return uint64_t{1} << static_cast<unsigned>(c);
}

bool running_as_root() noexcept
{
    return ::geteuid() == 0;
}

}  // namespace

TEST(CapabilitiesTest, DefaultConfigContainsExpectedRetainSet)
{
    auto cfg = default_capability_config();

    auto contains = [&](int c) {
        return std::find(cfg.retain.begin(), cfg.retain.end(), c) != cfg.retain.end();
    };
    EXPECT_TRUE(contains(cap::kBpf));
    EXPECT_TRUE(contains(cap::kPerfmon));
    EXPECT_TRUE(contains(cap::kDacReadSearch));
    EXPECT_TRUE(contains(cap::kSysResource));

    // We should NOT retain CAP_SYS_ADMIN by default -- the whole point
    // of the kernel 5.8 capability split is to avoid it.
    EXPECT_FALSE(contains(cap::kSysAdmin));

    EXPECT_TRUE(cfg.clear_inheritable);
    EXPECT_TRUE(cfg.clear_bounding);
    EXPECT_TRUE(cfg.clear_ambient);
}

TEST(CapabilitiesTest, SplitSupportProbeReturnsBoolean)
{
    // We can't assert true or false (depends on the host kernel), but
    // we can assert the probe doesn't crash and returns the same value
    // when called twice.
    const bool first  = capabilities_split_supported();
    const bool second = capabilities_split_supported();
    EXPECT_EQ(first, second);
}

TEST(CapabilitiesTest, ReadSnapshotReturnsValidMasks)
{
    auto snap_result = read_capability_snapshot();
    ASSERT_TRUE(snap_result) << "read_capability_snapshot failed: "
                             << (snap_result ? "" : snap_result.error().to_string());
    const auto& snap = snap_result.value();

    // The bounding set is always non-zero on a normal Linux process
    // (root or otherwise) -- it's the kernel-wide upper bound.
    EXPECT_NE(snap.bounding, 0u);

    // permitted is a subset of bounding.
    EXPECT_EQ(snap.permitted & ~snap.bounding, 0u)
        << "permitted set has caps outside bounding";

    // effective is a subset of permitted.
    EXPECT_EQ(snap.effective & ~snap.permitted, 0u)
        << "effective set has caps outside permitted";
}

TEST(CapabilitiesTest, RejectsEmptyRetainSet)
{
    if (!capabilities_split_supported()) {
        GTEST_SKIP() << "kernel < 5.8: drop is a no-op so empty-retain is not validated";
    }
    if (!running_as_root()) {
        GTEST_SKIP() << "drop requires root caps to exercise";
    }

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        CapabilityConfig cfg;
        cfg.retain.clear();  // empty
        auto res = drop_to_minimum(cfg);
        // We expect failure: empty retain is rejected.
        _exit(res ? 1 : 0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "empty retain should have been rejected, but drop_to_minimum returned ok";
}

TEST(CapabilitiesTest, DropReducesEffectiveSet)
{
    if (!capabilities_split_supported()) {
        GTEST_SKIP() << "kernel < 5.8: drop is a no-op";
    }
    if (!running_as_root()) {
        GTEST_SKIP() << "drop requires root caps to exercise";
    }

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        // Sentinel exit codes:
        //   10 = pre-snapshot read failed
        //   11 = pre-snapshot showed no caps (test would be vacuous)
        //   12 = drop_to_minimum returned an error
        //   13 = post-snapshot read failed
        //   14 = effective set was not reduced
        //   15 = effective set retained caps outside the requested mask
        //   0  = drop succeeded as expected
        auto pre = read_capability_snapshot();
        if (!pre) _exit(10);
        if (pre->effective == 0) _exit(11);

        CapabilityConfig cfg = default_capability_config();
        auto res = drop_to_minimum(cfg);
        if (!res) _exit(12);

        auto post = read_capability_snapshot();
        if (!post) _exit(13);

        if (post->effective >= pre->effective) _exit(14);

        // Build the requested mask manually from the same retain list.
        uint64_t want = 0;
        for (int c : cfg.retain) want |= cap_bit(c);
        if ((post->effective & ~want) != 0) _exit(15);

        _exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child sentinel: 10=pre-read 11=already-empty 12=drop-failed "
           "13=post-read 14=not-reduced 15=leaked-caps";
}

TEST(CapabilitiesTest, DropIsIdempotent)
{
    if (!capabilities_split_supported()) {
        GTEST_SKIP() << "kernel < 5.8";
    }
    if (!running_as_root()) {
        GTEST_SKIP() << "requires root";
    }

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        CapabilityConfig cfg = default_capability_config();
        if (!drop_to_minimum(cfg)) _exit(10);
        auto first = read_capability_snapshot();
        if (!first) _exit(11);

        // Re-call. Should not error and should not change the state.
        if (!drop_to_minimum(cfg)) _exit(12);
        auto second = read_capability_snapshot();
        if (!second) _exit(13);

        if (first->effective != second->effective) _exit(14);
        if (first->permitted != second->permitted) _exit(15);
        if (first->bounding != second->bounding) _exit(16);
        _exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child sentinel: 10/12=drop-failed 11/13=read-failed "
           "14/15/16=second-call-changed-state";
}

TEST(CapabilitiesTest, BoundingSetIsReducedWhenRequested)
{
    if (!capabilities_split_supported()) {
        GTEST_SKIP() << "kernel < 5.8";
    }
    if (!running_as_root()) {
        GTEST_SKIP() << "requires root";
    }

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        auto pre = read_capability_snapshot();
        if (!pre) _exit(10);

        CapabilityConfig cfg = default_capability_config();
        cfg.clear_bounding = true;
        if (!drop_to_minimum(cfg)) _exit(11);

        auto post = read_capability_snapshot();
        if (!post) _exit(12);

        // Bounding set must be a subset of the retain mask.
        uint64_t want = 0;
        for (int c : cfg.retain) want |= cap_bit(c);
        if ((post->bounding & ~want) != 0) _exit(13);

        // And it should be strictly smaller than what we started with
        // (a normal root process has CAP_SYS_ADMIN etc. in bounding).
        if (post->bounding >= pre->bounding) _exit(14);
        _exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child sentinel: 10/12=read-failed 11=drop-failed "
           "13=bounding-leaked 14=bounding-not-reduced";
}

}  // namespace aegis
