// cppcheck-suppress-file missingIncludeSystem
/*
 * Integration tests for the network-block-event time-window deduper.
 *
 * The lower-level `EventDeduper` primitive is exercised in
 * test_event_dedup.cpp; this file covers the wiring between
 * `configure_net_block_event_dedup` and `print_net_block_event` so
 * the daemon-facing behaviour is locked in:
 *
 *   * Disabled-by-default: when the operator never enables dedup,
 *     identical NetBlockEvents emit one stdout line each. Existing
 *     deployments must see no behaviour change.
 *   * Enabled with a long window: a true duplicate (every keying
 *     field identical) inside the window emits exactly once.
 *   * Per-field key separation: changing direction / protocol /
 *     family / cgid / pid / remote_ip / remote_port / local_port
 *     must NOT collapse into a prior key (semantically distinct
 *     events would otherwise be silently dropped).
 *   * IPv6 path keys on the address; distinct IPv6 destinations stay
 *     distinct.
 *
 * Tests do not cover suppressed-during-prior-window resurface here —
 * that depends on monotonic_clock_gettime under the hood and is
 * already covered by the EventDeduper unit tests with synthetic time.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "events.hpp"
#include "types.hpp"

using aegis::configure_net_block_event_dedup;
using aegis::kFamilyIPv4;
using aegis::kFamilyIPv6;
using aegis::kProtoTCP;
using aegis::kProtoUDP;
using aegis::NetBlockEvent;
using aegis::print_net_block_event;

namespace {

constexpr uint64_t kLongWindowMs = 60'000; // 60s — far longer than the test wall time.

NetBlockEvent make_net_block_event_ipv4()
{
    NetBlockEvent ev{};
    ev.pid = 4242;
    ev.ppid = 1;
    ev.start_time = 100;
    ev.parent_start_time = 50;
    ev.cgid = 0xc0ffeeULL;
    std::strncpy(ev.comm, "curl", sizeof(ev.comm) - 1);
    ev.family = kFamilyIPv4;
    ev.protocol = kProtoTCP;
    ev.local_port = 0;
    ev.remote_port = 443;
    ev.direction = 0; // egress connect
    ev.remote_ipv4 = 0x0100007fU; // 127.0.0.1 in network byte order
    std::strncpy(ev.action, "BLOCK", sizeof(ev.action) - 1);
    std::strncpy(ev.rule_type, "ip", sizeof(ev.rule_type) - 1);
    return ev;
}

NetBlockEvent make_net_block_event_ipv6()
{
    NetBlockEvent ev = make_net_block_event_ipv4();
    ev.family = kFamilyIPv6;
    ev.remote_ipv4 = 0;
    // ::1 — only the last byte is set
    ev.remote_ipv6[15] = 1;
    return ev;
}

std::size_t count_lines(const std::string& s)
{
    return static_cast<std::size_t>(std::count(s.begin(), s.end(), '\n'));
}

class NetBlockDedupTest : public ::testing::Test {
  protected:
    void TearDown() override
    {
        // Always reset to disabled so other tests in the binary that
        // emit NetBlockEvents are not affected by leftover state.
        configure_net_block_event_dedup(0, 0);
    }
};

} // namespace

TEST_F(NetBlockDedupTest, DisabledByDefaultEmitsEveryEvent)
{
    configure_net_block_event_dedup(0, 0);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    for (int i = 0; i < 5; ++i) {
        print_net_block_event(ev);
    }
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 5u) << out;
}

TEST_F(NetBlockDedupTest, EnabledSuppressesIdenticalDuplicates)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    for (int i = 0; i < 5; ++i) {
        print_net_block_event(ev);
    }
    const std::string out = testing::internal::GetCapturedStdout();
    // First emit only; duplicates inside the long window are suppressed.
    EXPECT_EQ(count_lines(out), 1u) << out;
}

TEST_F(NetBlockDedupTest, DistinctDirectionsDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    // 0=egress, 1=bind, 2=listen, 3=accept, 4=send, 5=recv. Each is a
    // semantically distinct security event class and must not collide
    // even if every other tuple element matches.
    for (uint8_t d = 0; d <= 5; ++d) {
        ev.direction = d;
        print_net_block_event(ev);
    }
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 6u) << out;
}

TEST_F(NetBlockDedupTest, DistinctProtocolsDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    ev.protocol = kProtoTCP;
    print_net_block_event(ev);
    ev.protocol = kProtoUDP;
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctFamiliesDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);

    testing::internal::CaptureStdout();
    auto ev4 = make_net_block_event_ipv4();
    print_net_block_event(ev4);
    auto ev6 = make_net_block_event_ipv6();
    print_net_block_event(ev6);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctCgidsDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    ev.cgid = 0x111;
    print_net_block_event(ev);
    ev.cgid = 0x222;
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctPidsDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    ev.pid = 100;
    print_net_block_event(ev);
    ev.pid = 200;
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctRemoteIPv4DoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    ev.remote_ipv4 = 0x0100007fU; // 127.0.0.1
    print_net_block_event(ev);
    ev.remote_ipv4 = 0x08080808U; // 8.8.8.8
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctRemoteIPv6DoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv6();

    testing::internal::CaptureStdout();
    ev.remote_ipv6[15] = 1;
    print_net_block_event(ev);
    ev.remote_ipv6[15] = 2;
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctRemotePortsDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();

    testing::internal::CaptureStdout();
    ev.remote_port = 80;
    print_net_block_event(ev);
    ev.remote_port = 443;
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, DistinctLocalPortsDoNotCollapse)
{
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();
    ev.direction = 1; // bind — local_port is the meaningful field

    testing::internal::CaptureStdout();
    ev.local_port = 8080;
    print_net_block_event(ev);
    ev.local_port = 9090;
    print_net_block_event(ev);
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 2u) << out;
}

TEST_F(NetBlockDedupTest, ReconfigureWithZeroWindowDisablesDedup)
{
    // Operator-facing toggle: setting the window back to zero must
    // restore the disabled-by-default behaviour, even after a prior
    // configure call populated state.
    configure_net_block_event_dedup(kLongWindowMs, 64);
    auto ev = make_net_block_event_ipv4();
    print_net_block_event(ev); // populate dedup state

    configure_net_block_event_dedup(0, 0);

    testing::internal::CaptureStdout();
    for (int i = 0; i < 3; ++i) {
        print_net_block_event(ev);
    }
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_EQ(count_lines(out), 3u) << out;
}
