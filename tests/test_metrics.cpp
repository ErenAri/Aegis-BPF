// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <string>

#include "commands_monitoring.hpp"

namespace aegis {
namespace {

TEST(MetricsTest, IncludesRingbufDropsInBlockMetrics)
{
    BlockStats stats{};
    stats.blocks = 42;
    stats.ringbuf_drops = 7;

    const std::string output = build_block_metrics_output(stats);
    EXPECT_NE(output.find("aegisbpf_blocks_total"), std::string::npos);
    EXPECT_NE(output.find("aegisbpf_ringbuf_drops_total"), std::string::npos);
}

TEST(MetricsTest, IncludesRingbufDropsInNetMetrics)
{
    NetBlockStats stats{};
    stats.connect_blocks = 3;
    stats.bind_blocks = 4;
    stats.ringbuf_drops = 5;

    const std::string output = build_net_metrics_output(stats);
    EXPECT_NE(output.find("aegisbpf_net_blocks_total"), std::string::npos);
    EXPECT_NE(output.find("aegisbpf_net_ringbuf_drops_total"), std::string::npos);
}

} // namespace
} // namespace aegis
