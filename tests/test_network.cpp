// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include "network_ops.hpp"

namespace aegis {
namespace {

TEST(ParseIpv4Test, ValidIp)
{
    uint32_t ip_be = 0;
    EXPECT_TRUE(parse_ipv4("192.168.1.1", ip_be));
    EXPECT_NE(ip_be, 0u);
}

TEST(ParseIpv4Test, ZeroAddress)
{
    uint32_t ip_be = 1;
    EXPECT_TRUE(parse_ipv4("0.0.0.0", ip_be));
    EXPECT_EQ(ip_be, 0u);
}

TEST(ParseIpv4Test, BroadcastAddress)
{
    uint32_t ip_be = 0;
    EXPECT_TRUE(parse_ipv4("255.255.255.255", ip_be));
    EXPECT_NE(ip_be, 0u);
}

TEST(ParseIpv4Test, InvalidFormat)
{
    uint32_t ip_be = 0;
    EXPECT_FALSE(parse_ipv4("not.an.ip.address", ip_be));
    EXPECT_FALSE(parse_ipv4("", ip_be));
    EXPECT_FALSE(parse_ipv4("192.168.1", ip_be));
    EXPECT_FALSE(parse_ipv4("192.168.1.1.1", ip_be));
}

TEST(ParseIpv4Test, OutOfRangeOctet)
{
    uint32_t ip_be = 0;
    EXPECT_FALSE(parse_ipv4("256.0.0.1", ip_be));
    EXPECT_FALSE(parse_ipv4("192.168.1.256", ip_be));
}

TEST(ParseIpv6Test, ValidIp)
{
    Ipv6Key ip{};
    EXPECT_TRUE(parse_ipv6("2001:db8::1", ip));
}

TEST(ParseIpv6Test, InvalidFormat)
{
    Ipv6Key ip{};
    EXPECT_FALSE(parse_ipv6("2001:db8::zzz", ip));
    EXPECT_FALSE(parse_ipv6("192.168.1.1", ip));
    EXPECT_FALSE(parse_ipv6("", ip));
}

TEST(ParseCidrV4Test, ValidCidr)
{
    uint32_t ip_be = 0;
    uint8_t prefix = 0;
    EXPECT_TRUE(parse_cidr_v4("192.168.1.0/24", ip_be, prefix));
    EXPECT_EQ(prefix, 24);
}

TEST(ParseCidrV4Test, SingleHost)
{
    uint32_t ip_be = 0;
    uint8_t prefix = 0;
    EXPECT_TRUE(parse_cidr_v4("10.0.0.1/32", ip_be, prefix));
    EXPECT_EQ(prefix, 32);
}

TEST(ParseCidrV4Test, InvalidPrefix)
{
    uint32_t ip_be = 0;
    uint8_t prefix = 0;
    EXPECT_FALSE(parse_cidr_v4("192.168.1.0/33", ip_be, prefix));
    EXPECT_FALSE(parse_cidr_v4("192.168.1.0/-1", ip_be, prefix));
}

TEST(ParseCidrV4Test, MissingPrefix)
{
    uint32_t ip_be = 0;
    uint8_t prefix = 0;
    EXPECT_FALSE(parse_cidr_v4("192.168.1.0", ip_be, prefix));
}

TEST(ParseCidrV6Test, ValidCidr)
{
    Ipv6Key ip{};
    uint8_t prefix = 0;
    EXPECT_TRUE(parse_cidr_v6("2001:db8::/32", ip, prefix));
    EXPECT_EQ(prefix, 32);
}

TEST(ParseCidrV6Test, InvalidPrefix)
{
    Ipv6Key ip{};
    uint8_t prefix = 0;
    EXPECT_FALSE(parse_cidr_v6("2001:db8::/129", ip, prefix));
}

TEST(ParseCidrV6Test, MissingPrefix)
{
    Ipv6Key ip{};
    uint8_t prefix = 0;
    EXPECT_FALSE(parse_cidr_v6("2001:db8::1", ip, prefix));
}

TEST(FormatIpv4Test, ValidAddresses)
{
    // Test roundtrip
    uint32_t ip_be = 0;
    EXPECT_TRUE(parse_ipv4("192.168.1.100", ip_be));
    std::string formatted = format_ipv4(ip_be);
    EXPECT_EQ(formatted, "192.168.1.100");
}

TEST(FormatIpv4Test, Localhost)
{
    uint32_t ip_be = 0;
    EXPECT_TRUE(parse_ipv4("127.0.0.1", ip_be));
    std::string formatted = format_ipv4(ip_be);
    EXPECT_EQ(formatted, "127.0.0.1");
}

TEST(FormatIpv6Test, ValidAddresses)
{
    Ipv6Key ip{};
    EXPECT_TRUE(parse_ipv6("2001:db8::abcd", ip));
    EXPECT_EQ(format_ipv6(ip), "2001:db8::abcd");
}

TEST(ProtocolNameTest, KnownProtocols)
{
    EXPECT_EQ(protocol_name(6), "tcp");
    EXPECT_EQ(protocol_name(17), "udp");
}

TEST(ProtocolNameTest, UnknownProtocol)
{
    std::string name = protocol_name(99);
    EXPECT_FALSE(name.empty());
}

TEST(DirectionNameTest, KnownDirections)
{
    EXPECT_EQ(direction_name(0), "egress");
    EXPECT_EQ(direction_name(1), "bind");
    EXPECT_EQ(direction_name(2), "both");
}

} // namespace
} // namespace aegis
