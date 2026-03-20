// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include <limits>
#include <string>
#include <vector>

#include "json_scan.hpp"

namespace aegis::json_scan {
namespace {

TEST(JsonScanTest, ExtractStringSupportsEscapes)
{
    const std::string json = R"({"reason":"line\nvalue \u0041 \\ \"quoted\""})";
    std::string out;
    ASSERT_TRUE(extract_string(json, "reason", out));
    EXPECT_EQ(out, "line\nvalue A \\ \"quoted\"");
}

TEST(JsonScanTest, ExtractUint64ParsesWholeToken)
{
    const std::string json = R"({"failed_rows":12345,"ignored":"x"})";
    uint64_t out = 0;
    ASSERT_TRUE(extract_uint64(json, "failed_rows", out));
    EXPECT_EQ(out, 12345u);
}

TEST(JsonScanTest, ExtractInt64HandlesNegativeValues)
{
    const std::string json = R"({"changed_at_unix":-42})";
    int64_t out = 0;
    ASSERT_TRUE(extract_int64(json, "changed_at_unix", out));
    EXPECT_EQ(out, -42);
}

TEST(JsonScanTest, ExtractInt64HandlesMinValue)
{
    const std::string json = R"({"changed_at_unix":-9223372036854775808})";
    int64_t out = 0;
    ASSERT_TRUE(extract_int64(json, "changed_at_unix", out));
    EXPECT_EQ(out, std::numeric_limits<int64_t>::min());
}

TEST(JsonScanTest, ExtractBoolParsesBooleanLiterals)
{
    const std::string json = R"({"enabled":false,"gate_pass":true})";
    bool enabled = true;
    bool gate_pass = false;
    ASSERT_TRUE(extract_bool(json, "enabled", enabled));
    ASSERT_TRUE(extract_bool(json, "gate_pass", gate_pass));
    EXPECT_FALSE(enabled);
    EXPECT_TRUE(gate_pass);
}

TEST(JsonScanTest, ExtractInt64ArrayParsesSignedArrays)
{
    const std::string json = R"({"transition_times_unix":[1, -2, 3]})";
    std::vector<int64_t> out;
    ASSERT_TRUE(extract_int64_array(json, "transition_times_unix", out));
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 1);
    EXPECT_EQ(out[1], -2);
    EXPECT_EQ(out[2], 3);
}

TEST(JsonScanTest, MissingKeyReturnsFalse)
{
    const std::string json = R"({"type":"block"})";
    std::string out;
    EXPECT_FALSE(extract_string(json, "action", out));
}

} // namespace
} // namespace aegis::json_scan
