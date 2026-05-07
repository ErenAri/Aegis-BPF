// cppcheck-suppress-file missingIncludeSystem
/*
 * Unit tests for the operator-visible ringbuf overflow policy parser.
 *
 * Contract verified here:
 *   * Default (empty input) selects PriorityFallback so existing
 *     deployments don't change behaviour silently.
 *   * The kebab-case canonical name and the underscore alias both
 *     resolve to the same enum value.
 *   * Parsing is case-insensitive (so config files and env vars don't
 *     have to fight over capitalisation).
 *   * Reserved roadmap names ("sample", "spool", "spool-to-disk") are
 *     recognised distinctly from "Unknown" so the CLI can emit a
 *     "reserved for future release" message instead of generic garbage.
 *   * The canonical name and description are stable, non-empty strings;
 *     the description does not end in a period (it is composed into a
 *     larger log line).
 */

#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "ringbuf_policy.hpp"

using aegis::parse_ringbuf_overflow_policy;
using aegis::ringbuf_overflow_policy_description;
using aegis::ringbuf_overflow_policy_name;
using aegis::RingbufOverflowPolicy;
using aegis::RingbufOverflowPolicyParseError;

namespace {

void expect_parses_to(const std::string& input, RingbufOverflowPolicy expected)
{
    RingbufOverflowPolicy out{};
    RingbufOverflowPolicyParseError err{};
    ASSERT_TRUE(parse_ringbuf_overflow_policy(input, out, err)) << "input=" << input;
    EXPECT_EQ(out, expected);
}

void expect_rejected(const std::string& input, RingbufOverflowPolicyParseError expected)
{
    RingbufOverflowPolicy out{};
    RingbufOverflowPolicyParseError err{};
    EXPECT_FALSE(parse_ringbuf_overflow_policy(input, out, err)) << "input=" << input;
    EXPECT_EQ(err, expected) << "input=" << input;
}

} // namespace

TEST(RingbufOverflowPolicy, EmptyInputDefaultsToPriorityFallback)
{
    expect_parses_to("", RingbufOverflowPolicy::PriorityFallback);
}

TEST(RingbufOverflowPolicy, KebabCaseCanonicalName)
{
    expect_parses_to("priority-fallback", RingbufOverflowPolicy::PriorityFallback);
}

TEST(RingbufOverflowPolicy, UnderscoreAliasResolvesToCanonical)
{
    expect_parses_to("priority_fallback", RingbufOverflowPolicy::PriorityFallback);
}

TEST(RingbufOverflowPolicy, CaseInsensitive)
{
    expect_parses_to("PRIORITY-FALLBACK", RingbufOverflowPolicy::PriorityFallback);
    expect_parses_to("Priority-Fallback", RingbufOverflowPolicy::PriorityFallback);
}

TEST(RingbufOverflowPolicy, ReservedRoadmapNamesAreFlaggedDistinctlyFromUnknown)
{
    expect_rejected("sample", RingbufOverflowPolicyParseError::Reserved);
    expect_rejected("spool", RingbufOverflowPolicyParseError::Reserved);
    expect_rejected("spool-to-disk", RingbufOverflowPolicyParseError::Reserved);
    expect_rejected("SPOOL_TO_DISK", RingbufOverflowPolicyParseError::Reserved);
}

TEST(RingbufOverflowPolicy, GarbageReturnsUnknown)
{
    expect_rejected("not-a-policy", RingbufOverflowPolicyParseError::Unknown);
    expect_rejected("priority", RingbufOverflowPolicyParseError::Unknown);
    expect_rejected("fallback", RingbufOverflowPolicyParseError::Unknown);
    expect_rejected("priority-fallback-extra", RingbufOverflowPolicyParseError::Unknown);
}

TEST(RingbufOverflowPolicy, NameIsStableCanonical)
{
    EXPECT_STREQ(ringbuf_overflow_policy_name(RingbufOverflowPolicy::PriorityFallback), "priority-fallback");
}

TEST(RingbufOverflowPolicy, DescriptionIsNonEmptyAndNoTrailingPeriod)
{
    const char* desc = ringbuf_overflow_policy_description(RingbufOverflowPolicy::PriorityFallback);
    ASSERT_NE(desc, nullptr);
    const std::size_t len = std::strlen(desc);
    EXPECT_GT(len, 0u);
    EXPECT_NE(desc[len - 1], '.') << "description: " << desc;
}
