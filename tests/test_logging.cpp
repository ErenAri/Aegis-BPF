// Tests for the structured logger field() overloads.
//
// Regression guard for the const char* -> bool overload trap: before a dedicated
// const char* overload existed, string-literal / C-string field values bound to
// field(key, bool) and rendered as "true" instead of the actual string.
#include "logging.hpp"

#include <gtest/gtest.h>

using namespace aegis;

TEST(LoggingTest, ConstCharPointerRendersValueNotBool)
{
    const char* prog = "handle_bprm_check_security";
    LogEntry e(LogLevel::Info, "msg");
    e.field("program", prog);

    ASSERT_EQ(e.fields().size(), 1u);
    EXPECT_EQ(e.fields()[0].first, "program");
    // Must be the string value, NOT "true".
    EXPECT_EQ(e.fields()[0].second, "handle_bprm_check_security");
}

TEST(LoggingTest, StringLiteralRendersValueNotBool)
{
    LogEntry e(LogLevel::Info, "msg");
    e.field("hook", "lsm/file_open");

    ASSERT_EQ(e.fields().size(), 1u);
    EXPECT_EQ(e.fields()[0].second, "lsm/file_open");
}

TEST(LoggingTest, StdStringStillRendersValue)
{
    LogEntry e(LogLevel::Info, "msg");
    std::string path = "/etc/aegisbpf/policy.conf";
    e.field("path", path);

    ASSERT_EQ(e.fields().size(), 1u);
    EXPECT_EQ(e.fields()[0].second, "/etc/aegisbpf/policy.conf");
}

TEST(LoggingTest, BoolStillRendersBool)
{
    LogEntry e(LogLevel::Info, "msg");
    bool enabled = true;
    e.field("enabled", enabled).field("disabled", false);

    ASSERT_EQ(e.fields().size(), 2u);
    EXPECT_EQ(e.fields()[0].second, "true");
    EXPECT_EQ(e.fields()[1].second, "false");
}

TEST(LoggingTest, NullConstCharPointerIsEmptyNotCrash)
{
    LogEntry e(LogLevel::Info, "msg");
    const char* nothing = nullptr;
    e.field("maybe", nothing);

    ASSERT_EQ(e.fields().size(), 1u);
    EXPECT_EQ(e.fields()[0].second, "");
}

TEST(LoggingTest, IntegerOverloadsUnaffected)
{
    LogEntry e(LogLevel::Info, "msg");
    e.field("i64", static_cast<int64_t>(-7)).field("u64", static_cast<uint64_t>(42));

    ASSERT_EQ(e.fields().size(), 2u);
    EXPECT_EQ(e.fields()[0].second, "-7");
    EXPECT_EQ(e.fields()[1].second, "42");
}
