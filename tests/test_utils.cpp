// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>

#include "utils.hpp"

namespace aegis {
namespace {

std::filesystem::path make_temp_file_path()
{
    static uint64_t counter = 0;
    return std::filesystem::temp_directory_path() /
           ("aegisbpf_utils_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) + "_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
}

TEST(TrimTest, EmptyString)
{
    EXPECT_EQ(trim(""), "");
}

TEST(TrimTest, NoWhitespace)
{
    EXPECT_EQ(trim("hello"), "hello");
}

TEST(TrimTest, LeadingWhitespace)
{
    EXPECT_EQ(trim("  hello"), "hello");
    EXPECT_EQ(trim("\t\thello"), "hello");
}

TEST(TrimTest, TrailingWhitespace)
{
    EXPECT_EQ(trim("hello  "), "hello");
    EXPECT_EQ(trim("hello\t\n"), "hello");
}

TEST(TrimTest, BothEnds)
{
    EXPECT_EQ(trim("  hello  "), "hello");
    EXPECT_EQ(trim("\n\thello world\t\n"), "hello world");
}

TEST(TrimTest, AllWhitespace)
{
    EXPECT_EQ(trim("   "), "");
    EXPECT_EQ(trim("\t\n\r"), "");
}

TEST(ParseKeyValueTest, ValidKeyValue)
{
    std::string key, value;
    EXPECT_TRUE(parse_key_value("foo=bar", key, value));
    EXPECT_EQ(key, "foo");
    EXPECT_EQ(value, "bar");
}

TEST(ParseKeyValueTest, WithWhitespace)
{
    std::string key, value;
    EXPECT_TRUE(parse_key_value("  foo  =  bar  ", key, value));
    EXPECT_EQ(key, "foo");
    EXPECT_EQ(value, "bar");
}

TEST(ParseKeyValueTest, EmptyValue)
{
    std::string key, value;
    EXPECT_TRUE(parse_key_value("foo=", key, value));
    EXPECT_EQ(key, "foo");
    EXPECT_EQ(value, "");
}

TEST(ParseKeyValueTest, NoEquals)
{
    std::string key, value;
    EXPECT_FALSE(parse_key_value("foobar", key, value));
}

TEST(ParseKeyValueTest, EmptyKey)
{
    std::string key, value;
    EXPECT_FALSE(parse_key_value("=bar", key, value));
}

TEST(ParseUint64Test, ValidNumber)
{
    uint64_t out = 0;
    EXPECT_TRUE(parse_uint64("12345", out));
    EXPECT_EQ(out, 12345u);
}

TEST(ParseUint64Test, Zero)
{
    uint64_t out = 999;
    EXPECT_TRUE(parse_uint64("0", out));
    EXPECT_EQ(out, 0u);
}

TEST(ParseUint64Test, LargeNumber)
{
    uint64_t out = 0;
    EXPECT_TRUE(parse_uint64("18446744073709551615", out));
    EXPECT_EQ(out, UINT64_MAX);
}

TEST(ParseUint64Test, EmptyString)
{
    uint64_t out = 0;
    EXPECT_FALSE(parse_uint64("", out));
}

TEST(ParseUint64Test, InvalidCharacters)
{
    uint64_t out = 0;
    EXPECT_FALSE(parse_uint64("123abc", out));
    EXPECT_FALSE(parse_uint64("abc", out));
    EXPECT_FALSE(parse_uint64("-1", out));
}

TEST(ParseInodeIdTest, ValidFormat)
{
    InodeId id{};
    EXPECT_TRUE(parse_inode_id("259:12345", id));
    EXPECT_EQ(id.dev, 259u);
    EXPECT_EQ(id.ino, 12345u);
}

TEST(ParseInodeIdTest, WithWhitespace)
{
    InodeId id{};
    EXPECT_TRUE(parse_inode_id(" 259 : 12345 ", id));
    EXPECT_EQ(id.dev, 259u);
    EXPECT_EQ(id.ino, 12345u);
}

TEST(ParseInodeIdTest, NoColon)
{
    InodeId id{};
    EXPECT_FALSE(parse_inode_id("259-12345", id));
}

TEST(ParseInodeIdTest, InvalidDev)
{
    InodeId id{};
    EXPECT_FALSE(parse_inode_id("abc:12345", id));
}

TEST(ParseInodeIdTest, DevTooLarge)
{
    InodeId id{};
    // Device numbers are 32-bit
    EXPECT_FALSE(parse_inode_id("4294967296:12345", id));
}

TEST(JoinListTest, EmptyList)
{
    std::vector<std::string> items;
    EXPECT_EQ(join_list(items), "");
}

TEST(JoinListTest, SingleItem)
{
    std::vector<std::string> items = {"hello"};
    EXPECT_EQ(join_list(items), "hello");
}

TEST(JoinListTest, MultipleItems)
{
    std::vector<std::string> items = {"a", "b", "c"};
    EXPECT_EQ(join_list(items), "a, b, c");
}

TEST(ToStringTest, NullTerminated)
{
    const char buf[] = "hello";
    EXPECT_EQ(to_string(buf, sizeof(buf)), "hello");
}

TEST(ToStringTest, NotNullTerminated)
{
    const char buf[] = {'h', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(to_string(buf, sizeof(buf)), "hello");
}

TEST(ToStringTest, PartialBuffer)
{
    const char buf[] = "hello world";
    EXPECT_EQ(to_string(buf, 5), "hello");
}

TEST(JsonEscapeTest, NoEscapeNeeded)
{
    EXPECT_EQ(json_escape("hello"), "hello");
}

TEST(JsonEscapeTest, Quotes)
{
    EXPECT_EQ(json_escape("say \"hello\""), "say \\\"hello\\\"");
}

TEST(JsonEscapeTest, Backslash)
{
    EXPECT_EQ(json_escape("path\\to\\file"), "path\\\\to\\\\file");
}

TEST(PrometheusEscapeLabelTest, NoEscapeNeeded)
{
    EXPECT_EQ(prometheus_escape_label("hello"), "hello");
}

TEST(PrometheusEscapeLabelTest, Newline)
{
    EXPECT_EQ(prometheus_escape_label("line1\nline2"), "line1\\nline2");
}

TEST(InodeToStringTest, Format)
{
    InodeId id{12345, 259, 0};
    EXPECT_EQ(inode_to_string(id), "259:12345");
}

TEST(BuildExecIdTest, ValidInput)
{
    EXPECT_EQ(build_exec_id(1234, 5678), "5678-1234");
}

TEST(BuildExecIdTest, ZeroPid)
{
    EXPECT_EQ(build_exec_id(0, 5678), "");
}

TEST(BuildExecIdTest, ZeroStartTime)
{
    EXPECT_EQ(build_exec_id(1234, 0), "");
}

TEST(ResolveCgroupPathTest, InvalidCgroupIdDoesNotThrow)
{
    EXPECT_NO_THROW({
        std::string path = resolve_cgroup_path(std::numeric_limits<uint64_t>::max());
        (void)path;
    });
}

TEST(ValidatePathTest, EmptyPath)
{
    auto result = validate_path("");
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidArgument);
}

TEST(ValidatePathTest, ValidPath)
{
    auto result = validate_path("/usr/bin/ls");
    EXPECT_TRUE(result);
    EXPECT_EQ(*result, "/usr/bin/ls");
}

TEST(ValidatePathTest, PathTooLong)
{
    std::string long_path(kDenyPathMax + 1, 'x');
    auto result = validate_path(long_path);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PathTooLong);
}

TEST(ValidatePathTest, PathWithNullBytes)
{
    std::string path_with_null = "/etc/shadow";
    path_with_null += '\0';
    path_with_null += "malicious";
    auto result = validate_path(path_with_null);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidArgument);
}

TEST(ValidateExistingPathTest, NonExistentPath)
{
    auto result = validate_existing_path("/nonexistent/path/to/nowhere");
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PathNotFound);
}

TEST(ValidateExistingPathTest, ExistingPath)
{
    // /etc should exist on all Linux systems
    auto result = validate_existing_path("/etc");
    EXPECT_TRUE(result);
    EXPECT_EQ(*result, "/etc");
}

TEST(ValidateExistingPathTest, SymlinkResolution)
{
    // /bin is often a symlink to /usr/bin on modern systems
    auto result = validate_existing_path("/bin");
    if (result) {
        // Just verify it returns a canonicalized path
        EXPECT_TRUE(result->front() == '/');
    }
}

TEST(ValidateFilePermissionsTest, RegularFilePasses)
{
    auto file = make_temp_file_path();
    {
        std::ofstream out(file);
        ASSERT_TRUE(out.is_open());
        out << "data";
    }
    std::error_code ec;
    std::filesystem::permissions(file,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                     std::filesystem::perms::group_read | std::filesystem::perms::others_read,
                                 std::filesystem::perm_options::replace, ec);
    ASSERT_FALSE(ec);

    auto result = validate_file_permissions(file.string(), false);
    EXPECT_TRUE(result);

    std::filesystem::remove(file, ec);
}

TEST(ValidateFilePermissionsTest, WorldWritableFileFails)
{
    auto file = make_temp_file_path();
    {
        std::ofstream out(file);
        ASSERT_TRUE(out.is_open());
        out << "data";
    }

    std::error_code ec;
    std::filesystem::permissions(file, std::filesystem::perms::others_write, std::filesystem::perm_options::add, ec);
    ASSERT_FALSE(ec);

    auto result = validate_file_permissions(file.string(), false);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::PermissionDenied);

    std::filesystem::permissions(file, std::filesystem::perms::others_write, std::filesystem::perm_options::remove, ec);
    std::filesystem::remove(file, ec);
}

} // namespace
} // namespace aegis
