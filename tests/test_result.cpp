#include <gtest/gtest.h>
#include "result.hpp"

namespace aegis {
namespace {

TEST(ResultTest, SuccessValue) {
    Result<int> r = 42;
    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(static_cast<bool>(r));
    EXPECT_EQ(*r, 42);
    EXPECT_EQ(r.value(), 42);
}

TEST(ResultTest, FailureError) {
    Result<int> r = Error(ErrorCode::InvalidArgument, "test error");
    EXPECT_FALSE(r.ok());
    EXPECT_FALSE(static_cast<bool>(r));
    EXPECT_EQ(r.error().code(), ErrorCode::InvalidArgument);
    EXPECT_EQ(r.error().message(), "test error");
}

TEST(ResultTest, ErrorWithContext) {
    Error e(ErrorCode::IoError, "file operation failed", "/path/to/file");
    EXPECT_EQ(e.to_string(), "file operation failed: /path/to/file");
}

TEST(ResultTest, ErrorWithoutContext) {
    Error e(ErrorCode::Unknown, "unknown error");
    EXPECT_EQ(e.to_string(), "unknown error");
}

TEST(ResultTest, ValueOr) {
    Result<int> success = 42;
    Result<int> failure = Error(ErrorCode::Unknown, "error");

    EXPECT_EQ(success.value_or(100), 42);
    EXPECT_EQ(failure.value_or(100), 100);
}

TEST(ResultTest, PointerOperator) {
    struct Point { int x; int y; };
    Result<Point> r = Point{10, 20};
    EXPECT_EQ(r->x, 10);
    EXPECT_EQ(r->y, 20);
}

TEST(ResultTest, MapSuccess) {
    Result<int> r = 10;
    auto doubled = r.map([](int x) { return x * 2; });
    EXPECT_TRUE(doubled.ok());
    EXPECT_EQ(*doubled, 20);
}

TEST(ResultTest, MapFailure) {
    Result<int> r = Error(ErrorCode::InvalidArgument, "error");
    auto doubled = r.map([](int x) { return x * 2; });
    EXPECT_FALSE(doubled.ok());
    EXPECT_EQ(doubled.error().code(), ErrorCode::InvalidArgument);
}

TEST(ResultVoidTest, Success) {
    Result<void> r;
    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(static_cast<bool>(r));
}

TEST(ResultVoidTest, Failure) {
    Result<void> r = Error(ErrorCode::IoError, "io failed");
    EXPECT_FALSE(r.ok());
    EXPECT_FALSE(static_cast<bool>(r));
    EXPECT_EQ(r.error().code(), ErrorCode::IoError);
}

TEST(ErrorTest, SystemError) {
    Error e = Error::system(ENOENT, "open file");
    EXPECT_EQ(e.code(), ErrorCode::IoError);
    EXPECT_EQ(e.message(), "open file");
}

TEST(ErrorTest, NotFoundError) {
    Error e = Error::not_found("config file");
    EXPECT_EQ(e.code(), ErrorCode::ResourceNotFound);
    EXPECT_EQ(e.message(), "config file not found");
}

TEST(ErrorTest, InvalidArgumentError) {
    Error e = Error::invalid_argument("path is empty");
    EXPECT_EQ(e.code(), ErrorCode::InvalidArgument);
}

TEST(ErrorTest, BpfError) {
    Error e = Error::bpf_error(-EPERM, "attach program");
    EXPECT_EQ(e.code(), ErrorCode::BpfLoadFailed);
}

} // namespace
} // namespace aegis
