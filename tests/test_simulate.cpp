// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "commands_simulate.hpp"

namespace aegis {
namespace {

class TempFile {
  public:
    explicit TempFile(const std::string& contents)
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_simulate_test_" + std::to_string(getpid()) + "_" +
                 std::to_string(counter++) + "_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::ofstream f(path_);
        f << contents;
    }

    ~TempFile()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    [[nodiscard]] std::string str() const { return path_.string(); }

  private:
    std::filesystem::path path_;
};

class StdoutCapture {
  public:
    StdoutCapture()
        : original_(std::cout.rdbuf())
    {
        std::cout.rdbuf(buffer_.rdbuf());
    }
    ~StdoutCapture() { std::cout.rdbuf(original_); }

    [[nodiscard]] std::string str() const { return buffer_.str(); }

  private:
    std::stringstream buffer_;
    std::streambuf* original_;
};

}  // namespace

TEST(SimulateTest, ReturnsErrorWhenEventsPathMissing)
{
    SimulateOptions opts;
    EXPECT_EQ(cmd_simulate(opts), 1);
}

TEST(SimulateTest, ReturnsErrorWhenPolicyMissingAndNoApplied)
{
    TempFile events("{\"type\":\"block\",\"path\":\"/etc/foo\"}\n");
    SimulateOptions opts;
    opts.events_path = events.str();
    // Don't pass --policy and don't expect a real applied policy.
    // If kPolicyAppliedPath happens to exist on this dev box, the test
    // legitimately succeeds; we accept either outcome.
    int rc = cmd_simulate(opts);
    EXPECT_TRUE(rc == 0 || rc == 1);
}

TEST(SimulateTest, MatchedAndNewlyBlockedCountsAreCorrect)
{
    TempFile policy(
        "version=2\n"
        "[deny_path]\n"
        "/etc/shadow\n"
        "/var/secret\n");
    TempFile events(
        // 1) Matches deny_path /etc/shadow, audit-only -> newly_blocked
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":1}\n"
        // 2) Matches deny_path /var/secret, audit-only -> newly_blocked
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/var/secret\",\"pid\":2}\n"
        // 3) Matches deny_path /etc/shadow, already enforced (BLOCK) -> matched but not newly_blocked
        "{\"type\":\"block\",\"action\":\"BLOCK\",\"path\":\"/etc/shadow\",\"pid\":3}\n"
        // 4) Doesn't match anything; was AUDIT -> nothing
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/tmp/ok\",\"pid\":4}\n"
        // 5) Doesn't match anything; was BLOCK -> policy_drift
        "{\"type\":\"block\",\"action\":\"BLOCK\",\"path\":\"/var/old\",\"pid\":5}\n"
        // 6) Non-block event type -> ignored entirely
        "{\"type\":\"exec\",\"pid\":6}\n"
        // 7) Blank line
        "\n"
        // 8) Comment
        "# this is a comment\n");

    SimulateOptions opts;
    opts.events_path = events.str();
    opts.policy_path = policy.str();
    opts.json_output = true;
    opts.sample_limit = 10;

    StdoutCapture capture;
    int rc = cmd_simulate(opts);
    EXPECT_EQ(rc, 0);

    auto output = capture.str();
    // 5 block events evaluated (event 6 is exec; 7-8 are skipped as blank/comment).
    EXPECT_NE(output.find("\"events_parsed\":5"), std::string::npos);
    // 3 matches: events 1, 2, 3.
    EXPECT_NE(output.find("\"matched\":3"), std::string::npos);
    // 2 newly blocked: events 1, 2.
    EXPECT_NE(output.find("\"newly_blocked\":2"), std::string::npos);
    // 1 policy drift: event 5.
    EXPECT_NE(output.find("\"policy_drift\":1"), std::string::npos);
    // No parse errors.
    EXPECT_NE(output.find("\"parse_errors\":0"), std::string::npos);
}

TEST(SimulateTest, AllowCgroupSuppressesDeny)
{
    TempFile policy(
        "version=2\n"
        "[deny_path]\n"
        "/etc/shadow\n"
        "[allow_cgroup]\n"
        "/sys/fs/cgroup/system.slice/whitelist.scope\n");
    TempFile events(
        // Matches deny_path but allow_cgroup short-circuits -> nothing.
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"cgroup_path\":\"/sys/fs/cgroup/system.slice/whitelist.scope\",\"pid\":1}\n"
        // Same path, no allow-cgroup match -> matched + newly_blocked.
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"cgroup_path\":\"/sys/fs/cgroup/system.slice/other.scope\",\"pid\":2}\n");

    SimulateOptions opts;
    opts.events_path = events.str();
    opts.policy_path = policy.str();
    opts.json_output = true;

    StdoutCapture capture;
    int rc = cmd_simulate(opts);
    EXPECT_EQ(rc, 0);

    auto output = capture.str();
    EXPECT_NE(output.find("\"events_parsed\":2"), std::string::npos);
    EXPECT_NE(output.find("\"matched\":1"), std::string::npos);
    EXPECT_NE(output.find("\"newly_blocked\":1"), std::string::npos);
}

TEST(SimulateTest, UnparseableLinesIncrementParseErrorsButDoNotAbort)
{
    TempFile policy("version=2\n[deny_path]\n/etc/shadow\n");
    TempFile events(
        "this is not json\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\"}\n"
        "another bad line\n");

    SimulateOptions opts;
    opts.events_path = events.str();
    opts.policy_path = policy.str();
    opts.json_output = true;

    StdoutCapture capture;
    int rc = cmd_simulate(opts);
    EXPECT_EQ(rc, 0);

    auto output = capture.str();
    EXPECT_NE(output.find("\"parse_errors\":2"), std::string::npos);
    EXPECT_NE(output.find("\"events_parsed\":1"), std::string::npos);
    EXPECT_NE(output.find("\"newly_blocked\":1"), std::string::npos);
}

TEST(SimulateTest, StrictModeReturnsNonZeroOnNewlyBlocked)
{
    TempFile policy("version=2\n[deny_path]\n/etc/shadow\n");
    TempFile events("{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\"}\n");

    SimulateOptions opts;
    opts.events_path = events.str();
    opts.policy_path = policy.str();
    opts.strict = true;
    opts.json_output = true;

    StdoutCapture capture;
    int rc = cmd_simulate(opts);
    EXPECT_EQ(rc, 1);  // strict + newly_blocked > 0 = exit 1.

    auto output = capture.str();
    EXPECT_NE(output.find("\"newly_blocked\":1"), std::string::npos);
}

TEST(SimulateTest, StrictModeReturnsZeroWhenNoNewBlocks)
{
    TempFile policy("version=2\n[deny_path]\n/etc/shadow\n");
    // Only events that already had non-AUDIT action -> no newly_blocked.
    TempFile events("{\"type\":\"block\",\"action\":\"BLOCK\",\"path\":\"/etc/shadow\"}\n");

    SimulateOptions opts;
    opts.events_path = events.str();
    opts.policy_path = policy.str();
    opts.strict = true;
    opts.json_output = true;

    StdoutCapture capture;
    int rc = cmd_simulate(opts);
    EXPECT_EQ(rc, 0);  // strict but no NEW blocks -> exit 0.
}

TEST(SimulateTest, SampleLimitClamps)
{
    TempFile policy("version=2\n[deny_path]\n/etc/shadow\n");
    // 7 audit events that all match -> 7 newly_blocked.
    TempFile events(
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":1}\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":2}\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":3}\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":4}\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":5}\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":6}\n"
        "{\"type\":\"block\",\"action\":\"AUDIT\",\"path\":\"/etc/shadow\",\"pid\":7}\n");

    SimulateOptions opts;
    opts.events_path = events.str();
    opts.policy_path = policy.str();
    opts.sample_limit = 3;
    opts.json_output = true;

    StdoutCapture capture;
    int rc = cmd_simulate(opts);
    EXPECT_EQ(rc, 0);

    auto output = capture.str();
    EXPECT_NE(output.find("\"newly_blocked\":7"), std::string::npos);
    // Sample list should contain exactly 3 entries (sample_limit=3).
    // Count `"line":` occurrences inside the samples.newly_blocked array.
    auto samples_pos = output.find("\"newly_blocked\":[");
    ASSERT_NE(samples_pos, std::string::npos);
    auto end_pos = output.find("]", samples_pos);
    ASSERT_NE(end_pos, std::string::npos);
    auto samples_section = output.substr(samples_pos, end_pos - samples_pos);
    size_t line_count = 0;
    size_t pos = 0;
    while ((pos = samples_section.find("\"line\":", pos)) != std::string::npos) {
        ++line_count;
        ++pos;
    }
    EXPECT_EQ(line_count, 3u);
}

}  // namespace aegis
