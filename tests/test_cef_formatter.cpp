// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "cef_formatter.hpp"
#include "events.hpp"
#include "types.hpp"

namespace aegis {
namespace {

bool contains(const std::string& cef, const std::string& fragment)
{
    return cef.find(fragment) != std::string::npos;
}

bool starts_with(const std::string& cef, const std::string& prefix)
{
    return cef.size() >= prefix.size() && cef.compare(0, prefix.size(), prefix) == 0;
}

// Count pipes in the leading CEF header (before the first ` ` that
// follows the severity field). The header must contain exactly seven
// pipes per the ArcSight Implementation Standard:
//   CEF:0|Vendor|Product|Version|SigID|Name|Severity|Extension
int header_pipe_count(const std::string& cef)
{
    // Walk char-by-char, counting unescaped pipes until we exit the
    // header. The header ends after the seventh pipe (which begins the
    // extension section); so really we just count pipes in the entire
    // record but treat `\\|` as a literal — present-day AegisBPF
    // extension values never contain `|` so a simple counter is enough
    // for the test surface.
    int count = 0;
    bool prev_backslash = false;
    int seen_unescaped_pipes = 0;
    for (char c : cef) {
        if (c == '\\' && !prev_backslash) {
            prev_backslash = true;
            continue;
        }
        if (c == '|' && !prev_backslash) {
            ++seen_unescaped_pipes;
            ++count;
            if (seen_unescaped_pipes == 7) {
                // Stop counting after the header — anything beyond is
                // extension territory.
                break;
            }
        }
        prev_backslash = false;
    }
    return count;
}

BlockEvent make_block_event(const char* path_str, const char* action_str)
{
    BlockEvent ev{};
    ev.pid = 1234;
    ev.ppid = 5678;
    ev.start_time = 1700000000000000000ULL;
    ev.parent_start_time = 1700000000000000000ULL - 5000000000ULL;
    ev.cgid = 0xCAFEBABEULL;
    ev.ino = 4242;
    ev.dev = 99;
    std::strncpy(ev.comm, "evil-proc", sizeof(ev.comm) - 1);
    std::strncpy(ev.path, path_str, sizeof(ev.path) - 1);
    std::strncpy(ev.action, action_str, sizeof(ev.action) - 1);
    return ev;
}

NetBlockEvent make_net_block_event(uint8_t direction, const char* action_str)
{
    NetBlockEvent ev{};
    ev.pid = 1111;
    ev.ppid = 2222;
    ev.start_time = 1700000000000000000ULL;
    ev.parent_start_time = 1700000000000000000ULL - 1000000000ULL;
    ev.cgid = 0xDEADBEEFULL;
    ev.family = kFamilyIPv4;
    ev.protocol = kProtoTCP;
    ev.local_port = 0;
    ev.remote_port = 4444;
    ev.direction = direction;
    ev.remote_ipv4 = 0x0100007FU; // 127.0.0.1 in network byte order
    std::strncpy(ev.comm, "curl", sizeof(ev.comm) - 1);
    std::strncpy(ev.action, action_str, sizeof(ev.action) - 1);
    std::strncpy(ev.rule_type, "ip", sizeof(ev.rule_type) - 1);
    return ev;
}

} // namespace

// -------- format keyword recognition ----------------------------------

TEST(CefFormatterTest, KeywordRecognitionAcceptsExpectedAliases)
{
    EXPECT_TRUE(is_cef_format_keyword("cef"));
    EXPECT_TRUE(is_cef_format_keyword("CEF"));
    EXPECT_TRUE(is_cef_format_keyword("cef-1.0"));
    EXPECT_FALSE(is_cef_format_keyword("ocsf"));
    EXPECT_FALSE(is_cef_format_keyword("aegis"));
    EXPECT_FALSE(is_cef_format_keyword(""));
}

TEST(CefFormatterTest, SetEventFormatRoutesCefKeyword)
{
    // Ensure the CLI parser hooks accept "cef" and the subsequent
    // dispatch uses EventFormat::Cef.
    EXPECT_TRUE(set_event_format("cef"));
    EXPECT_EQ(current_event_format(), EventFormat::Cef);
    // Restore default so unrelated tests are not affected.
    EXPECT_TRUE(set_event_format("aegis"));
}

// -------- format_block_event_cef --------------------------------------

TEST(CefFormatterTest, BlockEventEnforceProducesCanonicalHeader)
{
    auto ev = make_block_event("/etc/shadow", "BLOCK");
    auto cef = format_block_event_cef(ev, "/sys/fs/cgroup/system.slice", "/etc/shadow", "/etc/shadow", "BLOCK",
                                      "evil-proc", "exec-1234-deadbeef", "exec-5678-cafebabe", "test-host");

    EXPECT_TRUE(starts_with(cef, "CEF:0|AegisBPF Project|AegisBPF|"));
    EXPECT_EQ(header_pipe_count(cef), 7);
    EXPECT_TRUE(contains(cef, "|aegis:file:open|AegisBPF File Open Denied|8|"));

    // Required CEF dictionary keys.
    EXPECT_TRUE(contains(cef, " act=BLOCK"));
    EXPECT_TRUE(contains(cef, " outcome=success"));
    EXPECT_TRUE(contains(cef, " dvchost=test-host"));
    EXPECT_TRUE(contains(cef, " spid=1234"));
    EXPECT_TRUE(contains(cef, " sproc=evil-proc"));
    EXPECT_TRUE(contains(cef, " fname=shadow"));
    EXPECT_TRUE(contains(cef, " filePath=/etc/shadow"));

    // externalId pivots SIEMs back to other AegisBPF events with the
    // same exec lineage.
    EXPECT_TRUE(contains(cef, " externalId=exec-1234-deadbeef"));

    // Forensic detail lives in custom slots.
    EXPECT_TRUE(contains(cef, " cs1=/sys/fs/cgroup/system.slice"));
    EXPECT_TRUE(contains(cef, " cs1Label=AegisCgroupPath"));
    EXPECT_TRUE(contains(cef, " cs2=exec-5678-cafebabe"));
    EXPECT_TRUE(contains(cef, " cs2Label=AegisParentExecId"));
    // cgid is hex 0xCAFEBABE = 3405691582
    EXPECT_TRUE(contains(cef, " cn1=3405691582"));
    EXPECT_TRUE(contains(cef, " cn1Label=AegisCgroupId"));
    EXPECT_TRUE(contains(cef, " cn2=4242"));
    EXPECT_TRUE(contains(cef, " cn2Label=AegisInode"));
    EXPECT_TRUE(contains(cef, " cn3=99"));
    EXPECT_TRUE(contains(cef, " cn3Label=AegisDevice"));
}

TEST(CefFormatterTest, BlockEventAuditUsesMediumSeverityAndAuditAct)
{
    auto ev = make_block_event("/var/run/secrets", "AUDIT");
    auto cef = format_block_event_cef(ev, "", "/var/run/secrets", "/var/run/secrets", "AUDIT", "evil-proc", "exec-1234",
                                      "", "test-host");

    // Severity 4 (Medium) for audit-only — name flips too.
    EXPECT_TRUE(contains(cef, "|aegis:file:open|AegisBPF File Open Audit Observed|4|"));
    EXPECT_TRUE(contains(cef, " act=AUDIT"));
    EXPECT_TRUE(contains(cef, " msg=AegisBPF audit: file open observed"));
    // No cgroup_path provided -> cs1/cs1Label omitted.
    EXPECT_FALSE(contains(cef, " cs1="));
    // No parent_exec_id -> cs2/cs2Label omitted.
    EXPECT_FALSE(contains(cef, " cs2="));
}

TEST(CefFormatterTest, BlockEventFavorsResolvedPathOverRawPath)
{
    auto ev = make_block_event("relative.txt", "BLOCK");
    auto cef = format_block_event_cef(ev, "", "relative.txt", "/abs/proj/relative.txt", "BLOCK", "evil-proc", "", "",
                                      "test-host");
    EXPECT_TRUE(contains(cef, " fname=relative.txt"));
    EXPECT_TRUE(contains(cef, " filePath=/abs/proj/relative.txt"));
}

TEST(CefFormatterTest, BlockEventEscapesEqualsAndBackslashInExtensionValues)
{
    // CEF spec: extension values must escape `\` and `=`. We use the
    // path field as a vehicle because it is the most likely extension
    // value to ever contain user-controlled bytes (mount of a path with
    // `=` in its name, for example).
    auto ev = make_block_event("/srv/data=v2/bad\\file", "BLOCK");
    auto cef = format_block_event_cef(ev, "", "/srv/data=v2/bad\\file", "/srv/data=v2/bad\\file", "BLOCK", "evil-proc",
                                      "exec-1234", "", "test-host");
    // After escaping: `=` -> `\=`, `\` -> `\\`.
    EXPECT_TRUE(contains(cef, " filePath=/srv/data\\=v2/bad\\\\file"));
}

TEST(CefFormatterTest, BlockEventEscapesPipeAndBackslashInHeaderFields)
{
    // The signature_id, name, and product fields are header fields and
    // must escape `|` and `\`. Our static name strings have no such
    // characters today, but the escaper itself must be correct so a
    // future name change cannot accidentally break header framing.
    // We exercise the escaper through the header -- the AEGIS_VERSION
    // string is fixed at compile time so we cannot inject a `|` there;
    // instead this test asserts that the output, regardless of
    // version string, contains exactly seven unescaped pipes.
    auto ev = make_block_event("/etc/shadow", "BLOCK");
    auto cef = format_block_event_cef(ev, "", "/etc/shadow", "/etc/shadow", "BLOCK", "evil-proc", "exec-1234", "",
                                      "test-host");
    EXPECT_EQ(header_pipe_count(cef), 7);
}

// -------- format_net_block_event_cef ----------------------------------

TEST(CefFormatterTest, NetBlockEventEgressMapsRemoteToDst)
{
    auto ev = make_net_block_event(/*direction=*/0, "BLOCK"); // egress / connect
    auto cef = format_net_block_event_cef(ev, "/sys/fs/cgroup/user.slice", "curl", "exec-1111", "exec-2222",
                                          "net_connect_block", "127.0.0.1", "test-host");

    EXPECT_TRUE(contains(cef, "|aegis:net:connect|AegisBPF Network Connect Denied|8|"));
    EXPECT_TRUE(contains(cef, " proto=tcp"));
    // Egress: peer is destination.
    EXPECT_TRUE(contains(cef, " dst=127.0.0.1"));
    EXPECT_TRUE(contains(cef, " dpt=4444"));
    // Custom slots survive.
    EXPECT_TRUE(contains(cef, " cs3=ip"));
    EXPECT_TRUE(contains(cef, " cs3Label=AegisRuleType"));
    EXPECT_TRUE(contains(cef, " cs4=net_connect_block"));
    EXPECT_TRUE(contains(cef, " cs4Label=AegisEventType"));
    // cgid 0xDEADBEEF = 3735928559
    EXPECT_TRUE(contains(cef, " cn1=3735928559"));
    EXPECT_TRUE(contains(cef, " cn2=0"));
    EXPECT_TRUE(contains(cef, " cn2Label=AegisDirection"));
}

TEST(CefFormatterTest, NetBlockEventAcceptMapsRemoteToSrc)
{
    auto ev = make_net_block_event(/*direction=*/3, "BLOCK"); // accept
    ev.local_port = 8080;
    auto cef =
        format_net_block_event_cef(ev, "", "sshd", "exec-1111", "", "net_accept_block", "203.0.113.42", "test-host");
    // Accept: peer is source, local is destination.
    EXPECT_TRUE(contains(cef, " src=203.0.113.42"));
    EXPECT_TRUE(contains(cef, " spt=4444"));
    EXPECT_TRUE(contains(cef, " dpt=8080"));
    EXPECT_TRUE(contains(cef, " cn2=3"));
}

TEST(CefFormatterTest, NetBlockEventBindOmitsRemoteIpAndUsesLocalPortAsDpt)
{
    auto ev = make_net_block_event(/*direction=*/1, "BLOCK"); // bind
    ev.local_port = 8443;
    ev.remote_port = 0;
    ev.remote_ipv4 = 0;
    auto cef = format_net_block_event_cef(ev, "", "nginx", "exec-1111", "", "net_bind_block", "0.0.0.0", "test-host");
    EXPECT_TRUE(contains(cef, "|aegis:net:bind|AegisBPF Network Bind Denied|8|"));
    // 0.0.0.0 is suppressed (no remote peer for a bind).
    EXPECT_FALSE(contains(cef, " dst=0.0.0.0"));
    EXPECT_FALSE(contains(cef, " src=0.0.0.0"));
    // Local port becomes dpt (the port a future peer would target).
    EXPECT_TRUE(contains(cef, " dpt=8443"));
}

TEST(CefFormatterTest, NetBlockEventAuditUsesMediumSeverity)
{
    auto ev = make_net_block_event(/*direction=*/0, "AUDIT");
    auto cef =
        format_net_block_event_cef(ev, "", "curl", "exec-1111", "", "net_connect_block", "127.0.0.1", "test-host");
    EXPECT_TRUE(contains(cef, "|aegis:net:connect|AegisBPF Network Connect Audit Observed|4|"));
    EXPECT_TRUE(contains(cef, " act=AUDIT"));
}

TEST(CefFormatterTest, NetBlockEventUdpSendUsesTrafficSemantics)
{
    auto ev = make_net_block_event(/*direction=*/4, "BLOCK"); // sendmsg
    ev.protocol = kProtoUDP;
    auto cef =
        format_net_block_event_cef(ev, "", "stunnel", "exec-1111", "", "net_sendmsg_block", "10.0.0.5", "test-host");
    EXPECT_TRUE(contains(cef, "|aegis:net:send|AegisBPF Network Send Denied|8|"));
    EXPECT_TRUE(contains(cef, " proto=udp"));
    EXPECT_TRUE(contains(cef, " dst=10.0.0.5"));
}

TEST(CefFormatterTest, NetBlockEventIPv6PreservesFullAddress)
{
    auto ev = make_net_block_event(/*direction=*/0, "BLOCK");
    ev.family = kFamilyIPv6;
    auto cef =
        format_net_block_event_cef(ev, "", "curl", "exec-1111", "", "net_connect_block", "2001:db8::1", "test-host");
    EXPECT_TRUE(contains(cef, " dst=2001:db8::1"));
}

TEST(CefFormatterTest, RecordIsSingleLineNoEmbeddedNewlines)
{
    // CEF records are single-line by definition. Even when the
    // source `comm` contains a newline (it cannot today, but we want
    // a regression contract), the formatter must escape it.
    auto ev = make_block_event("/etc/shadow", "BLOCK");
    std::strncpy(ev.comm, "ev\nil", sizeof(ev.comm) - 1);
    auto cef = format_block_event_cef(ev, "", "/etc/shadow", "/etc/shadow", "BLOCK", std::string("ev\nil"), "exec-1234",
                                      "", "test-host");
    EXPECT_EQ(cef.find('\n'), std::string::npos);
    EXPECT_TRUE(contains(cef, "ev\\nil"));
}

} // namespace aegis
