// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "events.hpp"
#include "ocsf_formatter.hpp"
#include "types.hpp"

namespace aegis {
namespace {

bool has_field(const std::string& json, const std::string& key)
{
    return json.find("\"" + key + "\":") != std::string::npos;
}

bool has_value(const std::string& json, const std::string& kv)
{
    return json.find(kv) != std::string::npos;
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

// -------- format_block_event_ocsf -------------------------------------

TEST(OcsfFormatterTest, BlockEventEnforceContainsRequiredFields)
{
    auto ev = make_block_event("/etc/shadow", "BLOCK");
    auto json = format_block_event_ocsf(ev, "/sys/fs/cgroup/system.slice", "/etc/shadow", "/etc/shadow", "BLOCK",
                                        "evil-proc", "exec-1234-deadbeef", "exec-5678-cafebabe", "test-host");

    // OCSF required fields per File Activity 1001.
    EXPECT_TRUE(has_field(json, "class_uid"));
    EXPECT_TRUE(has_value(json, "\"class_uid\":1001"));
    EXPECT_TRUE(has_value(json, "\"category_uid\":1"));
    EXPECT_TRUE(has_value(json, "\"activity_id\":14"));
    EXPECT_TRUE(has_value(json, "\"type_uid\":100114"));
    EXPECT_TRUE(has_value(json, "\"action_id\":2"));      // Denied
    EXPECT_TRUE(has_value(json, "\"disposition_id\":2")); // Blocked
    EXPECT_TRUE(has_value(json, "\"status_id\":1"));      // Success
    EXPECT_TRUE(has_value(json, "\"severity_id\":4"));    // High
    EXPECT_TRUE(has_field(json, "time"));

    // Top-level structure.
    EXPECT_TRUE(has_field(json, "metadata"));
    EXPECT_TRUE(has_field(json, "actor"));
    EXPECT_TRUE(has_field(json, "device"));
    EXPECT_TRUE(has_field(json, "file"));
    EXPECT_TRUE(has_field(json, "unmapped"));

    // Metadata identifies the product.
    EXPECT_TRUE(has_value(json, "\"name\":\"AegisBPF\""));
    EXPECT_TRUE(has_value(json, "\"version\":\"1.1.0\""));

    // Actor process matches the event's pid/ppid/comm.
    EXPECT_TRUE(has_value(json, "\"pid\":1234"));
    EXPECT_TRUE(has_value(json, "\"name\":\"evil-proc\""));

    // File object derives name + parent_folder from the path.
    EXPECT_TRUE(has_value(json, "\"path\":\"/etc/shadow\""));
    EXPECT_TRUE(has_value(json, "\"name\":\"shadow\""));
    EXPECT_TRUE(has_value(json, "\"parent_folder\":\"/etc\""));

    // Forensic context lives under unmapped (preserved evidence).
    EXPECT_TRUE(has_value(json, "\"aegis_inode\":4242"));
    EXPECT_TRUE(has_value(json, "\"aegis_device\":99"));

    // The doc says hostname goes in device.
    EXPECT_TRUE(has_value(json, "\"hostname\":\"test-host\""));
}

TEST(OcsfFormatterTest, BlockEventAuditOnlyOmitsDispositionAndUsesAllowed)
{
    auto ev = make_block_event("/var/run/secrets", "AUDIT");
    auto json = format_block_event_ocsf(ev, "/sys/fs/cgroup/user.slice", "/var/run/secrets", "/var/run/secrets",
                                        "AUDIT", "evil-proc", "exec-1234", "exec-5678", "test-host");

    // In audit mode the action is Allowed and disposition is omitted.
    EXPECT_TRUE(has_value(json, "\"action_id\":1"));
    EXPECT_TRUE(has_value(json, "\"action\":\"Allowed\""));
    EXPECT_FALSE(has_value(json, "\"disposition_id\":"));
    // Severity drops to Low when the policy decision was just to log.
    EXPECT_TRUE(has_value(json, "\"severity_id\":2"));
}

TEST(OcsfFormatterTest, BlockEventFavorsResolvedPathOverRawPath)
{
    auto ev = make_block_event("relative.txt", "BLOCK");
    auto json = format_block_event_ocsf(ev, "", "relative.txt", "/abs/proj/relative.txt", "BLOCK", "evil-proc", "", "",
                                        "test-host");
    EXPECT_TRUE(has_value(json, "\"path\":\"/abs/proj/relative.txt\""));
    EXPECT_TRUE(has_value(json, "\"parent_folder\":\"/abs/proj\""));
    EXPECT_TRUE(has_value(json, "\"name\":\"relative.txt\""));
}

TEST(OcsfFormatterTest, BlockEventWithRootFile)
{
    auto ev = make_block_event("/passwd", "BLOCK");
    auto json = format_block_event_ocsf(ev, "", "/passwd", "/passwd", "BLOCK", "evil-proc", "", "", "test-host");
    EXPECT_TRUE(has_value(json, "\"name\":\"passwd\""));
    EXPECT_TRUE(has_value(json, "\"parent_folder\":\"/\""));
}

// -------- format_net_block_event_ocsf ----------------------------------

TEST(OcsfFormatterTest, NetEgressBlockMapsToNetworkActivityOpen)
{
    auto ev = make_net_block_event(0, "BLOCK"); // direction 0 = egress
    auto json = format_net_block_event_ocsf(ev, "/sys/fs/cgroup/system.slice", "curl", "exec-1111", "exec-2222",
                                            "net_connect_block", "127.0.0.1", "test-host");

    EXPECT_TRUE(has_value(json, "\"class_uid\":4001"));
    EXPECT_TRUE(has_value(json, "\"category_uid\":4"));
    EXPECT_TRUE(has_value(json, "\"activity_id\":1")); // Open
    EXPECT_TRUE(has_value(json, "\"type_uid\":400101"));
    EXPECT_TRUE(has_value(json, "\"action_id\":2"));      // Denied
    EXPECT_TRUE(has_value(json, "\"disposition_id\":2")); // Blocked
    EXPECT_TRUE(has_value(json, "\"severity_id\":4"));    // High

    // For egress, peer is the destination.
    EXPECT_TRUE(has_field(json, "dst_endpoint"));
    EXPECT_TRUE(has_value(json, "\"ip\":\"127.0.0.1\""));
    EXPECT_TRUE(has_value(json, "\"port\":4444"));

    // Connection info captures protocol.
    EXPECT_TRUE(has_value(json, "\"protocol_num\":6"));
    EXPECT_TRUE(has_value(json, "\"protocol_name\":\"tcp\""));
    EXPECT_TRUE(has_value(json, "\"protocol_ver_id\":4"));
}

TEST(OcsfFormatterTest, NetSendmsgBlockMapsToTrafficActivity)
{
    auto ev = make_net_block_event(4, "BLOCK"); // direction 4 = sendmsg
    auto json = format_net_block_event_ocsf(ev, "", "curl", "", "", "net_sendmsg_block", "127.0.0.1", "test-host");

    EXPECT_TRUE(has_value(json, "\"activity_id\":6")); // Traffic
    EXPECT_TRUE(has_value(json, "\"type_uid\":400106"));
    EXPECT_TRUE(has_value(json, "\"activity_name\":\"Traffic\""));
}

TEST(OcsfFormatterTest, NetAcceptBlockTreatsPeerAsSource)
{
    auto ev = make_net_block_event(3, "BLOCK"); // direction 3 = accept
    ev.local_port = 8080;
    auto json = format_net_block_event_ocsf(ev, "", "nginx", "", "", "net_accept_block", "10.0.0.5", "test-host");

    // Accepted connection: remote peer is the source, our local socket is dest.
    EXPECT_TRUE(has_field(json, "src_endpoint"));
    EXPECT_TRUE(has_value(json, "\"ip\":\"10.0.0.5\""));
    EXPECT_TRUE(has_field(json, "dst_endpoint"));
    EXPECT_TRUE(has_value(json, "\"port\":8080"));
}

TEST(OcsfFormatterTest, NetAuditOnlyOmitsDispositionAndUsesAllowed)
{
    auto ev = make_net_block_event(0, "AUDIT");
    auto json = format_net_block_event_ocsf(ev, "", "curl", "", "", "net_connect_block", "127.0.0.1", "test-host");
    EXPECT_TRUE(has_value(json, "\"action_id\":1"));
    EXPECT_TRUE(has_value(json, "\"action\":\"Allowed\""));
    EXPECT_FALSE(has_value(json, "\"disposition_id\":"));
    EXPECT_TRUE(has_value(json, "\"severity_id\":2"));
}

// -------- format_exec_event_ocsf ---------------------------------------

namespace {

ExecEvent make_exec_event(const char* comm_str)
{
    ExecEvent ev{};
    ev.pid = 9001;
    ev.ppid = 9000;
    ev.start_time = 1700000000000000000ULL;
    ev.cgid = 0xC0FFEEULL;
    std::strncpy(ev.comm, comm_str, sizeof(ev.comm) - 1);
    ev.ancestor_count = 2;
    ev.ancestor_pids[0] = 8000;
    ev.ancestor_pids[1] = 1;
    return ev;
}

ForensicEvent make_forensic_event(const char* comm_str, const char* action_str)
{
    ForensicEvent ev{};
    ev.pid = 7777;
    ev.ppid = 7776;
    ev.start_time = 1700000000000000000ULL;
    ev.parent_start_time = 1700000000000000000ULL - 2000000000ULL;
    ev.cgid = 0xBADF00DULL;
    ev.ino = 5151;
    ev.dev = 42;
    ev.uid = 1000;
    ev.gid = 1000;
    ev.exec_ino = 7373;
    ev.exec_dev = 42;
    ev.exec_stage = 2;
    ev.verified_exec = 1;
    ev.exec_identity_known = 1;
    std::strncpy(ev.comm, comm_str, sizeof(ev.comm) - 1);
    std::strncpy(ev.action, action_str, sizeof(ev.action) - 1);
    return ev;
}

} // namespace

TEST(OcsfFormatterTest, ExecEventMapsToProcessActivityLaunch)
{
    auto ev = make_exec_event("bash");
    auto json = format_exec_event_ocsf(ev, "/sys/fs/cgroup/user.slice", "bash", "exec-9001", "test-host");

    // Required Process Activity 1007 fields.
    EXPECT_TRUE(has_value(json, "\"class_uid\":1007"));
    EXPECT_TRUE(has_value(json, "\"category_uid\":1"));
    EXPECT_TRUE(has_value(json, "\"activity_id\":1")); // Launch
    EXPECT_TRUE(has_value(json, "\"type_uid\":100701"));
    EXPECT_TRUE(has_value(json, "\"action_id\":1"));   // Allowed (exec is observation)
    EXPECT_TRUE(has_value(json, "\"status_id\":1"));   // Success
    EXPECT_TRUE(has_value(json, "\"severity_id\":1")); // Informational

    // Exec is never a deny — disposition must be omitted.
    EXPECT_FALSE(has_value(json, "\"disposition_id\":"));

    // Required `process` object carries pid + name + parent.
    EXPECT_TRUE(has_field(json, "process"));
    EXPECT_TRUE(has_value(json, "\"pid\":9001"));
    EXPECT_TRUE(has_value(json, "\"name\":\"bash\""));
    EXPECT_TRUE(has_value(json, "\"parent_process\":{\"pid\":9000}"));

    // Top-level structure.
    EXPECT_TRUE(has_field(json, "metadata"));
    EXPECT_TRUE(has_field(json, "actor"));
    EXPECT_TRUE(has_field(json, "device"));
    EXPECT_TRUE(has_field(json, "unmapped"));

    // Ancestor lineage survives in unmapped.
    EXPECT_TRUE(has_value(json, "\"aegis_ancestors\":[8000,1]"));
    EXPECT_TRUE(has_value(json, "\"aegis_cgroup_id\":12648430"));
    EXPECT_TRUE(has_value(json, "\"hostname\":\"test-host\""));
}

TEST(OcsfFormatterTest, ExecEventOmitsParentWhenPpidZero)
{
    auto ev = make_exec_event("init");
    ev.ppid = 0;
    auto json = format_exec_event_ocsf(ev, "", "init", "exec-init", "test-host");
    EXPECT_FALSE(has_value(json, "\"parent_process\":"));
}

// -------- format_forensic_event_ocsf -----------------------------------

TEST(OcsfFormatterTest, ForensicEventEnforceMapsToProcessActivityDeniedLaunch)
{
    auto ev = make_forensic_event("malware", "BLOCK");
    auto json = format_forensic_event_ocsf(ev, "/sys/fs/cgroup/system.slice", "BLOCK", "malware", "exec-7777",
                                           "exec-7776", "test-host");

    EXPECT_TRUE(has_value(json, "\"class_uid\":1007"));
    EXPECT_TRUE(has_value(json, "\"category_uid\":1"));
    EXPECT_TRUE(has_value(json, "\"activity_id\":1"));    // Launch
    EXPECT_TRUE(has_value(json, "\"type_uid\":100701"));
    EXPECT_TRUE(has_value(json, "\"action_id\":2"));      // Denied
    EXPECT_TRUE(has_value(json, "\"disposition_id\":2")); // Blocked
    EXPECT_TRUE(has_value(json, "\"status_id\":1"));      // Success
    EXPECT_TRUE(has_value(json, "\"severity_id\":4"));    // High

    EXPECT_TRUE(has_field(json, "process"));
    EXPECT_TRUE(has_value(json, "\"pid\":7777"));
    EXPECT_TRUE(has_value(json, "\"name\":\"malware\""));
    EXPECT_TRUE(has_value(json, "\"parent_process\":{\"pid\":7776}"));

    // OCSF User/Group typing — uid is a String at the schema level.
    EXPECT_TRUE(has_value(json, "\"user\":{\"uid\":\"1000\"}"));
    EXPECT_TRUE(has_value(json, "\"group\":{\"uid\":\"1000\"}"));

    // Numeric duplicates plus all forensic-grade fields survive in unmapped.
    EXPECT_TRUE(has_value(json, "\"aegis_uid_int\":1000"));
    EXPECT_TRUE(has_value(json, "\"aegis_gid_int\":1000"));
    EXPECT_TRUE(has_value(json, "\"aegis_inode\":5151"));
    EXPECT_TRUE(has_value(json, "\"aegis_device\":42"));
    EXPECT_TRUE(has_value(json, "\"aegis_exec_inode\":7373"));
    EXPECT_TRUE(has_value(json, "\"aegis_exec_device\":42"));
    EXPECT_TRUE(has_value(json, "\"aegis_exec_stage\":2"));
    EXPECT_TRUE(has_value(json, "\"aegis_verified_exec\":true"));
    EXPECT_TRUE(has_value(json, "\"aegis_exec_identity_known\":true"));
    EXPECT_TRUE(has_value(json, "\"aegis_parent_exec_id\":\"exec-7776\""));
}

TEST(OcsfFormatterTest, ForensicEventAuditOmitsDispositionAndDowngradesSeverity)
{
    auto ev = make_forensic_event("noisy", "AUDIT");
    auto json = format_forensic_event_ocsf(ev, "", "AUDIT", "noisy", "exec-7777", "exec-7776", "test-host");

    EXPECT_TRUE(has_value(json, "\"action_id\":1"));
    EXPECT_TRUE(has_value(json, "\"action\":\"Allowed\""));
    EXPECT_FALSE(has_value(json, "\"disposition_id\":"));
    EXPECT_TRUE(has_value(json, "\"severity_id\":2")); // Low
}

TEST(OcsfFormatterTest, ForensicEventVerifiedExecFalseSerializesAsLiteralFalse)
{
    auto ev = make_forensic_event("unknown", "BLOCK");
    ev.verified_exec = 0;
    ev.exec_identity_known = 0;
    auto json = format_forensic_event_ocsf(ev, "", "BLOCK", "unknown", "", "", "test-host");
    EXPECT_TRUE(has_value(json, "\"aegis_verified_exec\":false"));
    EXPECT_TRUE(has_value(json, "\"aegis_exec_identity_known\":false"));
}

// -------- set_event_format / current_event_format ----------------------

TEST(OcsfFormatterTest, SetEventFormatAcceptsKnownKeywords)
{
    EventFormat saved = current_event_format();

    EXPECT_TRUE(set_event_format("aegis"));
    EXPECT_EQ(current_event_format(), EventFormat::Aegis);

    EXPECT_TRUE(set_event_format("ocsf"));
    EXPECT_EQ(current_event_format(), EventFormat::Ocsf);

    EXPECT_TRUE(set_event_format("OCSF"));
    EXPECT_EQ(current_event_format(), EventFormat::Ocsf);

    EXPECT_TRUE(set_event_format("ocsf-1.1.0"));
    EXPECT_EQ(current_event_format(), EventFormat::Ocsf);

    EXPECT_TRUE(set_event_format("default"));
    EXPECT_EQ(current_event_format(), EventFormat::Aegis);

    // Unknown values should fail and leave state unchanged.
    EXPECT_TRUE(set_event_format("aegis"));
    EXPECT_FALSE(set_event_format("not-a-format"));
    EXPECT_EQ(current_event_format(), EventFormat::Aegis);

    // Restore for downstream tests.
    if (saved == EventFormat::Aegis) {
        set_event_format("aegis");
    } else {
        set_event_format("ocsf");
    }
}

} // namespace aegis
