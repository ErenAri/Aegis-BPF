// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include <string>

#include "commands_simulate.hpp"
#include "policy.hpp"

namespace aegis {
namespace {

Policy build_policy(const std::vector<std::string>& deny_paths, const std::vector<std::string>& allow_cgroup_paths,
                    const std::vector<uint64_t>& allow_cgroup_ids = {})
{
    Policy p{};
    p.deny_paths = deny_paths;
    p.allow_cgroup_paths = allow_cgroup_paths;
    p.allow_cgroup_ids = allow_cgroup_ids;
    return p;
}

std::string make_block_event(const std::string& path, const std::string& cgroup_path = std::string(),
                             uint64_t cgid = 0)
{
    std::ostringstream oss;
    oss << "{\"type\":\"block\",\"path\":\"" << path << "\"";
    if (!cgroup_path.empty()) {
        oss << ",\"cgroup_path\":\"" << cgroup_path << "\",\"cgid\":" << cgid;
    }
    oss << ",\"action\":\"AUDIT\"}";
    return oss.str();
}

TEST(SimulateOneEvent, DenyPathMatchCountedAsWouldBlock)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev = make_block_event("/etc/shadow");

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.block_events, 1u);
    EXPECT_EQ(summary.would_block, 1u);
    EXPECT_EQ(summary.would_block_path, 1u);
    EXPECT_EQ(summary.would_block_inode, 0u);
    EXPECT_EQ(summary.would_allow, 0u);
    EXPECT_EQ(summary.no_match, 0u);
    EXPECT_EQ(rec.simulated_rule, "deny_path");
    EXPECT_TRUE(rec.deny_path_match);
    EXPECT_FALSE(rec.allow_match);
}

TEST(SimulateOneEvent, AllowCgroupPathOverridesDenyPath)
{
    const Policy policy = build_policy({"/etc/shadow"}, {"/system.slice/aegisbpfd.service"});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev = make_block_event("/etc/shadow", "/system.slice/aegisbpfd.service", 4242);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.would_allow, 1u);
    EXPECT_EQ(summary.would_block, 0u);
    EXPECT_EQ(rec.simulated_rule, "allow_cgroup");
    EXPECT_TRUE(rec.allow_match);
    // Allow takes precedence in the inferred-rule classification, but the
    // raw deny-path match flag should still be visible to operators
    // looking at per-event detail.
    EXPECT_TRUE(rec.deny_path_match);
}

TEST(SimulateOneEvent, AllowCgroupIdMatchesNumericCgid)
{
    const Policy policy = build_policy({"/etc/shadow"}, {}, {4242});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev = make_block_event("/etc/shadow", "/some/path", 4242);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.would_allow, 1u);
    EXPECT_EQ(rec.simulated_rule, "allow_cgroup");
}

TEST(SimulateOneEvent, NoMatchCounted)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    const std::string ev = make_block_event("/tmp/unrelated");

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr));
    EXPECT_EQ(summary.no_match, 1u);
    EXPECT_EQ(summary.would_block, 0u);
}

TEST(SimulateOneEvent, ResolvedPathFallsBackWhenRawPathMissesDenyList)
{
    // The agent emits `path` as the raw user-provided path and
    // `resolved_path` as the post-symlink resolution. A deny rule
    // targeting the resolved path must still match.
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    SimulateRecord rec{};
    const std::string ev =
        R"({"type":"block","path":"/etc/sh","resolved_path":"/etc/shadow","action":"AUDIT"})";

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, &rec));
    EXPECT_EQ(summary.would_block, 1u);
    EXPECT_EQ(rec.simulated_rule, "deny_path");
}

TEST(SimulateOneEvent, NonBlockEventSkipped)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};
    const std::string ev = R"({"type":"exec","path":"/etc/shadow","action":"AUDIT"})";

    EXPECT_FALSE(simulate_one_event(ev, policy, summary, nullptr));
    EXPECT_EQ(summary.skipped_non_block, 1u);
    EXPECT_EQ(summary.block_events, 0u);
}

TEST(SimulateOneEvent, NonJsonLineSkipped)
{
    const Policy policy = build_policy({"/etc/shadow"}, {});
    SimulateSummary summary{};

    EXPECT_FALSE(simulate_one_event("not json", policy, summary, nullptr));
    EXPECT_EQ(summary.skipped_non_json, 1u);
    EXPECT_EQ(summary.block_events, 0u);
}

TEST(SimulateOneEvent, EmptyLineSkippedAsNonJson)
{
    const Policy policy = build_policy({}, {});
    SimulateSummary summary{};

    EXPECT_FALSE(simulate_one_event("", policy, summary, nullptr));
    EXPECT_EQ(summary.skipped_non_json, 1u);
}

TEST(SimulateOneEvent, MalformedJsonMissingTypeIsParseError)
{
    const Policy policy = build_policy({}, {});
    SimulateSummary summary{};

    EXPECT_FALSE(simulate_one_event(R"({"path":"/etc/shadow"})", policy, summary, nullptr));
    EXPECT_EQ(summary.parse_errors, 1u);
    EXPECT_EQ(summary.skipped_non_json, 0u);
}

TEST(SimulateOneEvent, CountersPartitionBlockEvents)
{
    const Policy policy = build_policy({"/etc/shadow"}, {"/system.slice/agent.service"});
    SimulateSummary summary{};

    simulate_one_event(make_block_event("/etc/shadow"), policy, summary, nullptr);                 // would_block
    simulate_one_event(make_block_event("/etc/shadow", "/system.slice/agent.service", 1), policy,
                       summary, nullptr);                                                          // would_allow
    simulate_one_event(make_block_event("/tmp/x"), policy, summary, nullptr);                      // no_match
    simulate_one_event(R"({"type":"exec"})", policy, summary, nullptr);                            // skipped_non_block
    simulate_one_event("garbage", policy, summary, nullptr);                                       // skipped_non_json

    EXPECT_EQ(summary.total_lines, 5u);
    EXPECT_EQ(summary.block_events, 3u);
    // The four counters MUST partition block_events exactly. This is the
    // guarantee documented in `SimulateSummary` and the property
    // operators rely on when reading the dry-run report.
    EXPECT_EQ(summary.would_block + summary.would_allow + summary.no_match, summary.block_events);
}

// -- Network event simulation --------------------------------------------

Policy build_net_policy_with_ips(const std::vector<std::string>& deny_ips)
{
    Policy p{};
    p.network.deny_ips = deny_ips;
    p.network.enabled = true;
    return p;
}

Policy build_net_policy_with_cidrs(const std::vector<std::string>& deny_cidrs)
{
    Policy p{};
    p.network.deny_cidrs = deny_cidrs;
    p.network.enabled = true;
    return p;
}

Policy build_net_policy_with_ports(std::vector<PortRule> deny_ports)
{
    Policy p{};
    p.network.deny_ports = std::move(deny_ports);
    p.network.enabled = true;
    return p;
}

Policy build_net_policy_with_ip_ports(std::vector<IpPortRule> rules)
{
    Policy p{};
    p.network.deny_ip_ports = std::move(rules);
    p.network.enabled = true;
    return p;
}

std::string make_net_connect_event(const std::string& remote_ip, uint16_t remote_port, const std::string& protocol = "tcp",
                                   const std::string& family = "ipv4", const std::string& cgroup_path = std::string(),
                                   uint64_t cgid = 0)
{
    std::ostringstream oss;
    oss << R"({"type":"net_connect_block","family":")" << family << R"(","protocol":")" << protocol
        << R"(","direction":"egress","remote_ip":")" << remote_ip << R"(","remote_port":)" << remote_port
        << R"(,"rule_type":"ip","action":"AUDIT")";
    if (!cgroup_path.empty()) {
        oss << R"(,"cgroup_path":")" << cgroup_path << R"(","cgid":)" << cgid;
    }
    oss << "}";
    return oss.str();
}

std::string make_net_bind_event(uint16_t local_port, const std::string& protocol = "tcp",
                                const std::string& family = "ipv4")
{
    std::ostringstream oss;
    oss << R"({"type":"net_bind_block","family":")" << family << R"(","protocol":")" << protocol
        << R"(","direction":"bind","local_port":)" << local_port << R"(,"rule_type":"port","action":"AUDIT"})";
    return oss.str();
}

TEST(SimulateNetEvent, DenyIpv4ExactMatchCounted)
{
    const Policy policy = build_net_policy_with_ips({"203.0.113.5"});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("203.0.113.5", 443);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_block_events, 1u);
    EXPECT_EQ(summary.net_would_block, 1u);
    EXPECT_EQ(summary.net_would_block_ip, 1u);
    EXPECT_EQ(summary.net_would_allow, 0u);
    EXPECT_EQ(summary.net_no_match, 0u);
    EXPECT_TRUE(rec.deny_ip_match);
    EXPECT_FALSE(rec.deny_cidr_match);
    EXPECT_EQ(rec.simulated_rule, "deny_ip");
}

TEST(SimulateNetEvent, DenyIpv6ExactMatchCounted)
{
    const Policy policy = build_net_policy_with_ips({"2001:db8::1"});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("2001:db8::1", 8080, "tcp", "ipv6");

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_block, 1u);
    EXPECT_EQ(summary.net_would_block_ip, 1u);
    EXPECT_EQ(rec.simulated_rule, "deny_ip");
}

TEST(SimulateNetEvent, DenyCidrIpv4MatchesContainedAddress)
{
    const Policy policy = build_net_policy_with_cidrs({"10.0.0.0/8"});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("10.42.7.99", 443);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_block, 1u);
    EXPECT_EQ(summary.net_would_block_cidr, 1u);
    EXPECT_TRUE(rec.deny_cidr_match);
    EXPECT_EQ(rec.simulated_rule, "deny_cidr");
}

TEST(SimulateNetEvent, DenyCidrIpv4DoesNotMatchOutsideRange)
{
    const Policy policy = build_net_policy_with_cidrs({"10.0.0.0/8"});
    SimulateSummary summary{};
    const std::string ev = make_net_connect_event("192.168.1.1", 443);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, nullptr));
    EXPECT_EQ(summary.net_block_events, 1u);
    EXPECT_EQ(summary.net_no_match, 1u);
    EXPECT_EQ(summary.net_would_block, 0u);
}

TEST(SimulateNetEvent, DenyCidrIpv6MatchesContainedAddress)
{
    const Policy policy = build_net_policy_with_cidrs({"2001:db8::/32"});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("2001:db8:abcd::1", 443, "tcp", "ipv6");

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_block_cidr, 1u);
    EXPECT_TRUE(rec.deny_cidr_match);
}

TEST(SimulateNetEvent, DenyPortEgressMatchesRemotePort)
{
    PortRule rule{};
    rule.port = 6379;
    rule.protocol = 6; // tcp
    rule.direction = 0; // egress
    const Policy policy = build_net_policy_with_ports({rule});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("203.0.113.9", 6379);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_block_port, 1u);
    EXPECT_TRUE(rec.deny_port_match);
    EXPECT_EQ(rec.simulated_rule, "deny_port");
}

TEST(SimulateNetEvent, DenyPortBindMatchesLocalPort)
{
    PortRule rule{};
    rule.port = 9000;
    rule.protocol = 0;  // any protocol
    rule.direction = 1; // bind
    const Policy policy = build_net_policy_with_ports({rule});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_bind_event(9000);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_block_port, 1u);
    EXPECT_TRUE(rec.deny_port_match);
}

TEST(SimulateNetEvent, DenyPortBothDirectionMatchesEgressEvent)
{
    PortRule rule{};
    rule.port = 22;
    rule.protocol = 6; // tcp
    rule.direction = 2; // both
    const Policy policy = build_net_policy_with_ports({rule});
    SimulateSummary summary{};

    EXPECT_TRUE(simulate_one_event(make_net_connect_event("198.51.100.7", 22), policy, summary, nullptr, nullptr));
    EXPECT_EQ(summary.net_would_block_port, 1u);
}

TEST(SimulateNetEvent, DenyPortDirectionMismatchDoesNotBlock)
{
    /* Bind-only rule must NOT fire on egress event. Mirrors BPF semantics
     * where port_rule_matches() is direction-aware. */
    PortRule rule{};
    rule.port = 6379;
    rule.protocol = 0;
    rule.direction = 1; // bind only
    const Policy policy = build_net_policy_with_ports({rule});
    SimulateSummary summary{};

    EXPECT_TRUE(simulate_one_event(make_net_connect_event("203.0.113.9", 6379), policy, summary, nullptr, nullptr));
    EXPECT_EQ(summary.net_would_block, 0u);
    EXPECT_EQ(summary.net_no_match, 1u);
}

TEST(SimulateNetEvent, DenyIpPortExactTupleMatch)
{
    IpPortRule rule{};
    rule.ip = "203.0.113.9";
    rule.port = 6379;
    rule.protocol = 6; // tcp
    const Policy policy = build_net_policy_with_ip_ports({rule});
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("203.0.113.9", 6379);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_block_ip_port, 1u);
    EXPECT_TRUE(rec.deny_ip_port_match);
    EXPECT_EQ(rec.simulated_rule, "deny_ip_port");
}

TEST(SimulateNetEvent, AllowCgroupOverridesNetDeny)
{
    Policy policy = build_net_policy_with_ips({"203.0.113.5"});
    policy.allow_cgroup_paths.push_back("/system.slice/aegisbpfd.service");
    SimulateSummary summary{};
    SimulateNetRecord rec{};
    const std::string ev = make_net_connect_event("203.0.113.5", 443, "tcp", "ipv4",
                                                   "/system.slice/aegisbpfd.service", 4242);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, &rec));
    EXPECT_EQ(summary.net_would_allow, 1u);
    EXPECT_EQ(summary.net_would_block, 0u);
    EXPECT_TRUE(rec.allow_match);
    EXPECT_EQ(rec.simulated_rule, "allow_cgroup");
}

TEST(SimulateNetEvent, NoMatchCounted)
{
    const Policy policy = build_net_policy_with_ips({"198.51.100.1"});
    SimulateSummary summary{};
    const std::string ev = make_net_connect_event("203.0.113.99", 443);

    EXPECT_TRUE(simulate_one_event(ev, policy, summary, nullptr, nullptr));
    EXPECT_EQ(summary.net_block_events, 1u);
    EXPECT_EQ(summary.net_no_match, 1u);
    EXPECT_EQ(summary.net_would_block, 0u);
}

TEST(SimulateNetEvent, FileAndNetEventsTrackedIndependently)
{
    /* Mixed stream with one file block and one net block. The two
     * partition invariants must both hold simultaneously and the file-
     * event counters must not absorb net events (or vice versa). */
    Policy policy{};
    policy.deny_paths = {"/etc/shadow"};
    policy.network.deny_ips = {"203.0.113.5"};
    policy.network.enabled = true;
    SimulateSummary summary{};

    simulate_one_event(make_block_event("/etc/shadow"), policy, summary, nullptr);
    simulate_one_event(make_net_connect_event("203.0.113.5", 443), policy, summary, nullptr, nullptr);
    simulate_one_event(make_block_event("/tmp/x"), policy, summary, nullptr);
    simulate_one_event(make_net_connect_event("198.51.100.1", 443), policy, summary, nullptr, nullptr);

    EXPECT_EQ(summary.block_events, 2u);
    EXPECT_EQ(summary.net_block_events, 2u);
    EXPECT_EQ(summary.would_block + summary.would_allow + summary.no_match, summary.block_events);
    EXPECT_EQ(summary.net_would_block + summary.net_would_allow + summary.net_no_match, summary.net_block_events);
    EXPECT_EQ(summary.would_block, 1u);
    EXPECT_EQ(summary.no_match, 1u);
    EXPECT_EQ(summary.net_would_block, 1u);
    EXPECT_EQ(summary.net_no_match, 1u);
}

TEST(SimulateNetEvent, AnyProtocolRuleMatchesUdpEvent)
{
    /* Rule with protocol=0 (any) must match a UDP event the same way the
     * BPF lookup falls back from (port,proto,dir) → (port,0,dir). */
    PortRule rule{};
    rule.port = 53;
    rule.protocol = 0;
    rule.direction = 0;
    const Policy policy = build_net_policy_with_ports({rule});
    SimulateSummary summary{};

    EXPECT_TRUE(simulate_one_event(make_net_connect_event("203.0.113.9", 53, "udp"), policy, summary, nullptr, nullptr));
    EXPECT_EQ(summary.net_would_block_port, 1u);
}

} // namespace
} // namespace aegis
