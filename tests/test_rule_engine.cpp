// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>

#include <cstring>
#include <fstream>

#include "rule_engine.hpp"
#include "types.hpp"

using namespace aegis;

namespace {

ExecEvent make_exec_event(const char* comm, uint32_t pid = 1234, uint32_t ppid = 1)
{
    ExecEvent ev{};
    ev.pid = pid;
    ev.ppid = ppid;
    ev.start_time = 100;
    ev.cgid = 1;
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    ev.ancestor_count = 0;
    return ev;
}

BlockEvent make_block_event(const char* comm, const char* path)
{
    BlockEvent ev{};
    ev.pid = 1234;
    ev.ppid = 1;
    ev.start_time = 100;
    ev.cgid = 1;
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    std::strncpy(ev.path, path, sizeof(ev.path) - 1);
    return ev;
}

NetBlockEvent make_net_event(const char* comm, uint16_t port)
{
    NetBlockEvent ev{};
    ev.pid = 1234;
    ev.ppid = 1;
    ev.start_time = 100;
    ev.cgid = 1;
    ev.remote_port = port;
    ev.family = 2; /* AF_INET */
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    return ev;
}

} // namespace

/* =====================================================================
 * Declarative condition matching tests
 * ===================================================================== */

TEST(RuleEngineConditions, CommExactMatch)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "test-1";
    rule.name = "Detect curl";
    rule.severity = RuleSeverity::High;
    rule.conditions.push_back({ConditionType::CommExact, "curl", 0});
    engine.add_rule(std::move(rule));

    auto matches = engine.evaluate_exec(make_exec_event("curl"));
    ASSERT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].rule_id, "test-1");

    auto no_match = engine.evaluate_exec(make_exec_event("wget"));
    EXPECT_TRUE(no_match.empty());
}

TEST(RuleEngineConditions, CommPrefixMatch)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "test-2";
    rule.name = "Detect python variants";
    rule.severity = RuleSeverity::Medium;
    rule.conditions.push_back({ConditionType::CommPrefix, "python", 0});
    engine.add_rule(std::move(rule));

    EXPECT_EQ(engine.evaluate_exec(make_exec_event("python3")).size(), 1u);
    EXPECT_EQ(engine.evaluate_exec(make_exec_event("python")).size(), 1u);
    EXPECT_TRUE(engine.evaluate_exec(make_exec_event("ruby")).empty());
}

TEST(RuleEngineConditions, PathGlobMatch)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "test-3";
    rule.name = "Detect tmp writes";
    rule.severity = RuleSeverity::High;
    rule.conditions.push_back({ConditionType::PathGlob, "/tmp/*", 0});
    engine.add_rule(std::move(rule));

    auto matches = engine.evaluate_block(make_block_event("cat", "/tmp/malware"));
    EXPECT_EQ(matches.size(), 1u);

    auto no_match = engine.evaluate_block(make_block_event("cat", "/usr/bin/cat"));
    EXPECT_TRUE(no_match.empty());
}

TEST(RuleEngineConditions, PathPrefixMatch)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "test-4";
    rule.name = "Detect etc access";
    rule.severity = RuleSeverity::Medium;
    rule.conditions.push_back({ConditionType::PathPrefix, "/etc/", 0});
    engine.add_rule(std::move(rule));

    EXPECT_EQ(engine.evaluate_block(make_block_event("vi", "/etc/shadow")).size(), 1u);
    EXPECT_TRUE(engine.evaluate_block(make_block_event("vi", "/home/user/file")).empty());
}

TEST(RuleEngineConditions, ANDCompositionRequiresAllConditions)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "test-5";
    rule.name = "Curl accessing tmp";
    rule.severity = RuleSeverity::Critical;
    rule.conditions.push_back({ConditionType::CommExact, "curl", 0});
    rule.conditions.push_back({ConditionType::PathGlob, "/tmp/*", 0});
    engine.add_rule(std::move(rule));

    /* Both conditions met */
    EXPECT_EQ(engine.evaluate_block(make_block_event("curl", "/tmp/payload")).size(), 1u);
    /* Only comm matches */
    EXPECT_TRUE(engine.evaluate_block(make_block_event("curl", "/usr/bin/file")).empty());
    /* Only path matches */
    EXPECT_TRUE(engine.evaluate_block(make_block_event("wget", "/tmp/payload")).empty());
}

TEST(RuleEngineConditions, PortMatch)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "test-6";
    rule.name = "Block SSH";
    rule.severity = RuleSeverity::High;
    rule.conditions.push_back({ConditionType::PortEquals, "", 22});
    engine.add_rule(std::move(rule));

    EXPECT_EQ(engine.evaluate_net_block(make_net_event("ssh", 22)).size(), 1u);
    EXPECT_TRUE(engine.evaluate_net_block(make_net_event("ssh", 443)).empty());
}

/* =====================================================================
 * MITRE ATT&CK tag tests
 * ===================================================================== */

TEST(RuleEngineMitre, TagsIncludedInMatch)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "mitre-1";
    rule.name = "Shell execution";
    rule.severity = RuleSeverity::High;
    rule.mitre_tags = {"T1059.004", "T1071.001"};
    rule.conditions.push_back({ConditionType::CommExact, "bash", 0});
    engine.add_rule(std::move(rule));

    auto matches = engine.evaluate_exec(make_exec_event("bash"));
    ASSERT_EQ(matches.size(), 1u);
    ASSERT_EQ(matches[0].mitre_tags.size(), 2u);
    EXPECT_EQ(matches[0].mitre_tags[0], "T1059.004");
    EXPECT_EQ(matches[0].mitre_tags[1], "T1071.001");
}

/* =====================================================================
 * Rule action tests
 * ===================================================================== */

TEST(RuleEngineAction, DefaultIsAlert)
{
    DetectionRule rule;
    EXPECT_EQ(rule.action, RuleAction::Alert);
}

/* =====================================================================
 * JSON loading tests
 * ===================================================================== */

TEST(RuleEngineLoad, ParsesNewFormat)
{
    /* Write a temp rule file with the new format */
    std::string tmp_path = "/tmp/aegis_test_rules.json";
    {
        std::ofstream out(tmp_path);
        out << "[\n";
        out << "  {\"id\":\"r1\",\"name\":\"Curl detection\"," << "\"severity\":\"high\",\"action\":\"block\","
            << "\"mitre\":[\"T1071.001\"]," << "\"comm_exact\":\"curl\"}\n";
        out << "]\n";
    }

    RuleEngine engine;
    ASSERT_TRUE(engine.load_rules(tmp_path));
    EXPECT_EQ(engine.rule_count(), 1u);

    auto rules = engine.rules();
    EXPECT_EQ(rules[0].id, "r1");
    EXPECT_EQ(rules[0].action, RuleAction::Block);
    ASSERT_EQ(rules[0].mitre_tags.size(), 1u);
    EXPECT_EQ(rules[0].mitre_tags[0], "T1071.001");
    ASSERT_EQ(rules[0].conditions.size(), 1u);
    EXPECT_EQ(rules[0].conditions[0].type, ConditionType::CommExact);
    EXPECT_EQ(rules[0].conditions[0].value, "curl");

    std::remove(tmp_path.c_str());
}

TEST(RuleEngineLoad, BackwardCompatLegacyFormat)
{
    std::string tmp_path = "/tmp/aegis_test_rules_legacy.json";
    {
        std::ofstream out(tmp_path);
        out << "[{\"id\":\"legacy\",\"name\":\"Old rule\"," << "\"severity\":\"medium\",\"match_comm\":\"nmap\"}]\n";
    }

    RuleEngine engine;
    ASSERT_TRUE(engine.load_rules(tmp_path));
    EXPECT_EQ(engine.rule_count(), 1u);

    /* Legacy rules should have conditions parsed */
    auto rules = engine.rules();
    ASSERT_EQ(rules[0].conditions.size(), 1u);
    EXPECT_EQ(rules[0].conditions[0].type, ConditionType::CommExact);
    EXPECT_EQ(rules[0].conditions[0].value, "nmap");

    /* Should match via declarative engine */
    auto matches = engine.evaluate_exec(make_exec_event("nmap"));
    EXPECT_EQ(matches.size(), 1u);

    std::remove(tmp_path.c_str());
}

/* =====================================================================
 * Rule lifecycle tests
 * ===================================================================== */

TEST(RuleEngineLifecycle, AddAndRemove)
{
    RuleEngine engine;
    EXPECT_EQ(engine.rule_count(), 0u);

    DetectionRule r;
    r.id = "to-remove";
    r.name = "Temp rule";
    r.conditions.push_back({ConditionType::CommExact, "test", 0});
    engine.add_rule(std::move(r));
    EXPECT_EQ(engine.rule_count(), 1u);

    EXPECT_TRUE(engine.remove_rule("to-remove"));
    EXPECT_EQ(engine.rule_count(), 0u);
    EXPECT_FALSE(engine.remove_rule("nonexistent"));
}

TEST(RuleEngineLifecycle, DisabledRulesSkipped)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "disabled";
    rule.name = "Disabled rule";
    rule.enabled = false;
    rule.conditions.push_back({ConditionType::CommExact, "bash", 0});
    engine.add_rule(std::move(rule));

    EXPECT_TRUE(engine.evaluate_exec(make_exec_event("bash")).empty());
}

TEST(RuleEngineLifecycle, EvaluationCounters)
{
    RuleEngine engine;
    DetectionRule rule;
    rule.id = "counter";
    rule.name = "Counter rule";
    rule.conditions.push_back({ConditionType::CommExact, "ls", 0});
    engine.add_rule(std::move(rule));

    engine.evaluate_exec(make_exec_event("ls"));
    engine.evaluate_exec(make_exec_event("cat"));

    EXPECT_EQ(engine.total_evaluations(), 2u);
    EXPECT_EQ(engine.total_matches(), 1u);
}

/* =====================================================================
 * Struct layout tests
 * ===================================================================== */

TEST(StructLayout, ExecEventAncestryFields)
{
    ExecEvent ev{};
    ev.ancestor_count = 3;
    ev.ancestor_pids[0] = 100;
    ev.ancestor_pids[1] = 50;
    ev.ancestor_pids[2] = 10;

    EXPECT_EQ(ev.ancestor_count, 3);
    EXPECT_EQ(ev.ancestor_pids[0], 100u);
    EXPECT_EQ(ev.ancestor_pids[2], 10u);
    EXPECT_EQ(sizeof(ExecEvent), 80u);
}

TEST(StructLayout, OverlayCopyUpEventSize)
{
    EXPECT_EQ(sizeof(OverlayCopyUpEvent), 40u);
}

TEST(StructLayout, EventUnionContainsOverlay)
{
    Event ev{};
    ev.type = EVENT_OVERLAY_COPY_UP;
    ev.overlay_copy_up.pid = 42;
    ev.overlay_copy_up.cgid = 100;
    ev.overlay_copy_up.src_ino = 12345;
    ev.overlay_copy_up.src_dev = 678;
    ev.overlay_copy_up.deny_flags = 1;

    EXPECT_EQ(ev.overlay_copy_up.pid, 42u);
    EXPECT_EQ(ev.overlay_copy_up.src_ino, 12345u);
}
