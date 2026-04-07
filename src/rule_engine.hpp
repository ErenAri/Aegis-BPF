// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "types.hpp"

namespace aegis {

enum class RuleSeverity : uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
};

enum class RuleAction : uint8_t {
    Alert = 0, /* log + SIEM only */
    Block = 1, /* deny + log */
    Kill = 2,  /* SIGKILL + deny + log */
};

/* Condition types for the declarative rule engine.
 * Each condition evaluates a single attribute; rules compose
 * conditions with AND/OR logic. */
enum class ConditionType : uint8_t {
    CommExact,    /* exact match on process comm */
    CommPrefix,   /* prefix match (e.g. "python" matches "python3") */
    PathGlob,     /* fnmatch-style glob on file path */
    PathPrefix,   /* starts-with match on path */
    UidEquals,    /* numeric UID match */
    GidEquals,    /* numeric GID match */
    AncestorComm, /* match any ancestor by comm name */
    CgroupPath,   /* substring match on cgroup path */
    PortEquals,   /* match a network port */
    IpEquals,     /* match an IP address */
};

struct RuleCondition {
    ConditionType type;
    std::string value;    /* string value for pattern/match */
    uint32_t numeric = 0; /* numeric value for uid/gid/port */
};

struct RuleMatch {
    std::string rule_id;
    std::string rule_name;
    RuleSeverity severity;
    std::string description;
    uint64_t timestamp;
    std::vector<std::string> mitre_tags; /* MITRE ATT&CK technique IDs */
};

struct DetectionRule {
    std::string id;
    std::string name;
    std::string description;
    RuleSeverity severity = RuleSeverity::Medium;
    RuleAction action = RuleAction::Alert;
    bool enabled = true;

    /* MITRE ATT&CK technique IDs (e.g. "T1059.004", "T1071.001") */
    std::vector<std::string> mitre_tags;

    /* Declarative conditions — evaluated with AND (all must match).
     * For OR logic, create separate rules with the same id prefix. */
    std::vector<RuleCondition> conditions;

    /* Legacy function-based matchers (backward compatible) */
    std::function<bool(const ExecEvent&)> match_exec;
    std::function<bool(const BlockEvent&)> match_block;
    std::function<bool(const NetBlockEvent&)> match_net_block;
};

class RuleEngine {
  public:
    RuleEngine() = default;

    bool load_rules(const std::string& path);
    bool reload_rules(const std::string& path);
    void add_rule(DetectionRule rule);
    bool remove_rule(const std::string& id);

    std::vector<RuleMatch> evaluate_exec(const ExecEvent& ev);
    std::vector<RuleMatch> evaluate_block(const BlockEvent& ev);
    std::vector<RuleMatch> evaluate_net_block(const NetBlockEvent& ev);

    [[nodiscard]] std::vector<DetectionRule> rules() const;
    [[nodiscard]] size_t rule_count() const;

    [[nodiscard]] uint64_t total_evaluations() const { return total_evals_; }
    [[nodiscard]] uint64_t total_matches() const { return total_matches_; }

  private:
    mutable std::mutex mu_;
    std::vector<DetectionRule> rules_;
    uint64_t total_evals_ = 0;
    uint64_t total_matches_ = 0;

    static bool evaluate_condition_exec(const RuleCondition& cond, const ExecEvent& ev);
    static bool evaluate_condition_block(const RuleCondition& cond, const BlockEvent& ev);
    static bool evaluate_condition_net(const RuleCondition& cond, const NetBlockEvent& ev);
    static bool glob_match(const std::string& pattern, const std::string& text);
};

} // namespace aegis
