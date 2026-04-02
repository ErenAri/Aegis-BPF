// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <functional>
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

struct RuleMatch {
    std::string rule_id;
    std::string rule_name;
    RuleSeverity severity;
    std::string description;
    uint64_t timestamp;
};

struct DetectionRule {
    std::string id;
    std::string name;
    std::string description;
    RuleSeverity severity = RuleSeverity::Medium;
    bool enabled = true;

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
};

} // namespace aegis
