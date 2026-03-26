// cppcheck-suppress-file missingIncludeSystem
#include "rule_engine.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include "logging.hpp"

namespace aegis {

namespace {

std::string extract_json_string(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\":\"";
    auto pos = json.find(search);
    if (pos == std::string::npos)
        return "";
    pos += search.size();
    auto end = json.find('"', pos);
    if (end == std::string::npos)
        return "";
    return json.substr(pos, end - pos);
}

RuleSeverity parse_severity(const std::string& s)
{
    if (s == "critical")
        return RuleSeverity::Critical;
    if (s == "high")
        return RuleSeverity::High;
    if (s == "medium")
        return RuleSeverity::Medium;
    if (s == "low")
        return RuleSeverity::Low;
    return RuleSeverity::Info;
}

DetectionRule parse_rule_block(const std::string& block)
{
    DetectionRule rule;
    rule.id = extract_json_string(block, "id");
    rule.name = extract_json_string(block, "name");
    rule.description = extract_json_string(block, "description");
    rule.severity = parse_severity(extract_json_string(block, "severity"));

    std::string match_comm = extract_json_string(block, "match_comm");
    std::string match_path = extract_json_string(block, "match_path");

    if (!match_comm.empty()) {
        rule.match_exec = [match_comm](const ExecEvent& ev) -> bool {
            return std::strncmp(ev.comm, match_comm.c_str(), sizeof(ev.comm)) == 0;
        };
        rule.match_block = [match_comm](const BlockEvent& ev) -> bool {
            return std::strncmp(ev.comm, match_comm.c_str(), sizeof(ev.comm)) == 0;
        };
    }

    if (!match_path.empty()) {
        rule.match_block = [match_path](const BlockEvent& ev) -> bool {
            std::string path(ev.path, strnlen(ev.path, sizeof(ev.path)));
            return path.find(match_path) != std::string::npos;
        };
    }

    rule.enabled = (extract_json_string(block, "enabled") != "false");
    return rule;
}

} // namespace

bool RuleEngine::load_rules(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open()) {
        logger().log(SLOG_WARN("Failed to open rules file").field("path", path));
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    std::vector<DetectionRule> new_rules;
    size_t pos = 0;
    while ((pos = content.find('{', pos)) != std::string::npos) {
        auto end = content.find('}', pos);
        if (end == std::string::npos)
            break;
        std::string block = content.substr(pos, end - pos + 1);
        if (block.find("\"id\"") != std::string::npos) {
            auto rule = parse_rule_block(block);
            if (!rule.id.empty()) {
                new_rules.push_back(std::move(rule));
            }
        }
        pos = end + 1;
    }

    std::lock_guard<std::mutex> lock(mu_);
    rules_ = std::move(new_rules);

    logger().log(
        SLOG_INFO("Detection rules loaded").field("path", path).field("count", static_cast<int64_t>(rules_.size())));
    return true;
}

bool RuleEngine::reload_rules(const std::string& path)
{
    return load_rules(path);
}

void RuleEngine::add_rule(DetectionRule rule)
{
    std::lock_guard<std::mutex> lock(mu_);
    rules_.push_back(std::move(rule));
}

bool RuleEngine::remove_rule(const std::string& id)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = std::remove_if(rules_.begin(), rules_.end(), [&id](const DetectionRule& r) { return r.id == id; });
    if (it == rules_.end())
        return false;
    rules_.erase(it, rules_.end());
    return true;
}

std::vector<RuleMatch> RuleEngine::evaluate_exec(const ExecEvent& ev)
{
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<RuleMatch> matches;
    total_evals_++;

    for (const auto& rule : rules_) {
        if (!rule.enabled || !rule.match_exec)
            continue;
        if (rule.match_exec(ev)) {
            struct timespec ts {};
            clock_gettime(CLOCK_REALTIME, &ts);
            matches.push_back({rule.id, rule.name, rule.severity, rule.description, static_cast<uint64_t>(ts.tv_sec)});
            total_matches_++;
        }
    }
    return matches;
}

std::vector<RuleMatch> RuleEngine::evaluate_block(const BlockEvent& ev)
{
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<RuleMatch> matches;
    total_evals_++;

    for (const auto& rule : rules_) {
        if (!rule.enabled || !rule.match_block)
            continue;
        if (rule.match_block(ev)) {
            struct timespec ts {};
            clock_gettime(CLOCK_REALTIME, &ts);
            matches.push_back({rule.id, rule.name, rule.severity, rule.description, static_cast<uint64_t>(ts.tv_sec)});
            total_matches_++;
        }
    }
    return matches;
}

std::vector<RuleMatch> RuleEngine::evaluate_net_block(const NetBlockEvent& ev)
{
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<RuleMatch> matches;
    total_evals_++;

    for (const auto& rule : rules_) {
        if (!rule.enabled || !rule.match_net_block)
            continue;
        if (rule.match_net_block(ev)) {
            struct timespec ts {};
            clock_gettime(CLOCK_REALTIME, &ts);
            matches.push_back({rule.id, rule.name, rule.severity, rule.description, static_cast<uint64_t>(ts.tv_sec)});
            total_matches_++;
        }
    }
    return matches;
}

std::vector<DetectionRule> RuleEngine::rules() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return rules_;
}

size_t RuleEngine::rule_count() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return rules_.size();
}

} // namespace aegis
