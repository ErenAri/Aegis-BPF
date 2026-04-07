// cppcheck-suppress-file missingIncludeSystem
#include "rule_engine.hpp"

#include <arpa/inet.h>
#include <fnmatch.h>

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

/* Extract a JSON array of strings: "key":["v1","v2"] */
std::vector<std::string> extract_json_string_array(const std::string& json, const std::string& key)
{
    std::vector<std::string> result;
    std::string search = "\"" + key + "\":[";
    auto pos = json.find(search);
    if (pos == std::string::npos)
        return result;
    pos += search.size();
    auto end = json.find(']', pos);
    if (end == std::string::npos)
        return result;
    std::string arr = json.substr(pos, end - pos);
    size_t p = 0;
    while ((p = arr.find('"', p)) != std::string::npos) {
        auto q = arr.find('"', p + 1);
        if (q == std::string::npos)
            break;
        result.push_back(arr.substr(p + 1, q - p - 1));
        p = q + 1;
    }
    return result;
}

uint32_t extract_json_uint(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos)
        return 0;
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;
    uint32_t val = 0;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        val = val * 10 + static_cast<uint32_t>(json[pos] - '0');
        ++pos;
    }
    return val;
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

RuleAction parse_action(const std::string& s)
{
    if (s == "block")
        return RuleAction::Block;
    if (s == "kill")
        return RuleAction::Kill;
    return RuleAction::Alert;
}

ConditionType parse_condition_type(const std::string& s)
{
    if (s == "match_comm" || s == "comm_exact")
        return ConditionType::CommExact;
    if (s == "comm_prefix")
        return ConditionType::CommPrefix;
    if (s == "match_path_glob" || s == "path_glob")
        return ConditionType::PathGlob;
    if (s == "match_path" || s == "path_prefix")
        return ConditionType::PathPrefix;
    if (s == "uid")
        return ConditionType::UidEquals;
    if (s == "gid")
        return ConditionType::GidEquals;
    if (s == "ancestor_comm")
        return ConditionType::AncestorComm;
    if (s == "cgroup_path")
        return ConditionType::CgroupPath;
    if (s == "port")
        return ConditionType::PortEquals;
    if (s == "ip")
        return ConditionType::IpEquals;
    return ConditionType::CommExact;
}

/* Parse conditions from a rule block.  Supports both legacy flat format
 * (match_comm, match_path) and new declarative condition keys. */
std::vector<RuleCondition> parse_conditions(const std::string& block)
{
    std::vector<RuleCondition> conditions;

    /* Legacy: match_comm -> CommExact condition */
    std::string match_comm = extract_json_string(block, "match_comm");
    if (!match_comm.empty()) {
        conditions.push_back({ConditionType::CommExact, match_comm, 0});
    }

    /* Legacy: match_path -> PathPrefix condition */
    std::string match_path = extract_json_string(block, "match_path");
    if (!match_path.empty()) {
        conditions.push_back({ConditionType::PathPrefix, match_path, 0});
    }

    /* New: declarative condition keys */
    static const char* condition_keys[] = {
        "comm_exact", "comm_prefix", "path_glob", "path_prefix", "ancestor_comm", "cgroup_path", "ip", nullptr,
    };
    for (int i = 0; condition_keys[i]; ++i) {
        std::string val = extract_json_string(block, condition_keys[i]);
        if (!val.empty()) {
            conditions.push_back({parse_condition_type(condition_keys[i]), val, 0});
        }
    }

    /* Numeric conditions */
    if (block.find("\"uid\":") != std::string::npos) {
        conditions.push_back({ConditionType::UidEquals, "", extract_json_uint(block, "uid")});
    }
    if (block.find("\"gid\":") != std::string::npos) {
        conditions.push_back({ConditionType::GidEquals, "", extract_json_uint(block, "gid")});
    }
    if (block.find("\"port\":") != std::string::npos) {
        conditions.push_back({ConditionType::PortEquals, "", extract_json_uint(block, "port")});
    }

    return conditions;
}

DetectionRule parse_rule_block(const std::string& block)
{
    DetectionRule rule;
    rule.id = extract_json_string(block, "id");
    rule.name = extract_json_string(block, "name");
    rule.description = extract_json_string(block, "description");
    rule.severity = parse_severity(extract_json_string(block, "severity"));
    rule.action = parse_action(extract_json_string(block, "action"));
    rule.mitre_tags = extract_json_string_array(block, "mitre");
    rule.conditions = parse_conditions(block);

    /* Build function-based matchers from conditions for backward compat
     * (only if no declarative conditions were parsed) */
    if (rule.conditions.empty()) {
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
    }

    rule.enabled = (extract_json_string(block, "enabled") != "false");
    return rule;
}

} // namespace

bool RuleEngine::glob_match(const std::string& pattern, const std::string& text)
{
    return fnmatch(pattern.c_str(), text.c_str(), FNM_PATHNAME) == 0;
}

bool RuleEngine::evaluate_condition_exec(const RuleCondition& cond, const ExecEvent& ev)
{
    std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    switch (cond.type) {
        case ConditionType::CommExact:
            return comm == cond.value;
        case ConditionType::CommPrefix:
            return comm.compare(0, cond.value.size(), cond.value) == 0;
        case ConditionType::AncestorComm:
            /* Ancestor comm matching requires userspace enrichment;
             * not available from raw BPF exec events (only PIDs). */
            return false;
        case ConditionType::PathGlob:
        case ConditionType::PathPrefix:
        case ConditionType::UidEquals:
        case ConditionType::GidEquals:
        case ConditionType::CgroupPath:
        case ConditionType::PortEquals:
        case ConditionType::IpEquals:
            return false;
    }
    return false;
}

bool RuleEngine::evaluate_condition_block(const RuleCondition& cond, const BlockEvent& ev)
{
    std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    std::string path(ev.path, strnlen(ev.path, sizeof(ev.path)));

    switch (cond.type) {
        case ConditionType::CommExact:
            return comm == cond.value;
        case ConditionType::CommPrefix:
            return comm.compare(0, cond.value.size(), cond.value) == 0;
        case ConditionType::PathGlob:
            return glob_match(cond.value, path);
        case ConditionType::PathPrefix:
            return path.find(cond.value) != std::string::npos;
        case ConditionType::AncestorComm:
        case ConditionType::CgroupPath:
        case ConditionType::UidEquals:
        case ConditionType::GidEquals:
        case ConditionType::PortEquals:
        case ConditionType::IpEquals:
            return false;
    }
    return false;
}

bool RuleEngine::evaluate_condition_net(const RuleCondition& cond, const NetBlockEvent& ev)
{
    std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));

    switch (cond.type) {
        case ConditionType::CommExact:
            return comm == cond.value;
        case ConditionType::CommPrefix:
            return comm.compare(0, cond.value.size(), cond.value) == 0;
        case ConditionType::PortEquals:
            return ev.remote_port == static_cast<uint16_t>(cond.numeric);
        case ConditionType::IpEquals: {
            if (ev.family == 2) { /* AF_INET */
                char buf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &ev.remote_ipv4, buf, sizeof(buf));
                return cond.value == buf;
            }
            return false;
        }
        case ConditionType::AncestorComm:
        case ConditionType::PathGlob:
        case ConditionType::PathPrefix:
        case ConditionType::CgroupPath:
        case ConditionType::UidEquals:
        case ConditionType::GidEquals:
            return false;
    }
    return false;
}

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
        if (!rule.enabled)
            continue;

        bool matched = false;

        /* Try declarative conditions first (AND — all must match) */
        if (!rule.conditions.empty()) {
            matched = true;
            for (const auto& cond : rule.conditions) {
                if (!evaluate_condition_exec(cond, ev)) {
                    matched = false;
                    break;
                }
            }
        } else if (rule.match_exec) {
            matched = rule.match_exec(ev);
        }

        if (matched) {
            struct timespec ts {};
            clock_gettime(CLOCK_REALTIME, &ts);
            matches.push_back({rule.id, rule.name, rule.severity, rule.description, static_cast<uint64_t>(ts.tv_sec),
                               rule.mitre_tags});
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
        if (!rule.enabled)
            continue;

        bool matched = false;

        if (!rule.conditions.empty()) {
            matched = true;
            for (const auto& cond : rule.conditions) {
                if (!evaluate_condition_block(cond, ev)) {
                    matched = false;
                    break;
                }
            }
        } else if (rule.match_block) {
            matched = rule.match_block(ev);
        }

        if (matched) {
            struct timespec ts {};
            clock_gettime(CLOCK_REALTIME, &ts);
            matches.push_back({rule.id, rule.name, rule.severity, rule.description, static_cast<uint64_t>(ts.tv_sec),
                               rule.mitre_tags});
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
        if (!rule.enabled)
            continue;

        bool matched = false;

        if (!rule.conditions.empty()) {
            matched = true;
            for (const auto& cond : rule.conditions) {
                if (!evaluate_condition_net(cond, ev)) {
                    matched = false;
                    break;
                }
            }
        } else if (rule.match_net_block) {
            matched = rule.match_net_block(ev);
        }

        if (matched) {
            struct timespec ts {};
            clock_gettime(CLOCK_REALTIME, &ts);
            matches.push_back({rule.id, rule.name, rule.severity, rule.description, static_cast<uint64_t>(ts.tv_sec),
                               rule.mitre_tags});
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
