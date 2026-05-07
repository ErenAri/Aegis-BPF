// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Explain command implementation
 */

#include "commands_explain.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "json_scan.hpp"
#include "logging.hpp"
#include "policy.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

std::string read_stream(std::istream& in)
{
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

} // namespace

bool parse_explain_event(const std::string& json, ExplainEvent& out, std::string& error)
{
    if (!json_scan::extract_string(json, "type", out.type)) {
        error = "Event JSON missing required 'type' field";
        return false;
    }
    json_scan::extract_string(json, "path", out.path);
    json_scan::extract_string(json, "resolved_path", out.resolved_path);
    json_scan::extract_string(json, "cgroup_path", out.cgroup_path);
    json_scan::extract_string(json, "action", out.action);

    uint64_t value = 0;
    if (json_scan::extract_uint64(json, "ino", value)) {
        out.ino = value;
        out.has_ino = true;
    }
    if (json_scan::extract_uint64(json, "dev", value)) {
        out.dev = value;
        out.has_dev = true;
    }
    if (json_scan::extract_uint64(json, "cgid", value)) {
        out.cgid = value;
        out.has_cgid = true;
    }
    return true;
}

ExplainResult evaluate_event_against_policy(const ExplainEvent& event, const Policy& policy)
{
    ExplainResult result;

    if (event.has_cgid) {
        for (uint64_t id : policy.allow_cgroup_ids) {
            if (id == event.cgid) {
                result.allow_match = true;
                break;
            }
        }
    }
    if (!result.allow_match && !event.cgroup_path.empty()) {
        for (const auto& path : policy.allow_cgroup_paths) {
            if (path == event.cgroup_path) {
                result.allow_match = true;
                break;
            }
        }
    }

    if (event.has_ino && event.has_dev && event.dev <= UINT32_MAX) {
        InodeId id{event.ino, static_cast<uint32_t>(event.dev), 0};
        for (const auto& deny : policy.deny_inodes) {
            if (deny == id) {
                result.deny_inode_match = true;
                break;
            }
        }
    }

    if (!event.path.empty()) {
        for (const auto& deny : policy.deny_paths) {
            if (deny == event.path) {
                result.deny_path_match = true;
                break;
            }
        }
    }
    if (!result.deny_path_match && !event.resolved_path.empty()) {
        for (const auto& deny : policy.deny_paths) {
            if (deny == event.resolved_path) {
                result.deny_path_match = true;
                break;
            }
        }
    }

    if (result.allow_match) {
        result.inferred_rule = "allow_cgroup";
    } else if (result.deny_inode_match) {
        result.inferred_rule = "deny_inode";
    } else if (result.deny_path_match) {
        result.inferred_rule = "deny_path";
    } else {
        result.inferred_rule = "no_policy_match";
    }
    return result;
}

int cmd_explain(const std::string& event_path, const std::string& policy_path, bool json_output)
{
    std::string payload;
    if (event_path == "-") {
        payload = read_stream(std::cin);
    } else {
        std::ifstream in(event_path);
        if (!in.is_open()) {
            logger().log(SLOG_ERROR("Failed to open event file").field("path", event_path).error_code(errno));
            return 1;
        }
        payload = read_stream(in);
    }

    ExplainEvent event{};
    std::string parse_error;
    if (!parse_explain_event(payload, event, parse_error)) {
        logger().log(SLOG_ERROR("Failed to parse event JSON").field("error", parse_error));
        return 1;
    }

    if (event.type != "block") {
        logger().log(SLOG_ERROR("Explain currently supports block events only").field("type", event.type));
        return 1;
    }

    std::string policy_source = policy_path;
    if (policy_source.empty() && std::filesystem::exists(kPolicyAppliedPath)) {
        policy_source = kPolicyAppliedPath;
    }

    Policy policy{};
    bool policy_loaded = false;
    if (!policy_source.empty()) {
        PolicyIssues issues{};
        auto policy_result = parse_policy_file(policy_source, issues);
        report_policy_issues(issues);
        if (!policy_result) {
            logger().log(SLOG_ERROR("Failed to parse policy for explain")
                             .field("path", policy_source)
                             .field("error", policy_result.error().to_string()));
            return 1;
        }
        if (issues.has_errors()) {
            logger().log(SLOG_ERROR("Policy contains errors; cannot explain decision").field("path", policy_source));
            return 1;
        }
        policy = *policy_result;
        policy_loaded = true;
    }

    ExplainResult eval{};
    if (policy_loaded) {
        eval = evaluate_event_against_policy(event, policy);
    }
    const bool allow_match = eval.allow_match;
    const bool deny_inode_match = eval.deny_inode_match;
    const bool deny_path_match = eval.deny_path_match;
    const std::string inferred_rule = policy_loaded ? eval.inferred_rule : std::string("unknown");

    std::vector<std::string> notes;
    notes.emplace_back("Best-effort: evaluation uses provided policy and event fields.");
    notes.emplace_back("Inode-first enforcement: inode deny decisions override path matches.");
    if (!policy_loaded) {
        notes.emplace_back("No policy loaded; provide --policy or ensure an applied policy is present.");
    }
    if (!event.has_ino || !event.has_dev) {
        notes.emplace_back("Event missing inode/dev; inode match not evaluated.");
    }
    if (allow_match && !event.action.empty() && event.action != "AUDIT") {
        notes.emplace_back("Allowlist matched but event was blocked; policy may have changed.");
    }

    if (json_output) {
        std::ostringstream out;
        out << "{" << "\"type\":\"" << json_escape(event.type) << "\"";
        if (!event.action.empty()) {
            out << ",\"action\":\"" << json_escape(event.action) << "\"";
        }
        if (!event.path.empty()) {
            out << ",\"path\":\"" << json_escape(event.path) << "\"";
        }
        if (!event.resolved_path.empty()) {
            out << ",\"resolved_path\":\"" << json_escape(event.resolved_path) << "\"";
        }
        if (event.has_ino) {
            out << ",\"ino\":" << event.ino;
        }
        if (event.has_dev) {
            out << ",\"dev\":" << event.dev;
        }
        if (!event.cgroup_path.empty()) {
            out << ",\"cgroup_path\":\"" << json_escape(event.cgroup_path) << "\"";
        }
        if (event.has_cgid) {
            out << ",\"cgid\":" << event.cgid;
        }
        out << ",\"policy\":{\"path\":\"" << json_escape(policy_source)
            << "\",\"loaded\":" << (policy_loaded ? "true" : "false") << "}";
        out << ",\"matches\":{" << "\"allow_cgroup\":" << (policy_loaded ? (allow_match ? "true" : "false") : "false")
            << ",\"deny_inode\":" << (policy_loaded ? (deny_inode_match ? "true" : "false") : "false")
            << ",\"deny_path\":" << (policy_loaded ? (deny_path_match ? "true" : "false") : "false") << "}";
        out << ",\"inferred_rule\":\"" << json_escape(inferred_rule) << "\"";
        out << ",\"notes\":[";
        for (size_t i = 0; i < notes.size(); ++i) {
            if (i > 0) {
                out << ",";
            }
            out << "\"" << json_escape(notes[i]) << "\"";
        }
        out << "]}";
        std::cout << out.str() << '\n';
        return 0;
    }

    std::cout << "Explain (best-effort)" << '\n';
    std::cout << "  type: " << event.type << '\n';
    if (!event.action.empty()) {
        std::cout << "  action: " << event.action << '\n';
    }
    if (!event.path.empty()) {
        std::cout << "  path: " << event.path << '\n';
    }
    if (!event.resolved_path.empty()) {
        std::cout << "  resolved_path: " << event.resolved_path << '\n';
    }
    if (event.has_ino) {
        std::cout << "  ino: " << event.ino << '\n';
    }
    if (event.has_dev) {
        std::cout << "  dev: " << event.dev << '\n';
    }
    if (!event.cgroup_path.empty()) {
        std::cout << "  cgroup_path: " << event.cgroup_path << '\n';
    }
    if (event.has_cgid) {
        std::cout << "  cgid: " << event.cgid << '\n';
    }
    std::cout << "  policy: " << (policy_loaded ? policy_source : "not loaded") << '\n';
    if (policy_loaded) {
        std::cout << "  allow_cgroup_match: " << (allow_match ? "yes" : "no") << '\n';
        std::cout << "  deny_inode_match: " << (deny_inode_match ? "yes" : "no") << '\n';
        std::cout << "  deny_path_match: " << (deny_path_match ? "yes" : "no") << '\n';
    } else {
        std::cout << "  allow_cgroup_match: unknown" << '\n';
        std::cout << "  deny_inode_match: unknown" << '\n';
        std::cout << "  deny_path_match: unknown" << '\n';
    }
    std::cout << "  inferred_rule: " << inferred_rule << '\n';
    if (!notes.empty()) {
        std::cout << "  notes:" << '\n';
        for (const auto& note : notes) {
            std::cout << "    - " << note << '\n';
        }
    }
    return 0;
}

} // namespace aegis
