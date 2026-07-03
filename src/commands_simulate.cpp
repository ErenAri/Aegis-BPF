// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Policy simulate command
 *
 * `aegisbpf simulate --events past.jsonl --policy candidate.conf`
 *
 * Replays a stream of AegisBPF block events through a candidate policy
 * and reports what would change. The replay is in-memory, in-process,
 * with no kernel side effects — safe to run on the same host as a
 * production daemon, and safe to run offline against a captured event
 * file.
 */

#include "commands_simulate.hpp"

#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "json_scan.hpp"
#include "logging.hpp"
#include "policy.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

struct EventRecord {
    std::string raw;            // original JSON line for sampling
    std::string type;           // event "type" field
    std::string path;           // raw path from event (may be empty)
    std::string resolved_path;  // canonical path when present
    std::string cgroup_path;
    std::string action;         // AUDIT / TERM / KILL / INT / BLOCK
    uint64_t ino  = 0;
    uint64_t dev  = 0;
    uint64_t cgid = 0;
    bool has_ino  = false;
    bool has_dev  = false;
    bool has_cgid = false;
    size_t line_no = 0;
};

bool parse_event_line(const std::string& line, EventRecord& out)
{
    out.raw = line;
    if (!json_scan::extract_string(line, "type", out.type)) {
        return false;
    }
    json_scan::extract_string(line, "path", out.path);
    json_scan::extract_string(line, "resolved_path", out.resolved_path);
    json_scan::extract_string(line, "cgroup_path", out.cgroup_path);
    json_scan::extract_string(line, "action", out.action);

    uint64_t value = 0;
    if (json_scan::extract_uint64(line, "ino", value)) {
        out.ino = value;
        out.has_ino = true;
    }
    if (json_scan::extract_uint64(line, "dev", value)) {
        out.dev = value;
        out.has_dev = true;
    }
    if (json_scan::extract_uint64(line, "cgid", value)) {
        out.cgid = value;
        out.has_cgid = true;
    }
    return true;
}

/// Match an event against a policy. Returns true if the policy would
/// deny the event. The rule_type out-param identifies which kind of
/// rule matched ("deny_inode", "deny_path", "allow_cgroup", or empty
/// for no match).
bool would_deny(const Policy& policy, const EventRecord& ev, std::string& rule_type)
{
    // Allow-cgroup short-circuits everything else.
    if (ev.has_cgid) {
        for (uint64_t id : policy.allow_cgroup_ids) {
            if (id == ev.cgid) {
                rule_type = "allow_cgroup";
                return false;
            }
        }
    }
    if (!ev.cgroup_path.empty()) {
        for (const auto& path : policy.allow_cgroup_paths) {
            if (path == ev.cgroup_path) {
                rule_type = "allow_cgroup";
                return false;
            }
        }
    }

    // Inode match: highest-precedence deny.
    if (ev.has_ino && ev.has_dev && ev.dev <= UINT32_MAX) {
        InodeId id{ev.ino, static_cast<uint32_t>(ev.dev), 0};
        for (const auto& deny : policy.deny_inodes) {
            if (deny == id) {
                rule_type = "deny_inode";
                return true;
            }
        }
    }

    // Path match (raw and resolved both checked).
    if (!ev.path.empty()) {
        for (const auto& deny : policy.deny_paths) {
            if (deny == ev.path) {
                rule_type = "deny_path";
                return true;
            }
        }
    }
    if (!ev.resolved_path.empty()) {
        for (const auto& deny : policy.deny_paths) {
            if (deny == ev.resolved_path) {
                rule_type = "deny_path";
                return true;
            }
        }
    }

    rule_type.clear();
    return false;
}

bool was_audit_only(const std::string& action)
{
    return action.empty() || action == "AUDIT" || action == "audit";
}

void emit_text_report(size_t total, size_t parse_errors, size_t matched, size_t newly_blocked,
                      size_t policy_drift,
                      const std::vector<std::pair<EventRecord, std::string>>& newly_blocked_samples,
                      const std::vector<EventRecord>& policy_drift_samples,
                      const std::string& policy_source)
{
    std::cout << "AegisBPF policy simulator\n";
    std::cout << "Policy: " << (policy_source.empty() ? "<none>" : policy_source) << "\n";
    std::cout << "Events parsed: " << total;
    if (parse_errors > 0) {
        std::cout << " (skipped " << parse_errors << " unparseable line"
                  << (parse_errors == 1 ? "" : "s") << ")";
    }
    std::cout << "\n\n";
    std::cout << "Buckets:\n";
    std::cout << "  matched         = " << matched
              << "  (candidate policy would deny)\n";
    std::cout << "  newly_blocked   = " << newly_blocked
              << "  (matched AND original action was AUDIT)\n";
    std::cout << "  policy_drift    = " << policy_drift
              << "  (original action was non-AUDIT but candidate has no matching deny)\n";

    if (!newly_blocked_samples.empty()) {
        std::cout << "\nSample newly-blocked events:\n";
        for (const auto& [ev, rule_type] : newly_blocked_samples) {
            std::cout << "  line " << ev.line_no
                      << "  rule=" << rule_type
                      << "  type=" << ev.type;
            if (!ev.path.empty()) std::cout << "  path=" << ev.path;
            if (!ev.resolved_path.empty() && ev.resolved_path != ev.path) {
                std::cout << "  resolved_path=" << ev.resolved_path;
            }
            if (ev.has_ino) std::cout << "  ino=" << ev.ino;
            std::cout << "\n";
        }
    }
    if (!policy_drift_samples.empty()) {
        std::cout << "\nSample policy-drift events (currently blocked, not blocked under candidate):\n";
        for (const auto& ev : policy_drift_samples) {
            std::cout << "  line " << ev.line_no
                      << "  type=" << ev.type
                      << "  action=" << ev.action;
            if (!ev.path.empty()) std::cout << "  path=" << ev.path;
            std::cout << "\n";
        }
    }
}

void emit_json_report(size_t total, size_t parse_errors, size_t matched, size_t newly_blocked,
                      size_t policy_drift,
                      const std::vector<std::pair<EventRecord, std::string>>& newly_blocked_samples,
                      const std::vector<EventRecord>& policy_drift_samples,
                      const std::string& policy_source)
{
    std::ostringstream out;
    out << "{"
        << "\"policy\":\"" << json_escape(policy_source) << "\""
        << ",\"events_parsed\":" << total
        << ",\"parse_errors\":" << parse_errors
        << ",\"matched\":" << matched
        << ",\"newly_blocked\":" << newly_blocked
        << ",\"policy_drift\":" << policy_drift
        << ",\"samples\":{"
        << "\"newly_blocked\":[";
    bool first = true;
    for (const auto& [ev, rule_type] : newly_blocked_samples) {
        if (!first) out << ",";
        first = false;
        out << "{\"line\":" << ev.line_no
            << ",\"rule_type\":\"" << json_escape(rule_type) << "\""
            << ",\"event\":" << ev.raw
            << "}";
    }
    out << "],\"policy_drift\":[";
    first = true;
    for (const auto& ev : policy_drift_samples) {
        if (!first) out << ",";
        first = false;
        out << "{\"line\":" << ev.line_no
            << ",\"event\":" << ev.raw
            << "}";
    }
    out << "]}}";
    std::cout << out.str() << "\n";
}

}  // namespace

int cmd_simulate(const SimulateOptions& opts)
{
    if (opts.events_path.empty()) {
        logger().log(SLOG_ERROR("simulate: --events <file|-> is required"));
        return 1;
    }

    // Resolve policy source: explicit path > applied policy.
    std::string policy_source = opts.policy_path;
    if (policy_source.empty() && std::filesystem::exists(kPolicyAppliedPath)) {
        policy_source = kPolicyAppliedPath;
    }
    if (policy_source.empty()) {
        logger().log(SLOG_ERROR("simulate: no policy provided and no applied policy at default location")
                         .field("applied_policy_path", kPolicyAppliedPath));
        return 1;
    }

    // Parse the candidate policy.
    Policy policy{};
    {
        PolicyIssues issues{};
        auto policy_result = parse_policy_file(policy_source, issues);
        report_policy_issues(issues);
        if (!policy_result) {
            logger().log(SLOG_ERROR("simulate: failed to parse policy")
                             .field("path", policy_source)
                             .field("error", policy_result.error().to_string()));
            return 1;
        }
        if (issues.has_errors()) {
            logger().log(SLOG_ERROR("simulate: policy contains errors").field("path", policy_source));
            return 1;
        }
        policy = *policy_result;
    }

    // Open the events stream (file or stdin).
    std::ifstream file_in;
    std::istream* in = nullptr;
    if (opts.events_path == "-") {
        in = &std::cin;
    } else {
        file_in.open(opts.events_path);
        if (!file_in.is_open()) {
            logger().log(SLOG_ERROR("simulate: failed to open events file")
                             .field("path", opts.events_path)
                             .field("errno", static_cast<int64_t>(errno)));
            return 1;
        }
        in = &file_in;
    }

    size_t total = 0;
    size_t parse_errors = 0;
    size_t matched = 0;
    size_t newly_blocked = 0;
    size_t policy_drift = 0;

    std::vector<std::pair<EventRecord, std::string>> newly_blocked_samples;
    std::vector<EventRecord> policy_drift_samples;

    std::string line;
    size_t line_no = 0;
    while (std::getline(*in, line)) {
        ++line_no;
        // Skip blank lines and comments.
        bool only_whitespace = true;
        for (char c : line) {
            if (c != ' ' && c != '\t' && c != '\r') {
                only_whitespace = false;
                break;
            }
        }
        if (only_whitespace || line[0] == '#') continue;

        EventRecord ev{};
        ev.line_no = line_no;
        if (!parse_event_line(line, ev)) {
            ++parse_errors;
            continue;
        }
        // Only block-class events are evaluable today. Skip the rest
        // (exec, exec_argv, net_*_block, kernel_*_block, ...) so a
        // mixed-stream input file doesn't produce noise. This is the
        // same scope as `cmd_explain`.
        if (ev.type != "block") continue;

        ++total;

        std::string rule_type;
        const bool denied = would_deny(policy, ev, rule_type);

        if (denied) {
            ++matched;
            if (was_audit_only(ev.action)) {
                ++newly_blocked;
                if (newly_blocked_samples.size() < opts.sample_limit) {
                    newly_blocked_samples.emplace_back(ev, rule_type);
                }
            }
        } else if (!was_audit_only(ev.action)) {
            ++policy_drift;
            if (policy_drift_samples.size() < opts.sample_limit) {
                policy_drift_samples.push_back(ev);
            }
        }
    }

    if (opts.json_output) {
        emit_json_report(total, parse_errors, matched, newly_blocked, policy_drift,
                         newly_blocked_samples, policy_drift_samples, policy_source);
    } else {
        emit_text_report(total, parse_errors, matched, newly_blocked, policy_drift,
                         newly_blocked_samples, policy_drift_samples, policy_source);
    }

    if (opts.strict && newly_blocked > 0) {
        return 1;
    }
    return 0;
}

}  // namespace aegis
