// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Simulate command implementation
 *
 * Replays an audit-mode JSONL event stream against a candidate enforce
 * policy and reports what would change if that policy were applied.
 * Pure userspace; reuses the rule-match evaluator from `commands_explain.cpp`
 * so the simulator's verdicts match the live agent's precedence
 * (allow_cgroup → deny_inode → deny_path → no_policy_match).
 */

#include "commands_simulate.hpp"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "logging.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

bool line_looks_like_json(const std::string& line)
{
    for (char c : line) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        return c == '{';
    }
    return false;
}

void emit_json(std::ostream& out, const SimulateSummary& summary, const std::vector<SimulateRecord>& records,
               bool per_event, const std::string& policy_source)
{
    out << "{\"policy\":\"" << json_escape(policy_source) << "\"";
    out << ",\"summary\":{";
    out << "\"total_lines\":" << summary.total_lines;
    out << ",\"skipped_non_json\":" << summary.skipped_non_json;
    out << ",\"skipped_non_block\":" << summary.skipped_non_block;
    out << ",\"parse_errors\":" << summary.parse_errors;
    out << ",\"block_events\":" << summary.block_events;
    out << ",\"would_block\":" << summary.would_block;
    out << ",\"would_block_inode\":" << summary.would_block_inode;
    out << ",\"would_block_path\":" << summary.would_block_path;
    out << ",\"would_allow\":" << summary.would_allow;
    out << ",\"no_match\":" << summary.no_match;
    out << "}";

    if (per_event) {
        out << ",\"events\":[";
        for (size_t i = 0; i < records.size(); ++i) {
            if (i > 0)
                out << ",";
            const auto& r = records[i];
            out << "{";
            out << "\"path\":\"" << json_escape(r.path) << "\"";
            if (!r.resolved_path.empty())
                out << ",\"resolved_path\":\"" << json_escape(r.resolved_path) << "\"";
            if (!r.cgroup_path.empty())
                out << ",\"cgroup_path\":\"" << json_escape(r.cgroup_path) << "\"";
            if (r.has_ino)
                out << ",\"ino\":" << r.ino;
            if (r.has_dev)
                out << ",\"dev\":" << r.dev;
            if (r.has_cgid)
                out << ",\"cgid\":" << r.cgid;
            if (!r.original_action.empty())
                out << ",\"original_action\":\"" << json_escape(r.original_action) << "\"";
            out << ",\"simulated_rule\":\"" << json_escape(r.simulated_rule) << "\"";
            out << ",\"allow_match\":" << (r.allow_match ? "true" : "false");
            out << ",\"deny_inode_match\":" << (r.deny_inode_match ? "true" : "false");
            out << ",\"deny_path_match\":" << (r.deny_path_match ? "true" : "false");
            out << "}";
        }
        out << "]";
    }
    out << "}";
}

void emit_text(std::ostream& out, const SimulateSummary& summary, const std::vector<SimulateRecord>& records,
               bool per_event, const std::string& policy_source)
{
    out << "Simulate (dry-run) — candidate policy: " << policy_source << "\n";
    out << "  total_lines:        " << summary.total_lines << "\n";
    out << "  skipped_non_json:   " << summary.skipped_non_json << "\n";
    out << "  skipped_non_block:  " << summary.skipped_non_block << "\n";
    out << "  parse_errors:       " << summary.parse_errors << "\n";
    out << "  block_events:       " << summary.block_events << "\n";
    out << "  would_block:        " << summary.would_block << " (inode=" << summary.would_block_inode
        << " path=" << summary.would_block_path << ")\n";
    out << "  would_allow:        " << summary.would_allow << "\n";
    out << "  no_match:           " << summary.no_match << "\n";

    if (per_event && !records.empty()) {
        out << "\nPer-event detail:\n";
        for (const auto& r : records) {
            const std::string display_path = !r.resolved_path.empty() ? r.resolved_path : r.path;
            out << "  [" << r.simulated_rule << "] " << display_path;
            if (!r.original_action.empty())
                out << " (was=" << r.original_action << ")";
            out << "\n";
        }
    }
}

} // namespace

bool simulate_one_event(const std::string& line, const Policy& policy, SimulateSummary& summary,
                        SimulateRecord* record_out)
{
    summary.total_lines++;

    if (!line_looks_like_json(line)) {
        summary.skipped_non_json++;
        return false;
    }

    ExplainEvent event{};
    std::string parse_error;
    if (!parse_explain_event(line, event, parse_error)) {
        summary.parse_errors++;
        return false;
    }

    if (event.type != "block") {
        summary.skipped_non_block++;
        return false;
    }

    summary.block_events++;
    const ExplainResult eval = evaluate_event_against_policy(event, policy);

    if (eval.allow_match) {
        summary.would_allow++;
    } else if (eval.deny_inode_match || eval.deny_path_match) {
        summary.would_block++;
        if (eval.deny_inode_match)
            summary.would_block_inode++;
        if (eval.deny_path_match)
            summary.would_block_path++;
    } else {
        summary.no_match++;
    }

    if (record_out != nullptr) {
        record_out->path = event.path;
        record_out->resolved_path = event.resolved_path;
        record_out->cgroup_path = event.cgroup_path;
        record_out->ino = event.ino;
        record_out->dev = event.dev;
        record_out->cgid = event.cgid;
        record_out->has_ino = event.has_ino;
        record_out->has_dev = event.has_dev;
        record_out->has_cgid = event.has_cgid;
        record_out->original_action = event.action;
        record_out->simulated_rule = eval.inferred_rule;
        record_out->allow_match = eval.allow_match;
        record_out->deny_inode_match = eval.deny_inode_match;
        record_out->deny_path_match = eval.deny_path_match;
    }
    return true;
}

int cmd_simulate(const std::string& events_path, const std::string& policy_path, bool per_event, bool json_output)
{
    if (policy_path.empty()) {
        logger().log(SLOG_ERROR("simulate: --policy <candidate.conf> is required"));
        return 1;
    }

    PolicyIssues issues{};
    auto policy_result = parse_policy_file(policy_path, issues);
    report_policy_issues(issues);
    if (!policy_result) {
        logger().log(SLOG_ERROR("simulate: failed to parse candidate policy")
                         .field("path", policy_path)
                         .field("error", policy_result.error().to_string()));
        return 1;
    }
    if (issues.has_errors()) {
        logger().log(SLOG_ERROR("simulate: candidate policy has errors").field("path", policy_path));
        return 1;
    }
    const Policy policy = *policy_result;

    std::istream* in = &std::cin;
    std::ifstream file_stream;
    if (events_path != "-") {
        file_stream.open(events_path);
        if (!file_stream.is_open()) {
            logger().log(
                SLOG_ERROR("simulate: failed to open events file").field("path", events_path).error_code(errno));
            return 1;
        }
        in = &file_stream;
    }

    SimulateSummary summary{};
    std::vector<SimulateRecord> records;
    std::string line;
    while (std::getline(*in, line)) {
        if (per_event) {
            SimulateRecord rec;
            if (simulate_one_event(line, policy, summary, &rec)) {
                records.push_back(std::move(rec));
            }
        } else {
            simulate_one_event(line, policy, summary, nullptr);
        }
    }

    if (json_output) {
        emit_json(std::cout, summary, records, per_event, policy_path);
        std::cout << "\n";
    } else {
        emit_text(std::cout, summary, records, per_event, policy_path);
    }
    return 0;
}

} // namespace aegis
