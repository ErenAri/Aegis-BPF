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

#include "json_scan.hpp"
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
               const std::vector<SimulateNetRecord>& net_records, bool per_event,
               const std::string& policy_source)
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
    out << ",\"net_block_events\":" << summary.net_block_events;
    out << ",\"net_would_block\":" << summary.net_would_block;
    out << ",\"net_would_block_ip\":" << summary.net_would_block_ip;
    out << ",\"net_would_block_cidr\":" << summary.net_would_block_cidr;
    out << ",\"net_would_block_port\":" << summary.net_would_block_port;
    out << ",\"net_would_block_ip_port\":" << summary.net_would_block_ip_port;
    out << ",\"net_would_allow\":" << summary.net_would_allow;
    out << ",\"net_no_match\":" << summary.net_no_match;
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

        out << ",\"net_events\":[";
        for (size_t i = 0; i < net_records.size(); ++i) {
            if (i > 0)
                out << ",";
            const auto& r = net_records[i];
            out << "{";
            out << "\"type\":\"" << json_escape(r.event_type) << "\"";
            if (!r.family.empty())
                out << ",\"family\":\"" << json_escape(r.family) << "\"";
            if (!r.protocol.empty())
                out << ",\"protocol\":\"" << json_escape(r.protocol) << "\"";
            if (!r.direction.empty())
                out << ",\"direction\":\"" << json_escape(r.direction) << "\"";
            if (!r.remote_ip.empty())
                out << ",\"remote_ip\":\"" << json_escape(r.remote_ip) << "\"";
            if (r.has_remote_port)
                out << ",\"remote_port\":" << r.remote_port;
            if (r.has_local_port)
                out << ",\"local_port\":" << r.local_port;
            if (!r.cgroup_path.empty())
                out << ",\"cgroup_path\":\"" << json_escape(r.cgroup_path) << "\"";
            if (r.has_cgid)
                out << ",\"cgid\":" << r.cgid;
            if (!r.original_action.empty())
                out << ",\"original_action\":\"" << json_escape(r.original_action) << "\"";
            if (!r.original_rule_type.empty())
                out << ",\"original_rule_type\":\"" << json_escape(r.original_rule_type) << "\"";
            out << ",\"simulated_rule\":\"" << json_escape(r.simulated_rule) << "\"";
            out << ",\"allow_match\":" << (r.allow_match ? "true" : "false");
            out << ",\"deny_ip_match\":" << (r.deny_ip_match ? "true" : "false");
            out << ",\"deny_cidr_match\":" << (r.deny_cidr_match ? "true" : "false");
            out << ",\"deny_port_match\":" << (r.deny_port_match ? "true" : "false");
            out << ",\"deny_ip_port_match\":" << (r.deny_ip_port_match ? "true" : "false");
            out << "}";
        }
        out << "]";
    }
    out << "}";
}

void emit_text(std::ostream& out, const SimulateSummary& summary, const std::vector<SimulateRecord>& records,
               const std::vector<SimulateNetRecord>& net_records, bool per_event,
               const std::string& policy_source)
{
    out << "Simulate (dry-run) — candidate policy: " << policy_source << "\n";
    out << "  total_lines:           " << summary.total_lines << "\n";
    out << "  skipped_non_json:      " << summary.skipped_non_json << "\n";
    out << "  skipped_non_block:     " << summary.skipped_non_block << "\n";
    out << "  parse_errors:          " << summary.parse_errors << "\n";
    out << "  block_events:          " << summary.block_events << "\n";
    out << "  would_block:           " << summary.would_block << " (inode=" << summary.would_block_inode
        << " path=" << summary.would_block_path << ")\n";
    out << "  would_allow:           " << summary.would_allow << "\n";
    out << "  no_match:              " << summary.no_match << "\n";
    out << "  net_block_events:      " << summary.net_block_events << "\n";
    out << "  net_would_block:       " << summary.net_would_block << " (ip=" << summary.net_would_block_ip
        << " cidr=" << summary.net_would_block_cidr << " port=" << summary.net_would_block_port
        << " ip_port=" << summary.net_would_block_ip_port << ")\n";
    out << "  net_would_allow:       " << summary.net_would_allow << "\n";
    out << "  net_no_match:          " << summary.net_no_match << "\n";

    if (per_event && !records.empty()) {
        out << "\nPer-event detail (file):\n";
        for (const auto& r : records) {
            const std::string display_path = !r.resolved_path.empty() ? r.resolved_path : r.path;
            out << "  [" << r.simulated_rule << "] " << display_path;
            if (!r.original_action.empty())
                out << " (was=" << r.original_action << ")";
            out << "\n";
        }
    }

    if (per_event && !net_records.empty()) {
        out << "\nPer-event detail (network):\n";
        for (const auto& r : net_records) {
            out << "  [" << r.simulated_rule << "] " << r.event_type;
            if (!r.remote_ip.empty()) {
                out << " " << r.remote_ip;
                if (r.has_remote_port)
                    out << ":" << r.remote_port;
            } else if (r.has_local_port) {
                out << " :" << r.local_port;
            }
            if (!r.protocol.empty())
                out << "/" << r.protocol;
            if (!r.original_action.empty())
                out << " (was=" << r.original_action;
            if (!r.original_rule_type.empty())
                out << " rule_type=" << r.original_rule_type;
            if (!r.original_action.empty())
                out << ")";
            out << "\n";
        }
    }
}

} // namespace

namespace {

bool is_net_block_type(const std::string& type)
{
    /* Match any "net_*_block" event emitted by `print_net_block_event`. */
    if (type.size() < 11)
        return false;
    if (type.compare(0, 4, "net_") != 0)
        return false;
    return type.size() >= 6 && type.compare(type.size() - 6, 6, "_block") == 0;
}

bool simulate_file_block(const std::string& line, const Policy& policy, SimulateSummary& summary,
                         SimulateRecord* record_out)
{
    ExplainEvent event{};
    std::string parse_error;
    if (!parse_explain_event(line, event, parse_error)) {
        summary.parse_errors++;
        return false;
    }
    /* Caller has already confirmed type=="block". */
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

bool simulate_net_block(const std::string& line, const Policy& policy, SimulateSummary& summary,
                        SimulateNetRecord* record_out)
{
    NetExplainEvent event{};
    std::string parse_error;
    if (!parse_net_explain_event(line, event, parse_error)) {
        summary.parse_errors++;
        return false;
    }
    summary.net_block_events++;
    const NetExplainResult eval = evaluate_net_event_against_policy(event, policy);

    if (eval.allow_match) {
        summary.net_would_allow++;
    } else if (eval.deny_ip_port_match || eval.deny_ip_match || eval.deny_cidr_match || eval.deny_port_match) {
        summary.net_would_block++;
        if (eval.deny_ip_port_match)
            summary.net_would_block_ip_port++;
        if (eval.deny_ip_match)
            summary.net_would_block_ip++;
        if (eval.deny_cidr_match)
            summary.net_would_block_cidr++;
        if (eval.deny_port_match)
            summary.net_would_block_port++;
    } else {
        summary.net_no_match++;
    }

    if (record_out != nullptr) {
        record_out->event_type = event.type;
        record_out->family = event.family;
        record_out->protocol = event.protocol;
        record_out->direction = event.direction;
        record_out->remote_ip = event.remote_ip;
        record_out->cgroup_path = event.cgroup_path;
        record_out->original_action = event.action;
        record_out->original_rule_type = event.rule_type;
        record_out->simulated_rule = eval.inferred_rule;
        record_out->remote_port = event.remote_port;
        record_out->local_port = event.local_port;
        record_out->cgid = event.cgid;
        record_out->has_remote_port = event.has_remote_port;
        record_out->has_local_port = event.has_local_port;
        record_out->has_cgid = event.has_cgid;
        record_out->allow_match = eval.allow_match;
        record_out->deny_ip_match = eval.deny_ip_match;
        record_out->deny_cidr_match = eval.deny_cidr_match;
        record_out->deny_port_match = eval.deny_port_match;
        record_out->deny_ip_port_match = eval.deny_ip_port_match;
    }
    return true;
}

} // namespace

bool simulate_one_event(const std::string& line, const Policy& policy, SimulateSummary& summary,
                        SimulateRecord* record_out, SimulateNetRecord* net_record_out)
{
    summary.total_lines++;

    if (!line_looks_like_json(line)) {
        summary.skipped_non_json++;
        return false;
    }

    /* Peek at `type` first so we can dispatch without paying for both parsers. */
    std::string type;
    if (!json_scan::extract_string(line, "type", type)) {
        summary.parse_errors++;
        return false;
    }

    if (type == "block") {
        return simulate_file_block(line, policy, summary, record_out);
    }
    if (is_net_block_type(type)) {
        return simulate_net_block(line, policy, summary, net_record_out);
    }
    summary.skipped_non_block++;
    return false;
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
    std::vector<SimulateNetRecord> net_records;
    std::string line;
    while (std::getline(*in, line)) {
        if (per_event) {
            SimulateRecord file_rec;
            SimulateNetRecord net_rec;
            const uint64_t before_block = summary.block_events;
            const uint64_t before_net = summary.net_block_events;
            if (simulate_one_event(line, policy, summary, &file_rec, &net_rec)) {
                if (summary.block_events > before_block) {
                    records.push_back(std::move(file_rec));
                } else if (summary.net_block_events > before_net) {
                    net_records.push_back(std::move(net_rec));
                }
            }
        } else {
            simulate_one_event(line, policy, summary, nullptr, nullptr);
        }
    }

    if (json_output) {
        emit_json(std::cout, summary, records, net_records, per_event, policy_path);
        std::cout << "\n";
    } else {
        emit_text(std::cout, summary, records, net_records, per_event, policy_path);
    }
    return 0;
}

} // namespace aegis
