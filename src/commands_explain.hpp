// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>

#include "policy.hpp"

namespace aegis {

/**
 * Single event payload extracted from one line of the daemon's JSON event
 * stream. Only the fields the rule-match evaluator consumes are populated;
 * everything else is intentionally ignored so the parser stays
 * forwards-compatible with future event-schema additions.
 */
struct ExplainEvent {
    std::string type;
    std::string path;
    std::string resolved_path;
    std::string cgroup_path;
    std::string action;
    uint64_t ino = 0;
    uint64_t dev = 0;
    uint64_t cgid = 0;
    bool has_ino = false;
    bool has_dev = false;
    bool has_cgid = false;
};

/**
 * Outcome of evaluating one `ExplainEvent` against a candidate `Policy`.
 * `inferred_rule` follows the same precedence the live agent uses:
 * allow_cgroup → deny_inode → deny_path → no_policy_match.
 */
struct ExplainResult {
    bool allow_match = false;
    bool deny_inode_match = false;
    bool deny_path_match = false;
    std::string inferred_rule;
};

/**
 * Parse a single event JSON document into an `ExplainEvent`. Returns false
 * with `error` populated when the document is missing the required `type`
 * field; missing optional fields silently default to zero/empty.
 */
bool parse_explain_event(const std::string& json, ExplainEvent& out, std::string& error);

/**
 * Pure rule-match evaluator: applies the same allow/deny precedence the
 * runtime daemon uses. Network rules and `protect_*` flags are out of
 * scope for the v1 simulator and are not consulted here.
 */
ExplainResult evaluate_event_against_policy(const ExplainEvent& event, const Policy& policy);

int cmd_explain(const std::string& event_path, const std::string& policy_path, bool json_output = false);

} // namespace aegis
