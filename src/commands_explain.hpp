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
 * Network event payload extracted from one `net_*_block` JSON line. Mirrors
 * the schema produced by `print_net_block_event` in `events.cpp`. The
 * simulator only needs the fields the rule-match evaluator consumes;
 * remaining fields (`pid`, `ppid`, `comm`, k8s identity) are intentionally
 * ignored to keep the parser forwards-compatible.
 */
struct NetExplainEvent {
    std::string type;        /* "net_connect_block" / "net_bind_block" / ... */
    std::string family;      /* "ipv4" | "ipv6" */
    std::string protocol;    /* "tcp" | "udp" | numeric */
    std::string direction;   /* "egress" | "bind" | "listen" | "accept" | "send" | "recv" */
    std::string remote_ip;
    std::string cgroup_path;
    std::string action;
    std::string rule_type;   /* original rule_type (e.g. "ip", "port", "ip_port") */
    uint16_t remote_port = 0;
    uint16_t local_port = 0;
    uint64_t cgid = 0;
    bool has_remote_port = false;
    bool has_local_port = false;
    bool has_cgid = false;
};

/**
 * Outcome of evaluating one `NetExplainEvent` against a candidate `Policy`.
 * `inferred_rule` follows the same precedence the BPF runtime uses:
 * allow_cgroup → deny_ip_port → deny_ip → deny_cidr → deny_port → no_policy_match.
 */
struct NetExplainResult {
    bool allow_match = false;
    bool deny_ip_match = false;
    bool deny_cidr_match = false;
    bool deny_port_match = false;
    bool deny_ip_port_match = false;
    std::string inferred_rule;
};

/**
 * Parse a single event JSON document into an `ExplainEvent`. Returns false
 * with `error` populated when the document is missing the required `type`
 * field; missing optional fields silently default to zero/empty.
 */
bool parse_explain_event(const std::string& json, ExplainEvent& out, std::string& error);

/**
 * Parse a single network-event JSON document into a `NetExplainEvent`.
 * Returns false with `error` populated when the document is missing the
 * required `type` field; all other fields are optional.
 */
bool parse_net_explain_event(const std::string& json, NetExplainEvent& out, std::string& error);

/**
 * Pure rule-match evaluator: applies the same allow/deny precedence the
 * runtime daemon uses. Network rules and `protect_*` flags are out of
 * scope for this evaluator and are not consulted here.
 */
ExplainResult evaluate_event_against_policy(const ExplainEvent& event, const Policy& policy);

/**
 * Pure rule-match evaluator for network events. Mirrors the BPF runtime's
 * precedence (allow_cgroup → ip_port → ip → cidr → port). Cgroup-scoped
 * network deny rules (`policy.cgroup.deny_ips` / `deny_ports`) are out of
 * scope for the v1 simulator and are not consulted here.
 */
NetExplainResult evaluate_net_event_against_policy(const NetExplainEvent& event, const Policy& policy);

int cmd_explain(const std::string& event_path, const std::string& policy_path, bool json_output = false);

} // namespace aegis
