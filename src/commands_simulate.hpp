// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "commands_explain.hpp"
#include "policy.hpp"

namespace aegis {

/**
 * Aggregate outcome of replaying an event stream against a candidate policy.
 *
 * `total_lines` counts every input line (including malformed / non-block
 * events that were skipped) so operators can verify the input was consumed
 * end-to-end. `block_events` is the subset that parsed cleanly as a `block`
 * event and therefore got evaluated.
 *
 * The four counters partition `block_events` exactly:
 *   would_block + would_allow + no_match == block_events
 * (`would_block` covers both inode and path deny matches; the per-event
 * detail still distinguishes them.)
 */
struct SimulateSummary {
    uint64_t total_lines = 0;
    uint64_t skipped_non_json = 0;
    uint64_t skipped_non_block = 0;
    uint64_t parse_errors = 0;
    uint64_t block_events = 0;
    uint64_t would_block = 0;       // any deny match
    uint64_t would_block_inode = 0; // breakdown of `would_block` …
    uint64_t would_block_path = 0;
    uint64_t would_allow = 0;
    uint64_t no_match = 0;
};

/**
 * One per-event diff record. Used by `--per-event` mode and by tests.
 * `original_action` mirrors the event's recorded `action` field
 * (typically "AUDIT" when replaying audit-mode logs); `simulated_rule`
 * is what the candidate policy would do.
 */
struct SimulateRecord {
    std::string path;
    std::string resolved_path;
    std::string cgroup_path;
    uint64_t ino = 0;
    uint64_t dev = 0;
    uint64_t cgid = 0;
    bool has_ino = false;
    bool has_dev = false;
    bool has_cgid = false;
    std::string original_action;
    std::string simulated_rule;
    bool allow_match = false;
    bool deny_inode_match = false;
    bool deny_path_match = false;
};

/**
 * Evaluate one event JSON line against `policy` and update `summary` in
 * place. If `record_out` is non-null, populates a `SimulateRecord` for the
 * event when it parsed as a `block` event (returns false otherwise).
 */
bool simulate_one_event(const std::string& line, const Policy& policy, SimulateSummary& summary,
                        SimulateRecord* record_out = nullptr);

/**
 * `aegisbpf simulate <events>|- --policy <candidate.conf> [--per-event] [--json]`
 *
 * Replays an audit-mode JSONL event stream against a candidate enforce
 * policy and reports what would change. Pure userspace; does not touch
 * BPF or any pinned maps. Reading "-" consumes from stdin.
 */
int cmd_simulate(const std::string& events_path, const std::string& policy_path, bool per_event, bool json_output);

} // namespace aegis
