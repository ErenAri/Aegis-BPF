// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

struct SimulateOptions {
    /// Path to a JSONL file (one AegisBPF event per line) or "-" for
    /// stdin. Required.
    std::string events_path;

    /// Path to a candidate policy file (`.conf` INI). When empty, the
    /// applied policy at `kPolicyAppliedPath` is used if present.
    std::string policy_path;

    /// Emit JSON summary to stdout instead of human-readable text.
    bool json_output = false;

    /// Maximum number of sample events to include per bucket in the
    /// report. Default: 5. Set to 0 to disable samples (counts only).
    size_t sample_limit = 5;

    /// Exit non-zero (1) if the candidate policy would *newly* block
    /// any input event that was originally audit-only. Off by default
    /// because the simulator is informational; CI gates can opt in.
    bool strict = false;
};

/// Replay a stream of AegisBPF block events through a candidate
/// policy and report what would change.
///
/// Reads one JSON event per line from `opts.events_path`, evaluates
/// each against the policy at `opts.policy_path` (or the applied
/// policy), and reports four buckets:
///
///   total              -- events parsed
///   matched            -- candidate policy denies the event
///   newly_blocked      -- matched AND the input event was audit-only
///   policy_drift       -- input event was non-audit but candidate has
///                          no matching deny rule (rule was removed?)
///
/// On `--json`, returns a single JSON object with counts plus
/// `samples.<bucket>` arrays of up to `sample_limit` events.
///
/// Returns:
///   0 always, unless `opts.strict` is set and `newly_blocked > 0`,
///   in which case 1.
int cmd_simulate(const SimulateOptions& opts);

}  // namespace aegis
