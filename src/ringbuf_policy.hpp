// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>

namespace aegis {

/**
 * Operator-visible policy describing what the daemon does when the BPF
 * ring buffers cannot accept a new event (verifier `bpf_ringbuf_reserve`
 * returns NULL).
 *
 * Today the implicit, hard-coded behaviour is `PriorityFallback`: the
 * security-critical priority ringbuf is tried first, and on failure the
 * event falls back to the main events ringbuf (with a counter bump).
 * Telemetry events use the main buffer directly and are dropped on
 * pressure -- they are shed first by design so that enforcement and
 * forensic events survive load spikes.
 *
 * `Sample` and `SpoolToDisk` are roadmap values reserved here so that
 * the CLI parser can give a stable error ("not implemented yet") rather
 * than swallowing an unknown name. They are not selectable.
 *
 * The contract for v0.x:
 *   * `PriorityFallback` is the only supported value.
 *   * Operators can lock the daemon to that policy explicitly via
 *     `--ringbuf-overflow-policy=priority-fallback` (or the env var
 *     `AEGIS_RINGBUF_OVERFLOW_POLICY`); future versions will not
 *     silently change behaviour without an opt-in flag.
 *   * The active policy is logged at startup and surfaced in
 *     `aegisbpf metrics --json` so it is alertable.
 */
enum class RingbufOverflowPolicy : uint8_t {
    PriorityFallback = 0,
};

enum class RingbufOverflowPolicyParseError : uint8_t {
    Unknown = 0,
    Reserved = 1,
};

/**
 * Parse a policy name from CLI / env. Accepts:
 *   * "priority-fallback" / "priority_fallback" (case-insensitive)
 *   * Empty string -> defaults to PriorityFallback.
 *
 * Reserved roadmap names ("sample", "spool", "spool-to-disk") return
 * `Reserved` so the caller can render a clear "not yet implemented"
 * message. Anything else returns `Unknown`.
 */
bool parse_ringbuf_overflow_policy(const std::string& value, RingbufOverflowPolicy& out,
                                   RingbufOverflowPolicyParseError& err);

/**
 * Stable canonical name (kebab-case) for the policy, suitable for log
 * lines, metrics labels, and the CLI default value display.
 */
const char* ringbuf_overflow_policy_name(RingbufOverflowPolicy policy);

/**
 * Short human-readable description, used in startup logs and the docs
 * generator. One sentence, no trailing period.
 */
const char* ringbuf_overflow_policy_description(RingbufOverflowPolicy policy);

} // namespace aegis
