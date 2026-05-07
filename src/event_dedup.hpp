// cppcheck-suppress-file missingIncludeSystem
#pragma once

/*
 * AegisBPF - Bounded time-window event dedup
 *
 * High-rate workloads can flood the SIEM with identical block events
 * (e.g., a misbehaving binary touching the same denied path 10k/s).
 * This primitive coalesces them into one emission per (key, window):
 *   - First time a key is seen: emit, record timestamp.
 *   - Subsequent occurrences within `window_ns`: suppress, increment count.
 *   - Next occurrence after `window_ns` expires: emit with the
 *     accumulated suppressed count from the prior window (so the
 *     downstream consumer sees how many were collapsed and the count
 *     is never lost without notice).
 *
 * Capacity is bounded; oldest entry is evicted on insert when full.
 * Eviction loses the suppression count for that key, accounted for in
 * `evictions()` so it is observable, not silent.
 *
 * Disabled-by-default contract: `EventDeduper::is_enabled()` returns
 * false when the configured window is zero, in which case
 * `should_emit()` always returns true and never touches the table.
 * That is the only behaviour shipped by deployments that do not opt in.
 */

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace aegis {

struct EventDedupConfig {
    // Time window during which identical events are coalesced. Zero
    // disables the deduper (preserves baseline behaviour).
    uint64_t window_ns = 0;
    // Maximum number of distinct keys tracked simultaneously. When the
    // table is full and a brand-new key arrives, the entry with the
    // oldest first-seen timestamp is evicted to make room.
    std::size_t max_entries = 4096;
};

struct EventDedupDecision {
    // True when the caller should emit the event downstream. False
    // means the event is being suppressed inside the active window.
    bool emit = true;
    // When `emit` is true and the key was just promoted out of an
    // expired window, this is the count of events suppressed during
    // the prior window. Zero on first-ever sighting of the key.
    uint64_t suppressed_during_prior_window = 0;
};

class EventDeduper {
  public:
    EventDeduper() = default;
    explicit EventDeduper(const EventDedupConfig& cfg);

    bool is_enabled() const noexcept;

    // Returns the emit decision for `key` observed at `now_ns`. When
    // disabled (window_ns == 0), always returns {emit=true, 0}.
    EventDedupDecision should_emit(uint64_t key, uint64_t now_ns);

    // Total events suppressed since construction (across all keys).
    uint64_t total_suppressed() const noexcept;

    // Number of evictions that lost their suppressed counts because
    // the table was full. Operators should alarm if this is non-zero
    // and grows; it means the table is undersized for the workload.
    uint64_t evictions() const noexcept;

    // Current number of tracked keys (for tests / introspection).
    std::size_t active_keys() const noexcept;

  private:
    struct Entry {
        uint64_t window_start_ns = 0;
        uint64_t suppressed_count = 0;
    };

    void evict_oldest_locked();

    EventDedupConfig cfg_{};
    std::unordered_map<uint64_t, Entry> table_;
    uint64_t total_suppressed_ = 0;
    uint64_t evictions_ = 0;
};

// Hash a tuple of identifying fields into a single 64-bit dedup key.
// Used by event-emit sites so the dedup primitive itself stays event-shape
// agnostic. The hash is deterministic but not cryptographic - it is fine
// for collision-rate control on bounded tables, not for adversarial
// inputs (the daemon already runs as the trusted producer of these
// events; the keys are derived from kernel-side data not attacker-controlled).
uint64_t event_dedup_hash(uint32_t event_type_tag, uint64_t a, uint64_t b, uint64_t c);

} // namespace aegis
