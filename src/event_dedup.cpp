// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Bounded time-window event dedup implementation
 */

#include "event_dedup.hpp"

#include <algorithm>
#include <utility>

namespace aegis {

EventDeduper::EventDeduper(const EventDedupConfig& cfg) : cfg_(cfg)
{
    if (cfg_.max_entries > 0) {
        table_.reserve(cfg_.max_entries);
    }
}

bool EventDeduper::is_enabled() const noexcept
{
    return cfg_.window_ns > 0 && cfg_.max_entries > 0;
}

EventDedupDecision EventDeduper::should_emit(uint64_t key, uint64_t now_ns)
{
    if (!is_enabled()) {
        return EventDedupDecision{true, 0};
    }

    auto it = table_.find(key);
    if (it == table_.end()) {
        if (table_.size() >= cfg_.max_entries) {
            evict_oldest_locked();
        }
        Entry e{};
        e.window_start_ns = now_ns;
        e.suppressed_count = 0;
        table_.emplace(key, e);
        return EventDedupDecision{true, 0};
    }

    Entry& entry = it->second;
    const uint64_t age = (now_ns >= entry.window_start_ns) ? now_ns - entry.window_start_ns : 0;

    if (age < cfg_.window_ns) {
        entry.suppressed_count++;
        total_suppressed_++;
        return EventDedupDecision{false, 0};
    }

    // Window has expired: emit, surface accumulated suppressed count,
    // and reset the window starting now.
    const uint64_t suppressed = entry.suppressed_count;
    entry.window_start_ns = now_ns;
    entry.suppressed_count = 0;
    return EventDedupDecision{true, suppressed};
}

uint64_t EventDeduper::total_suppressed() const noexcept
{
    return total_suppressed_;
}

uint64_t EventDeduper::evictions() const noexcept
{
    return evictions_;
}

std::size_t EventDeduper::active_keys() const noexcept
{
    return table_.size();
}

void EventDeduper::evict_oldest_locked()
{
    if (table_.empty()) {
        return;
    }
    auto oldest = table_.begin();
    for (auto it = table_.begin(); it != table_.end(); ++it) {
        if (it->second.window_start_ns < oldest->second.window_start_ns) {
            oldest = it;
        }
    }
    evictions_++;
    // Suppressed count from the evicted entry is lost; the eviction
    // counter records that fact so it is observable.
    table_.erase(oldest);
}

uint64_t event_dedup_hash(uint32_t event_type_tag, uint64_t a, uint64_t b, uint64_t c)
{
    // 64-bit FNV-1a-style mix; deterministic, small, no allocations,
    // and does not depend on STL hashing (which differs across runs
    // when libstdc++ randomises std::hash<uint64_t>).
    constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
    constexpr uint64_t kFnvPrime = 1099511628211ULL;

    uint64_t h = kFnvOffset;
    auto mix = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            h ^= static_cast<uint8_t>(v & 0xFF);
            h *= kFnvPrime;
            v >>= 8;
        }
    };
    mix(static_cast<uint64_t>(event_type_tag));
    mix(a);
    mix(b);
    mix(c);
    return h;
}

} // namespace aegis
