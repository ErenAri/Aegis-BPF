// cppcheck-suppress-file missingIncludeSystem
/*
 * Unit tests for the bounded time-window event deduper.
 *
 * Contract verified here:
 *   * Default-constructed (window_ns == 0) deduper is disabled and
 *     never coalesces -- existing deployments must see no behaviour
 *     change.
 *   * First sighting of a key always emits with suppressed=0.
 *   * Duplicates inside the active window are suppressed and counted.
 *   * The first event after the window expires re-emits with the
 *     accumulated suppressed count from the prior window, then resets.
 *   * Distinct keys are independent.
 *   * When the table reaches max_entries and a new key arrives, the
 *     entry with the oldest window_start_ns is evicted, the eviction
 *     counter increments, and the new key starts cleanly.
 *   * The `event_dedup_hash` helper is deterministic and order-sensitive
 *     so different (event, fields) tuples do not alias.
 */

#include <gtest/gtest.h>

#include <cstdint>

#include "event_dedup.hpp"

using aegis::event_dedup_hash;
using aegis::EventDedupConfig;
using aegis::EventDedupDecision;
using aegis::EventDeduper;

namespace {

constexpr uint64_t kSec = 1'000'000'000ULL;

EventDeduper make_deduper(uint64_t window_ns, std::size_t max_entries = 64)
{
    EventDedupConfig cfg{};
    cfg.window_ns = window_ns;
    cfg.max_entries = max_entries;
    return EventDeduper(cfg);
}

} // namespace

TEST(EventDeduper, DefaultIsDisabled)
{
    EventDeduper d;
    EXPECT_FALSE(d.is_enabled());
    auto dec = d.should_emit(0xdead, 0);
    EXPECT_TRUE(dec.emit);
    EXPECT_EQ(dec.suppressed_during_prior_window, 0u);
    EXPECT_EQ(d.active_keys(), 0u);
    EXPECT_EQ(d.total_suppressed(), 0u);
}

TEST(EventDeduper, ZeroWindowIsDisabledEvenWithCapacity)
{
    auto d = make_deduper(0, 64);
    EXPECT_FALSE(d.is_enabled());
    for (int i = 0; i < 100; ++i) {
        auto dec = d.should_emit(42, static_cast<uint64_t>(i) * 1'000'000ULL);
        EXPECT_TRUE(dec.emit);
        EXPECT_EQ(dec.suppressed_during_prior_window, 0u);
    }
    EXPECT_EQ(d.total_suppressed(), 0u);
    EXPECT_EQ(d.active_keys(), 0u);
}

TEST(EventDeduper, ZeroMaxEntriesIsDisabled)
{
    auto d = make_deduper(kSec, 0);
    EXPECT_FALSE(d.is_enabled());
    auto dec = d.should_emit(7, 0);
    EXPECT_TRUE(dec.emit);
}

TEST(EventDeduper, FirstSightingEmitsWithZeroSuppressed)
{
    auto d = make_deduper(kSec);
    auto dec = d.should_emit(0xfeedface, 1'000);
    EXPECT_TRUE(dec.emit);
    EXPECT_EQ(dec.suppressed_during_prior_window, 0u);
    EXPECT_EQ(d.active_keys(), 1u);
}

TEST(EventDeduper, DuplicatesInWindowAreSuppressed)
{
    auto d = make_deduper(kSec);
    EXPECT_TRUE(d.should_emit(1, 0).emit);
    for (int i = 1; i <= 5; ++i) {
        auto dec = d.should_emit(1, static_cast<uint64_t>(i) * 100'000'000ULL);
        EXPECT_FALSE(dec.emit);
        EXPECT_EQ(dec.suppressed_during_prior_window, 0u);
    }
    EXPECT_EQ(d.total_suppressed(), 5u);
}

TEST(EventDeduper, NextEmitAfterWindowSurfacesSuppressedCount)
{
    auto d = make_deduper(kSec);
    EXPECT_TRUE(d.should_emit(1, 0).emit);
    for (int i = 0; i < 7; ++i) {
        d.should_emit(1, 100'000'000ULL); // all inside the 1s window
    }
    EXPECT_EQ(d.total_suppressed(), 7u);

    auto dec = d.should_emit(1, kSec + 1); // window expired
    EXPECT_TRUE(dec.emit);
    EXPECT_EQ(dec.suppressed_during_prior_window, 7u);

    // Next-next emit (still in new window) re-suppresses, not double-counts.
    auto dec2 = d.should_emit(1, kSec + 2);
    EXPECT_FALSE(dec2.emit);
}

TEST(EventDeduper, DistinctKeysAreIndependent)
{
    auto d = make_deduper(kSec);
    EXPECT_TRUE(d.should_emit(1, 0).emit);
    EXPECT_TRUE(d.should_emit(2, 0).emit);
    EXPECT_FALSE(d.should_emit(1, 100).emit);
    EXPECT_FALSE(d.should_emit(2, 100).emit);
    EXPECT_EQ(d.total_suppressed(), 2u);
    EXPECT_EQ(d.active_keys(), 2u);
}

TEST(EventDeduper, EvictionWhenFull)
{
    auto d = make_deduper(kSec, 2);
    // Fill: keys 1 (t=0) and 2 (t=1ms) tracked.
    EXPECT_TRUE(d.should_emit(1, 0).emit);
    EXPECT_TRUE(d.should_emit(2, 1'000'000).emit);
    EXPECT_EQ(d.active_keys(), 2u);
    // Insert key 3 at t=2ms -> table full, oldest (key 1, t=0) evicted.
    auto dec = d.should_emit(3, 2'000'000);
    EXPECT_TRUE(dec.emit);
    EXPECT_EQ(d.evictions(), 1u);
    EXPECT_EQ(d.active_keys(), 2u);
    // Key 1 is no longer tracked, so it re-emits as fresh.
    auto dec1 = d.should_emit(1, 3'000'000);
    EXPECT_TRUE(dec1.emit);
    EXPECT_EQ(dec1.suppressed_during_prior_window, 0u);
    EXPECT_EQ(d.evictions(), 2u); // inserting key 1 evicted another oldest
}

TEST(EventDeduper, HashIsDeterministicAndDistinguishesPositions)
{
    EXPECT_EQ(event_dedup_hash(1, 2, 3, 4), event_dedup_hash(1, 2, 3, 4));
    EXPECT_NE(event_dedup_hash(1, 2, 3, 4), event_dedup_hash(2, 1, 3, 4));
    EXPECT_NE(event_dedup_hash(1, 2, 3, 4), event_dedup_hash(1, 3, 2, 4));
    EXPECT_NE(event_dedup_hash(1, 2, 3, 4), event_dedup_hash(1, 2, 4, 3));
}

TEST(EventDeduper, NonMonotonicTimestampsDoNotUnderflow)
{
    auto d = make_deduper(kSec);
    EXPECT_TRUE(d.should_emit(99, 5'000'000).emit);
    // Clock-skew style: now < window_start. Should be treated as
    // age=0, i.e. still inside the window -> suppress.
    auto dec = d.should_emit(99, 1'000'000);
    EXPECT_FALSE(dec.emit);
}
