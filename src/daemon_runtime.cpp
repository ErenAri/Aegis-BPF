// cppcheck-suppress-file missingIncludeSystem
#include "daemon_runtime.hpp"

#include <unistd.h>

#include <atomic>
#include <csignal>
#include <ctime>
#include <mutex>

#include "bpf_ops.hpp"
#include "events.hpp"
#include "logging.hpp"

namespace aegis {

namespace {
volatile sig_atomic_t g_exiting = 0;
std::atomic<bool> g_heartbeat_running{false};
std::atomic<int> g_forced_exit_code{0};
std::mutex g_runtime_state_mu;
RuntimeStateTracker g_runtime_state;

void heartbeat_thread(BpfState* state, uint32_t ttl_seconds, uint32_t deny_rate_threshold,
                      uint32_t deny_rate_breach_limit)
{
    uint32_t sleep_interval = ttl_seconds / 2;
    if (sleep_interval < 1) {
        sleep_interval = 1;
    }

    uint64_t last_block_count = 0;
    uint32_t rate_breach_count = 0;
    bool deny_rate_state_emitted = false;
    bool map_capacity_state_emitted = false;

    if (deny_rate_threshold > 0 && state->block_stats) {
        auto stats = read_block_stats_map(state->block_stats);
        if (stats) {
            last_block_count = stats->blocks;
        }
    }

    while (g_heartbeat_running.load() && !g_exiting) {
        struct timespec ts {};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
        uint64_t new_deadline = now_ns + (static_cast<uint64_t>(ttl_seconds) * 1000000000ULL);

        auto result = update_deadman_deadline(*state, new_deadline);
        if (!result) {
            logger().log(SLOG_WARN("Failed to update deadman deadline").field("error", result.error().to_string()));
        }

        if (deny_rate_threshold > 0 && state->block_stats) {
            auto stats = read_block_stats_map(state->block_stats);
            if (stats) {
                uint64_t current_blocks = stats->blocks;
                uint64_t delta = current_blocks - last_block_count;
                double rate = static_cast<double>(delta) / static_cast<double>(sleep_interval);
                if (rate > static_cast<double>(deny_rate_threshold)) {
                    ++rate_breach_count;
                    logger().log(SLOG_WARN("Deny rate exceeded threshold")
                                     .field("rate", rate)
                                     .field("threshold", static_cast<int64_t>(deny_rate_threshold))
                                     .field("breach_count", static_cast<int64_t>(rate_breach_count))
                                     .field("breach_limit", static_cast<int64_t>(deny_rate_breach_limit)));
                    if (rate_breach_count >= deny_rate_breach_limit) {
                        AgentConfig cfg{};
                        cfg.audit_only = 1;
                        cfg.deadman_enabled = 1;
                        cfg.deadman_deadline_ns = new_deadline;
                        cfg.deadman_ttl_seconds = ttl_seconds;
                        cfg.event_sample_rate = 1;
                        auto revert_result = set_agent_config_full(*state, cfg);
                        if (revert_result) {
                            logger().log(SLOG_ERROR("Auto-revert: deny rate exceeded threshold, switched to audit-only")
                                             .field("rate", rate)
                                             .field("threshold", static_cast<int64_t>(deny_rate_threshold)));
                            if (!deny_rate_state_emitted) {
                                deny_rate_state_emitted = true;
                                emit_runtime_state_change(RuntimeState::AuditFallback, "DENY_RATE_THRESHOLD_EXCEEDED",
                                                          "rate=" + std::to_string(rate) +
                                                              ",threshold=" + std::to_string(deny_rate_threshold));
                            }
                        } else {
                            logger().log(
                                SLOG_ERROR("Auto-revert failed").field("error", revert_result.error().to_string()));
                        }
                        deny_rate_threshold = 0;
                    }
                } else {
                    rate_breach_count = 0;
                }
                last_block_count = current_blocks;
            }
        }

        auto pressure = check_map_pressure(*state);
        if (pressure.any_full) {
            for (const auto& m : pressure.maps) {
                if (m.utilization >= 1.0) {
                    logger().log(SLOG_ERROR("Map at capacity - new entries will be rejected")
                                     .field("map", m.name)
                                     .field("entries", static_cast<int64_t>(m.entry_count))
                                     .field("max_entries", static_cast<int64_t>(m.max_entries)));
                    if (!map_capacity_state_emitted) {
                        map_capacity_state_emitted = true;
                        emit_runtime_state_change(RuntimeState::Degraded, "MAP_CAPACITY_EXCEEDED",
                                                  "map=" + m.name + ",entries=" + std::to_string(m.entry_count) +
                                                      ",max=" + std::to_string(m.max_entries));
                    }
                }
            }
        } else if (pressure.any_critical) {
            for (const auto& m : pressure.maps) {
                if (m.utilization >= 0.95) {
                    logger().log(SLOG_ERROR("Map near capacity")
                                     .field("map", m.name)
                                     .field("entries", static_cast<int64_t>(m.entry_count))
                                     .field("max_entries", static_cast<int64_t>(m.max_entries))
                                     .field("utilization_pct", static_cast<int64_t>(m.utilization * 100)));
                }
            }
        } else if (pressure.any_warning) {
            for (const auto& m : pressure.maps) {
                if (m.utilization >= 0.80) {
                    logger().log(SLOG_WARN("Map utilization high")
                                     .field("map", m.name)
                                     .field("entries", static_cast<int64_t>(m.entry_count))
                                     .field("max_entries", static_cast<int64_t>(m.max_entries))
                                     .field("utilization_pct", static_cast<int64_t>(m.utilization * 100)));
                }
            }
        }

        for (uint32_t i = 0; i < sleep_interval && g_heartbeat_running.load() && !g_exiting; ++i) {
            sleep(1);
        }
    }
}

} // namespace

const char* runtime_state_name(RuntimeState state)
{
    switch (state) {
        case RuntimeState::Enforce:
            return "ENFORCE";
        case RuntimeState::AuditFallback:
            return "AUDIT_FALLBACK";
        case RuntimeState::Degraded:
            return "DEGRADED";
    }
    return "DEGRADED";
}

void reset_runtime_control(bool strict_mode, bool enforce_requested)
{
    g_exiting = 0;
    g_heartbeat_running.store(false);
    g_forced_exit_code.store(0);

    std::lock_guard<std::mutex> lock(g_runtime_state_mu);
    g_runtime_state = RuntimeStateTracker{};
    g_runtime_state.strict_mode = strict_mode;
    g_runtime_state.enforce_requested = enforce_requested;
}

RuntimeStateTracker snapshot_runtime_state()
{
    std::lock_guard<std::mutex> lock(g_runtime_state_mu);
    return g_runtime_state;
}

void emit_runtime_state_change(RuntimeState state, const std::string& reason_code, const std::string& detail)
{
    RuntimeStateTracker snapshot;
    {
        std::lock_guard<std::mutex> lock(g_runtime_state_mu);
        g_runtime_state.current = state;
        ++g_runtime_state.transition_id;
        if (state == RuntimeState::AuditFallback || state == RuntimeState::Degraded) {
            ++g_runtime_state.degradation_count;
        }
        snapshot = g_runtime_state;
    }

    emit_state_change_event(runtime_state_name(state), reason_code, detail, snapshot.strict_mode,
                            snapshot.transition_id, snapshot.degradation_count);

    logger().log(SLOG_INFO("AEGIS_STATE_CHANGE")
                     .field("event", "AEGIS_STATE_CHANGE")
                     .field("event_version", static_cast<int64_t>(1))
                     .field("state", runtime_state_name(state))
                     .field("reason_code", reason_code)
                     .field("detail", detail)
                     .field("strict_mode", snapshot.strict_mode)
                     .field("transition_id", static_cast<int64_t>(snapshot.transition_id))
                     .field("degradation_count", static_cast<int64_t>(snapshot.degradation_count)));

    if (snapshot.strict_mode && snapshot.enforce_requested &&
        (state == RuntimeState::AuditFallback || state == RuntimeState::Degraded)) {
        logger().log(SLOG_ERROR("Strict degrade mode triggered failure")
                         .field("reason_code", reason_code)
                         .field("state", runtime_state_name(state)));
        g_forced_exit_code.store(1);
        g_exiting = 1;
    }
}

bool exit_requested()
{
    return g_exiting != 0;
}

int forced_exit_code()
{
    return g_forced_exit_code.load();
}

void handle_signal(int)
{
    g_exiting = 1;
}

void start_deadman_heartbeat(std::thread& heartbeat, BpfState* state, uint32_t ttl_seconds,
                             uint32_t deny_rate_threshold, uint32_t deny_rate_breach_limit)
{
    if (ttl_seconds == 0 || state == nullptr) {
        return;
    }
    g_heartbeat_running.store(true);
    heartbeat = std::thread(heartbeat_thread, state, ttl_seconds, deny_rate_threshold, deny_rate_breach_limit);
}

void stop_deadman_heartbeat(std::thread& heartbeat)
{
    g_heartbeat_running.store(false);
    if (heartbeat.joinable()) {
        heartbeat.join();
    }
}

} // namespace aegis
