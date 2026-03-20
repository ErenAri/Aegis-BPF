// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <thread>

namespace aegis {

class BpfState;

enum class RuntimeState { Enforce, AuditFallback, Degraded };

struct RuntimeStateTracker {
    RuntimeState current = RuntimeState::Enforce;
    uint64_t transition_id = 0;
    uint64_t degradation_count = 0;
    bool strict_mode = false;
    bool enforce_requested = false;
};

const char* runtime_state_name(RuntimeState state);
void reset_runtime_control(bool strict_mode, bool enforce_requested);
RuntimeStateTracker snapshot_runtime_state();
void emit_runtime_state_change(RuntimeState state, const std::string& reason_code, const std::string& detail);
bool exit_requested();
int forced_exit_code();
void handle_signal(int);
void start_deadman_heartbeat(std::thread& heartbeat, BpfState* state, uint32_t ttl_seconds,
                             uint32_t deny_rate_threshold, uint32_t deny_rate_breach_limit);
void stop_deadman_heartbeat(std::thread& heartbeat);

} // namespace aegis
