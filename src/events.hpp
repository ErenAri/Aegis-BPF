// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "types.hpp"

namespace aegis {

// Event log sink management
extern EventLogSink g_event_sink;

bool sink_wants_stdout(EventLogSink sink);
bool sink_wants_journald(EventLogSink sink);
bool set_event_log_sink(const std::string& value);

using ExecEventCallback = void (*)(void* user_ctx, const ExecEvent& ev);

struct EventCallbacks {
    ExecEventCallback on_exec = nullptr;
    void* user_ctx = nullptr;
};

// Event handling
int handle_event(void* ctx, void* data, size_t size);
void print_exec_event(const ExecEvent& ev);
void print_block_event(const BlockEvent& ev);
void print_net_block_event(const NetBlockEvent& ev);
void emit_state_change_event(const std::string& state, const std::string& reason_code, const std::string& detail,
                             bool strict_mode, uint64_t transition_id, uint64_t degradation_count);

// Journald integration (only available when HAVE_SYSTEMD is defined)
#ifdef HAVE_SYSTEMD
void journal_send_exec(const ExecEvent& ev, const std::string& payload, const std::string& cgpath,
                       const std::string& comm, const std::string& exec_id);
void journal_send_block(const BlockEvent& ev, const std::string& payload, const std::string& cgpath,
                        const std::string& path, const std::string& resolved_path, const std::string& action,
                        const std::string& comm, const std::string& exec_id, const std::string& parent_exec_id);
#endif

} // namespace aegis
