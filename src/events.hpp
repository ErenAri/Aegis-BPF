#pragma once

#include "types.hpp"

#include <string>

namespace aegis {

// Event log sink management
extern EventLogSink g_event_sink;

bool sink_wants_stdout(EventLogSink sink);
bool sink_wants_journald(EventLogSink sink);
bool set_event_log_sink(const std::string& value);

// Event handling
int handle_event(void* ctx, void* data, size_t size);
void print_exec_event(const ExecEvent& ev);
void print_block_event(const BlockEvent& ev);

// Journald integration (only available when HAVE_SYSTEMD is defined)
#ifdef HAVE_SYSTEMD
void journal_send_exec(const ExecEvent& ev, const std::string& payload, const std::string& cgpath,
                       const std::string& comm, const std::string& exec_id);
void journal_send_block(const BlockEvent& ev, const std::string& payload, const std::string& cgpath,
                        const std::string& path, const std::string& resolved_path, const std::string& action,
                        const std::string& comm, const std::string& exec_id, const std::string& parent_exec_id);
#endif

}  // namespace aegis
