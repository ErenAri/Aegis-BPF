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

// Event format management. Default is `Aegis` (the AegisBPF-native
// JSON shape described in `config/event-schema.json`). Setting
// `Ocsf` makes the daemon emit OCSF 1.1.0 JSON for File and Network
// Activity events, suitable for direct ingestion by SIEMs that
// natively understand OCSF (Splunk, Elastic, Snowflake, AWS
// Security Lake). See `docs/SIEM_INTEGRATION.md`.
extern EventFormat g_event_format;
bool set_event_format(const std::string& value);
EventFormat current_event_format();

using ExecEventCallback = void (*)(void* user_ctx, const ExecEvent& ev);
using OverlayCopyUpCallback = void (*)(void* user_ctx, const OverlayCopyUpEvent& ev);

struct EventCallbacks {
    ExecEventCallback on_exec = nullptr;
    void* user_ctx = nullptr;
    OverlayCopyUpCallback on_overlay_copy_up = nullptr;
    void* overlay_ctx = nullptr;
};

// Configure the bounded time-window deduper for block events. Pass
// `window_ms == 0` to leave dedup disabled (the default and what
// existing deployments see). Must be called before the daemon's
// ringbuf consumer starts; the deduper is single-threaded.
void configure_block_event_dedup(uint64_t window_ms, std::size_t max_entries);

// Event handling
int handle_event(void* ctx, void* data, size_t size);
int handle_diag_event(void* ctx, void* data, size_t size);
void print_exec_event(const ExecEvent& ev);
void print_exec_argv_event(const ExecArgvEvent& ev);
void print_block_event(const BlockEvent& ev);
void print_net_block_event(const NetBlockEvent& ev);
void print_forensic_event(const ForensicEvent& ev);
void print_kernel_block_event(const KernelBlockEvent& ev);
void print_overlay_copy_up_event(const OverlayCopyUpEvent& ev);
void emit_state_change_event(const std::string& state, const std::string& reason_code, const std::string& detail,
                             bool strict_mode, uint64_t transition_id, uint64_t degradation_count);
void emit_control_change_event(const std::string& payload, const std::string& action, bool enabled, bool prev_enabled,
                               uint32_t uid, uint32_t pid, const std::string& node_name,
                               const std::string& reason_sha256, const std::string& reason);

// Journald integration (only available when HAVE_SYSTEMD is defined)
#ifdef HAVE_SYSTEMD
void journal_send_exec(const ExecEvent& ev, const std::string& payload, const std::string& cgpath,
                       const std::string& comm, const std::string& exec_id);
void journal_send_block(const BlockEvent& ev, const std::string& payload, const std::string& cgpath,
                        const std::string& path, const std::string& resolved_path, const std::string& action,
                        const std::string& comm, const std::string& exec_id, const std::string& parent_exec_id);
#endif

} // namespace aegis
