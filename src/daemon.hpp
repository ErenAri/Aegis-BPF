// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>

#include "types.hpp"

namespace aegis {

class BpfState;

// LSM hook mode enumeration
enum class LsmHookMode { FileOpen, InodePermission, Both };

enum class EnforceGateMode { FailClosed, AuditFallback };

// Parse LSM hook mode from string
bool parse_lsm_hook(const std::string& value, LsmHookMode& mode);

// Get LSM hook mode name
const char* lsm_hook_name(LsmHookMode mode);

bool parse_enforce_gate_mode(const std::string& value, EnforceGateMode& mode);
const char* enforce_gate_mode_name(EnforceGateMode mode);

// Main daemon run function
int daemon_run(bool audit_only, bool enable_seccomp, uint32_t deadman_ttl, uint8_t enforce_signal, bool allow_sigkill,
               LsmHookMode lsm_hook, uint32_t ringbuf_bytes, uint32_t event_sample_rate,
               uint32_t sigkill_escalation_threshold, uint32_t sigkill_escalation_window_seconds,
               uint32_t deny_rate_threshold = 0, uint32_t deny_rate_breach_limit = 3, bool allow_unsigned_bpf = false,
               bool allow_unknown_binary_identity = false, bool strict_degrade = false,
               EnforceGateMode enforce_gate_mode = EnforceGateMode::FailClosed);

} // namespace aegis
