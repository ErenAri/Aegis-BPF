// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

class BpfState;

Result<void> set_agent_config(BpfState& state, bool audit_only);
Result<void> set_exec_identity_flags(BpfState& state, uint8_t flags);
Result<void> set_agent_config_full(BpfState& state, const AgentConfig& config);
Result<void> set_emergency_disable(BpfState& state, bool disable);
Result<bool> read_emergency_disable(BpfState& state);
Result<void> refresh_policy_empty_hints(BpfState& state);
Result<void> update_deadman_deadline(BpfState& state, uint64_t deadline_ns);
Result<void> ensure_layout_version(BpfState& state);

} // namespace aegis
