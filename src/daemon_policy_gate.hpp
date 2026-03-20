// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "daemon.hpp"
#include "daemon_posture.hpp"
#include "daemon_test_hooks.hpp"
#include "events.hpp"
#include "exec_identity.hpp"
#include "result.hpp"
#include "types.hpp"

namespace aegis {

class BpfState;
struct KernelFeatures;

struct PolicyGateOutcome {
    bool audit_only = false;
    AgentConfig config{};
    AppliedPolicyRequirements policy_requirements{};
    bool kernel_exec_identity_enabled = false;
    size_t kernel_exec_identity_entries = 0;
    std::unique_ptr<ExecIdentityEnforcer> exec_identity_enforcer;
    EventCallbacks event_callbacks{};
};

Result<PolicyGateOutcome> evaluate_policy_gate(BpfState& state, const KernelFeatures& features,
                                               const std::string& applied_policy_path, bool audit_only,
                                               bool lsm_enabled, bool allow_unknown_binary_identity,
                                               uint8_t enforce_signal, EnforceGateMode enforce_gate_mode,
                                               const AgentConfig& config, SetAgentConfigFullFn set_agent_config_full);

} // namespace aegis
