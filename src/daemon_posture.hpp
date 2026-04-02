// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "kernel_features.hpp"
#include "result.hpp"

namespace aegis {

class BpfState;

struct AppliedPolicyRequirements {
    bool snapshot_present = false;
    bool parse_ok = false;
    bool network_required = false;
    bool network_connect_required = false;
    bool network_bind_required = false;
    bool exec_identity_required = false;
    bool exec_allowlist_required = false;
    bool verified_exec_required = false;
    bool verified_exec_runtime_deps_required = false;
    bool protect_connect = false;
    bool protect_runtime_deps = false;
    bool ima_appraisal_required = false;
    size_t protect_path_count = 0;
    size_t network_rule_count = 0;
    std::vector<std::string> allow_binary_hashes;
    // Cgroup-scoped deny rule counts (v6+ policies)
    size_t cgroup_deny_inode_count = 0;
    size_t cgroup_deny_ip_count = 0;
    size_t cgroup_deny_port_count = 0;
};

struct CapabilityReportRuntimeState {
    std::string current;
    uint64_t transition_id = 0;
    uint64_t degradation_count = 0;
    bool strict_mode = false;
    bool enforce_requested = false;
};

std::string applied_policy_path_from_env();
std::string capabilities_report_path_from_env();
Result<bool> read_exec_identity_mode_enabled(const BpfState& state);
Result<AppliedPolicyRequirements> load_applied_policy_requirements(const std::string& policy_path);
Result<void> write_capabilities_report(const std::string& output_path, const KernelFeatures& features,
                                       EnforcementCapability capability, bool audit_only, bool lsm_enabled,
                                       bool file_open_hook_attached, bool inode_permission_hook_attached,
                                       const BpfState& state, const std::string& applied_policy_path,
                                       const AppliedPolicyRequirements& policy_req, bool kernel_exec_identity_enabled,
                                       size_t kernel_exec_identity_entries,
                                       size_t userspace_exec_identity_allowlist_size,
                                       const CapabilityReportRuntimeState& runtime_state);

} // namespace aegis
