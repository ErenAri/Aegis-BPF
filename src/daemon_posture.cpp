// cppcheck-suppress-file missingIncludeSystem
#include "daemon_posture.hpp"

#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <filesystem>

#include "bpf_ops.hpp"
#include "policy.hpp"
#include "utils.hpp"

namespace aegis {

std::string applied_policy_path_from_env()
{
    const char* env = std::getenv("AEGIS_POLICY_APPLIED_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kPolicyAppliedPath;
}

std::string capabilities_report_path_from_env()
{
    const char* env = std::getenv("AEGIS_CAPABILITIES_REPORT_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kCapabilitiesReportPath;
}

Result<bool> read_exec_identity_mode_enabled(const BpfState& state)
{
    if (!state.exec_identity_mode) {
        return Error(ErrorCode::BpfMapOperationFailed, "Exec identity mode map not available");
    }
    uint32_t key = 0;
    uint8_t value = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(state.exec_identity_mode), &key, &value) == 0) {
        return value != 0;
    }
    if (errno == ENOENT) {
        return false;
    }
    return Error::system(errno, "Failed to read exec identity mode map");
}

Result<AppliedPolicyRequirements> load_applied_policy_requirements(const std::string& policy_path)
{
    AppliedPolicyRequirements req{};
    std::error_code ec;
    req.snapshot_present = std::filesystem::exists(policy_path, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to check applied policy snapshot", ec.message());
    }
    if (!req.snapshot_present) {
        req.parse_ok = false;
        return req;
    }

    PolicyIssues issues;
    auto parsed = parse_policy_file(policy_path, issues);
    if (!parsed) {
        if (!issues.errors.empty()) {
            return Error(ErrorCode::PolicyParseFailed, "Failed to parse applied policy snapshot",
                         issues.errors.front());
        }
        return parsed.error();
    }

    req.parse_ok = true;
    req.allow_binary_hashes = parsed->allow_binary_hashes;
    req.exec_allowlist_required = !req.allow_binary_hashes.empty();
    req.protect_connect = parsed->protect_connect;
    req.protect_runtime_deps = parsed->protect_runtime_deps;
    req.ima_appraisal_required = parsed->require_ima_appraisal;
    req.protect_path_count = parsed->protect_paths.size();
    req.verified_exec_required = req.protect_connect || req.protect_path_count > 0;
    req.verified_exec_runtime_deps_required = req.verified_exec_required && req.protect_runtime_deps;
    req.exec_identity_required = req.exec_allowlist_required || req.verified_exec_required;
    req.network_rule_count = parsed->network.deny_ips.size() + parsed->network.deny_cidrs.size() +
                             parsed->network.deny_ports.size() + parsed->network.deny_ip_ports.size();

    if (!parsed->network.deny_ips.empty() || !parsed->network.deny_cidrs.empty() ||
        !parsed->network.deny_ip_ports.empty()) {
        req.network_connect_required = true;
    }
    for (const auto& port_rule : parsed->network.deny_ports) {
        if (port_rule.direction == 0 || port_rule.direction == 2) {
            req.network_connect_required = true;
        }
        if (port_rule.direction == 1 || port_rule.direction == 2) {
            req.network_bind_required = true;
        }
    }
    if (parsed->protect_connect) {
        req.network_connect_required = true;
    }
    req.network_required = req.network_connect_required || req.network_bind_required;
    return req;
}

Result<void> write_capabilities_report(const std::string& output_path, const KernelFeatures& features,
                                       EnforcementCapability capability, bool audit_only, bool lsm_enabled,
                                       bool file_open_hook_attached, bool inode_permission_hook_attached,
                                       const BpfState& state, const std::string& applied_policy_path,
                                       const AppliedPolicyRequirements& policy_req, bool kernel_exec_identity_enabled,
                                       size_t kernel_exec_identity_entries,
                                       size_t userspace_exec_identity_allowlist_size,
                                       const CapabilityReportRuntimeState& runtime_state)
{
    std::error_code ec;
    const std::filesystem::path report_path(output_path);
    const std::filesystem::path parent = report_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to create capabilities report directory", ec.message());
        }
    }

    const bool bpffs = check_bpffs_mounted();
    const bool core_supported = features.btf && features.bpf_syscall;
    const bool network_requirements_met =
        (!policy_req.network_connect_required || state.socket_connect_hook_attached) &&
        (!policy_req.network_bind_required || state.socket_bind_hook_attached);
    const bool network_enforce_ready = !policy_req.network_required || network_requirements_met;
    const bool exec_identity_base_requirements_met =
        !policy_req.exec_identity_required || kernel_exec_identity_enabled || audit_only;
    const bool exec_runtime_deps_requirements_met =
        !policy_req.verified_exec_runtime_deps_required || state.exec_identity_runtime_deps_hook_attached || audit_only;
    const bool ima_requirements_met = !policy_req.ima_appraisal_required || features.ima_appraisal || audit_only;
    const bool exec_identity_requirements_met =
        exec_identity_base_requirements_met && exec_runtime_deps_requirements_met;
    const bool exec_identity_enforce_ready =
        (!policy_req.exec_identity_required || kernel_exec_identity_enabled) &&
        (!policy_req.verified_exec_runtime_deps_required || state.exec_identity_runtime_deps_hook_attached);
    const bool ima_enforce_ready = !policy_req.ima_appraisal_required || features.ima_appraisal;

    std::vector<std::string> enforce_blockers;
    if (capability != EnforcementCapability::Full) {
        enforce_blockers.emplace_back("CAPABILITY_AUDIT_ONLY");
    }
    if (!lsm_enabled) {
        enforce_blockers.emplace_back("BPF_LSM_DISABLED");
    }
    if (!core_supported) {
        enforce_blockers.emplace_back("CORE_UNSUPPORTED");
    }
    if (!bpffs) {
        enforce_blockers.emplace_back("BPFFS_UNMOUNTED");
    }
    if (!network_enforce_ready) {
        enforce_blockers.emplace_back("NETWORK_HOOK_UNAVAILABLE");
    }
    if (!exec_identity_enforce_ready) {
        enforce_blockers.emplace_back("EXEC_IDENTITY_UNAVAILABLE");
    }
    if (policy_req.verified_exec_runtime_deps_required && !state.exec_identity_runtime_deps_hook_attached) {
        enforce_blockers.emplace_back("EXEC_RUNTIME_DEPS_HOOK_UNAVAILABLE");
    }
    if (!ima_enforce_ready) {
        enforce_blockers.emplace_back("IMA_APPRAISAL_UNAVAILABLE");
    }
    const bool enforce_capable = enforce_blockers.empty();

    return atomic_write_stream(output_path, [&](std::ostream& out) -> bool {
        out << "{\n";
        out << "  \"schema_version\": 1,\n";
        out << "  \"schema_semver\": \"" << kCapabilitiesSchemaSemver << "\",\n";
        out << "  \"generated_at_unix\": " << static_cast<int64_t>(std::time(nullptr)) << ",\n";
        out << "  \"kernel_version\": \"" << json_escape(features.kernel_version) << "\",\n";
        out << "  \"capability\": \"" << json_escape(capability_name(capability)) << "\",\n";
        out << "  \"audit_only\": " << (audit_only ? "true" : "false") << ",\n";
        out << "  \"enforce_capable\": " << (enforce_capable ? "true" : "false") << ",\n";
        out << "  \"enforce_blockers\": [";
        for (size_t i = 0; i < enforce_blockers.size(); ++i) {
            if (i > 0) {
                out << ", ";
            }
            out << "\"" << json_escape(enforce_blockers[i]) << "\"";
        }
        out << "],\n";
        out << "  \"runtime_state\": \"" << json_escape(runtime_state.current) << "\",\n";
        out << "  \"lsm_enabled\": " << (lsm_enabled ? "true" : "false") << ",\n";
        out << "  \"core_supported\": " << (core_supported ? "true" : "false") << ",\n";
        out << "  \"features\": {\n";
        out << "    \"bpf_lsm\": " << (features.bpf_lsm ? "true" : "false") << ",\n";
        out << "    \"cgroup_v2\": " << (features.cgroup_v2 ? "true" : "false") << ",\n";
        out << "    \"btf\": " << (features.btf ? "true" : "false") << ",\n";
        out << "    \"bpf_syscall\": " << (features.bpf_syscall ? "true" : "false") << ",\n";
        out << "    \"ringbuf\": " << (features.ringbuf ? "true" : "false") << ",\n";
        out << "    \"tracepoints\": " << (features.tracepoints ? "true" : "false") << ",\n";
        out << "    \"bpffs\": " << (bpffs ? "true" : "false") << ",\n";
        out << "    \"ima\": " << (features.ima ? "true" : "false") << ",\n";
        out << "    \"ima_appraisal\": " << (features.ima_appraisal ? "true" : "false") << "\n";
        out << "  },\n";
        out << "  \"hooks\": {\n";
        out << "    \"lsm_file_open\": " << (file_open_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_inode_permission\": " << (inode_permission_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_bprm_check_security\": " << (state.exec_identity_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_file_mmap\": " << (state.exec_identity_runtime_deps_hook_attached ? "true" : "false")
            << ",\n";
        out << "    \"lsm_socket_connect\": " << (state.socket_connect_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_socket_bind\": " << (state.socket_bind_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_socket_listen\": " << (state.socket_listen_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_socket_accept\": " << (state.socket_accept_hook_attached ? "true" : "false") << ",\n";
        out << "    \"lsm_socket_sendmsg\": " << (state.socket_sendmsg_hook_attached ? "true" : "false") << "\n";
        out << "  },\n";
        out << "  \"policy\": {\n";
        out << "    \"applied_path\": \"" << json_escape(applied_policy_path) << "\",\n";
        out << "    \"snapshot_present\": " << (policy_req.snapshot_present ? "true" : "false") << ",\n";
        out << "    \"parse_ok\": " << (policy_req.parse_ok ? "true" : "false") << ",\n";
        out << "    \"network_rule_count\": " << static_cast<int64_t>(policy_req.network_rule_count) << ",\n";
        out << "    \"protect_path_count\": " << static_cast<int64_t>(policy_req.protect_path_count) << ",\n";
        out << "    \"protect_connect\": " << (policy_req.protect_connect ? "true" : "false") << ",\n";
        out << "    \"protect_runtime_deps\": " << (policy_req.protect_runtime_deps ? "true" : "false") << ",\n";
        out << "    \"require_ima_appraisal\": " << (policy_req.ima_appraisal_required ? "true" : "false") << ",\n";
        out << "    \"allow_binary_hash_count\": " << static_cast<int64_t>(policy_req.allow_binary_hashes.size())
            << "\n";
        out << "  },\n";
        out << "  \"requirements\": {\n";
        out << "    \"network_enforcement_required\": " << (policy_req.network_required ? "true" : "false") << ",\n";
        out << "    \"network_connect_required\": " << (policy_req.network_connect_required ? "true" : "false")
            << ",\n";
        out << "    \"network_bind_required\": " << (policy_req.network_bind_required ? "true" : "false") << ",\n";
        out << "    \"exec_identity_required\": " << (policy_req.exec_identity_required ? "true" : "false") << ",\n";
        out << "    \"exec_allowlist_required\": " << (policy_req.exec_allowlist_required ? "true" : "false") << ",\n";
        out << "    \"verified_exec_required\": " << (policy_req.verified_exec_required ? "true" : "false") << ",\n";
        out << "    \"verified_exec_runtime_deps_required\": "
            << (policy_req.verified_exec_runtime_deps_required ? "true" : "false") << ",\n";
        out << "    \"ima_appraisal_required\": " << (policy_req.ima_appraisal_required ? "true" : "false") << "\n";
        out << "  },\n";
        out << "  \"requirements_met\": {\n";
        out << "    \"network\": " << (network_requirements_met ? "true" : "false") << ",\n";
        out << "    \"exec_identity\": " << (exec_identity_requirements_met ? "true" : "false") << ",\n";
        out << "    \"exec_runtime_deps\": " << (exec_runtime_deps_requirements_met ? "true" : "false") << ",\n";
        out << "    \"ima_appraisal\": " << (ima_requirements_met ? "true" : "false") << "\n";
        out << "  },\n";
        out << "  \"exec_identity\": {\n";
        out << "    \"kernel_enabled\": " << (kernel_exec_identity_enabled ? "true" : "false") << ",\n";
        out << "    \"kernel_allow_exec_inode_entries\": " << static_cast<int64_t>(kernel_exec_identity_entries)
            << ",\n";
        out << "    \"runtime_deps_hook_attached\": "
            << (state.exec_identity_runtime_deps_hook_attached ? "true" : "false") << ",\n";
        out << "    \"userspace_fallback_allowlist_entries\": "
            << static_cast<int64_t>(userspace_exec_identity_allowlist_size) << "\n";
        out << "  },\n";
        out << "  \"state_transitions\": {\n";
        out << "    \"total\": " << static_cast<int64_t>(runtime_state.transition_id) << ",\n";
        out << "    \"degradation_total\": " << static_cast<int64_t>(runtime_state.degradation_count) << ",\n";
        out << "    \"strict_mode\": " << (runtime_state.strict_mode ? "true" : "false") << ",\n";
        out << "    \"enforce_requested\": " << (runtime_state.enforce_requested ? "true" : "false") << "\n";
        out << "  }\n";
        out << "}\n";
        return out.good();
    });
}

} // namespace aegis
