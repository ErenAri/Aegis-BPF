// cppcheck-suppress-file missingIncludeSystem
#include "daemon_policy_gate.hpp"

#include <filesystem>

#include "bpf_ops.hpp"
#include "daemon_runtime.hpp"
#include "logging.hpp"

namespace aegis {

namespace {

void on_exec_identity_event(void* user_ctx, const ExecEvent& ev)
{
    auto* enforcer = static_cast<ExecIdentityEnforcer*>(user_ctx);
    if (!enforcer) {
        return;
    }
    enforcer->on_exec(ev);
}

Result<void> switch_to_audit_only(BpfState& state, AgentConfig& config, SetAgentConfigFullFn set_agent_config_full)
{
    if (set_agent_config_full == nullptr) {
        return Error(ErrorCode::InvalidArgument, "Agent config updater is not configured");
    }
    config.audit_only = 1;
    auto update_result = set_agent_config_full(state, config);
    if (!update_result) {
        logger().log(
            SLOG_ERROR("Failed to switch to audit-only mode").field("error", update_result.error().to_string()));
        return update_result.error();
    }
    return {};
}

Result<void> fail_if_strict_degrade_triggered()
{
    if (forced_exit_code() != 0) {
        return Error(ErrorCode::Unknown, "Strict degrade mode triggered failure");
    }
    return {};
}

} // namespace

Result<PolicyGateOutcome> evaluate_policy_gate(BpfState& state, const KernelFeatures& features,
                                               const std::string& applied_policy_path, bool audit_only,
                                               bool lsm_enabled, bool allow_unknown_binary_identity,
                                               uint8_t enforce_signal, EnforceGateMode enforce_gate_mode,
                                               const AgentConfig& config, SetAgentConfigFullFn set_agent_config_full)
{
    PolicyGateOutcome outcome{};
    outcome.audit_only = audit_only;
    outcome.config = config;

    auto req_result = load_applied_policy_requirements(applied_policy_path);
    if (!req_result) {
        // In audit-only mode we can continue without evaluating policy requirements. This keeps
        // the daemon able to emit a capability report even if the applied policy snapshot exists
        // but is unreadable (e.g., root-owned on a shared host).
        //
        // In enforce mode we must fail closed because we cannot safely gate enforcement without
        // knowing what policy requirements are active.
        if (!outcome.audit_only) {
            logger().log(SLOG_ERROR("Failed to evaluate applied policy requirements")
                             .field("path", applied_policy_path)
                             .field("error", req_result.error().to_string()));
            return req_result.error();
        }

        logger().log(SLOG_WARN("Failed to evaluate applied policy requirements; continuing in audit-only mode")
                         .field("path", applied_policy_path)
                         .field("error", req_result.error().to_string()));
        std::error_code ec;
        outcome.policy_requirements.snapshot_present = std::filesystem::exists(applied_policy_path, ec);
        if (ec) {
            outcome.policy_requirements.snapshot_present = false;
        }
        outcome.policy_requirements.parse_ok = false;
        outcome.policy_requirements.network_required = false;
        outcome.policy_requirements.network_connect_required = false;
        outcome.policy_requirements.network_bind_required = false;
        outcome.policy_requirements.exec_identity_required = false;
        outcome.policy_requirements.exec_allowlist_required = false;
        outcome.policy_requirements.verified_exec_required = false;
        outcome.policy_requirements.verified_exec_runtime_deps_required = false;
        outcome.policy_requirements.protect_connect = false;
        outcome.policy_requirements.protect_runtime_deps = false;
        outcome.policy_requirements.ima_appraisal_required = false;
        outcome.policy_requirements.protect_path_count = 0;
        outcome.policy_requirements.network_rule_count = 0;
        outcome.policy_requirements.allow_binary_hashes.clear();
    } else {
        outcome.policy_requirements = *req_result;
    }

    if (outcome.policy_requirements.network_required) {
        const bool connect_ok =
            !outcome.policy_requirements.network_connect_required || state.socket_connect_hook_attached;
        const bool bind_ok = !outcome.policy_requirements.network_bind_required || state.socket_bind_hook_attached;
        if (!connect_ok || !bind_ok) {
            if (!outcome.audit_only) {
                const std::string detail =
                    "connect_required=" +
                    std::string(outcome.policy_requirements.network_connect_required ? "true" : "false") +
                    ",bind_required=" +
                    std::string(outcome.policy_requirements.network_bind_required ? "true" : "false") +
                    ",connect_hook_attached=" + std::string(state.socket_connect_hook_attached ? "true" : "false") +
                    ",bind_hook_attached=" + std::string(state.socket_bind_hook_attached ? "true" : "false");

                if (enforce_gate_mode == EnforceGateMode::AuditFallback) {
                    outcome.audit_only = true;
                    TRY(switch_to_audit_only(state, outcome.config, set_agent_config_full));

                    emit_runtime_state_change(RuntimeState::AuditFallback, "NETWORK_HOOK_UNAVAILABLE",
                                              "enforce requested; falling back to audit-only mode");
                    logger().log(SLOG_WARN("Network policy hooks unavailable; falling back to audit-only mode")
                                     .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                     .field("policy", applied_policy_path)
                                     .field("detail", detail));
                    TRY(fail_if_strict_degrade_triggered());
                } else {
                    emit_runtime_state_change(RuntimeState::Degraded, "NETWORK_HOOK_UNAVAILABLE", detail);
                    logger().log(SLOG_ERROR("Network policy requires unavailable kernel hooks")
                                     .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                     .field("policy", applied_policy_path)
                                     .field("connect_required", outcome.policy_requirements.network_connect_required)
                                     .field("bind_required", outcome.policy_requirements.network_bind_required)
                                     .field("connect_hook_attached", state.socket_connect_hook_attached)
                                     .field("bind_hook_attached", state.socket_bind_hook_attached));
                    return Error(ErrorCode::PolicyApplyFailed,
                                 "Network policy is active but required kernel hooks are unavailable");
                }
            } else {
                emit_runtime_state_change(RuntimeState::AuditFallback, "NETWORK_HOOK_UNAVAILABLE",
                                          "audit mode fallback for missing network hooks");
                logger().log(SLOG_WARN("Network policy hooks unavailable; running in audit-only fallback")
                                 .field("policy", applied_policy_path)
                                 .field("connect_required", outcome.policy_requirements.network_connect_required)
                                 .field("bind_required", outcome.policy_requirements.network_bind_required)
                                 .field("connect_hook_attached", state.socket_connect_hook_attached)
                                 .field("bind_hook_attached", state.socket_bind_hook_attached));
                TRY(fail_if_strict_degrade_triggered());
            }
        }
    }

    if (outcome.policy_requirements.ima_appraisal_required && !features.ima_appraisal) {
        const std::string detail = "ima_available=" + std::string(features.ima ? "true" : "false") +
                                   ",ima_appraisal=" + std::string(features.ima_appraisal ? "true" : "false");
        if (!outcome.audit_only) {
            if (enforce_gate_mode == EnforceGateMode::AuditFallback) {
                outcome.audit_only = true;
                TRY(switch_to_audit_only(state, outcome.config, set_agent_config_full));

                emit_runtime_state_change(RuntimeState::AuditFallback, "IMA_APPRAISAL_UNAVAILABLE",
                                          "enforce requested; falling back to audit-only mode");
                logger().log(SLOG_WARN("IMA appraisal requirement unmet; falling back to audit-only mode")
                                 .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                 .field("policy", applied_policy_path)
                                 .field("detail", detail));
                TRY(fail_if_strict_degrade_triggered());
            } else {
                emit_runtime_state_change(RuntimeState::Degraded, "IMA_APPRAISAL_UNAVAILABLE", detail);
                logger().log(SLOG_ERROR("Policy requires IMA appraisal but it is unavailable")
                                 .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                 .field("policy", applied_policy_path)
                                 .field("ima_available", features.ima)
                                 .field("ima_appraisal", features.ima_appraisal));
                return Error(ErrorCode::PolicyApplyFailed,
                             "Policy requires IMA appraisal but it is unavailable on this node");
            }
        } else {
            emit_runtime_state_change(RuntimeState::AuditFallback, "IMA_APPRAISAL_UNAVAILABLE",
                                      "audit mode fallback for missing IMA appraisal");
            logger().log(SLOG_WARN("IMA appraisal requirement unmet; running in audit-only fallback")
                             .field("policy", applied_policy_path)
                             .field("detail", detail));
            TRY(fail_if_strict_degrade_triggered());
        }
    }

    if (outcome.policy_requirements.exec_identity_required) {
        outcome.kernel_exec_identity_entries = map_entry_count(state.allow_exec_inode);

        auto exec_mode_result = read_exec_identity_mode_enabled(state);
        if (!exec_mode_result) {
            logger().log(SLOG_ERROR("Failed to read exec identity kernel mode state")
                             .field("error", exec_mode_result.error().to_string()));
            return exec_mode_result.error();
        }

        const bool kernel_hook_ready = lsm_enabled && state.exec_identity_hook_attached &&
                                       state.exec_identity_mode != nullptr && *exec_mode_result;
        outcome.kernel_exec_identity_enabled = kernel_hook_ready;

        const bool runtime_deps_hook_ready = state.exec_identity_runtime_deps_hook_attached;

        if (outcome.policy_requirements.verified_exec_required && !kernel_hook_ready) {
            const std::string detail = "bprm_check_security_hook_attached=" +
                                       std::string(state.exec_identity_hook_attached ? "true" : "false") +
                                       ",exec_mode_enabled=" + std::string(*exec_mode_result ? "true" : "false");
            if (!outcome.audit_only) {
                if (enforce_gate_mode == EnforceGateMode::AuditFallback) {
                    outcome.audit_only = true;
                    TRY(switch_to_audit_only(state, outcome.config, set_agent_config_full));

                    emit_runtime_state_change(RuntimeState::AuditFallback, "EXEC_IDENTITY_UNAVAILABLE",
                                              "enforce requested; falling back to audit-only mode");
                    logger().log(SLOG_WARN("Verified-exec enforcement unavailable; falling back to audit-only mode")
                                     .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                     .field("policy", applied_policy_path)
                                     .field("detail", detail));
                    TRY(fail_if_strict_degrade_triggered());
                } else {
                    emit_runtime_state_change(RuntimeState::Degraded, "EXEC_IDENTITY_UNAVAILABLE", detail);
                    logger().log(SLOG_ERROR("Verified-exec enforcement requires kernel exec identity hook")
                                     .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                     .field("policy", applied_policy_path)
                                     .field("lsm_enabled", lsm_enabled)
                                     .field("hook_attached", state.exec_identity_hook_attached)
                                     .field("exec_mode_enabled", *exec_mode_result));
                    return Error(ErrorCode::PolicyApplyFailed,
                                 "Verified-exec policy is active but kernel exec identity is unavailable");
                }
            } else {
                emit_runtime_state_change(RuntimeState::AuditFallback, "EXEC_IDENTITY_UNAVAILABLE",
                                          "audit mode fallback for missing exec identity hook");
                logger().log(SLOG_WARN("Verified-exec enforcement unavailable; running in audit-only fallback")
                                 .field("policy", applied_policy_path)
                                 .field("detail", detail));
                TRY(fail_if_strict_degrade_triggered());
            }
        }

        if (outcome.policy_requirements.verified_exec_runtime_deps_required && !runtime_deps_hook_ready) {
            const std::string detail = "file_mmap_hook_attached=" +
                                       std::string(state.exec_identity_runtime_deps_hook_attached ? "true" : "false");
            if (!outcome.audit_only) {
                if (enforce_gate_mode == EnforceGateMode::AuditFallback) {
                    outcome.audit_only = true;
                    TRY(switch_to_audit_only(state, outcome.config, set_agent_config_full));

                    emit_runtime_state_change(RuntimeState::AuditFallback, "EXEC_RUNTIME_DEPS_HOOK_UNAVAILABLE",
                                              "enforce requested; falling back to audit-only mode");
                    logger().log(SLOG_WARN("Runtime dependency trust hook unavailable; falling back to audit-only mode")
                                     .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                     .field("policy", applied_policy_path)
                                     .field("detail", detail));
                    TRY(fail_if_strict_degrade_triggered());
                } else {
                    emit_runtime_state_change(RuntimeState::Degraded, "EXEC_RUNTIME_DEPS_HOOK_UNAVAILABLE", detail);
                    logger().log(SLOG_ERROR("Runtime dependency trust requires file_mmap hook")
                                     .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                     .field("policy", applied_policy_path)
                                     .field("hook_attached", state.exec_identity_runtime_deps_hook_attached));
                    return Error(ErrorCode::PolicyApplyFailed,
                                 "Runtime dependency trust is required but file_mmap hook is unavailable");
                }
            } else {
                emit_runtime_state_change(RuntimeState::AuditFallback, "EXEC_RUNTIME_DEPS_HOOK_UNAVAILABLE",
                                          "audit mode fallback for missing runtime dependency trust hook");
                logger().log(SLOG_WARN("Runtime dependency trust hook unavailable; running in audit-only fallback")
                                 .field("policy", applied_policy_path)
                                 .field("detail", detail));
                TRY(fail_if_strict_degrade_triggered());
            }
        }

        if (outcome.policy_requirements.exec_allowlist_required) {
            const bool allowlist_ready = kernel_hook_ready && outcome.kernel_exec_identity_entries > 0;
            if (allowlist_ready) {
                logger().log(
                    SLOG_INFO("Kernel exec allowlist enforcement enabled")
                        .field("policy_hashes",
                               static_cast<int64_t>(outcome.policy_requirements.allow_binary_hashes.size()))
                        .field("allow_exec_inode_entries", static_cast<int64_t>(outcome.kernel_exec_identity_entries))
                        .field("policy", applied_policy_path));
            } else if (!outcome.audit_only && enforce_gate_mode == EnforceGateMode::AuditFallback) {
                outcome.audit_only = true;
                TRY(switch_to_audit_only(state, outcome.config, set_agent_config_full));

                emit_runtime_state_change(RuntimeState::AuditFallback, "EXEC_IDENTITY_UNAVAILABLE",
                                          "enforce requested; userspace audit fallback enabled");
                outcome.exec_identity_enforcer = std::make_unique<ExecIdentityEnforcer>(
                    outcome.policy_requirements.allow_binary_hashes, outcome.audit_only, allow_unknown_binary_identity,
                    enforce_signal);
                outcome.event_callbacks.on_exec = on_exec_identity_event;
                outcome.event_callbacks.user_ctx = outcome.exec_identity_enforcer.get();
                logger().log(
                    SLOG_WARN("Falling back to userspace exec allowlist checks in audit mode")
                        .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                        .field("policy_hashes",
                               static_cast<int64_t>(outcome.policy_requirements.allow_binary_hashes.size()))
                        .field("allow_unknown_binary_identity", allow_unknown_binary_identity)
                        .field("kernel_hook_attached", state.exec_identity_hook_attached)
                        .field("exec_mode_enabled", *exec_mode_result)
                        .field("allow_exec_inode_entries", static_cast<int64_t>(outcome.kernel_exec_identity_entries)));
                TRY(fail_if_strict_degrade_triggered());
            } else if (!outcome.audit_only) {
                emit_runtime_state_change(RuntimeState::Degraded, "EXEC_IDENTITY_UNAVAILABLE",
                                          "kernel hook and allowlist prerequisites not satisfied");
                logger().log(
                    SLOG_ERROR("Exec allowlist policy requires kernel hook and populated allowlist")
                        .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                        .field("policy", applied_policy_path)
                        .field("lsm_enabled", lsm_enabled)
                        .field("hook_attached", state.exec_identity_hook_attached)
                        .field("exec_mode_enabled", *exec_mode_result)
                        .field("allow_exec_inode_entries", static_cast<int64_t>(outcome.kernel_exec_identity_entries)));
                return Error(ErrorCode::PolicyApplyFailed,
                             "Exec allowlist policy is active but kernel enforcement is unavailable");
            } else {
                emit_runtime_state_change(RuntimeState::AuditFallback, "EXEC_IDENTITY_UNAVAILABLE",
                                          "userspace audit fallback enabled");
                outcome.exec_identity_enforcer = std::make_unique<ExecIdentityEnforcer>(
                    outcome.policy_requirements.allow_binary_hashes, outcome.audit_only, allow_unknown_binary_identity,
                    enforce_signal);
                outcome.event_callbacks.on_exec = on_exec_identity_event;
                outcome.event_callbacks.user_ctx = outcome.exec_identity_enforcer.get();
                logger().log(
                    SLOG_WARN("Falling back to userspace exec allowlist checks in audit mode")
                        .field("policy_hashes",
                               static_cast<int64_t>(outcome.policy_requirements.allow_binary_hashes.size()))
                        .field("allow_unknown_binary_identity", allow_unknown_binary_identity)
                        .field("kernel_hook_attached", state.exec_identity_hook_attached)
                        .field("allow_exec_inode_entries", static_cast<int64_t>(outcome.kernel_exec_identity_entries)));
                TRY(fail_if_strict_degrade_triggered());
            }
        }
    }

    return outcome;
}

} // namespace aegis
