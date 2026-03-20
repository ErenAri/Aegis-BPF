// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Daemon implementation
 *
 * Main daemon run loop and related functionality.
 */

#include "daemon.hpp"

#include <bpf/libbpf.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>

#include "bpf_ops.hpp"
#include "daemon_policy_gate.hpp"
#include "daemon_posture.hpp"
#include "daemon_runtime.hpp"
#include "daemon_test_hooks.hpp"
#include "events.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "seccomp.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {
Result<void> setup_agent_cgroup(BpfState& state);

// Production defaults for daemon dependencies
DaemonDeps make_default_deps()
{
    DaemonDeps d;
    d.validate_config_dir = validate_config_directory_permissions;
    d.detect_kernel_features = aegis::detect_kernel_features;
    d.detect_break_glass = aegis::detect_break_glass;
    d.bump_memlock_rlimit = aegis::bump_memlock_rlimit;
    d.load_bpf = aegis::load_bpf;
    d.ensure_layout_version = aegis::ensure_layout_version;
    d.set_agent_config_full = aegis::set_agent_config_full;
    d.populate_survival_allowlist = aegis::populate_survival_allowlist;
    d.setup_agent_cgroup = setup_agent_cgroup;
    d.attach_all = aegis::attach_all;
    return d;
}

DaemonDeps g_deps = make_default_deps();

class ScopedEnvOverride {
  public:
    ScopedEnvOverride(const char* key, const char* value) : key_(key)
    {
        const char* existing = std::getenv(key_);
        if (existing != nullptr) {
            had_previous_ = true;
            previous_ = existing;
        }
        ::setenv(key_, value, 1);
    }

    ~ScopedEnvOverride()
    {
        if (had_previous_) {
            ::setenv(key_, previous_.c_str(), 1);
        } else {
            ::unsetenv(key_);
        }
    }

    ScopedEnvOverride(const ScopedEnvOverride&) = delete;
    ScopedEnvOverride& operator=(const ScopedEnvOverride&) = delete;

  private:
    const char* key_;
    bool had_previous_ = false;
    std::string previous_;
};

Result<void> setup_agent_cgroup(BpfState& state)
{
    static constexpr const char* kAgentCgroup = "/sys/fs/cgroup/aegis_agent";

    std::error_code ec;
    std::filesystem::create_directories(kAgentCgroup, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to create cgroup", ec.message());
    }

    std::ofstream procs(std::string(kAgentCgroup) + "/cgroup.procs", std::ios::out | std::ios::trunc);
    if (!procs.is_open()) {
        return Error(ErrorCode::IoError, "Failed to open cgroup.procs", kAgentCgroup);
    }
    procs << getpid();
    procs.close();

    struct stat st {};
    if (stat(kAgentCgroup, &st) != 0) {
        return Error::system(errno, "stat failed for " + std::string(kAgentCgroup));
    }

    uint64_t cgid = static_cast<uint64_t>(st.st_ino);

    TRY(bump_memlock_rlimit());

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_cgroup_map");
    }

    return {};
}

const char* enforce_signal_name(uint8_t signal)
{
    switch (signal) {
        case kEnforceSignalNone:
            return "none";
        case kEnforceSignalInt:
            return "sigint";
        case kEnforceSignalKill:
            return "sigkill";
        default:
            return "sigterm";
    }
}

Result<void> validate_attach_contract(const BpfState& state, bool lsm_enabled, bool use_inode_permission,
                                      bool use_file_open)
{
    if (!state.attach_contract_valid) {
        return Error(ErrorCode::BpfAttachFailed, "Attach contract metadata missing");
    }
    const uint8_t expected = lsm_enabled
                                 ? static_cast<uint8_t>((use_inode_permission ? 1 : 0) + (use_file_open ? 1 : 0))
                                 : static_cast<uint8_t>(1);
    if (state.file_hooks_expected != expected) {
        return Error(ErrorCode::BpfAttachFailed, "Attach contract expected-hook mismatch",
                     "expected=" + std::to_string(expected) +
                         ", reported=" + std::to_string(state.file_hooks_expected));
    }
    if (state.file_hooks_attached != expected) {
        return Error(ErrorCode::BpfAttachFailed, "Attach contract attached-hook mismatch",
                     "expected=" + std::to_string(expected) +
                         ", attached=" + std::to_string(state.file_hooks_attached));
    }
    return {};
}

} // namespace

const char* lsm_hook_name(LsmHookMode mode)
{
    switch (mode) {
        case LsmHookMode::FileOpen:
            return "file_open";
        case LsmHookMode::InodePermission:
            return "inode_permission";
        case LsmHookMode::Both:
            return "both";
        default:
            return "unknown";
    }
}

bool parse_lsm_hook(const std::string& value, LsmHookMode& out)
{
    if (value == "file" || value == "file_open") {
        out = LsmHookMode::FileOpen;
        return true;
    }
    if (value == "inode" || value == "inode_permission") {
        out = LsmHookMode::InodePermission;
        return true;
    }
    if (value == "both") {
        out = LsmHookMode::Both;
        return true;
    }
    return false;
}

const char* enforce_gate_mode_name(EnforceGateMode mode)
{
    switch (mode) {
        case EnforceGateMode::FailClosed:
            return "fail-closed";
        case EnforceGateMode::AuditFallback:
            return "audit-fallback";
    }
    return "fail-closed";
}

bool parse_enforce_gate_mode(const std::string& value, EnforceGateMode& out)
{
    if (value == "fail-closed" || value == "fail_closed" || value == "failclosed") {
        out = EnforceGateMode::FailClosed;
        return true;
    }
    if (value == "audit-fallback" || value == "audit_fallback" || value == "auditfallback" || value == "audit") {
        out = EnforceGateMode::AuditFallback;
        return true;
    }
    return false;
}

// --- DaemonDeps struct-based API ---

DaemonDeps& daemon_deps()
{
    return g_deps;
}

void set_daemon_deps_for_test(const DaemonDeps& deps)
{
    auto defaults = make_default_deps();
    g_deps.validate_config_dir = deps.validate_config_dir ? deps.validate_config_dir : defaults.validate_config_dir;
    g_deps.detect_kernel_features =
        deps.detect_kernel_features ? deps.detect_kernel_features : defaults.detect_kernel_features;
    g_deps.detect_break_glass = deps.detect_break_glass ? deps.detect_break_glass : defaults.detect_break_glass;
    g_deps.bump_memlock_rlimit = deps.bump_memlock_rlimit ? deps.bump_memlock_rlimit : defaults.bump_memlock_rlimit;
    g_deps.load_bpf = deps.load_bpf ? deps.load_bpf : defaults.load_bpf;
    g_deps.ensure_layout_version =
        deps.ensure_layout_version ? deps.ensure_layout_version : defaults.ensure_layout_version;
    g_deps.set_agent_config_full =
        deps.set_agent_config_full ? deps.set_agent_config_full : defaults.set_agent_config_full;
    g_deps.populate_survival_allowlist =
        deps.populate_survival_allowlist ? deps.populate_survival_allowlist : defaults.populate_survival_allowlist;
    g_deps.setup_agent_cgroup = deps.setup_agent_cgroup ? deps.setup_agent_cgroup : defaults.setup_agent_cgroup;
    g_deps.attach_all = deps.attach_all ? deps.attach_all : defaults.attach_all;
}

void reset_daemon_deps_for_test()
{
    g_deps = make_default_deps();
}

// --- Legacy per-function API (delegates to DaemonDeps) ---

void set_validate_config_directory_permissions_for_test(ValidateConfigDirectoryPermissionsFn fn)
{
    g_deps.validate_config_dir = fn ? fn : make_default_deps().validate_config_dir;
}

void reset_validate_config_directory_permissions_for_test()
{
    g_deps.validate_config_dir = make_default_deps().validate_config_dir;
}

void set_detect_kernel_features_for_test(DetectKernelFeaturesFn fn)
{
    g_deps.detect_kernel_features = fn ? fn : make_default_deps().detect_kernel_features;
}

void reset_detect_kernel_features_for_test()
{
    g_deps.detect_kernel_features = make_default_deps().detect_kernel_features;
}

void set_detect_break_glass_for_test(DetectBreakGlassFn fn)
{
    g_deps.detect_break_glass = fn ? fn : make_default_deps().detect_break_glass;
}

void reset_detect_break_glass_for_test()
{
    g_deps.detect_break_glass = make_default_deps().detect_break_glass;
}

void set_bump_memlock_rlimit_for_test(BumpMemlockRlimitFn fn)
{
    g_deps.bump_memlock_rlimit = fn ? fn : make_default_deps().bump_memlock_rlimit;
}

void reset_bump_memlock_rlimit_for_test()
{
    g_deps.bump_memlock_rlimit = make_default_deps().bump_memlock_rlimit;
}

void set_load_bpf_for_test(LoadBpfFn fn)
{
    g_deps.load_bpf = fn ? fn : make_default_deps().load_bpf;
}

void reset_load_bpf_for_test()
{
    g_deps.load_bpf = make_default_deps().load_bpf;
}

void set_ensure_layout_version_for_test(EnsureLayoutVersionFn fn)
{
    g_deps.ensure_layout_version = fn ? fn : make_default_deps().ensure_layout_version;
}

void reset_ensure_layout_version_for_test()
{
    g_deps.ensure_layout_version = make_default_deps().ensure_layout_version;
}

void set_set_agent_config_full_for_test(SetAgentConfigFullFn fn)
{
    g_deps.set_agent_config_full = fn ? fn : make_default_deps().set_agent_config_full;
}

void reset_set_agent_config_full_for_test()
{
    g_deps.set_agent_config_full = make_default_deps().set_agent_config_full;
}

void set_populate_survival_allowlist_for_test(PopulateSurvivalAllowlistFn fn)
{
    g_deps.populate_survival_allowlist = fn ? fn : make_default_deps().populate_survival_allowlist;
}

void reset_populate_survival_allowlist_for_test()
{
    g_deps.populate_survival_allowlist = make_default_deps().populate_survival_allowlist;
}

void set_setup_agent_cgroup_for_test(SetupAgentCgroupFn fn)
{
    g_deps.setup_agent_cgroup = fn ? fn : make_default_deps().setup_agent_cgroup;
}

void reset_setup_agent_cgroup_for_test()
{
    g_deps.setup_agent_cgroup = make_default_deps().setup_agent_cgroup;
}

void set_attach_all_for_test(AttachAllFn fn)
{
    g_deps.attach_all = fn ? fn : make_default_deps().attach_all;
}

void reset_attach_all_for_test()
{
    g_deps.attach_all = make_default_deps().attach_all;
}

int daemon_run(bool audit_only, bool enable_seccomp, uint32_t deadman_ttl, uint8_t enforce_signal, bool allow_sigkill,
               LsmHookMode lsm_hook, uint32_t ringbuf_bytes, uint32_t event_sample_rate,
               uint32_t sigkill_escalation_threshold, uint32_t sigkill_escalation_window_seconds,
               uint32_t deny_rate_threshold, uint32_t deny_rate_breach_limit, bool allow_unsigned_bpf,
               bool allow_unknown_binary_identity, bool strict_degrade, EnforceGateMode enforce_gate_mode)
{
    const std::string trace_id = make_span_id("trace-daemon");
    ScopedSpan root_span("daemon.run", trace_id);
    auto fail = [&](const std::string& message) -> int {
        root_span.fail(message);
        return 1;
    };

    const bool enforce_requested = !audit_only;
    reset_runtime_control(strict_degrade, enforce_requested);

    // Check for break-glass mode FIRST
    bool break_glass_active = g_deps.detect_break_glass();
    if (break_glass_active) {
        logger().log(SLOG_WARN("Break-glass mode detected - forcing audit-only mode"));
        audit_only = true;
        emit_runtime_state_change(RuntimeState::AuditFallback, "BREAK_GLASS_ACTIVE",
                                  "break_glass marker file detected");
    }

    if (enforce_signal != kEnforceSignalNone && enforce_signal != kEnforceSignalInt &&
        enforce_signal != kEnforceSignalKill && enforce_signal != kEnforceSignalTerm) {
        logger().log(SLOG_WARN("Invalid enforce signal configured; using SIGTERM")
                         .field("signal", static_cast<int64_t>(enforce_signal)));
        enforce_signal = kEnforceSignalTerm;
    }
    if (enforce_signal == kEnforceSignalKill) {
        if (!kSigkillEnforcementCompiledIn) {
            logger().log(SLOG_ERROR("SIGKILL enforcement is disabled in this build")
                             .field("cmake_option", "ENABLE_SIGKILL_ENFORCEMENT=ON")
                             .field("runtime_gate", "--allow-sigkill"));
            return fail("SIGKILL enforcement is disabled in this build");
        }
        if (!allow_sigkill) {
            logger().log(SLOG_ERROR("SIGKILL enforcement requires explicit runtime gate")
                             .field("required_flag", "--allow-sigkill"));
            return fail("SIGKILL enforcement requires --allow-sigkill");
        }
    }
    if (allow_sigkill && enforce_signal != kEnforceSignalKill) {
        logger().log(SLOG_WARN("Ignoring --allow-sigkill because enforce signal is not kill")
                         .field("enforce_signal", enforce_signal_name(enforce_signal)));
    }
    if (sigkill_escalation_threshold == 0) {
        logger().log(SLOG_WARN("Invalid SIGKILL escalation threshold; using default")
                         .field("value", static_cast<int64_t>(sigkill_escalation_threshold))
                         .field("default", static_cast<int64_t>(kSigkillEscalationThresholdDefault)));
        sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
    }
    if (sigkill_escalation_window_seconds == 0) {
        logger().log(SLOG_WARN("Invalid SIGKILL escalation window; using default")
                         .field("value", static_cast<int64_t>(sigkill_escalation_window_seconds))
                         .field("default", static_cast<int64_t>(kSigkillEscalationWindowSecondsDefault)));
        sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    }

    // Validate config directory permissions (security check)
    {
        ScopedSpan config_span("daemon.validate_config_dir", trace_id, root_span.span_id());
        auto config_perm_result = g_deps.validate_config_dir("/etc/aegisbpf");
        if (!config_perm_result) {
            config_span.fail(config_perm_result.error().to_string());
            logger().log(SLOG_ERROR("Config directory permission check failed")
                             .field("error", config_perm_result.error().to_string()));
            return fail(config_perm_result.error().to_string());
        }
    }

    // Detect kernel features for graceful degradation
    KernelFeatures features{};
    {
        ScopedSpan feature_span("daemon.detect_kernel_features", trace_id, root_span.span_id());
        auto features_result = g_deps.detect_kernel_features();
        if (!features_result) {
            feature_span.fail(features_result.error().to_string());
            logger().log(
                SLOG_ERROR("Failed to detect kernel features").field("error", features_result.error().to_string()));
            return fail(features_result.error().to_string());
        }
        features = *features_result;
    }

    // Determine enforcement capability
    EnforcementCapability cap = determine_capability(features);
    logger().log(SLOG_INFO("Kernel feature detection complete")
                     .field("kernel_version", features.kernel_version)
                     .field("capability", capability_name(cap))
                     .field("bpf_lsm", features.bpf_lsm)
                     .field("cgroup_v2", features.cgroup_v2)
                     .field("btf", features.btf)
                     .field("ringbuf", features.ringbuf));

    // Handle capability-based decisions
    if (cap == EnforcementCapability::Disabled) {
        logger().log(SLOG_ERROR("Cannot run AegisBPF on this system")
                         .field("explanation", capability_explanation(features, cap)));
        return fail("Cannot run AegisBPF on this system");
    }

    bool lsm_enabled = features.bpf_lsm;

    bool startup_state_emitted = false;
    if (cap == EnforcementCapability::AuditOnly) {
        if (!audit_only) {
            const std::string explanation = capability_explanation(features, cap);
            if (enforce_gate_mode == EnforceGateMode::FailClosed) {
                emit_runtime_state_change(RuntimeState::Degraded, "CAPABILITY_AUDIT_ONLY", explanation);
                logger().log(SLOG_ERROR("Full enforcement requested but kernel is audit-only")
                                 .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                                 .field("explanation", explanation));
                return fail("Full enforcement requested but kernel capability is audit-only");
            }
            logger().log(SLOG_WARN("Full enforcement not available; falling back to audit-only mode")
                             .field("enforce_gate_mode", enforce_gate_mode_name(enforce_gate_mode))
                             .field("explanation", explanation));
            audit_only = true;
            emit_runtime_state_change(RuntimeState::AuditFallback, "CAPABILITY_AUDIT_ONLY", explanation);
            startup_state_emitted = true;
        } else {
            logger().log(
                SLOG_INFO("Running in audit-only mode").field("explanation", capability_explanation(features, cap)));
        }
    }
    if (!startup_state_emitted) {
        if (audit_only) {
            emit_runtime_state_change(RuntimeState::AuditFallback, "STARTUP_AUDIT_MODE",
                                      "agent started in audit-only mode");
        } else {
            emit_runtime_state_change(RuntimeState::Enforce, "STARTUP_ENFORCE_READY",
                                      "kernel supports enforce-capable mode");
        }
    }
    if (forced_exit_code() != 0) {
        return fail("Strict degrade mode triggered failure");
    }

    auto rlimit_result = g_deps.bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail(rlimit_result.error().to_string());
    }

    if (ringbuf_bytes > 0) {
        set_ringbuf_bytes(ringbuf_bytes);
    }

    // Enforce BPF hash verification in enforce mode. Allowing unsigned BPF is a
    // break-glass option and must be explicitly requested.
    std::unique_ptr<ScopedEnvOverride> require_hash_override;
    std::unique_ptr<ScopedEnvOverride> allow_unsigned_override;
    if (!audit_only) {
        require_hash_override = std::make_unique<ScopedEnvOverride>("AEGIS_REQUIRE_BPF_HASH", "1");
    }
    if (allow_unsigned_bpf) {
        allow_unsigned_override = std::make_unique<ScopedEnvOverride>("AEGIS_ALLOW_UNSIGNED_BPF", "1");
        logger().log(SLOG_WARN("Break-glass enabled: accepting unsigned or mismatched BPF object")
                         .field("flag", "--allow-unsigned-bpf"));
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    ScopedSpan load_span("daemon.load_bpf", trace_id, root_span.span_id());
    auto load_result = g_deps.load_bpf(true, false, state);
    if (!load_result) {
        load_span.fail(load_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        const std::string load_error = load_result.error().to_string();
        if (load_error.find("verifier") != std::string::npos || load_error.find("Verifier") != std::string::npos) {
            emit_runtime_state_change(RuntimeState::Degraded, "BPF_VERIFIER_REJECT", load_error);
        } else {
            emit_runtime_state_change(RuntimeState::Degraded, "BPF_LOAD_FAILED", load_error);
        }
        return fail(load_result.error().to_string());
    }

    ScopedSpan layout_span("daemon.ensure_layout_version", trace_id, root_span.span_id());
    auto version_result = g_deps.ensure_layout_version(state);
    if (!version_result) {
        layout_span.fail(version_result.error().to_string());
        logger().log(SLOG_ERROR("Layout version check failed").field("error", version_result.error().to_string()));
        return fail(version_result.error().to_string());
    }

    // Set up full agent config with deadman switch and break-glass
    AgentConfig config{};
    config.audit_only = audit_only ? 1 : 0;
    config.break_glass_active = break_glass_active ? 1 : 0;
    config.deadman_enabled = (deadman_ttl > 0) ? 1 : 0;
    config.enforce_signal = enforce_signal;
    config.deadman_ttl_seconds = deadman_ttl;
    config.event_sample_rate = event_sample_rate ? event_sample_rate : 1;
    config.sigkill_escalation_threshold = sigkill_escalation_threshold;
    config.sigkill_escalation_window_seconds = sigkill_escalation_window_seconds;
    if (config.deadman_enabled) {
        struct timespec ts {};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
        config.deadman_deadline_ns = now_ns + (static_cast<uint64_t>(deadman_ttl) * 1000000000ULL);
    }

    ScopedSpan cfg_span("daemon.set_agent_config", trace_id, root_span.span_id());
    auto config_result = g_deps.set_agent_config_full(state, config);
    if (!config_result) {
        cfg_span.fail(config_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to set agent config").field("error", config_result.error().to_string()));
        return fail(config_result.error().to_string());
    }

    // Populate survival allowlist with critical binaries
    auto survival_result = g_deps.populate_survival_allowlist(state);
    if (!survival_result) {
        logger().log(
            SLOG_WARN("Failed to populate survival allowlist").field("error", survival_result.error().to_string()));
    }

    ScopedSpan cgroup_span("daemon.setup_agent_cgroup", trace_id, root_span.span_id());
    auto cgroup_result = g_deps.setup_agent_cgroup(state);
    if (!cgroup_result) {
        cgroup_span.fail(cgroup_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to setup agent cgroup").field("error", cgroup_result.error().to_string()));
        return fail(cgroup_result.error().to_string());
    }

    bool file_policy_empty_hint = false;
    bool net_policy_empty_hint = false;
    {
        uint32_t key = 0;
        AgentConfig live_cfg{};
        int cfg_fd = state.config_map ? bpf_map__fd(state.config_map) : -1;
        if (cfg_fd >= 0 && bpf_map_lookup_elem(cfg_fd, &key, &live_cfg) == 0) {
            file_policy_empty_hint = live_cfg.file_policy_empty != 0;
            net_policy_empty_hint = live_cfg.net_policy_empty != 0;
        } else {
            logger().log(SLOG_WARN("Failed to read policy-empty hints; attaching hooks conservatively")
                             .field("errno", static_cast<int64_t>(errno)));
        }
    }

    bool use_inode_permission = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::InodePermission);
    bool use_file_open = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::FileOpen);
    bool attach_network_hooks = !audit_only || !net_policy_empty_hint;
    if (audit_only && file_policy_empty_hint) {
        if (use_inode_permission || use_file_open) {
            logger().log(SLOG_INFO("Audit mode optimization: skipping file hooks (no deny rules loaded)")
                             .field("lsm_hook", lsm_hook_name(lsm_hook))
                             .field("net_policy_empty", net_policy_empty_hint));
        }
        use_inode_permission = false;
        use_file_open = false;
    }
    if (audit_only && net_policy_empty_hint) {
        if (lsm_enabled) {
            logger().log(SLOG_INFO("Audit mode optimization: skipping network hooks (no deny rules loaded)"));
        }
        attach_network_hooks = false;
    }
    ScopedSpan attach_span("daemon.attach_programs", trace_id, root_span.span_id());
    auto attach_result =
        g_deps.attach_all(state, lsm_enabled, use_inode_permission, use_file_open, attach_network_hooks);
    if (!attach_result) {
        attach_span.fail(attach_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to attach programs").field("error", attach_result.error().to_string()));
        return fail(attach_result.error().to_string());
    }
    auto attach_contract_result = validate_attach_contract(state, lsm_enabled, use_inode_permission, use_file_open);
    if (!attach_contract_result) {
        attach_span.fail(attach_contract_result.error().to_string());
        logger().log(SLOG_ERROR("Attach contract validation failed")
                         .field("error", attach_contract_result.error().to_string())
                         .field("hooks_expected", static_cast<int64_t>(state.file_hooks_expected))
                         .field("hooks_attached", static_cast<int64_t>(state.file_hooks_attached)));
        return fail(attach_contract_result.error().to_string());
    }

    const std::string applied_policy_path = applied_policy_path_from_env();
    const std::string capabilities_report_path = capabilities_report_path_from_env();
    auto gate_result = evaluate_policy_gate(state, features, applied_policy_path, audit_only, lsm_enabled,
                                            allow_unknown_binary_identity, enforce_signal, enforce_gate_mode, config,
                                            g_deps.set_agent_config_full);
    if (!gate_result) {
        return fail(gate_result.error().to_string());
    }
    auto gate = std::move(*gate_result);
    audit_only = gate.audit_only;
    config = gate.config;
    const bool kernel_exec_identity_enabled = gate.kernel_exec_identity_enabled;
    const size_t kernel_exec_identity_entries = gate.kernel_exec_identity_entries;
    auto& exec_identity_enforcer = gate.exec_identity_enforcer;
    auto& event_callbacks = gate.event_callbacks;

    {
        const bool file_open_hook_attached = lsm_enabled && use_file_open;
        const bool inode_permission_hook_attached = lsm_enabled && use_inode_permission;
        RuntimeStateTracker runtime_state = snapshot_runtime_state();
        CapabilityReportRuntimeState report_runtime_state{};
        report_runtime_state.current = runtime_state_name(runtime_state.current);
        report_runtime_state.transition_id = runtime_state.transition_id;
        report_runtime_state.degradation_count = runtime_state.degradation_count;
        report_runtime_state.strict_mode = runtime_state.strict_mode;
        report_runtime_state.enforce_requested = runtime_state.enforce_requested;
        auto report_result = write_capabilities_report(
            capabilities_report_path, features, cap, audit_only, lsm_enabled, file_open_hook_attached,
            inode_permission_hook_attached, state, applied_policy_path, gate.policy_requirements,
            kernel_exec_identity_enabled, kernel_exec_identity_entries,
            exec_identity_enforcer ? exec_identity_enforcer->allowlist_size() : 0, report_runtime_state);
        if (!report_result) {
            logger().log(SLOG_WARN("Failed to write capability report")
                             .field("path", capabilities_report_path)
                             .field("error", report_result.error().to_string()));
        } else {
            logger().log(SLOG_INFO("Capability report written").field("path", capabilities_report_path));
        }
    }

    RingBufferGuard rb(ring_buffer__new(bpf_map__fd(state.events), handle_event,
                                        event_callbacks.on_exec ? &event_callbacks : nullptr, nullptr));
    if (!rb) {
        emit_runtime_state_change(RuntimeState::Degraded, "RINGBUF_CREATE_FAILED", "ring_buffer__new returned null");
        logger().log(SLOG_ERROR("Failed to create ring buffer"));
        return fail("Failed to create ring buffer");
    }

    // Apply seccomp filter after all initialization is complete
    if (enable_seccomp) {
        ScopedSpan seccomp_span("daemon.apply_seccomp", trace_id, root_span.span_id());
        auto seccomp_result = apply_seccomp_filter();
        if (!seccomp_result) {
            seccomp_span.fail(seccomp_result.error().to_string());
            logger().log(
                SLOG_ERROR("Failed to apply seccomp filter").field("error", seccomp_result.error().to_string()));
            return fail(seccomp_result.error().to_string());
        }
    }

    bool network_enabled = lsm_enabled && (state.deny_ipv4 != nullptr || state.deny_ipv6 != nullptr);
    RuntimeStateTracker runtime_state = snapshot_runtime_state();
    logger().log(
        SLOG_INFO("Agent started")
            .field("audit_only", audit_only)
            .field("strict_degrade", strict_degrade)
            .field("enforce_signal", enforce_signal_name(config.enforce_signal))
            .field("lsm_enabled", lsm_enabled)
            .field("lsm_hook", lsm_hook_name(lsm_hook))
            .field("network_enabled", network_enabled)
            .field("event_sample_rate", static_cast<int64_t>(config.event_sample_rate))
            .field("sigkill_escalation_threshold", static_cast<int64_t>(config.sigkill_escalation_threshold))
            .field("sigkill_escalation_window_seconds", static_cast<int64_t>(config.sigkill_escalation_window_seconds))
            .field("ringbuf_bytes", static_cast<int64_t>(ringbuf_bytes))
            .field("seccomp", enable_seccomp)
            .field("break_glass", break_glass_active)
            .field("deadman_ttl", static_cast<int64_t>(deadman_ttl))
            .field("exec_identity_kernel", kernel_exec_identity_enabled)
            .field("exec_identity_allow_exec_inode_entries", static_cast<int64_t>(kernel_exec_identity_entries))
            .field("exec_identity_userspace_fallback",
                   static_cast<int64_t>(exec_identity_enforcer ? exec_identity_enforcer->allowlist_size() : 0))
            .field("allow_unknown_binary_identity", allow_unknown_binary_identity)
            .field("runtime_state", runtime_state_name(runtime_state.current))
            .field("state_transition_total", static_cast<int64_t>(runtime_state.transition_id))
            .field("state_degradation_total", static_cast<int64_t>(runtime_state.degradation_count)));

    // Start heartbeat thread if deadman switch is enabled
    std::thread heartbeat;
    if (deadman_ttl > 0) {
        start_deadman_heartbeat(heartbeat, &state, deadman_ttl, deny_rate_threshold, deny_rate_breach_limit);
        logger().log(SLOG_INFO("Deadman switch heartbeat started")
                         .field("ttl_seconds", static_cast<int64_t>(deadman_ttl))
                         .field("deny_rate_threshold", static_cast<int64_t>(deny_rate_threshold))
                         .field("deny_rate_breach_limit", static_cast<int64_t>(deny_rate_breach_limit)));
    }

    int err = 0;
    ScopedSpan event_loop_span("daemon.event_loop", trace_id, root_span.span_id());
    while (!exit_requested()) {
        err = ring_buffer__poll(rb.get(), 250);
        if (err == -EINTR) {
            err = 0;
            // Signal interruptions (including SIGINT and scheduler stop/continue)
            // should not force an immediate shutdown. Respect the normal loop
            // exit condition via exit_requested() instead.
            continue;
        }
        if (err < 0) {
            emit_runtime_state_change(RuntimeState::Degraded, "RINGBUF_POLL_FAILED",
                                      "ring_buffer__poll error=" + std::to_string(-err));
            event_loop_span.fail("Ring buffer poll failed");
            logger().log(SLOG_ERROR("Ring buffer poll failed").error_code(-err));
            break;
        }
    }

    // Stop heartbeat thread
    if (deadman_ttl > 0) {
        stop_deadman_heartbeat(heartbeat);
    }

    logger().log(SLOG_INFO("Agent stopped"));
    if (forced_exit_code() != 0) {
        return fail("Strict degrade mode triggered failure");
    }
    if (err < 0) {
        return fail("Ring buffer poll failed");
    }
    return 0;
}

} // namespace aegis
