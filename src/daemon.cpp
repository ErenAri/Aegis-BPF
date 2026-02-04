// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Daemon implementation
 *
 * Main daemon run loop and related functionality.
 */

#include "daemon.hpp"
#include "daemon_test_hooks.hpp"
#include "bpf_ops.hpp"
#include "events.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "seccomp.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <bpf/libbpf.h>
#include <atomic>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace aegis {

namespace {
volatile sig_atomic_t g_exiting = 0;
std::atomic<bool> g_heartbeat_running{false};
Result<void> setup_agent_cgroup(BpfState& state);
ValidateConfigDirectoryPermissionsFn g_validate_config_directory_permissions =
    validate_config_directory_permissions;
DetectKernelFeaturesFn g_detect_kernel_features = detect_kernel_features;
BumpMemlockRlimitFn g_bump_memlock_rlimit = bump_memlock_rlimit;
LoadBpfFn g_load_bpf = load_bpf;
EnsureLayoutVersionFn g_ensure_layout_version = ensure_layout_version;
SetAgentConfigFullFn g_set_agent_config_full = set_agent_config_full;
PopulateSurvivalAllowlistFn g_populate_survival_allowlist = populate_survival_allowlist;
SetupAgentCgroupFn g_setup_agent_cgroup = setup_agent_cgroup;
AttachAllFn g_attach_all = attach_all;

void handle_signal(int)
{
    g_exiting = 1;
}

void heartbeat_thread(BpfState* state, uint32_t ttl_seconds)
{
    uint32_t sleep_interval = ttl_seconds / 2;
    if (sleep_interval < 1) {
        sleep_interval = 1;
    }

    while (g_heartbeat_running.load() && !g_exiting) {
        // Update deadman deadline
        struct timespec ts {};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
                          static_cast<uint64_t>(ts.tv_nsec);
        uint64_t new_deadline = now_ns + (static_cast<uint64_t>(ttl_seconds) * 1000000000ULL);

        auto result = update_deadman_deadline(*state, new_deadline);
        if (!result) {
            logger().log(SLOG_WARN("Failed to update deadman deadline")
                             .field("error", result.error().to_string()));
        }

        // Sleep for TTL/2, but check exit flags more frequently.
        for (uint32_t i = 0; i < sleep_interval && g_heartbeat_running.load() && !g_exiting; ++i) {
            sleep(1);
        }
    }
}

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

}  // namespace

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

void set_validate_config_directory_permissions_for_test(ValidateConfigDirectoryPermissionsFn fn)
{
    g_validate_config_directory_permissions = fn ? fn : validate_config_directory_permissions;
}

void reset_validate_config_directory_permissions_for_test()
{
    g_validate_config_directory_permissions = validate_config_directory_permissions;
}

void set_detect_kernel_features_for_test(DetectKernelFeaturesFn fn)
{
    g_detect_kernel_features = fn ? fn : detect_kernel_features;
}

void reset_detect_kernel_features_for_test()
{
    g_detect_kernel_features = detect_kernel_features;
}

void set_bump_memlock_rlimit_for_test(BumpMemlockRlimitFn fn)
{
    g_bump_memlock_rlimit = fn ? fn : bump_memlock_rlimit;
}

void reset_bump_memlock_rlimit_for_test()
{
    g_bump_memlock_rlimit = bump_memlock_rlimit;
}

void set_load_bpf_for_test(LoadBpfFn fn)
{
    g_load_bpf = fn ? fn : load_bpf;
}

void reset_load_bpf_for_test()
{
    g_load_bpf = load_bpf;
}

void set_ensure_layout_version_for_test(EnsureLayoutVersionFn fn)
{
    g_ensure_layout_version = fn ? fn : ensure_layout_version;
}

void reset_ensure_layout_version_for_test()
{
    g_ensure_layout_version = ensure_layout_version;
}

void set_set_agent_config_full_for_test(SetAgentConfigFullFn fn)
{
    g_set_agent_config_full = fn ? fn : set_agent_config_full;
}

void reset_set_agent_config_full_for_test()
{
    g_set_agent_config_full = set_agent_config_full;
}

void set_populate_survival_allowlist_for_test(PopulateSurvivalAllowlistFn fn)
{
    g_populate_survival_allowlist = fn ? fn : populate_survival_allowlist;
}

void reset_populate_survival_allowlist_for_test()
{
    g_populate_survival_allowlist = populate_survival_allowlist;
}

void set_setup_agent_cgroup_for_test(SetupAgentCgroupFn fn)
{
    g_setup_agent_cgroup = fn ? fn : setup_agent_cgroup;
}

void reset_setup_agent_cgroup_for_test()
{
    g_setup_agent_cgroup = setup_agent_cgroup;
}

void set_attach_all_for_test(AttachAllFn fn)
{
    g_attach_all = fn ? fn : attach_all;
}

void reset_attach_all_for_test()
{
    g_attach_all = attach_all;
}

int daemon_run(bool audit_only,
               bool enable_seccomp,
               uint32_t deadman_ttl,
               uint8_t enforce_signal,
               bool allow_sigkill,
               LsmHookMode lsm_hook,
               uint32_t ringbuf_bytes,
               uint32_t event_sample_rate,
               uint32_t sigkill_escalation_threshold,
               uint32_t sigkill_escalation_window_seconds)
{
    const std::string trace_id = make_span_id("trace-daemon");
    ScopedSpan root_span("daemon.run", trace_id);
    auto fail = [&](const std::string& message) -> int {
        root_span.fail(message);
        return 1;
    };

    // Check for break-glass mode FIRST
    bool break_glass_active = detect_break_glass();
    if (break_glass_active) {
        logger().log(SLOG_WARN("Break-glass mode detected - forcing audit-only mode"));
        audit_only = true;
    }

    if (enforce_signal != kEnforceSignalNone &&
        enforce_signal != kEnforceSignalInt &&
        enforce_signal != kEnforceSignalKill &&
        enforce_signal != kEnforceSignalTerm) {
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
        auto config_perm_result = g_validate_config_directory_permissions("/etc/aegisbpf");
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
        auto features_result = g_detect_kernel_features();
        if (!features_result) {
            feature_span.fail(features_result.error().to_string());
            logger().log(SLOG_ERROR("Failed to detect kernel features")
                             .field("error", features_result.error().to_string()));
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

    if (cap == EnforcementCapability::AuditOnly) {
        if (!audit_only) {
            logger().log(SLOG_WARN("Full enforcement not available; falling back to audit-only mode")
                             .field("explanation", capability_explanation(features, cap)));
            audit_only = true;
        }
        else {
            logger().log(SLOG_INFO("Running in audit-only mode")
                             .field("explanation", capability_explanation(features, cap)));
        }
    }

    auto rlimit_result = g_bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return fail(rlimit_result.error().to_string());
    }

    if (ringbuf_bytes > 0) {
        set_ringbuf_bytes(ringbuf_bytes);
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    ScopedSpan load_span("daemon.load_bpf", trace_id, root_span.span_id());
    auto load_result = g_load_bpf(true, false, state);
    if (!load_result) {
        load_span.fail(load_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return fail(load_result.error().to_string());
    }

    ScopedSpan layout_span("daemon.ensure_layout_version", trace_id, root_span.span_id());
    auto version_result = g_ensure_layout_version(state);
    if (!version_result) {
        layout_span.fail(version_result.error().to_string());
        logger().log(SLOG_ERROR("Layout version check failed")
                         .field("error", version_result.error().to_string()));
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
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
                          static_cast<uint64_t>(ts.tv_nsec);
        config.deadman_deadline_ns = now_ns + (static_cast<uint64_t>(deadman_ttl) * 1000000000ULL);
    }

    ScopedSpan cfg_span("daemon.set_agent_config", trace_id, root_span.span_id());
    auto config_result = g_set_agent_config_full(state, config);
    if (!config_result) {
        cfg_span.fail(config_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to set agent config")
                         .field("error", config_result.error().to_string()));
        return fail(config_result.error().to_string());
    }

    // Populate survival allowlist with critical binaries
    auto survival_result = g_populate_survival_allowlist(state);
    if (!survival_result) {
        logger().log(SLOG_WARN("Failed to populate survival allowlist")
                         .field("error", survival_result.error().to_string()));
    }

    ScopedSpan cgroup_span("daemon.setup_agent_cgroup", trace_id, root_span.span_id());
    auto cgroup_result = g_setup_agent_cgroup(state);
    if (!cgroup_result) {
        cgroup_span.fail(cgroup_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to setup agent cgroup")
                         .field("error", cgroup_result.error().to_string()));
        return fail(cgroup_result.error().to_string());
    }

    bool use_inode_permission = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::InodePermission);
    bool use_file_open = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::FileOpen);
    ScopedSpan attach_span("daemon.attach_programs", trace_id, root_span.span_id());
    auto attach_result = g_attach_all(state, lsm_enabled, use_inode_permission, use_file_open);
    if (!attach_result) {
        attach_span.fail(attach_result.error().to_string());
        logger().log(SLOG_ERROR("Failed to attach programs")
                         .field("error", attach_result.error().to_string()));
        return fail(attach_result.error().to_string());
    }

    RingBufferGuard rb(ring_buffer__new(bpf_map__fd(state.events), handle_event, nullptr, nullptr));
    if (!rb) {
        logger().log(SLOG_ERROR("Failed to create ring buffer"));
        return fail("Failed to create ring buffer");
    }

    // Apply seccomp filter after all initialization is complete
    if (enable_seccomp) {
        ScopedSpan seccomp_span("daemon.apply_seccomp", trace_id, root_span.span_id());
        auto seccomp_result = apply_seccomp_filter();
        if (!seccomp_result) {
            seccomp_span.fail(seccomp_result.error().to_string());
            logger().log(SLOG_ERROR("Failed to apply seccomp filter")
                             .field("error", seccomp_result.error().to_string()));
            return fail(seccomp_result.error().to_string());
        }
    }

    bool network_enabled = lsm_enabled && (state.deny_ipv4 != nullptr || state.deny_ipv6 != nullptr);
    logger().log(SLOG_INFO("Agent started")
                     .field("audit_only", audit_only)
                     .field("enforce_signal", enforce_signal_name(config.enforce_signal))
                     .field("lsm_enabled", lsm_enabled)
                     .field("lsm_hook", lsm_hook_name(lsm_hook))
                     .field("network_enabled", network_enabled)
                     .field("event_sample_rate", static_cast<int64_t>(config.event_sample_rate))
                     .field("sigkill_escalation_threshold",
                            static_cast<int64_t>(config.sigkill_escalation_threshold))
                     .field("sigkill_escalation_window_seconds",
                            static_cast<int64_t>(config.sigkill_escalation_window_seconds))
                     .field("ringbuf_bytes", static_cast<int64_t>(ringbuf_bytes))
                     .field("seccomp", enable_seccomp)
                     .field("break_glass", break_glass_active)
                     .field("deadman_ttl", static_cast<int64_t>(deadman_ttl)));

    // Start heartbeat thread if deadman switch is enabled
    std::thread heartbeat;
    if (deadman_ttl > 0) {
        g_heartbeat_running.store(true);
        heartbeat = std::thread(heartbeat_thread, &state, deadman_ttl);
        logger().log(SLOG_INFO("Deadman switch heartbeat started")
                         .field("ttl_seconds", static_cast<int64_t>(deadman_ttl)));
    }

    int err = 0;
    ScopedSpan event_loop_span("daemon.event_loop", trace_id, root_span.span_id());
    while (!g_exiting) {
        err = ring_buffer__poll(rb.get(), 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            event_loop_span.fail("Ring buffer poll failed");
            logger().log(SLOG_ERROR("Ring buffer poll failed").error_code(-err));
            break;
        }
    }

    // Stop heartbeat thread
    if (deadman_ttl > 0 && heartbeat.joinable()) {
        g_heartbeat_running.store(false);
        heartbeat.join();
    }

    logger().log(SLOG_INFO("Agent stopped"));
    if (err < 0) {
        return fail("Ring buffer poll failed");
    }
    return 0;
}

}  // namespace aegis
