// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Emergency control command implementations
 */

#include "commands_emergency.hpp"

#include <unistd.h>

#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>

#include "bpf_ops.hpp"
#include "control.hpp"
#include "events.hpp"
#include "logging.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

int fail_span(ScopedSpan& span, const std::string& message)
{
    span.fail(message);
    return 1;
}

std::string policy_applied_hash_path_from_env()
{
    const char* env = std::getenv("AEGIS_POLICY_APPLIED_HASH_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kPolicyAppliedHashPath;
}

std::string read_policy_hash_best_effort()
{
    std::error_code ec;
    const std::string path = policy_applied_hash_path_from_env();
    if (!std::filesystem::exists(path, ec) || ec) {
        return "";
    }
    return trim(read_file_first_line(path));
}

Result<void> validate_reason_pattern(const std::string& reason, const std::string& pattern)
{
    if (pattern.empty()) {
        return {};
    }
    try {
        const std::regex re(pattern);
        if (!std::regex_search(reason, re)) {
            return Error(ErrorCode::InvalidArgument, "Reason does not match required pattern", pattern);
        }
    } catch (const std::regex_error& e) {
        return Error(ErrorCode::InvalidArgument, "Invalid --reason-pattern regex", e.what());
    }
    return {};
}

std::string build_control_change_payload(const std::string& action, bool enabled, bool prev_enabled, int64_t changed_at,
                                         uint32_t uid, uint32_t pid, const std::string& node_name,
                                         const std::string& reason, const std::string& reason_sha256,
                                         const std::string& policy_hash, const EmergencyStormStatus& storm)
{
    std::ostringstream oss;
    oss << "{" << "\"type\":\"control_change\"" << ",\"event_version\":1" << ",\"control\":\"emergency_disable\""
        << ",\"action\":\"" << json_escape(action) << "\"" << ",\"enabled\":" << (enabled ? "true" : "false")
        << ",\"prev_enabled\":" << (prev_enabled ? "true" : "false") << ",\"changed_at_unix\":" << changed_at
        << ",\"uid\":" << uid << ",\"pid\":" << pid << ",\"node_name\":\"" << json_escape(node_name) << "\""
        << ",\"reason\":\"" << json_escape(reason) << "\"" << ",\"reason_sha256\":\"" << json_escape(reason_sha256)
        << "\"";
    if (!policy_hash.empty()) {
        oss << ",\"policy_hash\":\"" << json_escape(policy_hash) << "\"";
    }
    oss << ",\"storm_active\":" << (storm.active ? "true" : "false")
        << ",\"storm_transitions_in_window\":" << storm.transitions_in_window
        << ",\"storm_threshold\":" << storm.threshold << ",\"storm_window_seconds\":" << storm.window_seconds << "}";
    return oss.str();
}

int cmd_emergency_toggle(bool enable, const EmergencyToggleOptions& options)
{
    const std::string trace_id = make_span_id("trace-emergency");
    ScopedSpan span("cli.emergency_toggle", trace_id);

    if (options.reason.empty()) {
        logger().log(SLOG_ERROR("Missing required --reason"));
        return fail_span(span, "Missing required --reason");
    }

    auto pattern_result = validate_reason_pattern(options.reason, options.reason_pattern);
    if (!pattern_result) {
        logger().log(SLOG_ERROR("Reason pattern check failed").field("error", pattern_result.error().to_string()));
        return fail_span(span, pattern_result.error().to_string());
    }

    const EmergencyControlConfig control_cfg = emergency_control_config_from_env();

    auto lock_result = ScopedFileLock::acquire(control_lock_path_from_env(), control_cfg.lock_timeout_seconds);
    if (!lock_result) {
        logger().log(SLOG_ERROR("Failed to acquire control lock").field("error", lock_result.error().to_string()));
        return fail_span(span, lock_result.error().to_string());
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF state").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto prev_result = read_emergency_disable(state);
    if (!prev_result) {
        logger().log(SLOG_ERROR("Failed to read emergency state").field("error", prev_result.error().to_string()));
        return fail_span(span, prev_result.error().to_string());
    }
    const bool prev_enabled = *prev_result;
    if (prev_enabled == enable) {
        if (options.json_output) {
            std::cout << "{\"ok\":true,\"noop\":true,\"enabled\":" << (enable ? "true" : "false") << "}\n";
        } else {
            std::cout << "Emergency control already " << (enable ? "enabled" : "disabled") << ".\n";
        }
        return 0;
    }

    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    const uint32_t uid = static_cast<uint32_t>(::getuid());
    const uint32_t pid = static_cast<uint32_t>(::getpid());
    const std::string node_name = node_name_from_env_or_hostname();

    auto sanitized = sanitize_reason_and_hash(options.reason, control_cfg.reason_max_bytes);
    const std::string policy_hash = read_policy_hash_best_effort();

    EmergencyControlState control_state{};
    auto control_state_result = read_emergency_control_state(control_state_path_from_env());
    EmergencyStormStatus prev_storm{};
    if (control_state_result) {
        control_state = *control_state_result;
        prev_storm = evaluate_toggle_storm(control_state, control_cfg, now);
    }

    control_state.schema_version = 1;
    control_state.enabled = enable;
    control_state.changed_at_unix = now;
    control_state.uid = uid;
    control_state.pid = pid;
    control_state.node_name = node_name;
    control_state.reason = sanitized.sanitized;
    control_state.reason_sha256 = sanitized.raw_sha256_hex;
    control_state.transitions_total = control_state.transitions_total + 1;
    control_state.transition_times_unix.push_back(now);
    if (control_state.transition_times_unix.size() > 128) {
        control_state.transition_times_unix.erase(control_state.transition_times_unix.begin(),
                                                  control_state.transition_times_unix.end() - 128);
    }

    const auto storm = evaluate_toggle_storm(control_state, control_cfg, now);
    if (!prev_storm.active && storm.active) {
        logger().log(SLOG_WARN("Emergency control toggle storm detected")
                         .field("threshold", static_cast<int64_t>(storm.threshold))
                         .field("window_seconds", static_cast<int64_t>(storm.window_seconds))
                         .field("transitions_in_window", static_cast<int64_t>(storm.transitions_in_window)));
    }

    auto set_result = set_emergency_disable(state, enable);
    if (!set_result) {
        logger().log(
            SLOG_ERROR("Failed to update emergency disable flag").field("error", set_result.error().to_string()));
        return fail_span(span, set_result.error().to_string());
    }

    const std::string action = enable ? "disable" : "enable";
    const std::string payload =
        build_control_change_payload(action, enable, prev_enabled, now, uid, pid, node_name, sanitized.sanitized,
                                     sanitized.raw_sha256_hex, policy_hash, storm);

    const std::string log_path = control_log_path_from_env();
    auto rotate_result = rotate_jsonl_if_needed_pre_write(log_path, control_cfg.log_max_bytes,
                                                          control_cfg.log_max_files, payload.size() + 1);
    if (!rotate_result) {
        logger().log(SLOG_ERROR("Failed to rotate control log").field("error", rotate_result.error().to_string()));
        (void)set_emergency_disable(state, prev_enabled);
        return fail_span(span, rotate_result.error().to_string());
    }
    auto append_result = append_jsonl_line(log_path, payload);
    if (!append_result) {
        logger().log(SLOG_ERROR("Failed to append control log").field("error", append_result.error().to_string()));
        (void)set_emergency_disable(state, prev_enabled);
        return fail_span(span, append_result.error().to_string());
    }
    auto write_state_result = write_emergency_control_state(control_state_path_from_env(), control_state);
    if (!write_state_result) {
        logger().log(
            SLOG_WARN("Failed to write control state file").field("error", write_state_result.error().to_string()));
    }

#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink)) {
        emit_control_change_event(payload, action, enable, prev_enabled, uid, pid, node_name, sanitized.raw_sha256_hex,
                                  sanitized.sanitized);
    }
#endif

    if (options.json_output) {
        std::cout << payload << "\n";
    } else {
        if (enable) {
            logger().log(SLOG_WARN("Emergency disable ACTIVATED - enforcement bypassed (AUDIT-only)"));
            std::cout << "Emergency disable activated. Enforcement is bypassed (AUDIT-only).\n";
            std::cout << "Run 'aegisbpf emergency-enable --reason \"...\"' to re-enable enforcement.\n";
        } else {
            logger().log(SLOG_INFO("Emergency disable DEACTIVATED - enforcement resumed"));
            std::cout << "Emergency disable deactivated. Enforcement resumed.\n";
        }
        std::cout << "Audit log: " << log_path << "\n";
    }

    return 0;
}

} // namespace

int cmd_emergency_disable(const EmergencyToggleOptions& options)
{
    return cmd_emergency_toggle(true, options);
}

int cmd_emergency_enable(const EmergencyToggleOptions& options)
{
    return cmd_emergency_toggle(false, options);
}

int cmd_emergency_status(bool json_output)
{
    const std::string trace_id = make_span_id("trace-emergency-status");
    ScopedSpan span("cli.emergency_status", trace_id);

    const EmergencyControlConfig control_cfg = emergency_control_config_from_env();
    EmergencyControlState control_state{};
    bool state_present = false;
    auto control_state_result = read_emergency_control_state(control_state_path_from_env());
    if (control_state_result) {
        control_state = *control_state_result;
        state_present = true;
    }

    bool kernel_known = false;
    bool kernel_enabled = false;
    {
        auto rlimit_result = bump_memlock_rlimit();
        if (rlimit_result) {
            BpfState state;
            auto load_result = load_bpf(true, false, state);
            if (load_result) {
                auto enabled_result = read_emergency_disable(state);
                if (enabled_result) {
                    kernel_known = true;
                    kernel_enabled = *enabled_result;
                }
            }
        }
    }

    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    const auto storm = evaluate_toggle_storm(control_state, control_cfg, now);

    const bool enabled = kernel_known ? kernel_enabled : (state_present ? control_state.enabled : false);
    if (json_output) {
        std::ostringstream out;
        out << "{" << "\"ok\":true" << ",\"enabled\":" << (enabled ? "true" : "false")
            << ",\"kernel_state_known\":" << (kernel_known ? "true" : "false");
        if (kernel_known) {
            out << ",\"kernel_enabled\":" << (kernel_enabled ? "true" : "false");
        }
        out << ",\"state_present\":" << (state_present ? "true" : "false");
        if (state_present) {
            out << ",\"changed_at_unix\":" << control_state.changed_at_unix << ",\"uid\":" << control_state.uid
                << ",\"pid\":" << control_state.pid << ",\"node_name\":\"" << json_escape(control_state.node_name)
                << "\"" << ",\"reason\":\"" << json_escape(control_state.reason) << "\"" << ",\"reason_sha256\":\""
                << json_escape(control_state.reason_sha256) << "\""
                << ",\"transitions_total\":" << control_state.transitions_total;
        }
        out << ",\"storm_active\":" << (storm.active ? "true" : "false")
            << ",\"storm_transitions_in_window\":" << storm.transitions_in_window
            << ",\"storm_threshold\":" << storm.threshold << ",\"storm_window_seconds\":" << storm.window_seconds
            << "}\n";
        std::cout << out.str();
        return 0;
    }

    std::cout << "Emergency disable: " << (enabled ? "ENABLED (AUDIT-only)" : "disabled") << "\n";
    if (kernel_known) {
        std::cout << "Kernel flag: " << (kernel_enabled ? "enabled" : "disabled") << "\n";
    } else {
        std::cout << "Kernel flag: unknown (insufficient privileges or BPF unavailable)\n";
    }
    if (state_present) {
        std::cout << "Last change: " << control_state.changed_at_unix << " uid=" << control_state.uid
                  << " pid=" << control_state.pid << " node=" << control_state.node_name << "\n";
    } else {
        std::cout << "Control state file not present: " << control_state_path_from_env() << "\n";
    }
    if (storm.active) {
        std::cout << "Toggle storm: ACTIVE transitions_in_window=" << storm.transitions_in_window
                  << " threshold=" << storm.threshold << " window_seconds=" << storm.window_seconds << "\n";
    }
    return 0;
}

} // namespace aegis
