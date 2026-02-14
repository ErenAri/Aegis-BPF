// cppcheck-suppress-file missingIncludeSystem
#include "cli_run.hpp"

#include <cstdint>
#include <cstring>
#include <string>

#include "bpf_ops.hpp"
#include "cli_common.hpp"
#include "daemon.hpp"
#include "events.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

bool parse_u32_option(const std::string& value, uint32_t& out, const char* error_message, bool require_nonzero)
{
    uint64_t parsed = 0;
    if (!parse_uint64(value, parsed) || parsed > UINT32_MAX || (require_nonzero && parsed == 0)) {
        logger().log(SLOG_ERROR(error_message).field("value", value));
        return false;
    }
    out = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_enforce_signal_option(const std::string& value, uint8_t& out)
{
    if (value == "none" || value == "block") {
        out = kEnforceSignalNone;
        return true;
    }
    if (value == "term" || value == "sigterm") {
        out = kEnforceSignalTerm;
        return true;
    }
    if (value == "kill" || value == "sigkill") {
        out = kEnforceSignalKill;
        return true;
    }
    if (value == "int" || value == "sigint") {
        out = kEnforceSignalInt;
        return true;
    }

    uint64_t signal = 0;
    if (parse_uint64(value, signal) && signal <= UINT8_MAX &&
        (signal == kEnforceSignalNone || signal == kEnforceSignalInt || signal == kEnforceSignalKill ||
         signal == kEnforceSignalTerm)) {
        out = static_cast<uint8_t>(signal);
        return true;
    }

    logger().log(
        SLOG_ERROR("Invalid enforce signal").field("value", value).field("allowed", "none|term|kill|int|0|2|9|15"));
    return false;
}

} // namespace

int dispatch_run_command(int argc, char** argv, const char* prog)
{
    bool audit_only = false;
    bool enable_seccomp = false;
    bool allow_sigkill = false;
    uint32_t deadman_ttl = 0;
    uint8_t enforce_signal = kEnforceSignalTerm;
    uint32_t ringbuf_bytes = 0;
    uint32_t event_sample_rate = 1;
    uint32_t sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
    uint32_t sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    LsmHookMode lsm_hook = LsmHookMode::FileOpen;
    uint32_t deny_rate_threshold = 0;
    uint32_t deny_rate_breach_limit = 3;
    uint32_t max_deny_inodes = 0;
    uint32_t max_deny_paths = 0;
    uint32_t max_network_entries = 0;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--audit" || arg == "--mode=audit") {
            audit_only = true;
        } else if (arg == "--enforce" || arg == "--mode=enforce") {
            audit_only = false;
        } else if (arg == "--seccomp") {
            enable_seccomp = true;
        } else if (arg == "--allow-sigkill") {
            allow_sigkill = true;
        } else if (arg.rfind("--deadman-ttl=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--deadman-ttl="));
            if (!parse_u32_option(value, deadman_ttl, "Invalid deadman TTL value", false))
                return 1;
        } else if (arg == "--deadman-ttl") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], deadman_ttl, "Invalid deadman TTL value", false))
                return 1;
        } else if (arg.rfind("--log=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--log="));
            if (!set_event_log_sink(value))
                return usage(prog);
        } else if (arg == "--log") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!set_event_log_sink(argv[++i]))
                return usage(prog);
        } else if (arg.rfind("--log-level=", 0) == 0 || arg.rfind("--log-format=", 0) == 0) {
            // Already processed globally.
        } else if (arg.rfind("--ringbuf-bytes=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--ringbuf-bytes="));
            if (!parse_u32_option(value, ringbuf_bytes, "Invalid ringbuf size", false))
                return 1;
        } else if (arg == "--ringbuf-bytes") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], ringbuf_bytes, "Invalid ringbuf size", false))
                return 1;
        } else if (arg.rfind("--event-sample-rate=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--event-sample-rate="));
            if (!parse_u32_option(value, event_sample_rate, "Invalid event sample rate", true))
                return 1;
        } else if (arg == "--event-sample-rate") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], event_sample_rate, "Invalid event sample rate", true))
                return 1;
        } else if (arg.rfind("--enforce-signal=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--enforce-signal="));
            if (!parse_enforce_signal_option(value, enforce_signal))
                return 1;
        } else if (arg == "--enforce-signal") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_enforce_signal_option(argv[++i], enforce_signal))
                return 1;
        } else if (arg.rfind("--kill-escalation-threshold=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--kill-escalation-threshold="));
            if (!parse_u32_option(value, sigkill_escalation_threshold, "Invalid SIGKILL escalation threshold", true)) {
                return 1;
            }
        } else if (arg == "--kill-escalation-threshold") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], sigkill_escalation_threshold, "Invalid SIGKILL escalation threshold",
                                  true)) {
                return 1;
            }
        } else if (arg.rfind("--kill-escalation-window-seconds=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--kill-escalation-window-seconds="));
            if (!parse_u32_option(value, sigkill_escalation_window_seconds, "Invalid SIGKILL escalation window seconds",
                                  true)) {
                return 1;
            }
        } else if (arg == "--kill-escalation-window-seconds") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], sigkill_escalation_window_seconds,
                                  "Invalid SIGKILL escalation window seconds", true)) {
                return 1;
            }
        } else if (arg.rfind("--auto-revert-threshold=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--auto-revert-threshold="));
            if (!parse_u32_option(value, deny_rate_threshold, "Invalid auto-revert threshold", false))
                return 1;
        } else if (arg == "--auto-revert-threshold") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], deny_rate_threshold, "Invalid auto-revert threshold", false))
                return 1;
        } else if (arg.rfind("--auto-revert-breaches=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--auto-revert-breaches="));
            if (!parse_u32_option(value, deny_rate_breach_limit, "Invalid auto-revert breach limit", true))
                return 1;
        } else if (arg == "--auto-revert-breaches") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], deny_rate_breach_limit, "Invalid auto-revert breach limit", true))
                return 1;
        } else if (arg.rfind("--max-deny-inodes=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--max-deny-inodes="));
            if (!parse_u32_option(value, max_deny_inodes, "Invalid max deny inodes", true))
                return 1;
        } else if (arg == "--max-deny-inodes") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], max_deny_inodes, "Invalid max deny inodes", true))
                return 1;
        } else if (arg.rfind("--max-deny-paths=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--max-deny-paths="));
            if (!parse_u32_option(value, max_deny_paths, "Invalid max deny paths", true))
                return 1;
        } else if (arg == "--max-deny-paths") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], max_deny_paths, "Invalid max deny paths", true))
                return 1;
        } else if (arg.rfind("--max-network-entries=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--max-network-entries="));
            if (!parse_u32_option(value, max_network_entries, "Invalid max network entries", true))
                return 1;
        } else if (arg == "--max-network-entries") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_u32_option(argv[++i], max_network_entries, "Invalid max network entries", true))
                return 1;
        } else if (arg.rfind("--lsm-hook=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--lsm-hook="));
            if (!parse_lsm_hook(value, lsm_hook)) {
                logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                return 1;
            }
        } else if (arg == "--lsm-hook") {
            if (i + 1 >= argc)
                return usage(prog);
            std::string value = argv[++i];
            if (!parse_lsm_hook(value, lsm_hook)) {
                logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                return 1;
            }
        } else {
            return usage(prog);
        }
    }

    if (max_deny_inodes > 0) {
        set_max_deny_inodes(max_deny_inodes);
    }
    if (max_deny_paths > 0) {
        set_max_deny_paths(max_deny_paths);
    }
    if (max_network_entries > 0) {
        set_max_network_entries(max_network_entries);
    }

    return daemon_run(audit_only, enable_seccomp, deadman_ttl, enforce_signal, allow_sigkill, lsm_hook, ringbuf_bytes,
                      event_sample_rate, sigkill_escalation_threshold, sigkill_escalation_window_seconds,
                      deny_rate_threshold, deny_rate_breach_limit);
}

} // namespace aegis
