// cppcheck-suppress-file missingIncludeSystem
#include "cli_dispatch.hpp"

#include <cstring>
#include <string>

#include "cli_common.hpp"
#include "cli_network.hpp"
#include "cli_policy.hpp"
#include "cli_run.hpp"
#include "commands.hpp"
#include "daemon.hpp"
#include "events.hpp"

namespace aegis {

namespace {

int dispatch_block_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];
    if (sub == "add") {
        if (argc != 4)
            return usage(prog);
        return cmd_block_add(argv[3]);
    }
    if (sub == "del") {
        if (argc != 4)
            return usage(prog);
        return cmd_block_del(argv[3]);
    }
    if (sub == "list")
        return cmd_block_list();
    if (sub == "clear")
        return cmd_block_clear();
    return usage(prog);
}

int dispatch_allow_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];
    if (sub == "add") {
        if (argc != 4)
            return usage(prog);
        return cmd_allow_add(argv[3]);
    }
    if (sub == "del") {
        if (argc != 4)
            return usage(prog);
        return cmd_allow_del(argv[3]);
    }
    if (sub == "list") {
        if (argc > 3)
            return usage(prog);
        return cmd_allow_list();
    }
    return usage(prog);
}

int dispatch_keys_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];
    if (sub == "list")
        return cmd_keys_list();
    if (sub == "add") {
        if (argc != 4)
            return usage(prog);
        return cmd_keys_add(argv[3]);
    }
    return usage(prog);
}

int dispatch_survival_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];
    if (sub == "list")
        return cmd_survival_list();
    if (sub == "verify")
        return cmd_survival_verify();
    return usage(prog);
}

int dispatch_health_command(int argc, char** argv, const char* prog)
{
    bool json_output = false;
    bool require_enforce = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "--require-enforce") {
            require_enforce = true;
        } else {
            return usage(prog);
        }
    }
    return cmd_health(json_output, require_enforce);
}

int dispatch_doctor_command(int argc, char** argv, const char* prog)
{
    bool json_output = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else {
            return usage(prog);
        }
    }
    return cmd_doctor(json_output);
}

int dispatch_explain_command(int argc, char** argv, const char* prog)
{
    std::string event_path;
    std::string policy_path;
    bool json_output = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--event") {
            if (i + 1 >= argc)
                return usage(prog);
            event_path = argv[++i];
        } else if (arg == "--policy") {
            if (i + 1 >= argc)
                return usage(prog);
            policy_path = argv[++i];
        } else if (arg == "--json") {
            json_output = true;
        } else if (event_path.empty() && arg.rfind("--", 0) != 0) {
            event_path = arg;
        } else {
            return usage(prog);
        }
    }

    if (event_path.empty()) {
        return usage(prog);
    }

    return cmd_explain(event_path, policy_path, json_output);
}

int dispatch_metrics_command(int argc, char** argv, const char* prog)
{
    std::string out_path;
    bool detailed = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--out") {
            if (i + 1 >= argc)
                return usage(prog);
            out_path = argv[++i];
        } else if (arg == "--detailed") {
            detailed = true;
        } else {
            return usage(prog);
        }
    }
    return cmd_metrics(out_path, detailed);
}

int dispatch_capabilities_command(int argc, char** argv, const char* prog)
{
    bool json_output = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else {
            return usage(prog);
        }
    }
    return cmd_capabilities(json_output);
}

int dispatch_emergency_toggle_command(int argc, char** argv, const char* prog, bool disable)
{
    EmergencyToggleOptions options{};

#ifdef HAVE_SYSTEMD
    // Default to journald to avoid emitting JSON payloads to stdout unexpectedly.
    set_event_log_sink("journald");
#endif

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--reason") {
            if (i + 1 >= argc) {
                return usage(prog);
            }
            options.reason = argv[++i];
        } else if (arg.rfind("--reason=", 0) == 0) {
            options.reason = arg.substr(std::strlen("--reason="));
        } else if (arg == "--reason-pattern") {
            if (i + 1 >= argc) {
                return usage(prog);
            }
            options.reason_pattern = argv[++i];
        } else if (arg.rfind("--reason-pattern=", 0) == 0) {
            options.reason_pattern = arg.substr(std::strlen("--reason-pattern="));
        } else if (arg == "--json") {
            options.json_output = true;
        } else if (arg == "--log") {
            if (i + 1 >= argc) {
                return usage(prog);
            }
            if (!set_event_log_sink(argv[++i])) {
                return usage(prog);
            }
        } else if (arg.rfind("--log=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--log="));
            if (!set_event_log_sink(value)) {
                return usage(prog);
            }
        } else {
            return usage(prog);
        }
    }

    if (disable) {
        return cmd_emergency_disable(options);
    }
    return cmd_emergency_enable(options);
}

int dispatch_emergency_status_command(int argc, char** argv, const char* prog)
{
    bool json_output = false;
#ifdef HAVE_SYSTEMD
    // Default to journald for consistency with toggle commands.
    set_event_log_sink("journald");
#endif

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "--log") {
            if (i + 1 >= argc) {
                return usage(prog);
            }
            if (!set_event_log_sink(argv[++i])) {
                return usage(prog);
            }
        } else if (arg.rfind("--log=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--log="));
            if (!set_event_log_sink(value)) {
                return usage(prog);
            }
        } else {
            return usage(prog);
        }
    }
    return cmd_emergency_status(json_output);
}

} // namespace

int dispatch_cli(int argc, char** argv)
{
    configure_logging_from_args(argc, argv);

    if (argc == 1) {
        return daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                          kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
    }

    std::string cmd = argv[1];
    if (cmd == "run")
        return dispatch_run_command(argc, argv, argv[0]);
    if (cmd == "block")
        return dispatch_block_command(argc, argv, argv[0]);
    if (cmd == "allow")
        return dispatch_allow_command(argc, argv, argv[0]);
    if (cmd == "network")
        return dispatch_network_command(argc, argv, argv[0]);
    if (cmd == "policy")
        return dispatch_policy_command(argc, argv, argv[0]);
    if (cmd == "keys")
        return dispatch_keys_command(argc, argv, argv[0]);
    if (cmd == "survival")
        return dispatch_survival_command(argc, argv, argv[0]);
    if (cmd == "health")
        return dispatch_health_command(argc, argv, argv[0]);
    if (cmd == "doctor")
        return dispatch_doctor_command(argc, argv, argv[0]);
    if (cmd == "explain")
        return dispatch_explain_command(argc, argv, argv[0]);
    if (cmd == "metrics")
        return dispatch_metrics_command(argc, argv, argv[0]);
    if (cmd == "capabilities")
        return dispatch_capabilities_command(argc, argv, argv[0]);
    if (cmd == "stats") {
        bool detailed = false;
        if (argc == 3 && std::string(argv[2]) == "--detailed") {
            detailed = true;
        } else if (argc > 2) {
            return usage(argv[0]);
        }
        return cmd_stats(detailed);
    }
    if (cmd == "emergency-disable")
        return dispatch_emergency_toggle_command(argc, argv, argv[0], true);
    if (cmd == "emergency-enable")
        return dispatch_emergency_toggle_command(argc, argv, argv[0], false);
    if (cmd == "emergency-status")
        return dispatch_emergency_status_command(argc, argv, argv[0]);
    if (cmd == "probe")
        return cmd_probe();

    return usage(argv[0]);
}

} // namespace aegis
