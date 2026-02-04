// cppcheck-suppress-file missingIncludeSystem
#include "cli_common.hpp"

#include <iostream>

namespace aegis {

int usage(const char* prog)
{
    std::cerr << "Usage: " << prog
              << " run [--audit|--enforce] [--enforce-signal=none|term|kill|int] [--allow-sigkill] [--kill-escalation-threshold=<n>] [--kill-escalation-window-seconds=<seconds>] [--seccomp] [--deadman-ttl=<seconds>] [--lsm-hook=file|inode|both] [--ringbuf-bytes=<bytes>] [--event-sample-rate=<n>] [--log=stdout|journald|both] [--log-level=debug|info|warn|error] [--log-format=text|json]"
              << " | block {add|del|list|clear} [path]"
              << " | allow {add|del} <cgroup_path> | allow list"
              << " | network deny {add|del} --ip <ipv4|ipv6> | --cidr <cidr> | --port <port> [--protocol tcp|udp|any] [--direction egress|bind|both]"
              << " | network deny {list|clear}"
              << " | network stats"
              << " | survival {list|verify}"
              << " | policy {lint|validate|apply|export} <file> [--reset] [--sha256 <hex>|--sha256-file <path>] [--no-rollback] [--require-signature] [--verbose]"
              << " | policy sign <policy.conf> --key <private.key> --output <policy.signed>"
              << " | policy {show|rollback}"
              << " | keys {list|add <pubkey.pub>}"
              << " | stats [--detailed]"
              << " | metrics [--out <path>] [--detailed]"
              << " | health [--json]" << std::endl;
    return 1;
}

LogLevel parse_log_level(const std::string& value)
{
    if (value == "debug") return LogLevel::Debug;
    if (value == "info") return LogLevel::Info;
    if (value == "warn" || value == "warning") return LogLevel::Warn;
    if (value == "error") return LogLevel::Error;
    return LogLevel::Info;
}

void configure_logging_from_args(int argc, char** argv)
{
    LogLevel log_level = LogLevel::Info;
    bool json_format = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--log-level=", 0) == 0) {
            log_level = parse_log_level(arg.substr(12));
        }
        else if (arg.rfind("--log-format=", 0) == 0) {
            json_format = (arg.substr(13) == "json");
        }
    }

    logger().set_level(log_level);
    logger().set_json_format(json_format);
}

}  // namespace aegis
