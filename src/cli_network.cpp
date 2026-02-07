// cppcheck-suppress-file missingIncludeSystem
#include "cli_network.hpp"

#include <cstdint>
#include <string>

#include "cli_common.hpp"
#include "commands_network.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

bool parse_port(const std::string& value, uint16_t& port)
{
    uint64_t parsed = 0;
    if (!parse_uint64(value, parsed) || parsed == 0 || parsed > 65535) {
        logger().log(SLOG_ERROR("Invalid port").field("value", value));
        return false;
    }
    port = static_cast<uint16_t>(parsed);
    return true;
}

} // namespace

int dispatch_network_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];

    if (sub == "stats")
        return cmd_network_stats();
    if (sub != "deny")
        return usage(prog);

    if (argc < 4)
        return usage(prog);
    std::string action = argv[3];
    if (action == "list")
        return cmd_network_deny_list();
    if (action == "clear")
        return cmd_network_deny_clear();

    std::string ip;
    std::string cidr;
    std::string protocol = "any";
    std::string direction = "both";
    uint16_t port = 0;
    bool has_ip = false;
    bool has_cidr = false;
    bool has_port = false;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--ip") {
            if (i + 1 >= argc)
                return usage(prog);
            ip = argv[++i];
            has_ip = true;
        } else if (arg == "--cidr") {
            if (i + 1 >= argc)
                return usage(prog);
            cidr = argv[++i];
            has_cidr = true;
        } else if (arg == "--port") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_port(argv[++i], port))
                return 1;
            has_port = true;
        } else if (arg == "--protocol") {
            if (i + 1 >= argc)
                return usage(prog);
            protocol = argv[++i];
        } else if (arg == "--direction") {
            if (i + 1 >= argc)
                return usage(prog);
            direction = argv[++i];
        } else {
            return usage(prog);
        }
    }

    int selector_count = (has_ip ? 1 : 0) + (has_cidr ? 1 : 0) + (has_port ? 1 : 0);
    if (selector_count != 1) {
        logger().log(SLOG_ERROR("Specify exactly one of --ip, --cidr, or --port"));
        return 1;
    }

    if (action == "add") {
        if (has_ip)
            return cmd_network_deny_add_ip(ip);
        if (has_cidr)
            return cmd_network_deny_add_cidr(cidr);
        if (has_port)
            return cmd_network_deny_add_port(port, protocol, direction);
        return usage(prog);
    }
    if (action == "del") {
        if (has_ip)
            return cmd_network_deny_del_ip(ip);
        if (has_cidr)
            return cmd_network_deny_del_cidr(cidr);
        if (has_port)
            return cmd_network_deny_del_port(port, protocol, direction);
        return usage(prog);
    }

    return usage(prog);
}

} // namespace aegis
