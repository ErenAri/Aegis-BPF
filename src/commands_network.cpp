// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Network command implementations
 */

#include "commands_network.hpp"

#include <cstdint>
#include <iostream>

#include "bpf_ops.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
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

bool parse_protocol(const std::string& protocol_str, uint8_t& protocol)
{
    protocol = 0;
    if (protocol_str == "tcp") {
        protocol = 6;
    } else if (protocol_str == "udp") {
        protocol = 17;
    } else if (protocol_str != "any" && !protocol_str.empty()) {
        logger().log(SLOG_ERROR("Invalid protocol").field("protocol", protocol_str));
        return false;
    }
    return true;
}

bool parse_direction(const std::string& direction_str, uint8_t& direction)
{
    direction = 2;
    if (direction_str == "egress") {
        direction = 0;
    } else if (direction_str == "bind") {
        direction = 1;
    } else if (direction_str != "both" && !direction_str.empty()) {
        logger().log(SLOG_ERROR("Invalid direction").field("direction", direction_str));
        return false;
    }
    return true;
}

} // namespace

int cmd_network_deny_add_ip(const std::string& ip)
{
    const std::string trace_id = make_span_id("trace-net-deny-add-ip");
    ScopedSpan span("cli.network_deny_add_ip", trace_id);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto add_result = add_deny_ip(state, ip);
    if (!add_result) {
        logger().log(
            SLOG_ERROR("Failed to add deny IP").field("ip", ip).field("error", add_result.error().to_string()));
        return fail_span(span, add_result.error().to_string());
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_ERROR("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
        return fail_span(span, hints_result.error().to_string());
    }

    logger().log(SLOG_INFO("Added deny IP").field("ip", ip));
    return 0;
}

int cmd_network_deny_add_cidr(const std::string& cidr)
{
    const std::string trace_id = make_span_id("trace-net-deny-add-cidr");
    ScopedSpan span("cli.network_deny_add_cidr", trace_id);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto add_result = add_deny_cidr(state, cidr);
    if (!add_result) {
        logger().log(
            SLOG_ERROR("Failed to add deny CIDR").field("cidr", cidr).field("error", add_result.error().to_string()));
        return fail_span(span, add_result.error().to_string());
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_ERROR("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
        return fail_span(span, hints_result.error().to_string());
    }

    logger().log(SLOG_INFO("Added deny CIDR").field("cidr", cidr));
    return 0;
}

int cmd_network_deny_add_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str)
{
    const std::string trace_id = make_span_id("trace-net-deny-add-port");
    ScopedSpan span("cli.network_deny_add_port", trace_id);

    uint8_t protocol = 0;
    if (!parse_protocol(protocol_str, protocol))
        return fail_span(span, "Invalid protocol");

    uint8_t direction = 2;
    if (!parse_direction(direction_str, direction))
        return fail_span(span, "Invalid direction");

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto add_result = add_deny_port(state, port, protocol, direction);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny port")
                         .field("port", static_cast<int64_t>(port))
                         .field("error", add_result.error().to_string()));
        return fail_span(span, add_result.error().to_string());
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_ERROR("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
        return fail_span(span, hints_result.error().to_string());
    }

    logger().log(SLOG_INFO("Added deny port")
                     .field("port", static_cast<int64_t>(port))
                     .field("protocol", protocol_str.empty() ? "any" : protocol_str)
                     .field("direction", direction_str.empty() ? "both" : direction_str));
    return 0;
}

int cmd_network_deny_del_ip(const std::string& ip)
{
    const std::string trace_id = make_span_id("trace-net-deny-del-ip");
    ScopedSpan span("cli.network_deny_del_ip", trace_id);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto del_result = del_deny_ip(state, ip);
    if (!del_result) {
        logger().log(
            SLOG_ERROR("Failed to remove deny IP").field("ip", ip).field("error", del_result.error().to_string()));
        return fail_span(span, del_result.error().to_string());
    }

    // Best-effort; empty hints affect performance only.
    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(SLOG_WARN("Failed to refresh policy empty hints after delete")
                         .field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Removed deny IP").field("ip", ip));
    return 0;
}

int cmd_network_deny_del_cidr(const std::string& cidr)
{
    const std::string trace_id = make_span_id("trace-net-deny-del-cidr");
    ScopedSpan span("cli.network_deny_del_cidr", trace_id);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto del_result = del_deny_cidr(state, cidr);
    if (!del_result) {
        logger().log(SLOG_ERROR("Failed to remove deny CIDR")
                         .field("cidr", cidr)
                         .field("error", del_result.error().to_string()));
        return fail_span(span, del_result.error().to_string());
    }

    // Best-effort; empty hints affect performance only.
    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(SLOG_WARN("Failed to refresh policy empty hints after delete")
                         .field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Removed deny CIDR").field("cidr", cidr));
    return 0;
}

int cmd_network_deny_del_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str)
{
    const std::string trace_id = make_span_id("trace-net-deny-del-port");
    ScopedSpan span("cli.network_deny_del_port", trace_id);

    uint8_t protocol = 0;
    if (!parse_protocol(protocol_str, protocol))
        return fail_span(span, "Invalid protocol");

    uint8_t direction = 2;
    if (!parse_direction(direction_str, direction))
        return fail_span(span, "Invalid direction");

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto del_result = del_deny_port(state, port, protocol, direction);
    if (!del_result) {
        logger().log(SLOG_ERROR("Failed to remove deny port")
                         .field("port", static_cast<int64_t>(port))
                         .field("error", del_result.error().to_string()));
        return fail_span(span, del_result.error().to_string());
    }

    // Best-effort; empty hints affect performance only.
    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(SLOG_WARN("Failed to refresh policy empty hints after delete")
                         .field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Removed deny port").field("port", static_cast<int64_t>(port)));
    return 0;
}

int cmd_network_deny_list()
{
    const std::string trace_id = make_span_id("trace-net-deny-list");
    ScopedSpan span("cli.network_deny_list", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    std::cout << "Denied IPs:" << '\n';
    if (state.deny_ipv4) {
        auto ips_result = list_deny_ipv4(state);
        if (ips_result) {
            for (uint32_t ip : *ips_result) {
                std::cout << "  " << format_ipv4(ip) << '\n';
            }
        }
    }
    if (state.deny_ipv6) {
        auto ips_result = list_deny_ipv6(state);
        if (ips_result) {
            for (const auto& ip : *ips_result) {
                std::cout << "  " << format_ipv6(ip) << '\n';
            }
        }
    }

    std::cout << "\nDenied CIDRs:" << '\n';
    if (state.deny_cidr_v4) {
        auto cidrs_result = list_deny_cidr_v4(state);
        if (cidrs_result) {
            for (const auto& cidr : *cidrs_result) {
                std::cout << "  " << format_cidr_v4(cidr.first, cidr.second) << '\n';
            }
        }
    }
    if (state.deny_cidr_v6) {
        auto cidrs_result = list_deny_cidr_v6(state);
        if (cidrs_result) {
            for (const auto& cidr : *cidrs_result) {
                std::cout << "  " << format_cidr_v6(cidr.first, cidr.second) << '\n';
            }
        }
    }

    std::cout << "\nDenied Ports:" << '\n';
    if (state.deny_port) {
        auto ports_result = list_deny_ports(state);
        if (ports_result) {
            for (const auto& pr : *ports_result) {
                std::cout << "  " << pr.port << " (" << protocol_name(pr.protocol) << ", "
                          << direction_name(pr.direction) << ")" << '\n';
            }
        }
    }

    return 0;
}

int cmd_network_deny_clear()
{
    const std::string trace_id = make_span_id("trace-net-deny-clear");
    ScopedSpan span("cli.network_deny_clear", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    if (state.deny_ipv4) {
        clear_map_entries(state.deny_ipv4);
    }
    if (state.deny_ipv6) {
        clear_map_entries(state.deny_ipv6);
    }
    if (state.deny_cidr_v4) {
        clear_map_entries(state.deny_cidr_v4);
    }
    if (state.deny_cidr_v6) {
        clear_map_entries(state.deny_cidr_v6);
    }
    if (state.deny_port) {
        clear_map_entries(state.deny_port);
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_WARN("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Cleared all network deny rules"));
    return 0;
}

int cmd_network_stats()
{
    const std::string trace_id = make_span_id("trace-net-stats");
    ScopedSpan span("cli.network_stats", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto stats_result = read_net_block_stats(state);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read network stats").field("error", stats_result.error().to_string()));
        return fail_span(span, stats_result.error().to_string());
    }

    const auto& stats = *stats_result;
    std::cout << "Network Block Statistics:" << '\n';
    std::cout << "  Connect blocks: " << stats.connect_blocks << '\n';
    std::cout << "  Bind blocks: " << stats.bind_blocks << '\n';
    std::cout << "  Ringbuf drops: " << stats.ringbuf_drops << '\n';

    return 0;
}

} // namespace aegis
