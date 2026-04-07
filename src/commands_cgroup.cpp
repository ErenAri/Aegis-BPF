// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Cgroup-scoped deny command implementations
 */

#include "commands_cgroup.hpp"

#include <cerrno>
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

int cmd_cgroup_deny_add_inode(const std::string& cgroup, const std::string& inode_str)
{
    const std::string trace_id = make_span_id("trace-cg-deny-add-inode");
    ScopedSpan span("cli.cgroup_deny_add_inode", trace_id);

    InodeId inode{};
    if (!parse_inode_id(inode_str, inode)) {
        logger().log(SLOG_ERROR("Invalid inode format (expected dev:ino)").field("value", inode_str));
        return fail_span(span, "Invalid inode format");
    }

    auto cgid_result = resolve_cgroup_identifier(cgroup);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to resolve cgroup")
                         .field("cgroup", cgroup)
                         .field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }

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

    if (!state.deny_cgroup_inode) {
        logger().log(SLOG_ERROR("deny_cgroup_inode map not available"));
        return fail_span(span, "deny_cgroup_inode map not available");
    }

    auto add_result = add_cgroup_deny_inode_to_fd(bpf_map__fd(state.deny_cgroup_inode), *cgid_result, inode);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add cgroup deny inode")
                         .field("cgroup", cgroup)
                         .field("inode", inode_str)
                         .field("error", add_result.error().to_string()));
        return fail_span(span, add_result.error().to_string());
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_ERROR("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
        return fail_span(span, hints_result.error().to_string());
    }

    logger().log(SLOG_INFO("Added cgroup deny inode")
                     .field("cgroup", cgroup)
                     .field("cgid", static_cast<int64_t>(*cgid_result))
                     .field("inode", inode_str));
    return 0;
}

int cmd_cgroup_deny_add_ip(const std::string& cgroup, const std::string& ip)
{
    const std::string trace_id = make_span_id("trace-cg-deny-add-ip");
    ScopedSpan span("cli.cgroup_deny_add_ip", trace_id);

    auto cgid_result = resolve_cgroup_identifier(cgroup);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to resolve cgroup")
                         .field("cgroup", cgroup)
                         .field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }

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

    if (!state.deny_cgroup_ipv4) {
        logger().log(SLOG_ERROR("deny_cgroup_ipv4 map not available"));
        return fail_span(span, "deny_cgroup_ipv4 map not available");
    }

    auto add_result = add_cgroup_deny_ipv4_to_fd(bpf_map__fd(state.deny_cgroup_ipv4), *cgid_result, ip);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add cgroup deny IP")
                         .field("cgroup", cgroup)
                         .field("ip", ip)
                         .field("error", add_result.error().to_string()));
        return fail_span(span, add_result.error().to_string());
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_ERROR("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
        return fail_span(span, hints_result.error().to_string());
    }

    logger().log(SLOG_INFO("Added cgroup deny IP")
                     .field("cgroup", cgroup)
                     .field("cgid", static_cast<int64_t>(*cgid_result))
                     .field("ip", ip));
    return 0;
}

int cmd_cgroup_deny_add_port(const std::string& cgroup, uint16_t port, const std::string& protocol_str,
                             const std::string& direction_str)
{
    const std::string trace_id = make_span_id("trace-cg-deny-add-port");
    ScopedSpan span("cli.cgroup_deny_add_port", trace_id);

    uint8_t protocol = 0;
    if (!parse_protocol(protocol_str, protocol))
        return fail_span(span, "Invalid protocol");

    uint8_t direction = 2;
    if (!parse_direction(direction_str, direction))
        return fail_span(span, "Invalid direction");

    auto cgid_result = resolve_cgroup_identifier(cgroup);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to resolve cgroup")
                         .field("cgroup", cgroup)
                         .field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }

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

    if (!state.deny_cgroup_port) {
        logger().log(SLOG_ERROR("deny_cgroup_port map not available"));
        return fail_span(span, "deny_cgroup_port map not available");
    }

    PortRule rule{};
    rule.port = port;
    rule.protocol = protocol;
    rule.direction = direction;

    auto add_result = add_cgroup_deny_port_to_fd(bpf_map__fd(state.deny_cgroup_port), *cgid_result, rule);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add cgroup deny port")
                         .field("cgroup", cgroup)
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

    logger().log(SLOG_INFO("Added cgroup deny port")
                     .field("cgroup", cgroup)
                     .field("cgid", static_cast<int64_t>(*cgid_result))
                     .field("port", static_cast<int64_t>(port))
                     .field("protocol", protocol_str.empty() ? "any" : protocol_str)
                     .field("direction", direction_str.empty() ? "both" : direction_str));
    return 0;
}

int cmd_cgroup_deny_del_inode(const std::string& cgroup, const std::string& inode_str)
{
    const std::string trace_id = make_span_id("trace-cg-deny-del-inode");
    ScopedSpan span("cli.cgroup_deny_del_inode", trace_id);

    InodeId inode{};
    if (!parse_inode_id(inode_str, inode)) {
        logger().log(SLOG_ERROR("Invalid inode format (expected dev:ino)").field("value", inode_str));
        return fail_span(span, "Invalid inode format");
    }

    auto cgid_result = resolve_cgroup_identifier(cgroup);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to resolve cgroup")
                         .field("cgroup", cgroup)
                         .field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }

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

    if (!state.deny_cgroup_inode) {
        logger().log(SLOG_ERROR("deny_cgroup_inode map not available"));
        return fail_span(span, "deny_cgroup_inode map not available");
    }

    CgroupInodeKey key{};
    key.cgid = *cgid_result;
    key.inode = inode;
    if (bpf_map_delete_elem(bpf_map__fd(state.deny_cgroup_inode), &key)) {
        logger().log(SLOG_ERROR("Failed to delete cgroup deny inode")
                         .field("cgroup", cgroup)
                         .field("inode", inode_str)
                         .field("errno", static_cast<int64_t>(errno)));
        return fail_span(span, "Failed to delete cgroup deny inode");
    }

    // Best-effort; empty hints affect performance only.
    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(SLOG_WARN("Failed to refresh policy empty hints after delete")
                         .field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Removed cgroup deny inode").field("cgroup", cgroup).field("inode", inode_str));
    return 0;
}

int cmd_cgroup_deny_del_ip(const std::string& cgroup, const std::string& ip)
{
    const std::string trace_id = make_span_id("trace-cg-deny-del-ip");
    ScopedSpan span("cli.cgroup_deny_del_ip", trace_id);

    auto cgid_result = resolve_cgroup_identifier(cgroup);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to resolve cgroup")
                         .field("cgroup", cgroup)
                         .field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }

    uint32_t ip_be = 0;
    if (!parse_ipv4(ip, ip_be)) {
        logger().log(SLOG_ERROR("Invalid IPv4 address").field("ip", ip));
        return fail_span(span, "Invalid IPv4 address");
    }

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

    if (!state.deny_cgroup_ipv4) {
        logger().log(SLOG_ERROR("deny_cgroup_ipv4 map not available"));
        return fail_span(span, "deny_cgroup_ipv4 map not available");
    }

    CgroupIpv4Key key{};
    key.cgid = *cgid_result;
    key.addr = ip_be;
    key._pad = 0;
    if (bpf_map_delete_elem(bpf_map__fd(state.deny_cgroup_ipv4), &key)) {
        logger().log(SLOG_ERROR("Failed to delete cgroup deny IP")
                         .field("cgroup", cgroup)
                         .field("ip", ip)
                         .field("errno", static_cast<int64_t>(errno)));
        return fail_span(span, "Failed to delete cgroup deny IP");
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(SLOG_WARN("Failed to refresh policy empty hints after delete")
                         .field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Removed cgroup deny IP").field("cgroup", cgroup).field("ip", ip));
    return 0;
}

int cmd_cgroup_deny_del_port(const std::string& cgroup, uint16_t port, const std::string& protocol_str,
                             const std::string& direction_str)
{
    const std::string trace_id = make_span_id("trace-cg-deny-del-port");
    ScopedSpan span("cli.cgroup_deny_del_port", trace_id);

    uint8_t protocol = 0;
    if (!parse_protocol(protocol_str, protocol))
        return fail_span(span, "Invalid protocol");

    uint8_t direction = 2;
    if (!parse_direction(direction_str, direction))
        return fail_span(span, "Invalid direction");

    auto cgid_result = resolve_cgroup_identifier(cgroup);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to resolve cgroup")
                         .field("cgroup", cgroup)
                         .field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }

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

    if (!state.deny_cgroup_port) {
        logger().log(SLOG_ERROR("deny_cgroup_port map not available"));
        return fail_span(span, "deny_cgroup_port map not available");
    }

    CgroupPortKey key{};
    key.cgid = *cgid_result;
    key.port = port;
    key.protocol = protocol;
    key.direction = direction;
    key._pad = 0;
    if (bpf_map_delete_elem(bpf_map__fd(state.deny_cgroup_port), &key)) {
        logger().log(SLOG_ERROR("Failed to delete cgroup deny port")
                         .field("cgroup", cgroup)
                         .field("port", static_cast<int64_t>(port))
                         .field("errno", static_cast<int64_t>(errno)));
        return fail_span(span, "Failed to delete cgroup deny port");
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(SLOG_WARN("Failed to refresh policy empty hints after delete")
                         .field("error", hints_result.error().to_string()));
    }

    logger().log(
        SLOG_INFO("Removed cgroup deny port").field("cgroup", cgroup).field("port", static_cast<int64_t>(port)));
    return 0;
}

int cmd_cgroup_deny_list()
{
    const std::string trace_id = make_span_id("trace-cg-deny-list");
    ScopedSpan span("cli.cgroup_deny_list", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    std::cout << "Cgroup Denied Inodes:" << '\n';
    if (state.deny_cgroup_inode) {
        int fd = bpf_map__fd(state.deny_cgroup_inode);
        CgroupInodeKey key{};
        CgroupInodeKey next{};
        uint8_t value = 0;
        int rc = bpf_map_get_next_key(fd, nullptr, &key);
        while (rc == 0) {
            if (bpf_map_lookup_elem(fd, &key, &value) == 0) {
                std::cout << "  cgid:" << key.cgid << " " << key.inode.dev << ":" << key.inode.ino << '\n';
            }
            rc = bpf_map_get_next_key(fd, &key, &next);
            key = next;
        }
    }

    std::cout << "\nCgroup Denied IPs:" << '\n';
    if (state.deny_cgroup_ipv4) {
        int fd = bpf_map__fd(state.deny_cgroup_ipv4);
        CgroupIpv4Key key{};
        CgroupIpv4Key next{};
        uint8_t value = 0;
        int rc = bpf_map_get_next_key(fd, nullptr, &key);
        while (rc == 0) {
            if (bpf_map_lookup_elem(fd, &key, &value) == 0) {
                std::cout << "  cgid:" << key.cgid << " " << format_ipv4(key.addr) << '\n';
            }
            rc = bpf_map_get_next_key(fd, &key, &next);
            key = next;
        }
    }

    std::cout << "\nCgroup Denied Ports:" << '\n';
    if (state.deny_cgroup_port) {
        int fd = bpf_map__fd(state.deny_cgroup_port);
        CgroupPortKey key{};
        CgroupPortKey next{};
        uint8_t value = 0;
        int rc = bpf_map_get_next_key(fd, nullptr, &key);
        while (rc == 0) {
            if (bpf_map_lookup_elem(fd, &key, &value) == 0) {
                std::cout << "  cgid:" << key.cgid << " " << key.port << " (" << protocol_name(key.protocol) << ", "
                          << direction_name(key.direction) << ")" << '\n';
            }
            rc = bpf_map_get_next_key(fd, &key, &next);
            key = next;
        }
    }

    return 0;
}

int cmd_cgroup_deny_clear()
{
    const std::string trace_id = make_span_id("trace-cg-deny-clear");
    ScopedSpan span("cli.cgroup_deny_clear", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    if (state.deny_cgroup_inode) {
        clear_map_entries(state.deny_cgroup_inode);
    }
    if (state.deny_cgroup_ipv4) {
        clear_map_entries(state.deny_cgroup_ipv4);
    }
    if (state.deny_cgroup_port) {
        clear_map_entries(state.deny_cgroup_port);
    }

    auto hints_result = refresh_policy_empty_hints(state);
    if (!hints_result) {
        logger().log(
            SLOG_WARN("Failed to refresh policy empty hints").field("error", hints_result.error().to_string()));
    }

    logger().log(SLOG_INFO("Cleared all cgroup deny rules"));
    return 0;
}

} // namespace aegis
