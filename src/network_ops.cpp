// cppcheck-suppress-file missingIncludeSystem
#include "network_ops.hpp"

#include <arpa/inet.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <numeric>
#include <sstream>

#include "bpf_ops.hpp"
#include "logging.hpp"

namespace aegis {

bool parse_ipv4(const std::string& ip_str, uint32_t& ip_be)
{
    struct in_addr addr {};
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return false;
    }
    ip_be = addr.s_addr;
    return true;
}

bool parse_ipv6(const std::string& ip_str, Ipv6Key& ip)
{
    struct in6_addr addr {};
    if (inet_pton(AF_INET6, ip_str.c_str(), &addr) != 1) {
        return false;
    }
    std::memcpy(ip.addr, &addr, sizeof(ip.addr));
    return true;
}

bool parse_cidr_v4(const std::string& cidr_str, uint32_t& ip_be, uint8_t& prefix_len)
{
    size_t slash_pos = cidr_str.find('/');
    if (slash_pos == std::string::npos) {
        return false;
    }

    std::string ip_part = cidr_str.substr(0, slash_pos);
    std::string prefix_part = cidr_str.substr(slash_pos + 1);

    if (!parse_ipv4(ip_part, ip_be)) {
        return false;
    }

    try {
        int prefix = std::stoi(prefix_part);
        if (prefix < 0 || prefix > 32) {
            return false;
        }
        prefix_len = static_cast<uint8_t>(prefix);
    } catch (...) {
        return false;
    }

    return true;
}

bool parse_cidr_v6(const std::string& cidr_str, Ipv6Key& ip, uint8_t& prefix_len)
{
    size_t slash_pos = cidr_str.find('/');
    if (slash_pos == std::string::npos) {
        return false;
    }

    std::string ip_part = cidr_str.substr(0, slash_pos);
    std::string prefix_part = cidr_str.substr(slash_pos + 1);

    if (!parse_ipv6(ip_part, ip)) {
        return false;
    }

    try {
        int prefix = std::stoi(prefix_part);
        if (prefix < 0 || prefix > 128) {
            return false;
        }
        prefix_len = static_cast<uint8_t>(prefix);
    } catch (...) {
        return false;
    }

    return true;
}

std::string format_ipv4(uint32_t ip_be)
{
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr {};
    addr.s_addr = ip_be;
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
        return "?.?.?.?";
    }
    return std::string(buf);
}

std::string format_ipv6(const Ipv6Key& ip)
{
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, ip.addr, buf, sizeof(buf)) == nullptr) {
        return "::";
    }
    return std::string(buf);
}

std::string format_cidr_v4(uint32_t ip_be, uint8_t prefix_len)
{
    return format_ipv4(ip_be) + "/" + std::to_string(prefix_len);
}

std::string format_cidr_v6(const Ipv6Key& ip, uint8_t prefix_len)
{
    return format_ipv6(ip) + "/" + std::to_string(prefix_len);
}

namespace {

bool parse_ip_auto(const std::string& ip, uint32_t& ipv4_be, Ipv6Key& ipv6, bool& is_ipv6)
{
    if (parse_ipv4(ip, ipv4_be)) {
        is_ipv6 = false;
        return true;
    }
    if (parse_ipv6(ip, ipv6)) {
        is_ipv6 = true;
        return true;
    }
    return false;
}

bool parse_cidr_auto(const std::string& cidr, uint32_t& ipv4_be, Ipv6Key& ipv6, uint8_t& prefix_len, bool& is_ipv6)
{
    if (parse_cidr_v4(cidr, ipv4_be, prefix_len)) {
        is_ipv6 = false;
        return true;
    }
    if (parse_cidr_v6(cidr, ipv6, prefix_len)) {
        is_ipv6 = true;
        return true;
    }
    return false;
}

std::string format_net_ip_key(const NetIpKey& key)
{
    if (key.family == AF_INET) {
        uint32_t ip_be = 0;
        std::memcpy(&ip_be, key.addr, sizeof(ip_be));
        return format_ipv4(ip_be);
    }
    if (key.family == AF_INET6) {
        Ipv6Key ip{};
        std::memcpy(ip.addr, key.addr, sizeof(ip.addr));
        return format_ipv6(ip);
    }
    return "unknown";
}

} // namespace

std::string protocol_name(uint8_t protocol)
{
    switch (protocol) {
        case 0:
            return "any";
        case 6:
            return "tcp";
        case 17:
            return "udp";
        default:
            return std::to_string(protocol);
    }
}

std::string_view direction_name(uint8_t direction) noexcept
{
    switch (direction) {
        case 0:
            return "egress";
        case 1:
            return "bind";
        case 2:
            return "both";
        default:
            return "unknown";
    }
}

Result<void> load_network_maps(BpfState& state, bool reuse_pins)
{
    // Find network maps in the BPF object
    state.deny_ipv4 = bpf_object__find_map_by_name(state.obj, "deny_ipv4");
    state.deny_ipv6 = bpf_object__find_map_by_name(state.obj, "deny_ipv6");
    state.deny_port = bpf_object__find_map_by_name(state.obj, "deny_port");
    state.deny_cidr_v4 = bpf_object__find_map_by_name(state.obj, "deny_cidr_v4");
    state.deny_cidr_v6 = bpf_object__find_map_by_name(state.obj, "deny_cidr_v6");
    state.net_block_stats = bpf_object__find_map_by_name(state.obj, "net_block_stats");
    state.net_ip_stats = bpf_object__find_map_by_name(state.obj, "net_ip_stats");
    state.net_port_stats = bpf_object__find_map_by_name(state.obj, "net_port_stats");

    // Network maps are optional - don't fail if not present
    if (!state.deny_ipv4 && !state.deny_ipv6) {
        logger().log(SLOG_DEBUG("Network maps not found - network features disabled"));
        return {};
    }

    if (reuse_pins) {
        auto try_reuse_optional = [](bpf_map* map, const char* path, bool& reused) -> Result<void> {
            if (!map) {
                return {};
            }
            auto result = reuse_pinned_map(map, path, reused);
            if (result) {
                return {};
            }

            logger().log(SLOG_WARN("Failed to reuse optional network map; recreating map")
                             .field("path", path)
                             .field("error", result.error().to_string()));
            reused = false;
            std::error_code ec;
            std::filesystem::remove(path, ec);
            if (ec) {
                logger().log(SLOG_WARN("Failed to remove stale optional network map")
                                 .field("path", path)
                                 .field("error", ec.message()));
            }
            return {};
        };

        TRY(try_reuse_optional(state.deny_ipv4, kDenyIpv4Pin, state.deny_ipv4_reused));
        TRY(try_reuse_optional(state.deny_ipv6, kDenyIpv6Pin, state.deny_ipv6_reused));
        TRY(try_reuse_optional(state.deny_port, kDenyPortPin, state.deny_port_reused));
        TRY(try_reuse_optional(state.deny_cidr_v4, kDenyCidrV4Pin, state.deny_cidr_v4_reused));
        TRY(try_reuse_optional(state.deny_cidr_v6, kDenyCidrV6Pin, state.deny_cidr_v6_reused));
        TRY(try_reuse_optional(state.net_block_stats, kNetBlockStatsPin, state.net_block_stats_reused));
        TRY(try_reuse_optional(state.net_ip_stats, kNetIpStatsPin, state.net_ip_stats_reused));
        TRY(try_reuse_optional(state.net_port_stats, kNetPortStatsPin, state.net_port_stats_reused));
    }

    return {};
}

Result<void> pin_network_maps(BpfState& state)
{
    if (!state.deny_ipv4 && !state.deny_ipv6) {
        return {}; // Network maps not loaded
    }

    TRY(ensure_pin_dir());

    if (!state.deny_ipv4_reused && state.deny_ipv4) {
        TRY(pin_map(state.deny_ipv4, kDenyIpv4Pin));
    }
    if (!state.deny_ipv6_reused && state.deny_ipv6) {
        TRY(pin_map(state.deny_ipv6, kDenyIpv6Pin));
    }
    if (!state.deny_port_reused && state.deny_port) {
        TRY(pin_map(state.deny_port, kDenyPortPin));
    }
    if (!state.deny_cidr_v4_reused && state.deny_cidr_v4) {
        TRY(pin_map(state.deny_cidr_v4, kDenyCidrV4Pin));
    }
    if (!state.deny_cidr_v6_reused && state.deny_cidr_v6) {
        TRY(pin_map(state.deny_cidr_v6, kDenyCidrV6Pin));
    }
    if (!state.net_block_stats_reused && state.net_block_stats) {
        TRY(pin_map(state.net_block_stats, kNetBlockStatsPin));
    }
    if (!state.net_ip_stats_reused && state.net_ip_stats) {
        TRY(pin_map(state.net_ip_stats, kNetIpStatsPin));
    }
    if (!state.net_port_stats_reused && state.net_port_stats) {
        TRY(pin_map(state.net_port_stats, kNetPortStatsPin));
    }

    return {};
}

Result<void> attach_network_hooks(BpfState& state, bool lsm_enabled)
{
    if (!lsm_enabled) {
        logger().log(SLOG_WARN("BPF LSM not enabled - network enforcement disabled (audit only)"));
        return {};
    }

    // Attach socket_connect hook
    bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_socket_connect");
    if (prog) {
        bpf_link* link = bpf_program__attach_lsm(prog);
        int err = libbpf_get_error(link);
        if (err || !link) {
            logger().log(SLOG_WARN("Failed to attach socket_connect hook").field("error", static_cast<int64_t>(err)));
        } else {
            state.links.push_back(link);
            logger().log(SLOG_INFO("Attached network socket_connect hook"));
        }
    }

    // Attach socket_bind hook
    prog = bpf_object__find_program_by_name(state.obj, "handle_socket_bind");
    if (prog) {
        bpf_link* link = bpf_program__attach_lsm(prog);
        int err = libbpf_get_error(link);
        if (err || !link) {
            logger().log(SLOG_WARN("Failed to attach socket_bind hook").field("error", static_cast<int64_t>(err)));
        } else {
            state.links.push_back(link);
            logger().log(SLOG_INFO("Attached network socket_bind hook"));
        }
    }

    return {};
}

Result<void> add_deny_ipv4(BpfState& state, const std::string& ip)
{
    uint32_t ip_be;
    if (!parse_ipv4(ip, ip_be)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IPv4 address", ip);
    }
    return add_deny_ipv4_raw(state, ip_be);
}

Result<void> add_deny_ipv4_raw(BpfState& state, uint32_t ip_be)
{
    if (!state.deny_ipv4) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_ipv4 map not loaded");
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_ipv4), &ip_be, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_ipv4 map");
    }
    return {};
}

Result<void> del_deny_ipv4(BpfState& state, const std::string& ip)
{
    if (!state.deny_ipv4) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_ipv4 map not loaded");
    }

    uint32_t ip_be;
    if (!parse_ipv4(ip, ip_be)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IPv4 address", ip);
    }

    if (bpf_map_delete_elem(bpf_map__fd(state.deny_ipv4), &ip_be)) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "IP not in deny list", ip);
        }
        return Error::system(errno, "Failed to delete from deny_ipv4 map");
    }
    return {};
}

Result<std::vector<uint32_t>> list_deny_ipv4(BpfState& state)
{
    if (!state.deny_ipv4) {
        return std::vector<uint32_t>{};
    }

    std::vector<uint32_t> ips;
    int fd = bpf_map__fd(state.deny_ipv4);
    uint32_t key = 0;
    uint32_t next_key = 0;

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        ips.push_back(key);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return ips;
}

Result<void> add_deny_ipv6(BpfState& state, const std::string& ip)
{
    Ipv6Key key{};
    if (!parse_ipv6(ip, key)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IPv6 address", ip);
    }
    return add_deny_ipv6_raw(state, key);
}

Result<void> add_deny_ipv6_raw(BpfState& state, const Ipv6Key& key)
{
    if (!state.deny_ipv6) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_ipv6 map not loaded");
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_ipv6), &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_ipv6 map");
    }
    return {};
}

Result<void> del_deny_ipv6(BpfState& state, const std::string& ip)
{
    if (!state.deny_ipv6) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_ipv6 map not loaded");
    }

    Ipv6Key key{};
    if (!parse_ipv6(ip, key)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IPv6 address", ip);
    }

    if (bpf_map_delete_elem(bpf_map__fd(state.deny_ipv6), &key)) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "IP not in deny list", ip);
        }
        return Error::system(errno, "Failed to delete from deny_ipv6 map");
    }
    return {};
}

Result<std::vector<Ipv6Key>> list_deny_ipv6(BpfState& state)
{
    if (!state.deny_ipv6) {
        return std::vector<Ipv6Key>{};
    }

    std::vector<Ipv6Key> ips;
    int fd = bpf_map__fd(state.deny_ipv6);
    Ipv6Key key{};
    Ipv6Key next_key{};

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        ips.push_back(key);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return ips;
}

Result<void> add_deny_ip(BpfState& state, const std::string& ip)
{
    uint32_t ipv4_be = 0;
    Ipv6Key ipv6{};
    bool is_ipv6 = false;
    if (!parse_ip_auto(ip, ipv4_be, ipv6, is_ipv6)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IP address", ip);
    }
    if (is_ipv6) {
        return add_deny_ipv6_raw(state, ipv6);
    }
    return add_deny_ipv4_raw(state, ipv4_be);
}

Result<void> del_deny_ip(BpfState& state, const std::string& ip)
{
    uint32_t ipv4_be = 0;
    Ipv6Key ipv6{};
    bool is_ipv6 = false;
    if (!parse_ip_auto(ip, ipv4_be, ipv6, is_ipv6)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IP address", ip);
    }
    if (is_ipv6) {
        return del_deny_ipv6(state, ip);
    }
    return del_deny_ipv4(state, ip);
}

Result<void> add_deny_cidr_v4(BpfState& state, const std::string& cidr)
{
    if (!state.deny_cidr_v4) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_cidr_v4 map not loaded");
    }

    uint32_t ip_be;
    uint8_t prefix_len;
    if (!parse_cidr_v4(cidr, ip_be, prefix_len)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }

    Ipv4LpmKey key = {.prefixlen = prefix_len, .addr = ip_be};

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_cidr_v4), &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_cidr_v4 map");
    }
    return {};
}

Result<void> del_deny_cidr_v4(BpfState& state, const std::string& cidr)
{
    if (!state.deny_cidr_v4) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_cidr_v4 map not loaded");
    }

    uint32_t ip_be;
    uint8_t prefix_len;
    if (!parse_cidr_v4(cidr, ip_be, prefix_len)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }

    Ipv4LpmKey key = {.prefixlen = prefix_len, .addr = ip_be};

    if (bpf_map_delete_elem(bpf_map__fd(state.deny_cidr_v4), &key)) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "CIDR not in deny list", cidr);
        }
        return Error::system(errno, "Failed to delete from deny_cidr_v4 map");
    }
    return {};
}

Result<std::vector<std::pair<uint32_t, uint8_t>>> list_deny_cidr_v4(BpfState& state)
{
    if (!state.deny_cidr_v4) {
        return std::vector<std::pair<uint32_t, uint8_t>>{};
    }

    std::vector<std::pair<uint32_t, uint8_t>> cidrs;
    int fd = bpf_map__fd(state.deny_cidr_v4);
    Ipv4LpmKey key{};
    Ipv4LpmKey next_key{};

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        cidrs.emplace_back(key.addr, static_cast<uint8_t>(key.prefixlen));
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return cidrs;
}

Result<void> add_deny_cidr_v6(BpfState& state, const std::string& cidr)
{
    if (!state.deny_cidr_v6) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_cidr_v6 map not loaded");
    }

    Ipv6Key ip{};
    uint8_t prefix_len = 0;
    if (!parse_cidr_v6(cidr, ip, prefix_len)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }

    Ipv6LpmKey key = {.prefixlen = prefix_len, .addr = {0}};
    std::memcpy(key.addr, ip.addr, sizeof(key.addr));

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_cidr_v6), &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_cidr_v6 map");
    }
    return {};
}

Result<void> del_deny_cidr_v6(BpfState& state, const std::string& cidr)
{
    if (!state.deny_cidr_v6) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_cidr_v6 map not loaded");
    }

    Ipv6Key ip{};
    uint8_t prefix_len = 0;
    if (!parse_cidr_v6(cidr, ip, prefix_len)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }

    Ipv6LpmKey key = {.prefixlen = prefix_len, .addr = {0}};
    std::memcpy(key.addr, ip.addr, sizeof(key.addr));

    if (bpf_map_delete_elem(bpf_map__fd(state.deny_cidr_v6), &key)) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "CIDR not in deny list", cidr);
        }
        return Error::system(errno, "Failed to delete from deny_cidr_v6 map");
    }
    return {};
}

Result<std::vector<std::pair<Ipv6Key, uint8_t>>> list_deny_cidr_v6(BpfState& state)
{
    if (!state.deny_cidr_v6) {
        return std::vector<std::pair<Ipv6Key, uint8_t>>{};
    }

    std::vector<std::pair<Ipv6Key, uint8_t>> cidrs;
    int fd = bpf_map__fd(state.deny_cidr_v6);
    Ipv6LpmKey key{};
    Ipv6LpmKey next_key{};

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        Ipv6Key ip{};
        std::memcpy(ip.addr, key.addr, sizeof(ip.addr));
        cidrs.emplace_back(ip, static_cast<uint8_t>(key.prefixlen));
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return cidrs;
}

Result<void> add_deny_cidr(BpfState& state, const std::string& cidr)
{
    uint32_t ipv4_be = 0;
    Ipv6Key ipv6{};
    uint8_t prefix_len = 0;
    bool is_ipv6 = false;
    if (!parse_cidr_auto(cidr, ipv4_be, ipv6, prefix_len, is_ipv6)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }
    if (is_ipv6) {
        return add_deny_cidr_v6(state, cidr);
    }
    return add_deny_cidr_v4(state, cidr);
}

Result<void> del_deny_cidr(BpfState& state, const std::string& cidr)
{
    uint32_t ipv4_be = 0;
    Ipv6Key ipv6{};
    uint8_t prefix_len = 0;
    bool is_ipv6 = false;
    if (!parse_cidr_auto(cidr, ipv4_be, ipv6, prefix_len, is_ipv6)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }
    if (is_ipv6) {
        return del_deny_cidr_v6(state, cidr);
    }
    return del_deny_cidr_v4(state, cidr);
}

Result<void> add_deny_port(BpfState& state, uint16_t port, uint8_t protocol, uint8_t direction)
{
    if (!state.deny_port) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_port map not loaded");
    }

    PortKey key = {.port = port, .protocol = protocol, .direction = direction};

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_port), &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_port map");
    }
    return {};
}

Result<void> del_deny_port(BpfState& state, uint16_t port, uint8_t protocol, uint8_t direction)
{
    if (!state.deny_port) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_port map not loaded");
    }

    PortKey key = {.port = port, .protocol = protocol, .direction = direction};

    if (bpf_map_delete_elem(bpf_map__fd(state.deny_port), &key)) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "Port rule not in deny list");
        }
        return Error::system(errno, "Failed to delete from deny_port map");
    }
    return {};
}

Result<std::vector<PortKey>> list_deny_ports(BpfState& state)
{
    if (!state.deny_port) {
        return std::vector<PortKey>{};
    }

    std::vector<PortKey> ports;
    int fd = bpf_map__fd(state.deny_port);
    PortKey key{};
    PortKey next_key{};

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        ports.push_back(key);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return ports;
}

Result<NetBlockStats> read_net_block_stats(BpfState& state)
{
    if (!state.net_block_stats) {
        return NetBlockStats{};
    }

    int fd = bpf_map__fd(state.net_block_stats);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }

    std::vector<NetBlockStats> vals(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data())) {
        if (errno == ENOENT) {
            return NetBlockStats{};
        }
        return Error::system(errno, "Failed to read net_block_stats");
    }

    NetBlockStats out{};
    for (const auto& v : vals) {
        out.connect_blocks += v.connect_blocks;
        out.bind_blocks += v.bind_blocks;
        out.ringbuf_drops += v.ringbuf_drops;
    }
    return out;
}

Result<std::vector<std::pair<std::string, uint64_t>>> read_net_ip_stats(BpfState& state)
{
    if (!state.net_ip_stats) {
        return std::vector<std::pair<std::string, uint64_t>>{};
    }

    int fd = bpf_map__fd(state.net_ip_stats);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }

    std::vector<uint64_t> vals(cpu_cnt);
    NetIpKey key{};
    NetIpKey next_key{};
    std::vector<std::pair<std::string, uint64_t>> out;

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            return Error::system(errno, "Failed to read net_ip_stats");
        }
        uint64_t sum = std::accumulate(vals.begin(), vals.end(), uint64_t{0});
        out.emplace_back(format_net_ip_key(key), sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<std::pair<uint16_t, uint64_t>>> read_net_port_stats(BpfState& state)
{
    if (!state.net_port_stats) {
        return std::vector<std::pair<uint16_t, uint64_t>>{};
    }

    int fd = bpf_map__fd(state.net_port_stats);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }

    std::vector<uint64_t> vals(cpu_cnt);
    uint16_t key = 0;
    uint16_t next_key = 0;
    std::vector<std::pair<uint16_t, uint64_t>> out;

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            return Error::system(errno, "Failed to read net_port_stats");
        }
        uint64_t sum = std::accumulate(vals.begin(), vals.end(), uint64_t{0});
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<void> reset_net_block_stats(BpfState& state)
{
    if (!state.net_block_stats) {
        return {};
    }

    int fd = bpf_map__fd(state.net_block_stats);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }

    std::vector<NetBlockStats> zeros(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_update_elem(fd, &key, zeros.data(), BPF_ANY)) {
        return Error::system(errno, "Failed to reset net_block_stats");
    }
    return {};
}

Result<void> clear_network_maps(BpfState& state)
{
    if (state.deny_ipv4) {
        TRY(clear_map_entries(state.deny_ipv4));
    }
    if (state.deny_ipv6) {
        TRY(clear_map_entries(state.deny_ipv6));
    }
    if (state.deny_port) {
        TRY(clear_map_entries(state.deny_port));
    }
    if (state.deny_cidr_v4) {
        TRY(clear_map_entries(state.deny_cidr_v4));
    }
    if (state.deny_cidr_v6) {
        TRY(clear_map_entries(state.deny_cidr_v6));
    }
    if (state.net_ip_stats) {
        TRY(clear_map_entries(state.net_ip_stats));
    }
    if (state.net_port_stats) {
        TRY(clear_map_entries(state.net_port_stats));
    }
    TRY(reset_net_block_stats(state));
    return {};
}

// --- FD-accepting overloads for shadow map population ---

Result<void> add_deny_ip_to_fds(int ipv4_fd, int ipv6_fd, const std::string& ip)
{
    uint32_t ipv4_be = 0;
    Ipv6Key ipv6{};
    bool is_ipv6 = false;
    if (!parse_ip_auto(ip, ipv4_be, ipv6, is_ipv6)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IP address", ip);
    }
    uint8_t one = 1;
    if (is_ipv6) {
        if (ipv6_fd < 0) {
            return Error(ErrorCode::BpfMapOperationFailed, "Network deny_ipv6 shadow not available");
        }
        if (bpf_map_update_elem(ipv6_fd, &ipv6, &one, BPF_ANY)) {
            return Error::system(errno, "Failed to update shadow deny_ipv6 map");
        }
    } else {
        if (ipv4_fd < 0) {
            return Error(ErrorCode::BpfMapOperationFailed, "Network deny_ipv4 shadow not available");
        }
        if (bpf_map_update_elem(ipv4_fd, &ipv4_be, &one, BPF_ANY)) {
            return Error::system(errno, "Failed to update shadow deny_ipv4 map");
        }
    }
    return {};
}

Result<void> add_deny_cidr_to_fds(int cidr_v4_fd, int cidr_v6_fd, const std::string& cidr)
{
    uint32_t ipv4_be = 0;
    Ipv6Key ipv6{};
    uint8_t prefix_len = 0;
    bool is_ipv6 = false;
    if (!parse_cidr_auto(cidr, ipv4_be, ipv6, prefix_len, is_ipv6)) {
        return Error(ErrorCode::InvalidArgument, "Invalid CIDR notation", cidr);
    }
    uint8_t one = 1;
    if (is_ipv6) {
        if (cidr_v6_fd < 0) {
            return Error(ErrorCode::BpfMapOperationFailed, "Network deny_cidr_v6 shadow not available");
        }
        Ipv6LpmKey key = {.prefixlen = prefix_len, .addr = {0}};
        std::memcpy(key.addr, ipv6.addr, sizeof(key.addr));
        if (bpf_map_update_elem(cidr_v6_fd, &key, &one, BPF_ANY)) {
            return Error::system(errno, "Failed to update shadow deny_cidr_v6 map");
        }
    } else {
        if (cidr_v4_fd < 0) {
            return Error(ErrorCode::BpfMapOperationFailed, "Network deny_cidr_v4 shadow not available");
        }
        Ipv4LpmKey key = {.prefixlen = prefix_len, .addr = ipv4_be};
        if (bpf_map_update_elem(cidr_v4_fd, &key, &one, BPF_ANY)) {
            return Error::system(errno, "Failed to update shadow deny_cidr_v4 map");
        }
    }
    return {};
}

Result<void> add_deny_port_to_fd(int port_fd, uint16_t port, uint8_t protocol, uint8_t direction)
{
    if (port_fd < 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Network deny_port shadow not available");
    }
    PortKey key = {.port = port, .protocol = protocol, .direction = direction};
    uint8_t one = 1;
    if (bpf_map_update_elem(port_fd, &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update shadow deny_port map");
    }
    return {};
}

} // namespace aegis
