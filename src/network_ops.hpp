// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <string>
#include <utility>
#include <vector>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

class BpfState;

// Network map loading and initialization
Result<void> load_network_maps(BpfState& state, bool reuse_pins);
Result<void> pin_network_maps(BpfState& state);
Result<void> attach_network_hooks(BpfState& state, bool lsm_enabled);

// IPv4 deny operations
Result<void> add_deny_ipv4(BpfState& state, const std::string& ip);
Result<void> add_deny_ipv4_raw(BpfState& state, uint32_t ip_be);
Result<void> del_deny_ipv4(BpfState& state, const std::string& ip);
Result<std::vector<uint32_t>> list_deny_ipv4(BpfState& state);

// IPv6 deny operations
Result<void> add_deny_ipv6(BpfState& state, const std::string& ip);
Result<void> add_deny_ipv6_raw(BpfState& state, const Ipv6Key& key);
Result<void> del_deny_ipv6(BpfState& state, const std::string& ip);
Result<std::vector<Ipv6Key>> list_deny_ipv6(BpfState& state);

// IP deny operations (auto-detect IPv4/IPv6)
Result<void> add_deny_ip(BpfState& state, const std::string& ip);
Result<void> del_deny_ip(BpfState& state, const std::string& ip);

// CIDR deny operations (IPv4 LPM trie)
Result<void> add_deny_cidr_v4(BpfState& state, const std::string& cidr);
Result<void> del_deny_cidr_v4(BpfState& state, const std::string& cidr);
Result<std::vector<std::pair<uint32_t, uint8_t>>> list_deny_cidr_v4(BpfState& state);

// CIDR deny operations (IPv6 LPM trie)
Result<void> add_deny_cidr_v6(BpfState& state, const std::string& cidr);
Result<void> del_deny_cidr_v6(BpfState& state, const std::string& cidr);
Result<std::vector<std::pair<Ipv6Key, uint8_t>>> list_deny_cidr_v6(BpfState& state);

// CIDR deny operations (auto-detect IPv4/IPv6)
Result<void> add_deny_cidr(BpfState& state, const std::string& cidr);
Result<void> del_deny_cidr(BpfState& state, const std::string& cidr);

// Port deny operations
Result<void> add_deny_port(BpfState& state, uint16_t port, uint8_t protocol, uint8_t direction);
Result<void> del_deny_port(BpfState& state, uint16_t port, uint8_t protocol, uint8_t direction);
Result<std::vector<PortKey>> list_deny_ports(BpfState& state);

// Network statistics
Result<NetBlockStats> read_net_block_stats(BpfState& state);
Result<std::vector<std::pair<std::string, uint64_t>>> read_net_ip_stats(BpfState& state);
Result<std::vector<std::pair<uint16_t, uint64_t>>> read_net_port_stats(BpfState& state);
Result<void> reset_net_block_stats(BpfState& state);

// Clear all network rules
Result<void> clear_network_maps(BpfState& state);

// Utility functions
bool parse_ipv4(const std::string& ip_str, uint32_t& ip_be);
bool parse_ipv6(const std::string& ip_str, Ipv6Key& ip);
bool parse_cidr_v4(const std::string& cidr_str, uint32_t& ip_be, uint8_t& prefix_len);
bool parse_cidr_v6(const std::string& cidr_str, Ipv6Key& ip, uint8_t& prefix_len);
std::string format_ipv4(uint32_t ip_be);
std::string format_ipv6(const Ipv6Key& ip);
std::string format_cidr_v4(uint32_t ip_be, uint8_t prefix_len);
std::string format_cidr_v6(const Ipv6Key& ip, uint8_t prefix_len);
std::string protocol_name(uint8_t protocol);
std::string direction_name(uint8_t direction);

} // namespace aegis
