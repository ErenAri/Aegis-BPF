// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>

namespace aegis {

// Network commands
int cmd_network_deny_add_ip(const std::string& ip);
int cmd_network_deny_add_cidr(const std::string& cidr);
int cmd_network_deny_add_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str);
int cmd_network_deny_del_ip(const std::string& ip);
int cmd_network_deny_del_cidr(const std::string& cidr);
int cmd_network_deny_del_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str);
int cmd_network_deny_list();
int cmd_network_deny_clear();
int cmd_network_stats();

} // namespace aegis
