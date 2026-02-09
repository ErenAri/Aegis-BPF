// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "types.hpp"

namespace aegis {

// Stats and monitoring commands
int cmd_stats(bool detailed = false);
int cmd_metrics(const std::string& out_path, bool detailed = false);
int cmd_health(bool json_output = false);
int cmd_doctor(bool json_output = false);
int cmd_explain(const std::string& event_path, const std::string& policy_path, bool json_output = false);
int cmd_footprint(uint64_t deny_inodes = 0, uint64_t deny_paths = 0, uint64_t deny_ips = 0, uint64_t deny_cidrs = 0,
                  uint64_t deny_ports = 0, uint64_t ringbuf_bytes = 0);

// Test helpers (metrics formatting).
std::string build_block_metrics_output(const BlockStats& stats);
std::string build_net_metrics_output(const NetBlockStats& stats);

} // namespace aegis
