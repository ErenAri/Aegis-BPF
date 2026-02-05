// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "types.hpp"

#include <string>

namespace aegis {

// Stats and monitoring commands
int cmd_stats(bool detailed = false);
int cmd_metrics(const std::string& out_path, bool detailed = false);
int cmd_health(bool json_output = false);
int cmd_doctor(bool json_output = false);

// Test helpers (metrics formatting).
std::string build_block_metrics_output(const BlockStats& stats);
std::string build_net_metrics_output(const NetBlockStats& stats);

}  // namespace aegis
