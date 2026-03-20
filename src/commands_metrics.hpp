// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "types.hpp"

namespace aegis {

int cmd_stats(bool detailed = false);
int cmd_metrics(const std::string& out_path, bool detailed = false);

std::string build_block_metrics_output(const BlockStats& stats);
std::string build_net_metrics_output(const NetBlockStats& stats);

} // namespace aegis
