// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "bpf_ops.hpp"
#include "result.hpp"
#include "types.hpp"

namespace aegis {

int cmd_stats(bool detailed = false);
int cmd_metrics(const std::string& out_path, bool detailed = false);

// Build the full Prometheus exposition text from a loaded BpfState. Shared by the
// `metrics` CLI command and the daemon's optional HTTP /metrics endpoint (which
// reuses its already-loaded state instead of reloading per scrape).
Result<std::string> build_metrics_report(BpfState& state, bool detailed);

std::string build_block_metrics_output(const BlockStats& stats);
std::string build_net_metrics_output(const NetBlockStats& stats);

} // namespace aegis
