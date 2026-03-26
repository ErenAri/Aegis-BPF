// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "bpf_ops.hpp"

namespace aegis {

struct MapUsageEntry {
    std::string name;
    uint32_t current_entries;
    uint32_t max_entries;
    double usage_ratio; // 0.0 to 1.0
};

struct MapUsageReport {
    std::vector<MapUsageEntry> entries;
    bool any_above_threshold = false;
    uint32_t maps_checked = 0;
};

// Scan all BPF maps and report fill levels.
// Emits diagnostics when any map exceeds the warning threshold (0.0-1.0).
MapUsageReport check_map_capacity(const BpfState& state, double warn_threshold = 0.8);

// Format report as JSON string for /stats API endpoint
std::string map_usage_to_json(const MapUsageReport& report);

} // namespace aegis
