// cppcheck-suppress-file missingIncludeSystem
#include "map_monitor.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstdint>
#include <cstring>
#include <sstream>

#include "logging.hpp"

namespace aegis {

namespace {

uint32_t count_map_entries(bpf_map* map)
{
    if (!map)
        return 0;

    int fd = bpf_map__fd(map);
    if (fd < 0)
        return 0;

    uint32_t count = 0;
    uint32_t key_size = bpf_map__key_size(map);
    if (key_size == 0 || key_size > 256)
        return 0;

    // Use bpf_map_get_next_key to iterate all entries
    uint8_t key[256] = {};
    uint8_t next_key[256] = {};

    // Start iteration with NULL key to get the first key
    bool first = true;
    while (true) {
        int rc;
        if (first) {
            rc = bpf_map_get_next_key(fd, nullptr, next_key);
            first = false;
        } else {
            rc = bpf_map_get_next_key(fd, key, next_key);
        }
        if (rc != 0)
            break;
        count++;
        std::memcpy(key, next_key, key_size);
        if (count > 1000000) // safety limit
            break;
    }

    return count;
}

void check_single_map(const char* name, bpf_map* map, double warn_threshold, std::vector<MapUsageEntry>& entries,
                      bool& any_above)
{
    if (!map)
        return;

    uint32_t max = bpf_map__max_entries(map);
    if (max == 0)
        return;

    // Skip ring buffers and perf event arrays (not meaningful to count entries)
    uint32_t map_type = bpf_map__type(map);
    if (map_type == BPF_MAP_TYPE_RINGBUF || map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY)
        return;

    uint32_t current = count_map_entries(map);
    double ratio = static_cast<double>(current) / static_cast<double>(max);

    entries.push_back({name, current, max, ratio});

    if (ratio >= warn_threshold) {
        any_above = true;
        logger().log(SLOG_WARN("Map capacity warning")
                         .field("map", name)
                         .field("current", static_cast<int64_t>(current))
                         .field("max", static_cast<int64_t>(max))
                         .field("usage_pct", static_cast<int64_t>(ratio * 100)));
    }
}

} // namespace

MapUsageReport check_map_capacity(const BpfState& state, double warn_threshold)
{
    MapUsageReport report;

    struct MapInfo {
        const char* name;
        bpf_map* map;
    };

    const MapInfo maps[] = {
        {"deny_inode", state.deny_inode},
        {"deny_path", state.deny_path},
        {"allow_cgroup", state.allow_cgroup},
        {"allow_exec_inode", state.allow_exec_inode},
        {"survival_allowlist", state.survival_allowlist},
        {"deny_ipv4", state.deny_ipv4},
        {"deny_ipv6", state.deny_ipv6},
        {"deny_port", state.deny_port},
        {"deny_ip_port_v4", state.deny_ip_port_v4},
        {"deny_ip_port_v6", state.deny_ip_port_v6},
        {"dead_processes", state.dead_processes},
    };

    for (const auto& m : maps) {
        check_single_map(m.name, m.map, warn_threshold, report.entries, report.any_above_threshold);
        if (m.map)
            report.maps_checked++;
    }

    return report;
}

std::string map_usage_to_json(const MapUsageReport& report)
{
    std::ostringstream oss;
    oss << "{\"map_usage\":[";
    for (size_t i = 0; i < report.entries.size(); i++) {
        if (i > 0)
            oss << ",";
        const auto& e = report.entries[i];
        oss << "{\"name\":\"" << e.name << "\"" << ",\"current\":" << e.current_entries << ",\"max\":" << e.max_entries
            << ",\"usage_ratio\":" << e.usage_ratio << "}";
    }
    oss << "],\"maps_checked\":" << report.maps_checked
        << ",\"any_above_threshold\":" << (report.any_above_threshold ? "true" : "false") << "}";
    return oss.str();
}

} // namespace aegis
