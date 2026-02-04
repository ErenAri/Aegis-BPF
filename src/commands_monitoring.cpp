// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Stats, metrics, and health command implementations
 */

#include "commands_monitoring.hpp"

#include "bpf_ops.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <sstream>
#include <utility>
#include <unistd.h>
#include <vector>

namespace aegis {

namespace {

int fail_span(ScopedSpan& span, const std::string& message)
{
    span.fail(message);
    return 1;
}

void append_metric_header(std::ostringstream& oss,
                          const std::string& name,
                          const std::string& type,
                          const std::string& help)
{
    oss << "# HELP " << name << " " << help << "\n";
    oss << "# TYPE " << name << " " << type << "\n";
}

void append_metric_sample(std::ostringstream& oss, const std::string& name, uint64_t value)
{
    oss << name << " " << value << "\n";
}

void append_metric_sample(std::ostringstream& oss,
                          const std::string& name,
                          const std::vector<std::pair<std::string, std::string>>& labels,
                          uint64_t value)
{
    oss << name;
    if (!labels.empty()) {
        oss << "{";
        for (size_t i = 0; i < labels.size(); ++i) {
            if (i > 0) {
                oss << ",";
            }
            oss << labels[i].first << "=\"" << prometheus_escape_label(labels[i].second) << "\"";
        }
        oss << "}";
    }
    oss << " " << value << "\n";
}

size_t safe_map_entry_count(bpf_map* map)
{
    return map ? map_entry_count(map) : 0;
}

Result<void> verify_pinned_map_access(const char* pin_path)
{
    int fd = bpf_obj_get(pin_path);
    if (fd < 0) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "Pinned map not found", pin_path);
        }
        return Error::system(errno, "Failed to open pinned map");
    }
    close(fd);
    return {};
}

}  // namespace

int cmd_stats(bool detailed)
{
    const std::string trace_id = make_span_id("trace-stats");
    ScopedSpan span("cli.stats", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
                         .field("error", stats_result.error().to_string()));
        return fail_span(span, stats_result.error().to_string());
    }

    const auto& stats = *stats_result;
    std::cout << "Block Statistics:" << std::endl;
    std::cout << "  Total blocks: " << stats.blocks << std::endl;
    std::cout << "  Ringbuf drops: " << stats.ringbuf_drops << std::endl;

    if (!detailed) {
        return 0;
    }

    std::cout << std::endl;
    std::cout << "Detailed Block Statistics (for debugging only):" << std::endl;
    std::cout << "WARNING: This output is NOT suitable for Prometheus metrics." << std::endl;
    std::cout << "         Use `aegisbpf metrics` for low-cardinality production metrics."
              << std::endl;

    auto cgroup_stats_result = read_cgroup_block_counts(state.deny_cgroup_stats);
    if (cgroup_stats_result) {
        auto cgroup_stats = *cgroup_stats_result;
        std::sort(cgroup_stats.begin(), cgroup_stats.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::cout << "  Top blocked cgroups:" << std::endl;
        size_t limit = std::min<size_t>(10, cgroup_stats.size());
        for (size_t i = 0; i < limit; ++i) {
            const auto& [cgid, count] = cgroup_stats[i];
            std::string cgroup_path = resolve_cgroup_path(cgid);
            if (cgroup_path.empty()) {
                cgroup_path = "cgid:" + std::to_string(cgid);
            }
            std::cout << "    " << cgroup_path << ": " << count << std::endl;
        }
    }

    auto path_stats_result = read_path_block_counts(state.deny_path_stats);
    if (path_stats_result) {
        auto path_stats = *path_stats_result;
        std::sort(path_stats.begin(), path_stats.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::cout << "  Top blocked paths:" << std::endl;
        size_t limit = std::min<size_t>(10, path_stats.size());
        for (size_t i = 0; i < limit; ++i) {
            const auto& [path, count] = path_stats[i];
            std::cout << "    " << path << ": " << count << std::endl;
        }
    }

    if (state.net_ip_stats) {
        auto net_ip_stats_result = read_net_ip_stats(state);
        if (net_ip_stats_result) {
            auto net_ip_stats = *net_ip_stats_result;
            std::sort(net_ip_stats.begin(), net_ip_stats.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            std::cout << "  Top blocked destination IPs:" << std::endl;
            size_t limit = std::min<size_t>(10, net_ip_stats.size());
            for (size_t i = 0; i < limit; ++i) {
                const auto& [ip, count] = net_ip_stats[i];
                std::cout << "    " << ip << ": " << count << std::endl;
            }
        }
    }

    if (state.net_port_stats) {
        auto net_port_stats_result = read_net_port_stats(state);
        if (net_port_stats_result) {
            auto net_port_stats = *net_port_stats_result;
            std::sort(net_port_stats.begin(), net_port_stats.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            std::cout << "  Top blocked destination ports:" << std::endl;
            size_t limit = std::min<size_t>(10, net_port_stats.size());
            for (size_t i = 0; i < limit; ++i) {
                const auto& [port, count] = net_port_stats[i];
                std::cout << "    " << port << ": " << count << std::endl;
            }
        }
    }

    return 0;
}

int cmd_metrics(const std::string& out_path, bool detailed)
{
    const std::string trace_id = make_span_id("trace-metrics");
    ScopedSpan span("cli.metrics", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    std::ostringstream oss;

    // Core block stats
    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
                         .field("error", stats_result.error().to_string()));
        return fail_span(span, stats_result.error().to_string());
    }
    const auto& stats = *stats_result;
    append_metric_header(oss, "aegisbpf_blocks_total", "counter",
                         "Total number of blocked operations");
    append_metric_sample(oss, "aegisbpf_blocks_total", stats.blocks);
    append_metric_header(oss, "aegisbpf_ringbuf_drops_total", "counter",
                         "Number of dropped events");
    append_metric_sample(oss, "aegisbpf_ringbuf_drops_total", stats.ringbuf_drops);

    if (detailed) {
        oss << "# NOTE high-cardinality metrics enabled (--detailed)\n";

        auto cgroup_stats_result = read_cgroup_block_counts(state.deny_cgroup_stats);
        if (!cgroup_stats_result) {
            logger().log(SLOG_ERROR("Failed to read cgroup block stats")
                             .field("error", cgroup_stats_result.error().to_string()));
            return fail_span(span, cgroup_stats_result.error().to_string());
        }
        auto cgroup_stats = *cgroup_stats_result;
        std::sort(cgroup_stats.begin(), cgroup_stats.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        append_metric_header(oss, "aegisbpf_blocks_by_cgroup_total", "counter",
                             "Blocked operations by cgroup");
        for (const auto& [cgid, count] : cgroup_stats) {
            std::string cgroup_path = resolve_cgroup_path(cgid);
            if (cgroup_path.empty()) {
                cgroup_path = "cgid:" + std::to_string(cgid);
            }
            append_metric_sample(
                oss,
                "aegisbpf_blocks_by_cgroup_total",
                {
                    {"cgroup_id", std::to_string(cgid)},
                    {"cgroup_path", cgroup_path},
                },
                count);
        }

        auto inode_stats_result = read_inode_block_counts(state.deny_inode_stats);
        if (!inode_stats_result) {
            logger().log(SLOG_ERROR("Failed to read inode block stats")
                             .field("error", inode_stats_result.error().to_string()));
            return fail_span(span, inode_stats_result.error().to_string());
        }
        auto inode_stats = *inode_stats_result;
        std::sort(inode_stats.begin(), inode_stats.end(),
                  [](const auto& a, const auto& b) {
                      if (a.first.dev != b.first.dev) {
                          return a.first.dev < b.first.dev;
                      }
                      return a.first.ino < b.first.ino;
                  });
        append_metric_header(oss, "aegisbpf_blocks_by_inode_total", "counter",
                             "Blocked operations by inode");
        for (const auto& [inode, count] : inode_stats) {
            append_metric_sample(
                oss,
                "aegisbpf_blocks_by_inode_total",
                {{"inode", inode_to_string(inode)}},
                count);
        }

        auto path_stats_result = read_path_block_counts(state.deny_path_stats);
        if (!path_stats_result) {
            logger().log(SLOG_ERROR("Failed to read path block stats")
                             .field("error", path_stats_result.error().to_string()));
            return fail_span(span, path_stats_result.error().to_string());
        }
        auto path_stats = *path_stats_result;
        std::sort(path_stats.begin(), path_stats.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        append_metric_header(oss, "aegisbpf_blocks_by_path_total", "counter",
                             "Blocked operations by path");
        for (const auto& [path, count] : path_stats) {
            append_metric_sample(
                oss,
                "aegisbpf_blocks_by_path_total",
                {{"path", path}},
                count);
        }
    }

    // Network counters are optional: emit when maps are available.
    if (state.net_block_stats) {
        auto net_stats_result = read_net_block_stats(state);
        if (!net_stats_result) {
            logger().log(SLOG_ERROR("Failed to read network block stats")
                             .field("error", net_stats_result.error().to_string()));
            return fail_span(span, net_stats_result.error().to_string());
        }

        const auto& net_stats = *net_stats_result;
        append_metric_header(oss, "aegisbpf_net_blocks_total", "counter",
                             "Blocked network operations by direction");
        append_metric_sample(
            oss,
            "aegisbpf_net_blocks_total",
            {{"type", "connect"}},
            net_stats.connect_blocks);
        append_metric_sample(
            oss,
            "aegisbpf_net_blocks_total",
            {{"type", "bind"}},
            net_stats.bind_blocks);

        append_metric_header(oss, "aegisbpf_net_ringbuf_drops_total", "counter",
                             "Dropped network events");
        append_metric_sample(oss, "aegisbpf_net_ringbuf_drops_total", net_stats.ringbuf_drops);
    }

    if (detailed) {
        if (state.net_ip_stats) {
            auto net_ip_stats_result = read_net_ip_stats(state);
            if (!net_ip_stats_result) {
                logger().log(SLOG_ERROR("Failed to read network IP stats")
                                 .field("error", net_ip_stats_result.error().to_string()));
                return fail_span(span, net_ip_stats_result.error().to_string());
            }
            auto net_ip_stats = *net_ip_stats_result;
            std::sort(net_ip_stats.begin(), net_ip_stats.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });
            append_metric_header(oss, "aegisbpf_net_blocks_by_ip_total", "counter",
                                 "Blocked network operations by destination IP");
            for (const auto& [ip, count] : net_ip_stats) {
                append_metric_sample(
                    oss,
                    "aegisbpf_net_blocks_by_ip_total",
                    {{"ip", ip}},
                    count);
            }
        }

        if (state.net_port_stats) {
            auto net_port_stats_result = read_net_port_stats(state);
            if (!net_port_stats_result) {
                logger().log(SLOG_ERROR("Failed to read network port stats")
                                 .field("error", net_port_stats_result.error().to_string()));
                return fail_span(span, net_port_stats_result.error().to_string());
            }
            auto net_port_stats = *net_port_stats_result;
            std::sort(net_port_stats.begin(), net_port_stats.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });
            append_metric_header(oss, "aegisbpf_net_blocks_by_port_total", "counter",
                                 "Blocked network operations by port");
            for (const auto& [port, count] : net_port_stats) {
                append_metric_sample(
                    oss,
                    "aegisbpf_net_blocks_by_port_total",
                    {{"port", std::to_string(port)}},
                    count);
            }
        }
    }

    // Map entry counts
    append_metric_header(oss, "aegisbpf_deny_inode_entries", "gauge",
                         "Number of deny inode entries");
    append_metric_sample(oss, "aegisbpf_deny_inode_entries", safe_map_entry_count(state.deny_inode));
    append_metric_header(oss, "aegisbpf_deny_path_entries", "gauge",
                         "Number of deny path entries");
    append_metric_sample(oss, "aegisbpf_deny_path_entries", safe_map_entry_count(state.deny_path));
    append_metric_header(oss, "aegisbpf_allow_cgroup_entries", "gauge",
                         "Number of allow cgroup entries");
    append_metric_sample(oss, "aegisbpf_allow_cgroup_entries", safe_map_entry_count(state.allow_cgroup));
    append_metric_header(oss, "aegisbpf_net_rules_total", "gauge",
                         "Number of active network deny rules by type");
    uint64_t ip_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_ipv4)) +
                             static_cast<uint64_t>(safe_map_entry_count(state.deny_ipv6));
    uint64_t cidr_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_cidr_v4)) +
                               static_cast<uint64_t>(safe_map_entry_count(state.deny_cidr_v6));
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "ip"}},
                         ip_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "cidr"}},
                         cidr_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "port"}},
                         safe_map_entry_count(state.deny_port));

    std::string metrics = oss.str();

    if (out_path.empty() || out_path == "-") {
        std::cout << metrics;
    }
    else {
        std::ofstream out(out_path);
        if (!out.is_open()) {
            logger().log(SLOG_ERROR("Failed to open metrics output file").field("path", out_path));
            return fail_span(span, "Failed to open metrics output file");
        }
        out << metrics;
    }

    return 0;
}

int cmd_health(bool json_output)
{
    const std::string trace_id = make_span_id("trace-health");
    ScopedSpan root_span("cli.health", trace_id);
    auto fail = [&](const std::string& error) -> int {
        root_span.fail(error);
        return 1;
    };

    ScopedSpan feature_span("health.detect_kernel_features", trace_id, root_span.span_id());
    auto features_result = detect_kernel_features();
    if (!features_result) {
        feature_span.fail(features_result.error().to_string());
        if (json_output) {
            std::cout << "{\"ok\":false,\"error\":\""
                      << json_escape(features_result.error().to_string())
                      << "\"}" << std::endl;
        }
        else {
            logger().log(SLOG_ERROR("Kernel feature detection failed")
                             .field("error", features_result.error().to_string()));
        }
        return fail(features_result.error().to_string());
    }
    const auto& features = *features_result;
    EnforcementCapability capability = determine_capability(features);
    bool bpffs_mounted = check_bpffs_mounted();

    bool prereqs_ok = false;
    bool bpf_load_ok = false;
    bool required_maps_ok = false;
    bool layout_ok = false;
    bool required_pins_ok = false;
    bool network_maps_present = false;
    bool network_pins_ok = true;

    auto emit_json = [&](bool ok, const std::string& error) {
        std::ostringstream out;
        out << "{"
            << "\"ok\":" << (ok ? "true" : "false")
            << ",\"capability\":\"" << json_escape(capability_name(capability)) << "\""
            << ",\"mode\":\"" << (capability == EnforcementCapability::AuditOnly ? "audit-only" : "enforce") << "\""
            << ",\"kernel_version\":\"" << json_escape(features.kernel_version) << "\""
            << ",\"features\":{"
            << "\"bpf_lsm\":" << (features.bpf_lsm ? "true" : "false")
            << ",\"cgroup_v2\":" << (features.cgroup_v2 ? "true" : "false")
            << ",\"btf\":" << (features.btf ? "true" : "false")
            << ",\"bpf_syscall\":" << (features.bpf_syscall ? "true" : "false")
            << ",\"ringbuf\":" << (features.ringbuf ? "true" : "false")
            << ",\"tracepoints\":" << (features.tracepoints ? "true" : "false")
            << ",\"bpffs\":" << (bpffs_mounted ? "true" : "false")
            << "}"
            << ",\"checks\":{"
            << "\"prereqs\":" << (prereqs_ok ? "true" : "false")
            << ",\"bpf_load\":" << (bpf_load_ok ? "true" : "false")
            << ",\"required_maps\":" << (required_maps_ok ? "true" : "false")
            << ",\"layout_version\":" << (layout_ok ? "true" : "false")
            << ",\"required_pins\":" << (required_pins_ok ? "true" : "false")
            << ",\"network_pins\":" << (network_pins_ok ? "true" : "false")
            << "}"
            << ",\"network_maps_present\":" << (network_maps_present ? "true" : "false");
        if (!error.empty()) {
            out << ",\"error\":\"" << json_escape(error) << "\"";
        }
        out << "}";
        std::cout << out.str() << std::endl;
    };

    if (!json_output) {
        std::cout << "Kernel version: " << features.kernel_version << std::endl;
        std::cout << "Capability: " << capability_name(capability) << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "  bpf_lsm: " << (features.bpf_lsm ? "yes" : "no") << std::endl;
        std::cout << "  cgroup_v2: " << (features.cgroup_v2 ? "yes" : "no") << std::endl;
        std::cout << "  btf: " << (features.btf ? "yes" : "no") << std::endl;
        std::cout << "  bpf_syscall: " << (features.bpf_syscall ? "yes" : "no") << std::endl;
        std::cout << "  ringbuf: " << (features.ringbuf ? "yes" : "no") << std::endl;
        std::cout << "  tracepoints: " << (features.tracepoints ? "yes" : "no") << std::endl;
        std::cout << "  bpffs: " << (bpffs_mounted ? "yes" : "no") << std::endl;
    }

    prereqs_ok = features.cgroup_v2 && features.btf && features.bpf_syscall &&
                 bpffs_mounted && capability != EnforcementCapability::Disabled;
    if (!prereqs_ok) {
        std::string error = "Kernel prerequisites are not met: " +
                            capability_explanation(features, capability);
        if (json_output) {
            emit_json(false, error);
        }
        else {
            logger().log(SLOG_ERROR("Kernel prerequisites are not met")
                             .field("explanation", capability_explanation(features, capability)));
        }
        return fail(error);
    }

    BpfState state;
    ScopedSpan load_span("health.load_bpf", trace_id, root_span.span_id());
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        load_span.fail(load_result.error().to_string());
        if (json_output) {
            emit_json(false, "BPF load failed: " + load_result.error().to_string());
        }
        else {
            logger().log(SLOG_ERROR("BPF health check failed - cannot load BPF object")
                             .field("error", load_result.error().to_string()));
        }
        return fail(load_result.error().to_string());
    }
    bpf_load_ok = true;

    // Check required maps exist
    if (!state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.events) {
        if (json_output) {
            emit_json(false, "BPF health check failed - missing required maps");
        }
        else {
            logger().log(SLOG_ERROR("BPF health check failed - missing required maps"));
        }
        return fail("BPF health check failed - missing required maps");
    }
    required_maps_ok = true;

    // Check layout version by ensuring it
    ScopedSpan layout_span("health.ensure_layout_version", trace_id, root_span.span_id());
    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        layout_span.fail(version_result.error().to_string());
        if (json_output) {
            emit_json(false, "Layout version check failed: " + version_result.error().to_string());
        }
        else {
            logger().log(SLOG_ERROR("BPF health check failed - layout version check failed")
                             .field("error", version_result.error().to_string()));
        }
        return fail(version_result.error().to_string());
    }
    layout_ok = true;

    const std::array<const char*, 9> required_pin_paths = {
        kDenyInodePin,
        kDenyPathPin,
        kAllowCgroupPin,
        kBlockStatsPin,
        kDenyCgroupStatsPin,
        kDenyInodeStatsPin,
        kDenyPathStatsPin,
        kAgentMetaPin,
        kSurvivalAllowlistPin,
    };
    for (const char* pin_path : required_pin_paths) {
        auto pin_result = verify_pinned_map_access(pin_path);
        if (!pin_result) {
            if (json_output) {
                emit_json(false, std::string("Pinned map check failed: ") + pin_path + " (" +
                                     pin_result.error().to_string() + ")");
            }
            else {
                logger().log(SLOG_ERROR("Pinned map check failed")
                                 .field("path", pin_path)
                                 .field("error", pin_result.error().to_string()));
            }
            return fail("Pinned map check failed: " + std::string(pin_path));
        }
    }
    required_pins_ok = true;

    // Network maps are optional; validate pin paths only for maps present in the loaded object.
    const std::array<std::pair<bpf_map*, const char*>, 8> optional_network_maps = {{
        {state.deny_ipv4, kDenyIpv4Pin},
        {state.deny_ipv6, kDenyIpv6Pin},
        {state.deny_port, kDenyPortPin},
        {state.deny_cidr_v4, kDenyCidrV4Pin},
        {state.deny_cidr_v6, kDenyCidrV6Pin},
        {state.net_block_stats, kNetBlockStatsPin},
        {state.net_ip_stats, kNetIpStatsPin},
        {state.net_port_stats, kNetPortStatsPin},
    }};
    for (const auto& [map, pin_path] : optional_network_maps) {
        if (!map) {
            continue;
        }
        network_maps_present = true;
        auto pin_result = verify_pinned_map_access(pin_path);
        if (!pin_result) {
            network_pins_ok = false;
            if (json_output) {
                emit_json(false, std::string("Network pinned map check failed: ") + pin_path + " (" +
                                     pin_result.error().to_string() + ")");
            }
            else {
                logger().log(SLOG_ERROR("Network pinned map check failed")
                                 .field("path", pin_path)
                                 .field("error", pin_result.error().to_string()));
            }
            return fail("Network pinned map check failed: " + std::string(pin_path));
        }
    }

    if (json_output) {
        emit_json(true, std::string());
        return 0;
    }

    if (capability == EnforcementCapability::AuditOnly) {
        std::cout << "Health check passed (audit-only capability)" << std::endl;
        std::cout << "  Note: BPF LSM is unavailable; enforcement actions run in audit mode." << std::endl;
        return 0;
    }

    std::cout << "Health check passed" << std::endl;
    return 0;
}

}  // namespace aegis
