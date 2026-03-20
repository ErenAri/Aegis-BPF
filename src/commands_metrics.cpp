// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Stats and metrics command implementations
 */

#include "commands_metrics.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>
#include <vector>

#include "bpf_ops.hpp"
#include "control.hpp"
#include "json_scan.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

constexpr uint64_t MAX_DENY_INODE_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_PATH_ENTRIES = 16384;
constexpr uint64_t MAX_ALLOW_CGROUP_ENTRIES = 1024;
constexpr uint64_t MAX_ALLOW_EXEC_INODE_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_IPV4_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_IPV6_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_PORT_ENTRIES = 4096;
constexpr uint64_t MAX_DENY_IP_PORT_V4_ENTRIES = 4096;
constexpr uint64_t MAX_DENY_IP_PORT_V6_ENTRIES = 4096;
constexpr uint64_t MAX_DENY_CIDR_V4_ENTRIES = 16384;
constexpr uint64_t MAX_DENY_CIDR_V6_ENTRIES = 16384;

int fail_span(ScopedSpan& span, const std::string& message)
{
    span.fail(message);
    return 1;
}

void append_metric_header(std::ostringstream& oss, const std::string& name, const std::string& type,
                          const std::string& help)
{
    oss << "# HELP " << name << " " << help << "\n";
    oss << "# TYPE " << name << " " << type << "\n";
}

void append_metric_sample(std::ostringstream& oss, const std::string& name, uint64_t value)
{
    oss << name << " " << value << "\n";
}

void append_metric_sample(std::ostringstream& oss, const std::string& name,
                          const std::vector<std::pair<std::string, std::string>>& labels, uint64_t value)
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

void append_metric_sample(std::ostringstream& oss, const std::string& name,
                          const std::vector<std::pair<std::string, std::string>>& labels, double value)
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
    oss << " " << std::fixed << std::setprecision(6) << value << "\n";
}

size_t safe_map_entry_count(bpf_map* map)
{
    return map ? map_entry_count(map) : 0;
}

double calculate_map_utilization(bpf_map* map, uint64_t max_entries)
{
    if (!map || max_entries == 0) {
        return 0.0;
    }
    uint64_t current = map_entry_count(map);
    return static_cast<double>(current) / static_cast<double>(max_entries);
}

std::string env_path_or_default(const char* env_name, const char* fallback)
{
    const char* value = std::getenv(env_name);
    if (value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::string(fallback);
}

struct CapabilityMetricsSample {
    bool report_present = false;
    bool parse_ok = false;
    bool enforce_capable = false;
    std::string runtime_state = "UNKNOWN";
};

CapabilityMetricsSample read_capability_metrics_sample()
{
    CapabilityMetricsSample sample{};
    const std::string path = env_path_or_default("AEGIS_CAPABILITIES_REPORT_PATH", kCapabilitiesReportPath);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
        return sample;
    }

    sample.report_present = true;
    std::ifstream in(path);
    if (!in.is_open()) {
        return sample;
    }

    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string payload = buf.str();

    std::string runtime_state;
    bool enforce_capable = false;
    if (!json_scan::extract_string(payload, "runtime_state", runtime_state)) {
        return sample;
    }
    if (!json_scan::extract_bool(payload, "enforce_capable", enforce_capable)) {
        return sample;
    }

    sample.runtime_state = runtime_state;
    sample.enforce_capable = enforce_capable;
    sample.parse_ok = true;
    return sample;
}

struct PerfSloMetricsSample {
    bool summary_present = false;
    bool parse_ok = false;
    bool gate_pass = true;
    uint64_t failed_rows = 0;
};

PerfSloMetricsSample read_perf_slo_metrics_sample()
{
    PerfSloMetricsSample sample{};
    const std::string path =
        env_path_or_default("AEGIS_PERF_SLO_SUMMARY_PATH", "/var/lib/aegisbpf/perf-slo-summary.json");
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
        return sample;
    }

    sample.summary_present = true;
    std::ifstream in(path);
    if (!in.is_open()) {
        return sample;
    }

    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string payload = buf.str();

    bool gate_pass = true;
    if (!json_scan::extract_bool(payload, "gate_pass", gate_pass)) {
        return sample;
    }
    sample.gate_pass = gate_pass;

    uint64_t failed_rows = 0;
    if (json_scan::extract_uint64(payload, "failed_rows", failed_rows)) {
        sample.failed_rows = failed_rows;
    }
    sample.parse_ok = true;
    return sample;
}

} // namespace

std::string build_block_metrics_output(const BlockStats& stats)
{
    std::ostringstream oss;
    append_metric_header(oss, "aegisbpf_blocks_total", "counter", "Total number of blocked operations");
    append_metric_sample(oss, "aegisbpf_blocks_total", stats.blocks);
    append_metric_header(oss, "aegisbpf_ringbuf_drops_total", "counter", "Number of dropped events");
    append_metric_sample(oss, "aegisbpf_ringbuf_drops_total", stats.ringbuf_drops);
    return oss.str();
}

std::string build_net_metrics_output(const NetBlockStats& stats)
{
    std::ostringstream oss;
    append_metric_header(oss, "aegisbpf_net_blocks_total", "counter", "Blocked network operations by direction");
    append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "connect"}}, stats.connect_blocks);
    append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "bind"}}, stats.bind_blocks);
    append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "listen"}}, stats.listen_blocks);
    append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "accept"}}, stats.accept_blocks);
    append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "send"}}, stats.sendmsg_blocks);
    append_metric_header(oss, "aegisbpf_net_ringbuf_drops_total", "counter", "Dropped network events");
    append_metric_sample(oss, "aegisbpf_net_ringbuf_drops_total", stats.ringbuf_drops);
    return oss.str();
}

int cmd_stats(bool detailed)
{
    const std::string trace_id = make_span_id("trace-stats");
    ScopedSpan span("cli.stats", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats").field("error", stats_result.error().to_string()));
        return fail_span(span, stats_result.error().to_string());
    }

    const auto& stats = *stats_result;
    std::cout << "Block Statistics:" << '\n';
    std::cout << "  Total blocks: " << stats.blocks << '\n';
    std::cout << "  Ringbuf drops: " << stats.ringbuf_drops << '\n';

    if (!detailed) {
        return 0;
    }

    std::cout << '\n';
    std::cout << "Detailed Block Statistics (for debugging only):" << '\n';
    std::cout << "WARNING: This output is NOT suitable for Prometheus metrics." << '\n';
    std::cout << "         Use `aegisbpf metrics` for low-cardinality production metrics." << '\n';

    auto cgroup_stats_result = read_cgroup_block_counts(state.deny_cgroup_stats);
    if (cgroup_stats_result) {
        auto cgroup_stats = *cgroup_stats_result;
        std::sort(cgroup_stats.begin(), cgroup_stats.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::cout << "  Top blocked cgroups:" << '\n';
        size_t limit = std::min<size_t>(10, cgroup_stats.size());
        for (size_t i = 0; i < limit; ++i) {
            const auto& [cgid, count] = cgroup_stats[i];
            std::string cgroup_path = resolve_cgroup_path(cgid);
            if (cgroup_path.empty()) {
                cgroup_path = "cgid:" + std::to_string(cgid);
            }
            std::cout << "    " << cgroup_path << ": " << count << '\n';
        }
    }

    auto path_stats_result = read_path_block_counts(state.deny_path_stats);
    if (path_stats_result) {
        auto path_stats = *path_stats_result;
        std::sort(path_stats.begin(), path_stats.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::cout << "  Top blocked paths:" << '\n';
        size_t limit = std::min<size_t>(10, path_stats.size());
        for (size_t i = 0; i < limit; ++i) {
            const auto& [path, count] = path_stats[i];
            std::cout << "    " << path << ": " << count << '\n';
        }
    }

    if (state.net_ip_stats) {
        auto net_ip_stats_result = read_net_ip_stats(state);
        if (net_ip_stats_result) {
            auto net_ip_stats = *net_ip_stats_result;
            std::sort(net_ip_stats.begin(), net_ip_stats.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            std::cout << "  Top blocked destination IPs:" << '\n';
            size_t limit = std::min<size_t>(10, net_ip_stats.size());
            for (size_t i = 0; i < limit; ++i) {
                const auto& [ip, count] = net_ip_stats[i];
                std::cout << "    " << ip << ": " << count << '\n';
            }
        }
    }

    if (state.net_port_stats) {
        auto net_port_stats_result = read_net_port_stats(state);
        if (net_port_stats_result) {
            auto net_port_stats = *net_port_stats_result;
            std::sort(net_port_stats.begin(), net_port_stats.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            std::cout << "  Top blocked destination ports:" << '\n';
            size_t limit = std::min<size_t>(10, net_port_stats.size());
            for (size_t i = 0; i < limit; ++i) {
                const auto& [port, count] = net_port_stats[i];
                std::cout << "    " << port << ": " << count << '\n';
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
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    std::ostringstream oss;

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats").field("error", stats_result.error().to_string()));
        return fail_span(span, stats_result.error().to_string());
    }
    const auto& stats = *stats_result;
    append_metric_header(oss, "aegisbpf_blocks_total", "counter", "Total number of blocked operations");
    append_metric_sample(oss, "aegisbpf_blocks_total", stats.blocks);
    append_metric_header(oss, "aegisbpf_ringbuf_drops_total", "counter", "Number of dropped events");
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
        append_metric_header(oss, "aegisbpf_blocks_by_cgroup_total", "counter", "Blocked operations by cgroup");
        for (const auto& [cgid, count] : cgroup_stats) {
            std::string cgroup_path = resolve_cgroup_path(cgid);
            if (cgroup_path.empty()) {
                cgroup_path = "cgid:" + std::to_string(cgid);
            }
            append_metric_sample(oss, "aegisbpf_blocks_by_cgroup_total",
                                 {{"cgroup_id", std::to_string(cgid)}, {"cgroup_path", cgroup_path}}, count);
        }

        auto inode_stats_result = read_inode_block_counts(state.deny_inode_stats);
        if (!inode_stats_result) {
            logger().log(
                SLOG_ERROR("Failed to read inode block stats").field("error", inode_stats_result.error().to_string()));
            return fail_span(span, inode_stats_result.error().to_string());
        }
        auto inode_stats = *inode_stats_result;
        std::sort(inode_stats.begin(), inode_stats.end(), [](const auto& a, const auto& b) {
            if (a.first.dev != b.first.dev) {
                return a.first.dev < b.first.dev;
            }
            return a.first.ino < b.first.ino;
        });
        append_metric_header(oss, "aegisbpf_blocks_by_inode_total", "counter", "Blocked operations by inode");
        for (const auto& [inode, count] : inode_stats) {
            append_metric_sample(oss, "aegisbpf_blocks_by_inode_total", {{"inode", inode_to_string(inode)}}, count);
        }

        auto path_stats_result = read_path_block_counts(state.deny_path_stats);
        if (!path_stats_result) {
            logger().log(
                SLOG_ERROR("Failed to read path block stats").field("error", path_stats_result.error().to_string()));
            return fail_span(span, path_stats_result.error().to_string());
        }
        auto path_stats = *path_stats_result;
        std::sort(path_stats.begin(), path_stats.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        append_metric_header(oss, "aegisbpf_blocks_by_path_total", "counter", "Blocked operations by path");
        for (const auto& [path, count] : path_stats) {
            append_metric_sample(oss, "aegisbpf_blocks_by_path_total", {{"path", path}}, count);
        }
    }

    if (state.net_block_stats) {
        auto net_stats_result = read_net_block_stats(state);
        if (!net_stats_result) {
            logger().log(
                SLOG_ERROR("Failed to read network block stats").field("error", net_stats_result.error().to_string()));
            return fail_span(span, net_stats_result.error().to_string());
        }

        const auto& net_stats = *net_stats_result;
        append_metric_header(oss, "aegisbpf_net_blocks_total", "counter", "Blocked network operations by direction");
        append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "connect"}}, net_stats.connect_blocks);
        append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "bind"}}, net_stats.bind_blocks);
        append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "listen"}}, net_stats.listen_blocks);
        append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "accept"}}, net_stats.accept_blocks);
        append_metric_sample(oss, "aegisbpf_net_blocks_total", {{"type", "send"}}, net_stats.sendmsg_blocks);

        append_metric_header(oss, "aegisbpf_net_ringbuf_drops_total", "counter", "Dropped network events");
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
                append_metric_sample(oss, "aegisbpf_net_blocks_by_ip_total", {{"ip", ip}}, count);
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
                append_metric_sample(oss, "aegisbpf_net_blocks_by_port_total", {{"port", std::to_string(port)}}, count);
            }
        }
    }

    append_metric_header(oss, "aegisbpf_deny_inode_entries", "gauge", "Number of deny inode entries");
    append_metric_sample(oss, "aegisbpf_deny_inode_entries", safe_map_entry_count(state.deny_inode));
    append_metric_header(oss, "aegisbpf_deny_path_entries", "gauge", "Number of deny path entries");
    append_metric_sample(oss, "aegisbpf_deny_path_entries", safe_map_entry_count(state.deny_path));
    append_metric_header(oss, "aegisbpf_allow_cgroup_entries", "gauge", "Number of allow cgroup entries");
    append_metric_sample(oss, "aegisbpf_allow_cgroup_entries", safe_map_entry_count(state.allow_cgroup));
    append_metric_header(oss, "aegisbpf_allow_exec_inode_entries", "gauge",
                         "Number of exec-identity allowlist inode entries");
    append_metric_sample(oss, "aegisbpf_allow_exec_inode_entries", safe_map_entry_count(state.allow_exec_inode));
    append_metric_header(oss, "aegisbpf_net_rules_total", "gauge", "Number of active network deny rules by type");
    uint64_t ip_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_ipv4)) +
                             static_cast<uint64_t>(safe_map_entry_count(state.deny_ipv6));
    uint64_t ip_port_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_ip_port_v4)) +
                                  static_cast<uint64_t>(safe_map_entry_count(state.deny_ip_port_v6));
    uint64_t cidr_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_cidr_v4)) +
                               static_cast<uint64_t>(safe_map_entry_count(state.deny_cidr_v6));
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "ip"}}, ip_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "ip_port"}}, ip_port_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "cidr"}}, cidr_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "port"}}, safe_map_entry_count(state.deny_port));

    append_metric_header(oss, "aegisbpf_map_utilization", "gauge", "BPF map utilization ratio (0.0 to 1.0)");
    double deny_inode_util = calculate_map_utilization(state.deny_inode, MAX_DENY_INODE_ENTRIES);
    double deny_path_util = calculate_map_utilization(state.deny_path, MAX_DENY_PATH_ENTRIES);
    double allow_cgroup_util = calculate_map_utilization(state.allow_cgroup, MAX_ALLOW_CGROUP_ENTRIES);
    double allow_exec_inode_util = calculate_map_utilization(state.allow_exec_inode, MAX_ALLOW_EXEC_INODE_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_inode"}}, deny_inode_util);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_path"}}, deny_path_util);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "allow_cgroup"}}, allow_cgroup_util);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "allow_exec_inode"}}, allow_exec_inode_util);

    if (state.deny_ipv4 || state.deny_ipv6) {
        double ipv4_util = calculate_map_utilization(state.deny_ipv4, MAX_DENY_IPV4_ENTRIES);
        double ipv6_util = calculate_map_utilization(state.deny_ipv6, MAX_DENY_IPV6_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_ipv4"}}, ipv4_util);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_ipv6"}}, ipv6_util);
    }
    if (state.deny_port) {
        double port_util = calculate_map_utilization(state.deny_port, MAX_DENY_PORT_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_port"}}, port_util);
    }
    if (state.deny_ip_port_v4 || state.deny_ip_port_v6) {
        double ip_port_v4_util = calculate_map_utilization(state.deny_ip_port_v4, MAX_DENY_IP_PORT_V4_ENTRIES);
        double ip_port_v6_util = calculate_map_utilization(state.deny_ip_port_v6, MAX_DENY_IP_PORT_V6_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_ip_port_v4"}}, ip_port_v4_util);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_ip_port_v6"}}, ip_port_v6_util);
    }
    if (state.deny_cidr_v4 || state.deny_cidr_v6) {
        double cidr_v4_util = calculate_map_utilization(state.deny_cidr_v4, MAX_DENY_CIDR_V4_ENTRIES);
        double cidr_v6_util = calculate_map_utilization(state.deny_cidr_v6, MAX_DENY_CIDR_V6_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_cidr_v4"}}, cidr_v4_util);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_cidr_v6"}}, cidr_v6_util);
    }

    append_metric_header(oss, "aegisbpf_map_capacity", "gauge", "Maximum BPF map capacity");
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_inode"}}, MAX_DENY_INODE_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_path"}}, MAX_DENY_PATH_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "allow_cgroup"}}, MAX_ALLOW_CGROUP_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "allow_exec_inode"}}, MAX_ALLOW_EXEC_INODE_ENTRIES);
    if (state.deny_ipv4 || state.deny_ipv6) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_ipv4"}}, MAX_DENY_IPV4_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_ipv6"}}, MAX_DENY_IPV6_ENTRIES);
    }
    if (state.deny_port) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_port"}}, MAX_DENY_PORT_ENTRIES);
    }
    if (state.deny_ip_port_v4 || state.deny_ip_port_v6) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_ip_port_v4"}}, MAX_DENY_IP_PORT_V4_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_ip_port_v6"}}, MAX_DENY_IP_PORT_V6_ENTRIES);
    }
    if (state.deny_cidr_v4 || state.deny_cidr_v6) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_cidr_v4"}}, MAX_DENY_CIDR_V4_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_cidr_v6"}}, MAX_DENY_CIDR_V6_ENTRIES);
    }

    const EmergencyControlConfig control_cfg = emergency_control_config_from_env();
    EmergencyControlState control_state{};
    auto control_state_result = read_emergency_control_state(control_state_path_from_env());
    if (control_state_result) {
        control_state = *control_state_result;
    }
    append_metric_header(oss, "aegisbpf_emergency_toggle_transitions_total", "counter",
                         "Total number of emergency control state transitions");
    append_metric_sample(oss, "aegisbpf_emergency_toggle_transitions_total",
                         control_state_result ? control_state.transitions_total : 0);
    append_metric_header(oss, "aegisbpf_emergency_toggle_storm_active", "gauge",
                         "Whether an emergency control toggle storm is active (1=true, 0=false)");
    const auto storm = evaluate_toggle_storm(control_state, control_cfg, static_cast<int64_t>(std::time(nullptr)));
    append_metric_sample(oss, "aegisbpf_emergency_toggle_storm_active", storm.active ? 1 : 0);

    const auto capability_sample = read_capability_metrics_sample();
    append_metric_header(oss, "aegisbpf_capability_report_present", "gauge",
                         "Whether daemon capability report is present (1=true, 0=false)");
    append_metric_sample(oss, "aegisbpf_capability_report_present", capability_sample.report_present ? 1 : 0);
    append_metric_header(oss, "aegisbpf_capability_contract_valid", "gauge",
                         "Whether capability report could be parsed for posture metrics (1=true, 0=false)");
    append_metric_sample(oss, "aegisbpf_capability_contract_valid", capability_sample.parse_ok ? 1 : 0);
    append_metric_header(oss, "aegisbpf_enforce_capable", "gauge",
                         "Whether node is enforce-capable per capability report (1=true, 0=false)");
    append_metric_sample(oss, "aegisbpf_enforce_capable",
                         (capability_sample.parse_ok && capability_sample.enforce_capable) ? 1 : 0);
    append_metric_header(oss, "aegisbpf_runtime_state", "gauge",
                         "Runtime posture state from capability report (1 for active state label)");
    const std::array<const char*, 4> runtime_states = {"ENFORCE", "AUDIT_FALLBACK", "DEGRADED", "UNKNOWN"};
    for (const char* state_name : runtime_states) {
        const bool active = capability_sample.parse_ok ? (capability_sample.runtime_state == state_name)
                                                       : (std::string(state_name) == "UNKNOWN");
        append_metric_sample(oss, "aegisbpf_runtime_state", {{"state", state_name}},
                             static_cast<uint64_t>(active ? 1 : 0));
    }

    const auto perf_slo_sample = read_perf_slo_metrics_sample();
    append_metric_header(oss, "aegisbpf_perf_slo_summary_present", "gauge",
                         "Whether perf SLO summary artifact is present (1=true, 0=false)");
    append_metric_sample(oss, "aegisbpf_perf_slo_summary_present", perf_slo_sample.summary_present ? 1 : 0);
    append_metric_header(oss, "aegisbpf_perf_slo_gate_pass", "gauge",
                         "Perf SLO gate status from summary artifact (1=pass, 0=fail)");
    append_metric_sample(
        oss, "aegisbpf_perf_slo_gate_pass",
        (perf_slo_sample.summary_present && perf_slo_sample.parse_ok && !perf_slo_sample.gate_pass) ? 0 : 1);
    append_metric_header(oss, "aegisbpf_perf_slo_failed_rows", "gauge",
                         "Number of failed rows in perf SLO summary (0 when missing)");
    append_metric_sample(oss, "aegisbpf_perf_slo_failed_rows",
                         (perf_slo_sample.summary_present && perf_slo_sample.parse_ok) ? perf_slo_sample.failed_rows
                                                                                       : 0);

    std::string metrics = oss.str();

    if (out_path.empty() || out_path == "-") {
        std::cout << metrics;
    } else {
        std::ofstream out(out_path);
        if (!out.is_open()) {
            logger().log(SLOG_ERROR("Failed to open metrics output file").field("path", out_path));
            return fail_span(span, "Failed to open metrics output file");
        }
        out << metrics;
    }

    return 0;
}

} // namespace aegis
