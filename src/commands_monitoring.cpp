// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Stats, metrics, and health command implementations
 */

#include "commands_monitoring.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>
#include <vector>

#include "bpf_ops.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "policy.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

// BPF map capacity constants (must match bpf/aegis.bpf.c)
constexpr uint64_t MAX_DENY_INODE_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_PATH_ENTRIES = 16384;
constexpr uint64_t MAX_ALLOW_CGROUP_ENTRIES = 1024;
constexpr uint64_t MAX_DENY_IPV4_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_IPV6_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_PORT_ENTRIES = 4096;
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

struct ExplainEvent {
    std::string type;
    std::string path;
    std::string resolved_path;
    std::string cgroup_path;
    std::string action;
    uint64_t ino = 0;
    uint64_t dev = 0;
    uint64_t cgid = 0;
    bool has_ino = false;
    bool has_dev = false;
    bool has_cgid = false;
};

std::string read_stream(std::istream& in)
{
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

bool find_json_value_start(const std::string& json, const std::string& key, size_t& pos)
{
    const std::string needle = "\"" + key + "\"";
    size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return false;
    }
    size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return false;
    }
    pos = colon + 1;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }
    return pos < json.size();
}

bool extract_json_string(const std::string& json, const std::string& key, std::string& out)
{
    size_t pos = 0;
    if (!find_json_value_start(json, key, pos)) {
        return false;
    }
    if (json[pos] != '"') {
        return false;
    }
    ++pos;
    std::string result;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (escape) {
            switch (c) {
                case '"':
                    result.push_back('"');
                    break;
                case '\\':
                    result.push_back('\\');
                    break;
                case 'n':
                    result.push_back('\n');
                    break;
                case 'r':
                    result.push_back('\r');
                    break;
                case 't':
                    result.push_back('\t');
                    break;
                default:
                    result.push_back(c);
                    break;
            }
            escape = false;
            continue;
        }
        if (c == '\\') {
            escape = true;
            continue;
        }
        if (c == '"') {
            out = result;
            return true;
        }
        result.push_back(c);
    }
    return false;
}

bool extract_json_uint64(const std::string& json, const std::string& key, uint64_t& out)
{
    size_t pos = 0;
    if (!find_json_value_start(json, key, pos)) {
        return false;
    }
    std::string token;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        token.push_back(json[pos]);
        ++pos;
    }
    if (token.empty()) {
        return false;
    }
    return parse_uint64(token, out);
}

bool parse_explain_event(const std::string& json, ExplainEvent& out, std::string& error)
{
    if (!extract_json_string(json, "type", out.type)) {
        error = "Event JSON missing required 'type' field";
        return false;
    }
    extract_json_string(json, "path", out.path);
    extract_json_string(json, "resolved_path", out.resolved_path);
    extract_json_string(json, "cgroup_path", out.cgroup_path);
    extract_json_string(json, "action", out.action);

    uint64_t value = 0;
    if (extract_json_uint64(json, "ino", value)) {
        out.ino = value;
        out.has_ino = true;
    }
    if (extract_json_uint64(json, "dev", value)) {
        out.dev = value;
        out.has_dev = true;
    }
    if (extract_json_uint64(json, "cgid", value)) {
        out.cgid = value;
        out.has_cgid = true;
    }
    return true;
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

    // Core block stats
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
                                 {
                                     {"cgroup_id", std::to_string(cgid)},
                                     {"cgroup_path", cgroup_path},
                                 },
                                 count);
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

    // Network counters are optional: emit when maps are available.
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

    // Map entry counts
    append_metric_header(oss, "aegisbpf_deny_inode_entries", "gauge", "Number of deny inode entries");
    append_metric_sample(oss, "aegisbpf_deny_inode_entries", safe_map_entry_count(state.deny_inode));
    append_metric_header(oss, "aegisbpf_deny_path_entries", "gauge", "Number of deny path entries");
    append_metric_sample(oss, "aegisbpf_deny_path_entries", safe_map_entry_count(state.deny_path));
    append_metric_header(oss, "aegisbpf_allow_cgroup_entries", "gauge", "Number of allow cgroup entries");
    append_metric_sample(oss, "aegisbpf_allow_cgroup_entries", safe_map_entry_count(state.allow_cgroup));
    append_metric_header(oss, "aegisbpf_net_rules_total", "gauge", "Number of active network deny rules by type");
    uint64_t ip_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_ipv4)) +
                             static_cast<uint64_t>(safe_map_entry_count(state.deny_ipv6));
    uint64_t cidr_rule_count = static_cast<uint64_t>(safe_map_entry_count(state.deny_cidr_v4)) +
                               static_cast<uint64_t>(safe_map_entry_count(state.deny_cidr_v6));
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "ip"}}, ip_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "cidr"}}, cidr_rule_count);
    append_metric_sample(oss, "aegisbpf_net_rules_total", {{"type", "port"}}, safe_map_entry_count(state.deny_port));

    // Map utilization (entries / capacity)
    append_metric_header(oss, "aegisbpf_map_utilization", "gauge", "BPF map utilization ratio (0.0 to 1.0)");
    double deny_inode_util = calculate_map_utilization(state.deny_inode, MAX_DENY_INODE_ENTRIES);
    double deny_path_util = calculate_map_utilization(state.deny_path, MAX_DENY_PATH_ENTRIES);
    double allow_cgroup_util = calculate_map_utilization(state.allow_cgroup, MAX_ALLOW_CGROUP_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_inode"}}, deny_inode_util);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_path"}}, deny_path_util);
    append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "allow_cgroup"}}, allow_cgroup_util);

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
    if (state.deny_cidr_v4 || state.deny_cidr_v6) {
        double cidr_v4_util = calculate_map_utilization(state.deny_cidr_v4, MAX_DENY_CIDR_V4_ENTRIES);
        double cidr_v6_util = calculate_map_utilization(state.deny_cidr_v6, MAX_DENY_CIDR_V6_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_cidr_v4"}}, cidr_v4_util);
        append_metric_sample(oss, "aegisbpf_map_utilization", {{"map", "deny_cidr_v6"}}, cidr_v6_util);
    }

    // Map capacity limits
    append_metric_header(oss, "aegisbpf_map_capacity", "gauge", "Maximum BPF map capacity");
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_inode"}}, MAX_DENY_INODE_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_path"}}, MAX_DENY_PATH_ENTRIES);
    append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "allow_cgroup"}}, MAX_ALLOW_CGROUP_ENTRIES);
    if (state.deny_ipv4 || state.deny_ipv6) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_ipv4"}}, MAX_DENY_IPV4_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_ipv6"}}, MAX_DENY_IPV6_ENTRIES);
    }
    if (state.deny_port) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_port"}}, MAX_DENY_PORT_ENTRIES);
    }
    if (state.deny_cidr_v4 || state.deny_cidr_v6) {
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_cidr_v4"}}, MAX_DENY_CIDR_V4_ENTRIES);
        append_metric_sample(oss, "aegisbpf_map_capacity", {{"map", "deny_cidr_v6"}}, MAX_DENY_CIDR_V6_ENTRIES);
    }

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

struct HealthReport {
    bool ok = false;
    std::string error;
    KernelFeatures features{};
    EnforcementCapability capability = EnforcementCapability::Disabled;
    std::string kernel_version = "unknown";
    bool bpffs_mounted = false;
    bool prereqs_ok = false;
    bool bpf_load_ok = false;
    bool required_maps_ok = false;
    bool layout_ok = false;
    bool required_pins_ok = false;
    bool network_maps_present = false;
    bool network_pins_ok = true;
};

struct DoctorAdvice {
    std::string code;
    std::string message;
    std::string remediation;
};

HealthReport collect_health_report(const std::string& trace_id, const std::string& parent_span_id)
{
    HealthReport report;

    ScopedSpan feature_span("health.detect_kernel_features", trace_id, parent_span_id);
    auto features_result = detect_kernel_features();
    if (!features_result) {
        feature_span.fail(features_result.error().to_string());
        logger().log(SLOG_ERROR("Kernel feature detection failed").field("error", features_result.error().to_string()));
        report.error = features_result.error().to_string();
        return report;
    }
    report.features = *features_result;
    report.kernel_version = report.features.kernel_version;
    report.capability = determine_capability(report.features);
    report.bpffs_mounted = check_bpffs_mounted();

    report.prereqs_ok = report.features.cgroup_v2 && report.features.btf && report.features.bpf_syscall &&
                        report.bpffs_mounted && report.capability != EnforcementCapability::Disabled;
    if (!report.prereqs_ok) {
        report.error =
            "Kernel prerequisites are not met: " + capability_explanation(report.features, report.capability);
        logger().log(SLOG_ERROR("Kernel prerequisites are not met")
                         .field("explanation", capability_explanation(report.features, report.capability)));
        return report;
    }

    BpfState state;
    ScopedSpan load_span("health.load_bpf", trace_id, parent_span_id);
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        load_span.fail(load_result.error().to_string());
        logger().log(SLOG_ERROR("BPF health check failed - cannot load BPF object")
                         .field("error", load_result.error().to_string()));
        report.error = "BPF load failed: " + load_result.error().to_string();
        return report;
    }
    report.bpf_load_ok = true;

    if (!state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.events) {
        logger().log(SLOG_ERROR("BPF health check failed - missing required maps"));
        report.error = "BPF health check failed - missing required maps";
        return report;
    }
    report.required_maps_ok = true;

    ScopedSpan layout_span("health.ensure_layout_version", trace_id, parent_span_id);
    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        layout_span.fail(version_result.error().to_string());
        logger().log(SLOG_ERROR("BPF health check failed - layout version check failed")
                         .field("error", version_result.error().to_string()));
        report.error = "Layout version check failed: " + version_result.error().to_string();
        return report;
    }
    report.layout_ok = true;

    const std::array<const char*, 9> required_pin_paths = {
        kDenyInodePin,      kDenyPathPin,      kAllowCgroupPin, kBlockStatsPin,        kDenyCgroupStatsPin,
        kDenyInodeStatsPin, kDenyPathStatsPin, kAgentMetaPin,   kSurvivalAllowlistPin,
    };
    for (const char* pin_path : required_pin_paths) {
        auto pin_result = verify_pinned_map_access(pin_path);
        if (!pin_result) {
            logger().log(SLOG_ERROR("Pinned map check failed")
                             .field("path", pin_path)
                             .field("error", pin_result.error().to_string()));
            report.error = "Pinned map check failed: " + std::string(pin_path);
            return report;
        }
    }
    report.required_pins_ok = true;

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
        report.network_maps_present = true;
        auto pin_result = verify_pinned_map_access(pin_path);
        if (!pin_result) {
            report.network_pins_ok = false;
            logger().log(SLOG_ERROR("Network pinned map check failed")
                             .field("path", pin_path)
                             .field("error", pin_result.error().to_string()));
            report.error = "Network pinned map check failed: " + std::string(pin_path);
            return report;
        }
    }

    report.ok = true;
    return report;
}

std::string build_health_json(const HealthReport& report)
{
    std::ostringstream out;
    out << "{" << "\"ok\":" << (report.ok ? "true" : "false") << ",\"capability\":\""
        << json_escape(capability_name(report.capability)) << "\"" << ",\"mode\":\""
        << (report.capability == EnforcementCapability::AuditOnly ? "audit-only" : "enforce") << "\""
        << ",\"kernel_version\":\"" << json_escape(report.kernel_version) << "\"" << ",\"features\":{"
        << "\"bpf_lsm\":" << (report.features.bpf_lsm ? "true" : "false")
        << ",\"cgroup_v2\":" << (report.features.cgroup_v2 ? "true" : "false")
        << ",\"btf\":" << (report.features.btf ? "true" : "false")
        << ",\"bpf_syscall\":" << (report.features.bpf_syscall ? "true" : "false")
        << ",\"ringbuf\":" << (report.features.ringbuf ? "true" : "false")
        << ",\"tracepoints\":" << (report.features.tracepoints ? "true" : "false")
        << ",\"bpffs\":" << (report.bpffs_mounted ? "true" : "false") << "}" << ",\"checks\":{"
        << "\"prereqs\":" << (report.prereqs_ok ? "true" : "false")
        << ",\"bpf_load\":" << (report.bpf_load_ok ? "true" : "false")
        << ",\"required_maps\":" << (report.required_maps_ok ? "true" : "false")
        << ",\"layout_version\":" << (report.layout_ok ? "true" : "false")
        << ",\"required_pins\":" << (report.required_pins_ok ? "true" : "false")
        << ",\"network_pins\":" << (report.network_pins_ok ? "true" : "false") << "}"
        << ",\"network_maps_present\":" << (report.network_maps_present ? "true" : "false");
    if (!report.error.empty()) {
        out << ",\"error\":\"" << json_escape(report.error) << "\"";
    }
    out << "}";
    return out.str();
}

void emit_health_json(const HealthReport& report)
{
    std::cout << build_health_json(report) << '\n';
}

std::vector<DoctorAdvice> build_doctor_advice(const HealthReport& report)
{
    std::vector<DoctorAdvice> advice;
    if (!report.features.bpf_lsm) {
        advice.push_back({"bpf_lsm_disabled", "BPF LSM is not enabled; enforcement will be audit-only.",
                          "Enable BPF LSM via kernel command line (lsm=...,...,bpf) and reboot."});
    }
    if (!report.features.btf) {
        advice.push_back({"missing_btf", "Kernel BTF is missing; verifier compatibility is reduced.",
                          "Use a kernel built with CONFIG_DEBUG_INFO_BTF=y."});
    }
    if (!report.bpffs_mounted) {
        advice.push_back({"bpffs_unmounted", "bpffs is not mounted at /sys/fs/bpf.",
                          "Mount bpffs: sudo mount -t bpf bpffs /sys/fs/bpf."});
    }
    if (report.capability == EnforcementCapability::AuditOnly) {
        advice.push_back({"audit_only", "Enforcement capability is audit-only.",
                          "Ensure BPF LSM is enabled to allow deny enforcement."});
    }
    if (!report.bpf_load_ok) {
        advice.push_back({"bpf_load_failed", "Failed to load BPF programs.",
                          "Check kernel logs and verify libbpf, BTF, and permissions."});
    }
    if (!report.layout_ok) {
        advice.push_back({"layout_mismatch", "Pinned map layout mismatch detected.",
                          "Run 'sudo aegisbpf block clear' to reset pinned maps."});
    }
    if (report.network_maps_present && !report.network_pins_ok) {
        advice.push_back(
            {"network_pins", "Network pinned map access failed.", "Verify bpffs permissions and pinned network maps."});
    }
    return advice;
}

void emit_doctor_text(const HealthReport& report, const std::vector<DoctorAdvice>& advice)
{
    std::cout << "AegisBPF Doctor" << '\n';
    std::cout << "status: " << (report.ok ? "ok" : "error") << '\n';
    std::cout << "capability: " << capability_name(report.capability) << '\n';
    std::cout << "kernel: " << report.kernel_version << '\n';
    std::cout << "checks: prereqs=" << (report.prereqs_ok ? "ok" : "fail")
              << " bpf_load=" << (report.bpf_load_ok ? "ok" : "fail")
              << " required_maps=" << (report.required_maps_ok ? "ok" : "fail")
              << " layout=" << (report.layout_ok ? "ok" : "fail")
              << " required_pins=" << (report.required_pins_ok ? "ok" : "fail")
              << " network_pins=" << (report.network_pins_ok ? "ok" : "fail") << '\n';
    if (!report.error.empty()) {
        std::cout << "error: " << report.error << '\n';
    }
    if (advice.empty()) {
        std::cout << "advice: none" << '\n';
        return;
    }
    std::cout << "advice:" << '\n';
    for (const auto& item : advice) {
        std::cout << "- [" << item.code << "] " << item.message << '\n';
        if (!item.remediation.empty()) {
            std::cout << "  remediation: " << item.remediation << '\n';
        }
    }
}

void emit_doctor_json(const HealthReport& report, const std::vector<DoctorAdvice>& advice)
{
    std::ostringstream out;
    out << "{" << "\"ok\":" << (report.ok ? "true" : "false") << ",\"report\":" << build_health_json(report)
        << ",\"advice\":[";
    for (size_t i = 0; i < advice.size(); ++i) {
        const auto& item = advice[i];
        if (i > 0) {
            out << ",";
        }
        out << "{" << "\"code\":\"" << json_escape(item.code) << "\"" << ",\"message\":\"" << json_escape(item.message)
            << "\"";
        if (!item.remediation.empty()) {
            out << ",\"remediation\":\"" << json_escape(item.remediation) << "\"";
        }
        out << "}";
    }
    out << "]}";
    std::cout << out.str() << '\n';
}

int cmd_health(bool json_output)
{
    const std::string trace_id = make_span_id("trace-health");
    ScopedSpan root_span("cli.health", trace_id);
    auto fail = [&](const std::string& error) -> int {
        root_span.fail(error);
        return 1;
    };
    HealthReport report = collect_health_report(trace_id, root_span.span_id());

    if (json_output) {
        emit_health_json(report);
        return report.ok ? 0 : 1;
    }

    std::cout << "Kernel version: " << report.kernel_version << '\n';
    std::cout << "Capability: " << capability_name(report.capability) << '\n';
    std::cout << "Features:" << '\n';
    std::cout << "  bpf_lsm: " << (report.features.bpf_lsm ? "yes" : "no") << '\n';
    std::cout << "  cgroup_v2: " << (report.features.cgroup_v2 ? "yes" : "no") << '\n';
    std::cout << "  btf: " << (report.features.btf ? "yes" : "no") << '\n';
    std::cout << "  bpf_syscall: " << (report.features.bpf_syscall ? "yes" : "no") << '\n';
    std::cout << "  ringbuf: " << (report.features.ringbuf ? "yes" : "no") << '\n';
    std::cout << "  tracepoints: " << (report.features.tracepoints ? "yes" : "no") << '\n';
    std::cout << "  bpffs: " << (report.bpffs_mounted ? "yes" : "no") << '\n';

    if (!report.ok) {
        return fail(report.error.empty() ? "Health check failed" : report.error);
    }

    if (report.capability == EnforcementCapability::AuditOnly) {
        std::cout << "Health check passed (audit-only capability)" << '\n';
        std::cout << "  Note: BPF LSM is unavailable; enforcement actions run in audit mode." << '\n';
        return 0;
    }

    std::cout << "Health check passed" << '\n';
    return 0;
}

int cmd_doctor(bool json_output)
{
    const std::string trace_id = make_span_id("trace-doctor");
    ScopedSpan root_span("cli.doctor", trace_id);

    HealthReport report = collect_health_report(trace_id, root_span.span_id());
    auto advice = build_doctor_advice(report);

    if (!report.ok && !report.error.empty()) {
        root_span.fail(report.error);
    }

    if (json_output) {
        emit_doctor_json(report, advice);
        return report.ok ? 0 : 1;
    }

    emit_doctor_text(report, advice);
    return report.ok ? 0 : 1;
}

int cmd_explain(const std::string& event_path, const std::string& policy_path, bool json_output)
{
    std::string payload;
    if (event_path == "-") {
        payload = read_stream(std::cin);
    } else {
        std::ifstream in(event_path);
        if (!in.is_open()) {
            logger().log(SLOG_ERROR("Failed to open event file").field("path", event_path).error_code(errno));
            return 1;
        }
        payload = read_stream(in);
    }

    ExplainEvent event{};
    std::string parse_error;
    if (!parse_explain_event(payload, event, parse_error)) {
        logger().log(SLOG_ERROR("Failed to parse event JSON").field("error", parse_error));
        return 1;
    }

    if (event.type != "block") {
        logger().log(SLOG_ERROR("Explain currently supports block events only").field("type", event.type));
        return 1;
    }

    std::string policy_source = policy_path;
    if (policy_source.empty() && std::filesystem::exists(kPolicyAppliedPath)) {
        policy_source = kPolicyAppliedPath;
    }

    Policy policy{};
    bool policy_loaded = false;
    if (!policy_source.empty()) {
        PolicyIssues issues{};
        auto policy_result = parse_policy_file(policy_source, issues);
        report_policy_issues(issues);
        if (!policy_result) {
            logger().log(SLOG_ERROR("Failed to parse policy for explain")
                             .field("path", policy_source)
                             .field("error", policy_result.error().to_string()));
            return 1;
        }
        if (issues.has_errors()) {
            logger().log(SLOG_ERROR("Policy contains errors; cannot explain decision").field("path", policy_source));
            return 1;
        }
        policy = *policy_result;
        policy_loaded = true;
    }

    bool allow_match = false;
    bool deny_inode_match = false;
    bool deny_path_match = false;

    if (policy_loaded) {
        if (event.has_cgid) {
            for (uint64_t id : policy.allow_cgroup_ids) {
                if (id == event.cgid) {
                    allow_match = true;
                    break;
                }
            }
        }
        if (!allow_match && !event.cgroup_path.empty()) {
            for (const auto& path : policy.allow_cgroup_paths) {
                if (path == event.cgroup_path) {
                    allow_match = true;
                    break;
                }
            }
        }

        if (event.has_ino && event.has_dev && event.dev <= UINT32_MAX) {
            InodeId id{event.ino, static_cast<uint32_t>(event.dev), 0};
            for (const auto& deny : policy.deny_inodes) {
                if (deny == id) {
                    deny_inode_match = true;
                    break;
                }
            }
        }

        if (!event.path.empty()) {
            for (const auto& deny : policy.deny_paths) {
                if (deny == event.path) {
                    deny_path_match = true;
                    break;
                }
            }
        }
        if (!deny_path_match && !event.resolved_path.empty()) {
            for (const auto& deny : policy.deny_paths) {
                if (deny == event.resolved_path) {
                    deny_path_match = true;
                    break;
                }
            }
        }
    }

    std::string inferred_rule;
    if (!policy_loaded) {
        inferred_rule = "unknown";
    } else if (allow_match) {
        inferred_rule = "allow_cgroup";
    } else if (deny_inode_match) {
        inferred_rule = "deny_inode";
    } else if (deny_path_match) {
        inferred_rule = "deny_path";
    } else {
        inferred_rule = "no_policy_match";
    }

    std::vector<std::string> notes;
    notes.emplace_back("Best-effort: evaluation uses provided policy and event fields.");
    notes.emplace_back("Inode-first enforcement: inode deny decisions override path matches.");
    if (!policy_loaded) {
        notes.emplace_back("No policy loaded; provide --policy or ensure an applied policy is present.");
    }
    if (!event.has_ino || !event.has_dev) {
        notes.emplace_back("Event missing inode/dev; inode match not evaluated.");
    }
    if (allow_match && !event.action.empty() && event.action != "AUDIT") {
        notes.emplace_back("Allowlist matched but event was blocked; policy may have changed.");
    }

    if (json_output) {
        std::ostringstream out;
        out << "{" << "\"type\":\"" << json_escape(event.type) << "\"";
        if (!event.action.empty()) {
            out << ",\"action\":\"" << json_escape(event.action) << "\"";
        }
        if (!event.path.empty()) {
            out << ",\"path\":\"" << json_escape(event.path) << "\"";
        }
        if (!event.resolved_path.empty()) {
            out << ",\"resolved_path\":\"" << json_escape(event.resolved_path) << "\"";
        }
        if (event.has_ino) {
            out << ",\"ino\":" << event.ino;
        }
        if (event.has_dev) {
            out << ",\"dev\":" << event.dev;
        }
        if (!event.cgroup_path.empty()) {
            out << ",\"cgroup_path\":\"" << json_escape(event.cgroup_path) << "\"";
        }
        if (event.has_cgid) {
            out << ",\"cgid\":" << event.cgid;
        }
        out << ",\"policy\":{\"path\":\"" << json_escape(policy_source)
            << "\",\"loaded\":" << (policy_loaded ? "true" : "false") << "}";
        out << ",\"matches\":{" << "\"allow_cgroup\":" << (policy_loaded ? (allow_match ? "true" : "false") : "false")
            << ",\"deny_inode\":" << (policy_loaded ? (deny_inode_match ? "true" : "false") : "false")
            << ",\"deny_path\":" << (policy_loaded ? (deny_path_match ? "true" : "false") : "false") << "}";
        out << ",\"inferred_rule\":\"" << json_escape(inferred_rule) << "\"";
        out << ",\"notes\":[";
        for (size_t i = 0; i < notes.size(); ++i) {
            if (i > 0) {
                out << ",";
            }
            out << "\"" << json_escape(notes[i]) << "\"";
        }
        out << "]}";
        std::cout << out.str() << '\n';
        return 0;
    }

    std::cout << "Explain (best-effort)" << '\n';
    std::cout << "  type: " << event.type << '\n';
    if (!event.action.empty()) {
        std::cout << "  action: " << event.action << '\n';
    }
    if (!event.path.empty()) {
        std::cout << "  path: " << event.path << '\n';
    }
    if (!event.resolved_path.empty()) {
        std::cout << "  resolved_path: " << event.resolved_path << '\n';
    }
    if (event.has_ino) {
        std::cout << "  ino: " << event.ino << '\n';
    }
    if (event.has_dev) {
        std::cout << "  dev: " << event.dev << '\n';
    }
    if (!event.cgroup_path.empty()) {
        std::cout << "  cgroup_path: " << event.cgroup_path << '\n';
    }
    if (event.has_cgid) {
        std::cout << "  cgid: " << event.cgid << '\n';
    }
    std::cout << "  policy: " << (policy_loaded ? policy_source : "not loaded") << '\n';
    if (policy_loaded) {
        std::cout << "  allow_cgroup_match: " << (allow_match ? "yes" : "no") << '\n';
        std::cout << "  deny_inode_match: " << (deny_inode_match ? "yes" : "no") << '\n';
        std::cout << "  deny_path_match: " << (deny_path_match ? "yes" : "no") << '\n';
    } else {
        std::cout << "  allow_cgroup_match: unknown" << '\n';
        std::cout << "  deny_inode_match: unknown" << '\n';
        std::cout << "  deny_path_match: unknown" << '\n';
    }
    std::cout << "  inferred_rule: " << inferred_rule << '\n';
    if (!notes.empty()) {
        std::cout << "  notes:" << '\n';
        for (const auto& note : notes) {
            std::cout << "    - " << note << '\n';
        }
    }
    return 0;
}

} // namespace aegis
