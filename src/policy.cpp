// cppcheck-suppress-file missingIncludeSystem
#include "policy.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <unordered_set>

#include "binary_scan.hpp"
#include "bpf_ops.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "sha256.hpp"
#include "tracing.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

thread_local std::string g_policy_trace_id;

class PolicyTraceScope {
  public:
    explicit PolicyTraceScope(std::string trace_id) : previous_(std::move(g_policy_trace_id))
    {
        g_policy_trace_id = std::move(trace_id);
    }

    ~PolicyTraceScope() { g_policy_trace_id = previous_; }

  private:
    std::string previous_;
};

std::string active_policy_trace_id()
{
    if (!g_policy_trace_id.empty()) {
        return g_policy_trace_id;
    }
    return make_span_id("trace-policy");
}

std::string env_or_default_path(const char* env_name, const char* fallback)
{
    const char* env = std::getenv(env_name);
    if (env && *env) {
        return std::string(env);
    }
    return fallback;
}

std::string policy_applied_path()
{
    return env_or_default_path("AEGIS_POLICY_APPLIED_PATH", kPolicyAppliedPath);
}

std::string policy_applied_prev_path()
{
    return env_or_default_path("AEGIS_POLICY_APPLIED_PREV_PATH", kPolicyAppliedPrevPath);
}

std::string policy_applied_hash_path()
{
    return env_or_default_path("AEGIS_POLICY_APPLIED_HASH_PATH", kPolicyAppliedHashPath);
}

} // namespace

void report_policy_issues(const PolicyIssues& issues)
{
    for (const auto& err : issues.errors) {
        logger().log(SLOG_ERROR("Policy error").field("detail", err));
    }
    for (const auto& warn : issues.warnings) {
        logger().log(SLOG_WARN("Policy warning").field("detail", warn));
    }
}

// Helper to parse port rule: port[:protocol[:direction]]
static bool parse_port_rule(const std::string& str, PortRule& rule)
{
    rule = {};
    rule.direction = 2; // both

    std::vector<std::string> parts;
    std::string current;
    for (char c : str) {
        if (c == ':') {
            parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    parts.push_back(current);

    if (parts.empty() || parts[0].empty()) {
        return false;
    }

    uint64_t port = 0;
    if (!parse_uint64(parts[0], port) || port == 0 || port > 65535) {
        return false;
    }
    rule.port = static_cast<uint16_t>(port);

    if (parts.size() > 1 && !parts[1].empty()) {
        if (parts[1] == "tcp") {
            rule.protocol = 6;
        } else if (parts[1] == "udp") {
            rule.protocol = 17;
        } else if (parts[1] == "any") {
            rule.protocol = 0;
        } else {
            return false;
        }
    }

    if (parts.size() > 2 && !parts[2].empty()) {
        if (parts[2] == "egress" || parts[2] == "connect") {
            rule.direction = 0;
        } else if (parts[2] == "bind") {
            rule.direction = 1;
        } else if (parts[2] == "both") {
            rule.direction = 2;
        } else {
            return false;
        }
    }

    return true;
}

Result<Policy> parse_policy_file(const std::string& path, PolicyIssues& issues)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        issues.errors.push_back("Failed to open '" + path + "': " + std::strerror(errno));
        return Error(ErrorCode::PolicyParseFailed, "Failed to open policy file", path);
    }

    Policy policy{};
    std::string section;
    std::unordered_set<std::string> deny_path_seen;
    std::unordered_set<std::string> deny_inode_seen;
    std::unordered_set<std::string> protect_path_seen;
    std::unordered_set<std::string> allow_path_seen;
    std::unordered_set<uint64_t> allow_id_seen;
    std::unordered_set<std::string> deny_ip_seen;
    std::unordered_set<std::string> deny_cidr_seen;
    std::unordered_set<std::string> deny_port_seen;
    std::string line;
    size_t line_no = 0;

    std::unordered_set<std::string> deny_hash_seen;
    std::unordered_set<std::string> allow_hash_seen;

    // Valid sections
    static const std::unordered_set<std::string> valid_sections = {
        "deny_path", "deny_inode", "protect_path",     "protect_connect",   "allow_cgroup", "deny_ip",
        "deny_cidr", "deny_port",  "deny_binary_hash", "allow_binary_hash", "scan_paths"};

    while (std::getline(in, line)) {
        ++line_no;
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trim(trimmed.substr(1, trimmed.size() - 2));
            if (valid_sections.find(section) == valid_sections.end()) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": unknown section '" + section + "'");
                section.clear();
            }
            if (section == "protect_connect") {
                policy.protect_connect = true;
            }
            continue;
        }

        if (section.empty()) {
            std::string key;
            std::string value;
            if (!parse_key_value(trimmed, key, value)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": expected key=value in header");
                continue;
            }
            if (key == "version") {
                uint64_t version = 0;
                if (!parse_uint64(value, version) || version == 0 ||
                    version > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
                    issues.errors.push_back("line " + std::to_string(line_no) + ": invalid version");
                    continue;
                }
                policy.version = static_cast<int>(version);
            } else {
                issues.errors.push_back("line " + std::to_string(line_no) + ": unknown header key '" + key + "'");
            }
            continue;
        }

        if (section == "deny_path") {
            if (trimmed.size() >= kDenyPathMax) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": deny_path is too long");
                continue;
            }
            if (!trimmed.empty() && trimmed.front() != '/') {
                issues.warnings.push_back("line " + std::to_string(line_no) + ": deny_path is relative");
            }
            if (deny_path_seen.insert(trimmed).second) {
                policy.deny_paths.push_back(trimmed);
            }
            continue;
        }

        if (section == "protect_path") {
            if (trimmed.size() >= kDenyPathMax) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": protect_path is too long");
                continue;
            }
            if (!trimmed.empty() && trimmed.front() != '/') {
                issues.warnings.push_back("line " + std::to_string(line_no) + ": protect_path is relative");
            }
            if (protect_path_seen.insert(trimmed).second) {
                policy.protect_paths.push_back(trimmed);
            }
            continue;
        }

        if (section == "protect_connect") {
            // Presence of the section enables connect protection. Entries are not used.
            issues.warnings.push_back("line " + std::to_string(line_no) +
                                      ": [protect_connect] does not take entries; ignoring '" + trimmed + "'");
            continue;
        }

        if (section == "deny_inode") {
            InodeId id{};
            if (!parse_inode_id(trimmed, id)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": invalid inode format (dev:ino)");
                continue;
            }
            std::string id_key = inode_to_string(id);
            if (deny_inode_seen.insert(id_key).second) {
                policy.deny_inodes.push_back(id);
            }
            continue;
        }

        if (section == "allow_cgroup") {
            if (trimmed.rfind("cgid:", 0) == 0) {
                std::string id_str = trim(trimmed.substr(5));
                uint64_t cgid = 0;
                if (!parse_uint64(id_str, cgid)) {
                    issues.errors.push_back("line " + std::to_string(line_no) + ": invalid cgid value");
                    continue;
                }
                if (allow_id_seen.insert(cgid).second) {
                    policy.allow_cgroup_ids.push_back(cgid);
                }
                continue;
            }
            if (!trimmed.empty() && trimmed.front() != '/') {
                issues.warnings.push_back("line " + std::to_string(line_no) + ": allow_cgroup path is relative");
            }
            if (allow_path_seen.insert(trimmed).second) {
                policy.allow_cgroup_paths.push_back(trimmed);
            }
            continue;
        }

        // Network sections
        if (section == "deny_ip") {
            uint32_t ip_be;
            Ipv6Key ipv6{};
            if (!parse_ipv4(trimmed, ip_be) && !parse_ipv6(trimmed, ipv6)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": invalid IP address '" + trimmed + "'");
                continue;
            }
            if (deny_ip_seen.insert(trimmed).second) {
                policy.network.deny_ips.push_back(trimmed);
                policy.network.enabled = true;
            }
            continue;
        }

        if (section == "deny_cidr") {
            uint32_t ip_be;
            uint8_t prefix_len;
            Ipv6Key ipv6{};
            if (!parse_cidr_v4(trimmed, ip_be, prefix_len) && !parse_cidr_v6(trimmed, ipv6, prefix_len)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": invalid CIDR notation '" + trimmed +
                                        "'");
                continue;
            }
            if (deny_cidr_seen.insert(trimmed).second) {
                policy.network.deny_cidrs.push_back(trimmed);
                policy.network.enabled = true;
            }
            continue;
        }

        if (section == "deny_port") {
            // Format: port[:protocol[:direction]]
            PortRule rule{};
            if (!parse_port_rule(trimmed, rule)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": invalid port rule '" + trimmed + "'");
                continue;
            }
            if (deny_port_seen.insert(trimmed).second) {
                policy.network.deny_ports.push_back(rule);
                policy.network.enabled = true;
            }
            continue;
        }

        if (section == "deny_binary_hash") {
            // Format: sha256:<hex_digest>
            if (trimmed.rfind("sha256:", 0) != 0) {
                issues.errors.push_back("line " + std::to_string(line_no) +
                                        ": deny_binary_hash entry must start with 'sha256:'");
                continue;
            }
            std::string hash = trimmed.substr(7);
            if (hash.size() != 64) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": sha256 hash must be 64 hex characters");
                continue;
            }
            bool valid_hex = true;
            for (char c : hash) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    valid_hex = false;
                    break;
                }
            }
            if (!valid_hex) {
                issues.errors.push_back("line " + std::to_string(line_no) +
                                        ": sha256 hash contains non-hex characters");
                continue;
            }
            // Normalize to lowercase
            std::transform(hash.begin(), hash.end(), hash.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (deny_hash_seen.insert(hash).second) {
                policy.deny_binary_hashes.push_back(hash);
            }
            continue;
        }

        if (section == "allow_binary_hash") {
            // Format: sha256:<hex_digest>
            if (trimmed.rfind("sha256:", 0) != 0) {
                issues.errors.push_back("line " + std::to_string(line_no) +
                                        ": allow_binary_hash entry must start with 'sha256:'");
                continue;
            }
            std::string hash = trimmed.substr(7);
            if (hash.size() != 64) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": sha256 hash must be 64 hex characters");
                continue;
            }
            bool valid_hex = true;
            for (char c : hash) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    valid_hex = false;
                    break;
                }
            }
            if (!valid_hex) {
                issues.errors.push_back("line " + std::to_string(line_no) +
                                        ": sha256 hash contains non-hex characters");
                continue;
            }
            // Normalize to lowercase
            std::transform(hash.begin(), hash.end(), hash.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (allow_hash_seen.insert(hash).second) {
                policy.allow_binary_hashes.push_back(hash);
            }
            continue;
        }

        if (section == "scan_paths") {
            if (trimmed.empty() || trimmed.front() != '/') {
                issues.warnings.push_back("line " + std::to_string(line_no) + ": scan_paths entry should be absolute");
            }
            policy.scan_paths.push_back(trimmed);
            continue;
        }
    }

    if (policy.version == 0) {
        issues.errors.push_back("missing header key: version");
    }
    // Accept version 1..4 (2 adds network, 3 adds binary hash sections, 4 adds exec-identity protected resources)
    if (policy.version < 1 || policy.version > 4) {
        issues.errors.push_back("unsupported policy version: " + std::to_string(policy.version));
    }

    // deny_binary_hash requires version >= 3
    if (!policy.deny_binary_hashes.empty() && policy.version < 3) {
        issues.errors.push_back("[deny_binary_hash] requires version=3 or higher");
    }
    if (!policy.allow_binary_hashes.empty() && policy.version < 3) {
        issues.errors.push_back("[allow_binary_hash] requires version=3 or higher");
    }

    if ((!policy.protect_paths.empty() || policy.protect_connect) && policy.version < 4) {
        issues.errors.push_back("[protect_path]/[protect_connect] requires version=4 or higher");
    }

    if (!issues.errors.empty()) {
        return Error(ErrorCode::PolicyParseFailed, "Policy parsing failed with errors");
    }
    return policy;
}

Result<void> record_applied_policy(const std::string& path, const std::string& hash)
{
    const std::string applied_path = policy_applied_path();
    const std::string applied_prev_path = policy_applied_prev_path();
    const std::string applied_hash_path = policy_applied_hash_path();

    auto db_result = ensure_db_dir();
    if (!db_result) {
        return db_result.error();
    }

    std::error_code ec;
    if (std::filesystem::exists(applied_path, ec)) {
        std::filesystem::copy_file(applied_path, applied_prev_path, std::filesystem::copy_options::overwrite_existing,
                                   ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to backup applied policy", ec.message());
        }
    }

    std::ifstream in(path);
    if (!in.is_open()) {
        return Error::system(errno, "Failed to open policy file for recording");
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    auto write_result = atomic_write_file(applied_path, content);
    if (!write_result) {
        return write_result.error();
    }

    if (!hash.empty()) {
        auto hash_result = atomic_write_file(applied_hash_path, hash + "\n");
        if (!hash_result) {
            return hash_result.error();
        }
    } else {
        std::error_code rm_ec;
        std::filesystem::remove(applied_hash_path, rm_ec);
        if (rm_ec) {
            return Error(ErrorCode::IoError, "Failed to remove policy hash file", rm_ec.message());
        }
    }
    return {};
}

// cppcheck-suppress constParameterReference
Result<void> reset_policy_maps(BpfState& state)
{
    TRY(clear_map_entries(state.deny_inode));
    TRY(clear_map_entries(state.deny_path));
    TRY(clear_map_entries(state.allow_cgroup));
    TRY(clear_map_entries(state.allow_exec_inode));
    TRY(clear_map_entries(state.deny_cgroup_stats));
    TRY(clear_map_entries(state.deny_inode_stats));
    TRY(clear_map_entries(state.deny_path_stats));
    TRY(set_exec_identity_mode(state, false));
    TRY(set_exec_identity_flags(state, 0));

    if (state.block_stats) {
        TRY(reset_block_stats_map(state.block_stats));
    }

    // Clear network maps if available
    if (state.deny_ipv4) {
        TRY(clear_map_entries(state.deny_ipv4));
    }
    if (state.deny_ipv6) {
        TRY(clear_map_entries(state.deny_ipv6));
    }
    if (state.deny_port) {
        TRY(clear_map_entries(state.deny_port));
    }
    if (state.deny_cidr_v4) {
        TRY(clear_map_entries(state.deny_cidr_v4));
    }
    if (state.deny_cidr_v6) {
        TRY(clear_map_entries(state.deny_cidr_v6));
    }

    std::error_code ec;
    std::filesystem::remove(kDenyDbPath, ec);
    return {};
}

Result<void> policy_lint(const std::string& path)
{
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        return result.error();
    }
    return {};
}

Result<void> apply_policy_internal_impl_fn(const std::string& path, const std::string& computed_hash, bool reset,
                                           bool record)
{
    ScopedSpan root_span("policy.apply_internal", active_policy_trace_id());
    auto fail = [&](const Error& err) -> Result<void> {
        root_span.fail(err.to_string());
        return err;
    };

    Policy policy{};
    {
        ScopedSpan span("policy.parse", root_span.trace_id(), root_span.span_id());
        PolicyIssues issues;
        auto policy_result = parse_policy_file(path, issues);
        report_policy_issues(issues);
        if (!policy_result) {
            span.fail(policy_result.error().to_string());
            return fail(policy_result.error());
        }
        policy = *policy_result;
    }

    {
        ScopedSpan span("policy.bump_memlock", root_span.trace_id(), root_span.span_id());
        auto rlimit_result = bump_memlock_rlimit();
        if (!rlimit_result) {
            span.fail(rlimit_result.error().to_string());
            return fail(rlimit_result.error());
        }
    }

    BpfState state;
    {
        ScopedSpan span("policy.load_bpf", root_span.trace_id(), root_span.span_id());
        auto load_result = load_bpf(true, false, state);
        if (!load_result) {
            span.fail(load_result.error().to_string());
            return fail(load_result.error());
        }
    }

    {
        ScopedSpan span("policy.ensure_layout_version", root_span.trace_id(), root_span.span_id());
        auto version_result = ensure_layout_version(state);
        if (!version_result) {
            span.fail(version_result.error().to_string());
            return fail(version_result.error());
        }
    }

    DenyEntries entries;
    {
        ScopedSpan span("policy.prepare_entries", root_span.trace_id(), root_span.span_id());
        entries = reset ? DenyEntries{} : read_deny_db();
    }

    std::vector<BinaryScanResult> allow_binary_matches;
    if (!policy.allow_binary_hashes.empty()) {
        ScopedSpan span("policy.scan_allow_binary_hashes", root_span.trace_id(), root_span.span_id());
        auto scan_result = scan_for_binary_hashes(policy.allow_binary_hashes, policy.scan_paths);
        if (!scan_result) {
            span.fail(scan_result.error().to_string());
            return fail(scan_result.error());
        }
        allow_binary_matches = std::move(*scan_result);
        if (allow_binary_matches.empty()) {
            Error err(ErrorCode::PolicyApplyFailed,
                      "allow_binary_hash policy has no matching binaries on this host; refusing fail-closed policy");
            span.fail(err.to_string());
            return fail(err);
        }
    }

    size_t expected_allow_exec_inode_entries = 0;

    // --- Shadow-then-sync path: populate shadow maps, verify, then sync to live ---
    // Attempt to create shadow maps. If creation fails (old kernel, insufficient memory),
    // fall back to the direct-mutation approach.
    bool use_shadow = false;
    ShadowMapSet shadows;
    {
        ScopedSpan span("policy.create_shadows", root_span.trace_id(), root_span.span_id());
        auto shadow_result = create_shadow_map_set(state);
        if (shadow_result) {
            shadows = std::move(*shadow_result);
            use_shadow = true;
            logger().log(SLOG_INFO("Shadow maps created for crash-safe policy apply"));
        } else {
            logger().log(SLOG_WARN("Shadow map creation failed; falling back to direct apply")
                             .field("error", shadow_result.error().to_string()));
        }
    }

    if (use_shadow) {
        // Populate shadow maps (live maps untouched)
        {
            ScopedSpan span("policy.populate_shadows", root_span.trace_id(), root_span.span_id());
            for (const auto& deny_path : policy.deny_paths) {
                auto result = add_deny_path_to_fds(shadows.deny_inode.fd(), shadows.deny_path.fd(), deny_path, entries);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            for (const auto& protect_path : policy.protect_paths) {
                auto result = add_rule_path_to_fds(shadows.deny_inode.fd(), shadows.deny_path.fd(), protect_path,
                                                   kRuleFlagProtectByVerifiedExec, entries);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            for (const auto& id : policy.deny_inodes) {
                auto result = add_deny_inode_to_fd(shadows.deny_inode.fd(), id, entries);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            // Scan for binaries matching deny_binary_hash entries and add their inodes
            if (!policy.deny_binary_hashes.empty()) {
                auto scan_result = scan_for_binary_hashes(policy.deny_binary_hashes, policy.scan_paths);
                if (scan_result) {
                    for (const auto& match : *scan_result) {
                        auto result = add_deny_inode_to_fd(shadows.deny_inode.fd(), match.inode, entries);
                        if (!result) {
                            logger().log(SLOG_WARN("Failed to add binary hash match to shadow")
                                             .field("path", match.path)
                                             .field("hash", match.hash)
                                             .field("error", result.error().message()));
                        }
                    }
                } else {
                    logger().log(SLOG_WARN("Binary hash scan failed").field("error", scan_result.error().to_string()));
                }
            }

            for (const auto& cgid : policy.allow_cgroup_ids) {
                auto result = add_allow_cgroup_to_fd(shadows.allow_cgroup.fd(), cgid);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            for (const auto& cgpath : policy.allow_cgroup_paths) {
                auto result = add_allow_cgroup_path_to_fd(shadows.allow_cgroup.fd(), cgpath);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }

            std::unordered_set<InodeId, InodeIdHash> allow_exec_seen;
            for (const auto& match : allow_binary_matches) {
                if (!allow_exec_seen.insert(match.inode).second) {
                    continue;
                }
                auto result = add_allow_exec_inode_to_fd(shadows.allow_exec_inode.fd(), match.inode);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            expected_allow_exec_inode_entries = allow_exec_seen.size();
        }

        // Populate shadow network maps
        if (policy.network.enabled) {
            ScopedSpan span("policy.populate_shadow_network", root_span.trace_id(), root_span.span_id());
            for (const auto& ip : policy.network.deny_ips) {
                auto result = add_deny_ip_to_fds(shadows.deny_ipv4.fd(), shadows.deny_ipv6.fd(), ip);
                if (!result) {
                    logger().log(SLOG_WARN("Failed to add deny IP to shadow")
                                     .field("ip", ip)
                                     .field("error", result.error().message()));
                }
            }
            for (const auto& cidr : policy.network.deny_cidrs) {
                auto result = add_deny_cidr_to_fds(shadows.deny_cidr_v4.fd(), shadows.deny_cidr_v6.fd(), cidr);
                if (!result) {
                    logger().log(SLOG_WARN("Failed to add deny CIDR to shadow")
                                     .field("cidr", cidr)
                                     .field("error", result.error().message()));
                }
            }
            for (const auto& port_rule : policy.network.deny_ports) {
                auto result = add_deny_port_to_fd(shadows.deny_port.fd(), port_rule.port, port_rule.protocol,
                                                  port_rule.direction);
                if (!result) {
                    logger().log(SLOG_WARN("Failed to add deny port to shadow")
                                     .field("port", static_cast<int64_t>(port_rule.port))
                                     .field("error", result.error().message()));
                }
            }
        }

        // Verify shadow map entry counts before touching live maps
        {
            ScopedSpan span("policy.verify_shadows", root_span.trace_id(), root_span.span_id());
            size_t shadow_inode_count =
                map_fd_entry_count(shadows.deny_inode.fd(), bpf_map__key_size(state.deny_inode));
            if (shadow_inode_count != entries.size()) {
                Error err(ErrorCode::BpfMapOperationFailed, "Shadow verify failed for deny_inode",
                          "expected=" + std::to_string(entries.size()) +
                              " actual=" + std::to_string(shadow_inode_count));
                span.fail(err.to_string());
                logger().log(SLOG_ERROR("Shadow verify failed for deny_inode")
                                 .field("expected", static_cast<int64_t>(entries.size()))
                                 .field("actual", static_cast<int64_t>(shadow_inode_count)));
                return fail(err);
            }

            size_t shadow_path_count = map_fd_entry_count(shadows.deny_path.fd(), bpf_map__key_size(state.deny_path));
            const size_t expected_min_path_rules = policy.deny_paths.size() + policy.protect_paths.size();
            if (shadow_path_count < expected_min_path_rules) {
                Error err(ErrorCode::BpfMapOperationFailed, "Shadow verify failed for deny_path",
                          "expected>=" + std::to_string(expected_min_path_rules) +
                              " actual=" + std::to_string(shadow_path_count));
                span.fail(err.to_string());
                return fail(err);
            }

            if (!allow_binary_matches.empty()) {
                size_t shadow_allow_exec_count =
                    map_fd_entry_count(shadows.allow_exec_inode.fd(), bpf_map__key_size(state.allow_exec_inode));
                if (shadow_allow_exec_count < expected_allow_exec_inode_entries) {
                    Error err(ErrorCode::BpfMapOperationFailed, "Shadow verify failed for allow_exec_inode",
                              "expected>=" + std::to_string(expected_allow_exec_inode_entries) +
                                  " actual=" + std::to_string(shadow_allow_exec_count));
                    span.fail(err.to_string());
                    return fail(err);
                }
            }
        }

        // Sync shadow maps into live maps
        {
            ScopedSpan span("policy.sync_shadows_to_live", root_span.trace_id(), root_span.span_id());

            if (reset) {
                TRY(reset_policy_maps(state));
            }

            TRY(sync_from_shadow(state.deny_inode, shadows.deny_inode.fd()));
            TRY(sync_from_shadow(state.deny_path, shadows.deny_path.fd()));
            TRY(sync_from_shadow(state.allow_cgroup, shadows.allow_cgroup.fd()));
            TRY(sync_from_shadow(state.allow_exec_inode, shadows.allow_exec_inode.fd()));

            if (policy.network.enabled) {
                TRY(sync_from_shadow(state.deny_ipv4, shadows.deny_ipv4.fd()));
                TRY(sync_from_shadow(state.deny_ipv6, shadows.deny_ipv6.fd()));
                TRY(sync_from_shadow(state.deny_port, shadows.deny_port.fd()));
                TRY(sync_from_shadow(state.deny_cidr_v4, shadows.deny_cidr_v4.fd()));
                TRY(sync_from_shadow(state.deny_cidr_v6, shadows.deny_cidr_v6.fd()));
            }

            logger().log(SLOG_INFO("Shadow maps synced to live maps"));
        }
    } else {
        // Fallback: direct-mutation path (original behavior)
        if (reset) {
            ScopedSpan span("policy.reset_maps", root_span.trace_id(), root_span.span_id());
            auto reset_result = reset_policy_maps(state);
            if (!reset_result) {
                span.fail(reset_result.error().to_string());
                return fail(reset_result.error());
            }
        }

        {
            ScopedSpan span("policy.apply_file_rules", root_span.trace_id(), root_span.span_id());
            auto clear_allow_exec = clear_map_entries(state.allow_exec_inode);
            if (!clear_allow_exec) {
                span.fail(clear_allow_exec.error().to_string());
                return fail(clear_allow_exec.error());
            }

            for (const auto& deny_path : policy.deny_paths) {
                auto result = add_deny_path(state, deny_path, entries);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            for (const auto& protect_path : policy.protect_paths) {
                auto result = add_rule_path_to_fds(bpf_map__fd(state.deny_inode), bpf_map__fd(state.deny_path),
                                                   protect_path, kRuleFlagProtectByVerifiedExec, entries);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            for (const auto& id : policy.deny_inodes) {
                auto result = add_deny_inode(state, id, entries);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            // Scan for binaries matching deny_binary_hash entries and add their inodes
            if (!policy.deny_binary_hashes.empty()) {
                auto scan_result = scan_for_binary_hashes(policy.deny_binary_hashes, policy.scan_paths);
                if (scan_result) {
                    for (const auto& match : *scan_result) {
                        auto result = add_deny_inode(state, match.inode, entries);
                        if (!result) {
                            logger().log(SLOG_WARN("Failed to add binary hash match")
                                             .field("path", match.path)
                                             .field("hash", match.hash)
                                             .field("error", result.error().message()));
                        }
                    }
                } else {
                    logger().log(SLOG_WARN("Binary hash scan failed").field("error", scan_result.error().to_string()));
                }
            }

            for (const auto& cgid : policy.allow_cgroup_ids) {
                auto result = add_allow_cgroup(state, cgid);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            for (const auto& cgpath : policy.allow_cgroup_paths) {
                auto result = add_allow_cgroup_path(state, cgpath);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }

            std::unordered_set<InodeId, InodeIdHash> allow_exec_seen;
            for (const auto& match : allow_binary_matches) {
                if (!allow_exec_seen.insert(match.inode).second) {
                    continue;
                }
                auto result = add_allow_exec_inode(state, match.inode);
                if (!result) {
                    span.fail(result.error().to_string());
                    return fail(result.error());
                }
            }
            expected_allow_exec_inode_entries = allow_exec_seen.size();
        }

        if (policy.network.enabled) {
            ScopedSpan span("policy.apply_network_rules", root_span.trace_id(), root_span.span_id());
            for (const auto& ip : policy.network.deny_ips) {
                auto result = add_deny_ip(state, ip);
                if (!result) {
                    logger().log(
                        SLOG_WARN("Failed to add deny IP").field("ip", ip).field("error", result.error().message()));
                }
            }
            for (const auto& cidr : policy.network.deny_cidrs) {
                auto result = add_deny_cidr(state, cidr);
                if (!result) {
                    logger().log(SLOG_WARN("Failed to add deny CIDR")
                                     .field("cidr", cidr)
                                     .field("error", result.error().message()));
                }
            }
            for (const auto& port_rule : policy.network.deny_ports) {
                auto result = add_deny_port(state, port_rule.port, port_rule.protocol, port_rule.direction);
                if (!result) {
                    logger().log(SLOG_WARN("Failed to add deny port")
                                     .field("port", static_cast<int64_t>(port_rule.port))
                                     .field("error", result.error().message()));
                }
            }
            logger().log(SLOG_INFO("Network policy applied")
                             .field("deny_ips", static_cast<int64_t>(policy.network.deny_ips.size()))
                             .field("deny_cidrs", static_cast<int64_t>(policy.network.deny_cidrs.size()))
                             .field("deny_ports", static_cast<int64_t>(policy.network.deny_ports.size())));
        }
    }

    // Verify phase: confirm live map entry counts match expectations
    {
        ScopedSpan span("policy.verify_maps", root_span.trace_id(), root_span.span_id());

        auto verify_deny_inode = verify_map_entry_count(state.deny_inode, entries.size());
        if (!verify_deny_inode) {
            span.fail(verify_deny_inode.error().to_string());
            logger().log(SLOG_ERROR("Post-apply verification failed for deny_inode map")
                             .field("error", verify_deny_inode.error().to_string()));
            return fail(verify_deny_inode.error());
        }

        size_t deny_path_actual = map_entry_count(state.deny_path);
        const size_t expected_min_path_rules = policy.deny_paths.size() + policy.protect_paths.size();
        if (deny_path_actual < expected_min_path_rules) {
            Error err(ErrorCode::BpfMapOperationFailed, "Post-apply verification failed for deny_path map",
                      "expected>=" + std::to_string(expected_min_path_rules) +
                          " actual=" + std::to_string(deny_path_actual));
            span.fail(err.to_string());
            logger().log(SLOG_ERROR("Post-apply verification failed for deny_path map")
                             .field("expected_min", static_cast<int64_t>(expected_min_path_rules))
                             .field("actual", static_cast<int64_t>(deny_path_actual)));
            return fail(err);
        }

        size_t expected_cgroup = policy.allow_cgroup_ids.size() + policy.allow_cgroup_paths.size();
        if (expected_cgroup > 0) {
            size_t cgroup_actual = map_entry_count(state.allow_cgroup);
            if (cgroup_actual < expected_cgroup) {
                Error err(ErrorCode::BpfMapOperationFailed, "Post-apply verification failed for allow_cgroup map",
                          "expected>=" + std::to_string(expected_cgroup) + " actual=" + std::to_string(cgroup_actual));
                span.fail(err.to_string());
                return fail(err);
            }
        }

        if (!allow_binary_matches.empty()) {
            size_t allow_exec_actual = map_entry_count(state.allow_exec_inode);
            if (allow_exec_actual < expected_allow_exec_inode_entries) {
                Error err(ErrorCode::BpfMapOperationFailed, "Post-apply verification failed for allow_exec_inode map",
                          "expected>=" + std::to_string(expected_allow_exec_inode_entries) +
                              " actual=" + std::to_string(allow_exec_actual));
                span.fail(err.to_string());
                logger().log(SLOG_ERROR("Post-apply verification failed for allow_exec_inode map")
                                 .field("expected_min", static_cast<int64_t>(expected_allow_exec_inode_entries))
                                 .field("actual", static_cast<int64_t>(allow_exec_actual)));
                return fail(err);
            }
        }

        if (policy.network.enabled) {
            size_t expected_ipv4 = 0;
            size_t expected_ipv6 = 0;
            for (const auto& ip : policy.network.deny_ips) {
                uint32_t ip_be;
                Ipv6Key ipv6{};
                if (parse_ipv4(ip, ip_be)) {
                    ++expected_ipv4;
                } else if (parse_ipv6(ip, ipv6)) {
                    ++expected_ipv6;
                }
            }

            if (expected_ipv4 > 0 && state.deny_ipv4) {
                auto v = verify_map_entry_count(state.deny_ipv4, expected_ipv4);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (expected_ipv6 > 0 && state.deny_ipv6) {
                auto v = verify_map_entry_count(state.deny_ipv6, expected_ipv6);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (!policy.network.deny_ports.empty() && state.deny_port) {
                auto v = verify_map_entry_count(state.deny_port, policy.network.deny_ports.size());
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }

            size_t expected_cidr_v4 = 0;
            size_t expected_cidr_v6 = 0;
            for (const auto& cidr : policy.network.deny_cidrs) {
                uint32_t ip_be;
                uint8_t prefix_len;
                Ipv6Key ipv6{};
                if (parse_cidr_v4(cidr, ip_be, prefix_len)) {
                    ++expected_cidr_v4;
                } else if (parse_cidr_v6(cidr, ipv6, prefix_len)) {
                    ++expected_cidr_v6;
                }
            }
            if (expected_cidr_v4 > 0 && state.deny_cidr_v4) {
                auto v = verify_map_entry_count(state.deny_cidr_v4, expected_cidr_v4);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (expected_cidr_v6 > 0 && state.deny_cidr_v6) {
                auto v = verify_map_entry_count(state.deny_cidr_v6, expected_cidr_v6);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
        }
    }

    {
        ScopedSpan span("policy.refresh_policy_empty_hints", root_span.trace_id(), root_span.span_id());
        auto hints_result = refresh_policy_empty_hints(state);
        if (!hints_result) {
            span.fail(hints_result.error().to_string());
            return fail(hints_result.error());
        }
    }

    {
        ScopedSpan span("policy.set_exec_identity_mode", root_span.trace_id(), root_span.span_id());
        size_t allow_exec_count = map_entry_count(state.allow_exec_inode);
        bool exec_identity_enabled = allow_exec_count > 0 || policy.protect_connect || !policy.protect_paths.empty();
        auto mode_result = set_exec_identity_mode(state, exec_identity_enabled);
	        if (!mode_result) {
	            span.fail(mode_result.error().to_string());
	            return fail(mode_result.error());
	        }
	        uint8_t exec_flags = 0;
	        if (allow_exec_count > 0) {
	            exec_flags |= kExecIdentityFlagAllowlistEnforce;
	        }
	        if (policy.protect_connect) {
	            exec_flags |= kExecIdentityFlagProtectConnect;
	        }
	        if (!policy.protect_paths.empty()) {
	            exec_flags |= kExecIdentityFlagProtectFiles;
	        }
	        auto flags_result = set_exec_identity_flags(state, exec_flags);
	        if (!flags_result) {
	            span.fail(flags_result.error().to_string());
	            return fail(flags_result.error());
        }
        logger().log(SLOG_INFO("Exec identity kernel mode updated")
                         .field("enabled", exec_identity_enabled)
                         .field("allow_exec_inode_entries", static_cast<int64_t>(allow_exec_count))
                         .field("exec_identity_flags", static_cast<int64_t>(exec_flags))
                         .field("protect_connect", policy.protect_connect)
                         .field("protect_paths", static_cast<int64_t>(policy.protect_paths.size())));
    }

    // Commit phase: persist state to disk atomically
    {
        ScopedSpan span("policy.write_deny_db", root_span.trace_id(), root_span.span_id());
        auto write_result = write_deny_db(entries);
        if (!write_result) {
            span.fail(write_result.error().to_string());
            return fail(write_result.error());
        }
    }

    if (record) {
        ScopedSpan span("policy.record_applied_policy", root_span.trace_id(), root_span.span_id());
        auto record_result = record_applied_policy(path, computed_hash);
        if (!record_result) {
            span.fail(record_result.error().to_string());
            return fail(record_result.error());
        }
    }
    return {};
}

static ApplyPolicyInternalFn g_apply_policy_internal_fn = apply_policy_internal_impl_fn;

Result<void> apply_policy_internal(const std::string& path, const std::string& computed_hash, bool reset, bool record)
{
    return g_apply_policy_internal_fn(path, computed_hash, reset, record);
}

void set_apply_policy_internal_for_test(ApplyPolicyInternalFn fn)
{
    g_apply_policy_internal_fn = fn ? fn : apply_policy_internal_impl_fn;
}

void reset_apply_policy_internal_for_test()
{
    g_apply_policy_internal_fn = apply_policy_internal_impl_fn;
}

Result<void> policy_apply(const std::string& path, bool reset, const std::string& cli_hash,
                          const std::string& cli_hash_file, bool rollback_on_failure,
                          const std::string& trace_id_override)
{
    std::string trace_id = trace_id_override;
    if (trace_id.empty()) {
        trace_id = make_span_id("trace-policy-apply");
    }
    PolicyTraceScope trace_scope(trace_id);
    ScopedSpan root_span("policy.apply", trace_id);
    auto fail = [&](const Error& err) -> Result<void> {
        root_span.fail(err.to_string());
        return err;
    };

    const std::string applied_path = policy_applied_path();

    std::string expected_hash = cli_hash;
    std::string hash_file = cli_hash_file;

    if (expected_hash.empty()) {
        const char* env = std::getenv("AEGIS_POLICY_SHA256");
        if (env && *env) {
            expected_hash = env;
        }
    }
    if (hash_file.empty()) {
        const char* env = std::getenv("AEGIS_POLICY_SHA256_FILE");
        if (env && *env) {
            hash_file = env;
        }
    }

    if (!expected_hash.empty() && !hash_file.empty()) {
        return fail(Error(ErrorCode::InvalidArgument, "Provide either --sha256 or --sha256-file (not both)"));
    }

    {
        ScopedSpan span("policy.validate_inputs", trace_id, root_span.span_id());
        auto policy_perms = validate_file_permissions(path, false);
        if (!policy_perms) {
            span.fail(policy_perms.error().to_string());
            return fail(policy_perms.error());
        }

        if (!hash_file.empty()) {
            auto hash_perms = validate_file_permissions(hash_file, false);
            if (!hash_perms) {
                span.fail(hash_perms.error().to_string());
                return fail(hash_perms.error());
            }
            if (!read_sha256_file(hash_file, expected_hash)) {
                Error err(ErrorCode::IoError, "Failed to read sha256 file", hash_file);
                span.fail(err.to_string());
                return fail(err);
            }
        }

        if (!expected_hash.empty()) {
            if (!parse_sha256_token(expected_hash, expected_hash)) {
                Error err(ErrorCode::InvalidArgument, "Invalid sha256 value format");
                span.fail(err.to_string());
                return fail(err);
            }
        }
    }

    std::string computed_hash;
    {
        ScopedSpan span("policy.integrity_check", trace_id, root_span.span_id());
        if (!expected_hash.empty()) {
            if (!verify_policy_hash(path, expected_hash, computed_hash)) {
                Error err(ErrorCode::PolicyHashMismatch, "Policy sha256 mismatch");
                span.fail(err.to_string());
                return fail(err);
            }
        } else if (!sha256_file_hex(path, computed_hash)) {
            logger().log(SLOG_WARN("Failed to compute policy sha256; continuing without hash"));
            computed_hash.clear();
        }
    }

    // Snapshot current deny entries in memory before applying, for rollback fallback
    DenyEntries pre_apply_snapshot = read_deny_db();

    Result<void> result;
    {
        ScopedSpan span("policy.apply_internal_call", trace_id, root_span.span_id());
        result = apply_policy_internal(path, computed_hash, reset, true);
        if (!result) {
            span.fail(result.error().to_string());
        }
    }

    if (!result && rollback_on_failure) {
        std::error_code ec;
        bool file_rollback_succeeded = false;

        if (std::filesystem::exists(applied_path, ec)) {
            // Verify integrity of the rollback policy file before replaying
            std::string rollback_hash;
            std::string stored_hash = read_file_first_line(policy_applied_hash_path());
            bool hash_ok = true;
            if (!stored_hash.empty()) {
                std::string actual_hash;
                if (sha256_file_hex(applied_path, actual_hash) && actual_hash == stored_hash) {
                    rollback_hash = stored_hash;
                } else {
                    logger().log(SLOG_WARN("Rollback policy hash mismatch; skipping file-based rollback")
                                     .field("stored_hash", stored_hash)
                                     .field("actual_hash", actual_hash));
                    hash_ok = false;
                }
            }

            if (hash_ok) {
                logger().log(SLOG_WARN("Apply failed; rolling back to last applied policy"));
                ScopedSpan span("policy.rollback_last_applied", trace_id, root_span.span_id());
                auto rollback_result = apply_policy_internal(applied_path, rollback_hash, true, false);
                if (rollback_result) {
                    file_rollback_succeeded = true;
                } else {
                    span.fail(rollback_result.error().to_string());
                    logger().log(SLOG_ERROR("File-based rollback failed; attempting in-memory snapshot restore")
                                     .field("error", rollback_result.error().to_string()));
                }
            }
        }

        // Fallback: restore from in-memory snapshot if file-based rollback failed
        if (!file_rollback_succeeded && !pre_apply_snapshot.empty()) {
            ScopedSpan span("policy.rollback_inmemory", trace_id, root_span.span_id());
            logger().log(SLOG_WARN("Restoring maps from in-memory snapshot")
                             .field("snapshot_entries", static_cast<int64_t>(pre_apply_snapshot.size())));
            BpfState rollback_state;
            auto load_result = load_bpf(true, false, rollback_state);
            if (load_result) {
                auto reset_result = reset_policy_maps(rollback_state);
                if (reset_result) {
                    bool snapshot_ok = true;
                    for (const auto& [inode_id, path_str] : pre_apply_snapshot) {
                        uint8_t one = 1;
                        if (bpf_map_update_elem(bpf_map__fd(rollback_state.deny_inode), &inode_id, &one, BPF_ANY)) {
                            snapshot_ok = false;
                            break;
                        }
                        if (!path_str.empty() && path_str.size() < kDenyPathMax) {
                            PathKey pk{};
                            fill_path_key(path_str, pk);
                            bpf_map_update_elem(bpf_map__fd(rollback_state.deny_path), &pk, &one, BPF_ANY);
                        }
                    }
                    if (snapshot_ok) {
                        auto db_result = write_deny_db(pre_apply_snapshot);
                        if (db_result) {
                            logger().log(SLOG_INFO("In-memory snapshot restore succeeded")
                                             .field("entries", static_cast<int64_t>(pre_apply_snapshot.size())));
                        } else {
                            logger().log(SLOG_ERROR("In-memory snapshot: deny.db write failed")
                                             .field("error", db_result.error().to_string()));
                        }
                    } else {
                        span.fail("In-memory snapshot restore failed: map update error");
                        logger().log(SLOG_ERROR("In-memory snapshot restore failed: map update error"));
                    }
                } else {
                    span.fail(reset_result.error().to_string());
                    logger().log(SLOG_ERROR("In-memory snapshot: map reset failed")
                                     .field("error", reset_result.error().to_string()));
                }
            } else {
                span.fail(load_result.error().to_string());
                logger().log(
                    SLOG_ERROR("In-memory snapshot: BPF load failed").field("error", load_result.error().to_string()));
            }
        }

        return fail(result.error());
    }

    if (!result) {
        return fail(result.error());
    }

    return result;
}

Result<void> write_policy_file(const std::string& path, std::vector<std::string> deny_paths,
                               std::vector<std::string> deny_inodes, std::vector<std::string> allow_cgroups)
{
    std::sort(deny_paths.begin(), deny_paths.end());
    deny_paths.erase(std::unique(deny_paths.begin(), deny_paths.end()), deny_paths.end());
    std::sort(deny_inodes.begin(), deny_inodes.end());
    deny_inodes.erase(std::unique(deny_inodes.begin(), deny_inodes.end()), deny_inodes.end());
    std::sort(allow_cgroups.begin(), allow_cgroups.end());
    allow_cgroups.erase(std::unique(allow_cgroups.begin(), allow_cgroups.end()), allow_cgroups.end());

    return atomic_write_stream(path, [&](std::ostream& out) -> bool {
        out << "version=1\n";
        if (!deny_paths.empty()) {
            out << "\n[deny_path]\n";
            for (const auto& p : deny_paths) {
                out << p << "\n";
            }
        }
        if (!deny_inodes.empty()) {
            out << "\n[deny_inode]\n";
            for (const auto& p : deny_inodes) {
                out << p << "\n";
            }
        }
        if (!allow_cgroups.empty()) {
            out << "\n[allow_cgroup]\n";
            for (const auto& p : allow_cgroups) {
                out << p << "\n";
            }
        }
        return out.good();
    });
}

Result<void> policy_export(const std::string& path)
{
    TRY(bump_memlock_rlimit());

    BpfState state;
    TRY(load_bpf(true, false, state));

    auto db = read_deny_db();
    std::vector<std::string> deny_paths;
    std::vector<std::string> deny_inodes;
    for (const auto& kv : db) {
        if (!kv.second.empty()) {
            deny_paths.push_back(kv.second);
        } else {
            deny_inodes.push_back(inode_to_string(kv.first));
        }
    }

    auto allow_ids_result = read_allow_cgroup_ids(state.allow_cgroup);
    if (!allow_ids_result) {
        return allow_ids_result.error();
    }

    std::vector<std::string> allow_entries;
    for (uint64_t id : *allow_ids_result) {
        std::string cgpath = resolve_cgroup_path(id);
        if (!cgpath.empty()) {
            allow_entries.push_back(cgpath);
        } else {
            allow_entries.push_back("cgid:" + std::to_string(id));
        }
    }

    return write_policy_file(path, deny_paths, deny_inodes, allow_entries);
}

Result<void> policy_show()
{
    const std::string applied_path = policy_applied_path();
    const std::string applied_hash_path = policy_applied_hash_path();

    std::ifstream in(applied_path);
    if (!in.is_open()) {
        return Error(ErrorCode::ResourceNotFound, "No applied policy found", applied_path);
    }
    std::string hash = read_file_first_line(applied_hash_path);
    if (!hash.empty()) {
        std::cout << "# applied_sha256: " << hash << "\n";
    }
    std::cout << in.rdbuf();
    return {};
}

Result<void> policy_rollback()
{
    const std::string applied_prev_path = policy_applied_prev_path();

    if (!std::filesystem::exists(applied_prev_path)) {
        return Error(ErrorCode::ResourceNotFound, "No rollback policy found", applied_prev_path);
    }
    std::string computed_hash;
    sha256_file_hex(applied_prev_path, computed_hash);
    return apply_policy_internal(applied_prev_path, computed_hash, true, true);
}

} // namespace aegis
