// cppcheck-suppress-file missingIncludeSystem
#include "policy_parse.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <unordered_set>

#include "logging.hpp"
#include "network_ops.hpp"
#include "utils.hpp"

namespace aegis {

void report_policy_issues(const PolicyIssues& issues)
{
    for (const auto& err : issues.errors) {
        logger().log(SLOG_ERROR("Policy error").field("detail", err));
    }
    for (const auto& warn : issues.warnings) {
        logger().log(SLOG_WARN("Policy warning").field("detail", warn));
    }
}

namespace {

bool parse_port_rule(const std::string& str, PortRule& rule)
{
    rule = {};
    rule.direction = 2;

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

std::string canonical_ip_port_rule_key(const IpPortRule& rule)
{
    return rule.ip + "|" + std::to_string(rule.port) + "|" + std::to_string(rule.protocol);
}

} // namespace

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
    std::unordered_set<std::string> deny_ip_port_seen;
    std::string line;
    size_t line_no = 0;

    std::unordered_set<std::string> deny_hash_seen;
    std::unordered_set<std::string> allow_hash_seen;

    static const std::unordered_set<std::string> valid_sections = {"deny_path",
                                                                   "deny_inode",
                                                                   "protect_path",
                                                                   "protect_connect",
                                                                   "protect_runtime_deps",
                                                                   "require_ima_appraisal",
                                                                   "allow_cgroup",
                                                                   "deny_ip",
                                                                   "deny_cidr",
                                                                   "deny_port",
                                                                   "deny_ip_port",
                                                                   "deny_binary_hash",
                                                                   "allow_binary_hash",
                                                                   "scan_paths"};

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
            if (section == "protect_runtime_deps") {
                policy.protect_runtime_deps = true;
            }
            if (section == "require_ima_appraisal") {
                policy.require_ima_appraisal = true;
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
            issues.warnings.push_back("line " + std::to_string(line_no) +
                                      ": [protect_connect] does not take entries; ignoring '" + trimmed + "'");
            continue;
        }

        if (section == "protect_runtime_deps") {
            issues.warnings.push_back("line " + std::to_string(line_no) +
                                      ": [protect_runtime_deps] does not take entries; ignoring '" + trimmed + "'");
            continue;
        }

        if (section == "require_ima_appraisal") {
            issues.warnings.push_back("line " + std::to_string(line_no) +
                                      ": [require_ima_appraisal] does not take entries; ignoring '" + trimmed + "'");
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

        if (section == "deny_ip_port") {
            auto rule_result = parse_ip_port_rule(trimmed);
            if (!rule_result) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": invalid IP:port rule '" + trimmed + "'");
                continue;
            }
            std::string key = canonical_ip_port_rule_key(*rule_result);
            if (deny_ip_port_seen.insert(key).second) {
                policy.network.deny_ip_ports.push_back(*rule_result);
                policy.network.enabled = true;
            }
            continue;
        }

        if (section == "deny_binary_hash") {
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
            std::transform(hash.begin(), hash.end(), hash.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (deny_hash_seen.insert(hash).second) {
                policy.deny_binary_hashes.push_back(hash);
            }
            continue;
        }

        if (section == "allow_binary_hash") {
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
    if (policy.version < 1 || policy.version > 5) {
        issues.errors.push_back("unsupported policy version: " + std::to_string(policy.version));
    }

    if (!policy.deny_binary_hashes.empty() && policy.version < 3) {
        issues.errors.push_back("[deny_binary_hash] requires version=3 or higher");
    }
    if (!policy.allow_binary_hashes.empty() && policy.version < 3) {
        issues.errors.push_back("[allow_binary_hash] requires version=3 or higher");
    }

    if ((!policy.protect_paths.empty() || policy.protect_connect || policy.protect_runtime_deps) &&
        policy.version < 4) {
        issues.errors.push_back("[protect_path]/[protect_connect]/[protect_runtime_deps] requires version=4 or higher");
    }

    if (policy.require_ima_appraisal && policy.version < 5) {
        issues.errors.push_back("[require_ima_appraisal] requires version=5 or higher");
    }

    if (policy.protect_runtime_deps && !policy.protect_connect && policy.protect_paths.empty()) {
        issues.errors.push_back("[protect_runtime_deps] requires [protect_connect] or [protect_path]");
    }

    if (!issues.errors.empty()) {
        return Error(ErrorCode::PolicyParseFailed, "Policy parsing failed with errors");
    }
    return policy;
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

} // namespace aegis
