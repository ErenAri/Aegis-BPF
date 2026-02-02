#include "policy.hpp"
#include "bpf_ops.hpp"
#include "logging.hpp"
#include "sha256.hpp"
#include "utils.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <unordered_set>

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
    std::unordered_set<std::string> allow_path_seen;
    std::unordered_set<uint64_t> allow_id_seen;
    std::string line;
    size_t line_no = 0;

    while (std::getline(in, line)) {
        ++line_no;
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trim(trimmed.substr(1, trimmed.size() - 2));
            if (section != "deny_path" && section != "deny_inode" && section != "allow_cgroup") {
                issues.errors.push_back("line " + std::to_string(line_no) + ": unknown section '" + section + "'");
                section.clear();
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
            }
            else {
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
    }

    if (policy.version == 0) {
        issues.errors.push_back("missing header key: version");
    }
    if (policy.version != 1) {
        issues.errors.push_back("unsupported policy version: " + std::to_string(policy.version));
    }

    if (!issues.errors.empty()) {
        return Error(ErrorCode::PolicyParseFailed, "Policy parsing failed with errors");
    }
    return policy;
}

Result<void> record_applied_policy(const std::string& path, const std::string& hash)
{
    auto db_result = ensure_db_dir();
    if (!db_result) {
        return db_result.error();
    }

    std::error_code ec;
    if (std::filesystem::exists(kPolicyAppliedPath, ec)) {
        std::filesystem::copy_file(
            kPolicyAppliedPath, kPolicyAppliedPrevPath,
            std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to backup applied policy", ec.message());
        }
    }

    std::ifstream in(path);
    if (!in.is_open()) {
        return Error::system(errno, "Failed to open policy file for recording");
    }
    std::ofstream out(kPolicyAppliedPath, std::ios::trunc);
    if (!out.is_open()) {
        return Error::system(errno, "Failed to open applied policy file for writing");
    }
    out << in.rdbuf();
    if (!out.good()) {
        return Error(ErrorCode::IoError, "Failed to write applied policy file");
    }

    if (!hash.empty()) {
        std::ofstream hout(kPolicyAppliedHashPath, std::ios::trunc);
        if (!hout.is_open()) {
            return Error::system(errno, "Failed to open policy hash file for writing");
        }
        hout << hash << "\n";
    }
    else {
        std::error_code rm_ec;
        std::filesystem::remove(kPolicyAppliedHashPath, rm_ec);
        if (rm_ec) {
            return Error(ErrorCode::IoError, "Failed to remove policy hash file", rm_ec.message());
        }
    }
    return {};
}

Result<void> reset_policy_maps(BpfState& state)
{
    TRY(clear_map_entries(state.deny_inode));
    TRY(clear_map_entries(state.deny_path));
    TRY(clear_map_entries(state.allow_cgroup));
    TRY(clear_map_entries(state.deny_cgroup_stats));
    TRY(clear_map_entries(state.deny_inode_stats));
    TRY(clear_map_entries(state.deny_path_stats));

    if (state.block_stats) {
        TRY(reset_block_stats_map(state.block_stats));
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

Result<void> apply_policy_internal(const std::string& path, const std::string& computed_hash, bool reset, bool record)
{
    PolicyIssues issues;
    auto policy_result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!policy_result) {
        return policy_result.error();
    }
    Policy policy = *policy_result;

    TRY(bump_memlock_rlimit());

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        return load_result.error();
    }

    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        return version_result.error();
    }

    if (reset) {
        auto reset_result = reset_policy_maps(state);
        if (!reset_result) {
            return reset_result.error();
        }
    }

    DenyEntries entries = reset ? DenyEntries{} : read_deny_db();

    for (const auto& deny_path : policy.deny_paths) {
        auto result = add_deny_path(state, deny_path, entries);
        if (!result) {
            return result.error();
        }
    }
    for (const auto& id : policy.deny_inodes) {
        auto result = add_deny_inode(state, id, entries);
        if (!result) {
            return result.error();
        }
    }
    for (const auto& cgid : policy.allow_cgroup_ids) {
        auto result = add_allow_cgroup(state, cgid);
        if (!result) {
            return result.error();
        }
    }
    for (const auto& cgpath : policy.allow_cgroup_paths) {
        auto result = add_allow_cgroup_path(state, cgpath);
        if (!result) {
            return result.error();
        }
    }

    auto write_result = write_deny_db(entries);
    if (!write_result) {
        return write_result.error();
    }

    if (record) {
        auto record_result = record_applied_policy(path, computed_hash);
        if (!record_result) {
            return record_result.error();
        }
    }
    return {};
}

Result<void> policy_apply(const std::string& path, bool reset, const std::string& cli_hash,
                          const std::string& cli_hash_file, bool rollback_on_failure)
{
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
        return Error(ErrorCode::InvalidArgument, "Provide either --sha256 or --sha256-file (not both)");
    }

    if (!hash_file.empty()) {
        if (!read_sha256_file(hash_file, expected_hash)) {
            return Error(ErrorCode::IoError, "Failed to read sha256 file", hash_file);
        }
    }

    if (!expected_hash.empty()) {
        if (!parse_sha256_token(expected_hash, expected_hash)) {
            return Error(ErrorCode::InvalidArgument, "Invalid sha256 value format");
        }
    }

    std::string computed_hash;
    if (!expected_hash.empty()) {
        if (!verify_policy_hash(path, expected_hash, computed_hash)) {
            return Error(ErrorCode::PolicyHashMismatch, "Policy sha256 mismatch");
        }
    }
    else if (!sha256_file_hex(path, computed_hash)) {
        logger().log(SLOG_WARN("Failed to compute policy sha256; continuing without hash"));
        computed_hash.clear();
    }

    auto result = apply_policy_internal(path, computed_hash, reset, true);
    if (!result && rollback_on_failure) {
        std::error_code ec;
        if (std::filesystem::exists(kPolicyAppliedPath, ec)) {
            logger().log(SLOG_WARN("Apply failed; rolling back to last applied policy"));
            auto rollback_result = apply_policy_internal(kPolicyAppliedPath, std::string(), true, false);
            if (!rollback_result) {
                logger().log(SLOG_ERROR("Rollback failed; maps may be inconsistent")
                                 .field("error", rollback_result.error().to_string()));
            }
        }
        return result.error();
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

    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) {
        return Error(ErrorCode::IoError, "Failed to write policy file", path);
    }
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
    return {};
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
        }
        else {
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
        }
        else {
            allow_entries.push_back("cgid:" + std::to_string(id));
        }
    }

    return write_policy_file(path, deny_paths, deny_inodes, allow_entries);
}

Result<void> policy_show()
{
    std::ifstream in(kPolicyAppliedPath);
    if (!in.is_open()) {
        return Error(ErrorCode::ResourceNotFound, "No applied policy found", kPolicyAppliedPath);
    }
    std::string hash = read_file_first_line(kPolicyAppliedHashPath);
    if (!hash.empty()) {
        std::cout << "# applied_sha256: " << hash << "\n";
    }
    std::cout << in.rdbuf();
    return {};
}

Result<void> policy_rollback()
{
    if (!std::filesystem::exists(kPolicyAppliedPrevPath)) {
        return Error(ErrorCode::ResourceNotFound, "No rollback policy found", kPolicyAppliedPrevPath);
    }
    std::string computed_hash;
    sha256_file_hex(kPolicyAppliedPrevPath, computed_hash);
    return apply_policy_internal(kPolicyAppliedPrevPath, computed_hash, true, true);
}

}  // namespace aegis
