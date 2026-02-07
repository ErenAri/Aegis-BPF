// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Policy command implementations
 */

#include "commands_policy.hpp"

#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

#include "crypto.hpp"
#include "logging.hpp"
#include "policy.hpp"
#include "tracing.hpp"
#include "utils.hpp"

namespace aegis {

int cmd_policy_lint(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-policy-lint");
    ScopedSpan span("cli.policy_lint", trace_id);
    auto result = policy_lint(path);
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_lint_fix(const std::string& path, const std::string& out_path)
{
    const std::string trace_id = make_span_id("trace-policy-lint-fix");
    ScopedSpan span("cli.policy_lint_fix", trace_id);

    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        span.fail(result.error().to_string());
        return 1;
    }
    if (issues.has_errors()) {
        span.fail("Policy contains errors");
        return 1;
    }

    const Policy& policy = *result;
    std::vector<std::string> deny_inodes;
    deny_inodes.reserve(policy.deny_inodes.size());
    for (const auto& id : policy.deny_inodes) {
        deny_inodes.push_back(inode_to_string(id));
    }

    std::vector<std::string> allow_entries = policy.allow_cgroup_paths;
    allow_entries.reserve(policy.allow_cgroup_paths.size() + policy.allow_cgroup_ids.size());
    for (uint64_t id : policy.allow_cgroup_ids) {
        allow_entries.push_back("cgid:" + std::to_string(id));
    }

    std::string target = out_path.empty() ? (path + ".fixed") : out_path;
    auto write_result = write_policy_file(target, policy.deny_paths, deny_inodes, allow_entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write normalized policy")
                         .field("path", target)
                         .field("error", write_result.error().to_string()));
        span.fail(write_result.error().to_string());
        return 1;
    }

    std::cout << "Wrote normalized policy to " << target << "\n";
    return 0;
}

int cmd_policy_validate(const std::string& path, bool verbose)
{
    const std::string trace_id = make_span_id("trace-policy-validate");
    ScopedSpan span("cli.policy_validate", trace_id);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        logger().log(SLOG_ERROR("Policy validation failed").field("error", result.error().to_string()));
        span.fail(result.error().to_string());
        return 1;
    }
    const Policy& policy = *result;

    std::cout << "Policy validation successful.\n\n";
    std::cout << "Summary:\n";
    std::cout << "  Deny paths: " << policy.deny_paths.size() << "\n";
    std::cout << "  Deny inodes: " << policy.deny_inodes.size() << "\n";
    std::cout << "  Allow cgroup IDs: " << policy.allow_cgroup_ids.size() << "\n";
    std::cout << "  Allow cgroup paths: " << policy.allow_cgroup_paths.size() << "\n";

    if (policy.network.enabled) {
        std::cout << "  Network deny IPs: " << policy.network.deny_ips.size() << "\n";
        std::cout << "  Network deny CIDRs: " << policy.network.deny_cidrs.size() << "\n";
        std::cout << "  Network deny ports: " << policy.network.deny_ports.size() << "\n";
    }

    if (verbose) {
        if (!policy.deny_paths.empty()) {
            std::cout << "\nDeny paths:\n";
            for (const auto& p : policy.deny_paths) {
                std::cout << "  - " << p << "\n";
            }
        }
        if (!policy.deny_inodes.empty()) {
            std::cout << "\nDeny inodes:\n";
            for (const auto& id : policy.deny_inodes) {
                std::cout << "  - " << id.dev << ":" << id.ino << "\n";
            }
        }
        if (!policy.allow_cgroup_paths.empty()) {
            std::cout << "\nAllow cgroup paths:\n";
            for (const auto& p : policy.allow_cgroup_paths) {
                std::cout << "  - " << p << "\n";
            }
        }
        if (policy.network.enabled) {
            if (!policy.network.deny_ips.empty()) {
                std::cout << "\nNetwork deny IPs:\n";
                for (const auto& ip : policy.network.deny_ips) {
                    std::cout << "  - " << ip << "\n";
                }
            }
            if (!policy.network.deny_cidrs.empty()) {
                std::cout << "\nNetwork deny CIDRs:\n";
                for (const auto& cidr : policy.network.deny_cidrs) {
                    std::cout << "  - " << cidr << "\n";
                }
            }
            if (!policy.network.deny_ports.empty()) {
                std::cout << "\nNetwork deny ports:\n";
                for (const auto& pr : policy.network.deny_ports) {
                    std::string proto = (pr.protocol == 6) ? "tcp" : (pr.protocol == 17) ? "udp" : "any";
                    std::string dir = (pr.direction == 0) ? "egress" : (pr.direction == 1) ? "bind" : "both";
                    std::cout << "  - port " << pr.port << " (" << proto << ", " << dir << ")\n";
                }
            }
        }
    }

    if (!issues.warnings.empty()) {
        std::cout << "\nWarnings: " << issues.warnings.size() << "\n";
    }

    return 0;
}

int cmd_policy_apply(const std::string& path, bool reset, const std::string& sha256, const std::string& sha256_file,
                     bool rollback_on_failure)
{
    const std::string trace_id = make_span_id("trace-policy-cli");
    ScopedSpan span("cli.policy_apply", trace_id);
    auto result = policy_apply(path, reset, sha256, sha256_file, rollback_on_failure, trace_id);
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_apply_signed(const std::string& bundle_path, bool require_signature)
{
    const std::string trace_id = make_span_id("trace-policy-signed");
    ScopedSpan root_span("cli.policy_apply_signed", trace_id);
    auto fail = [&](const std::string& message) -> int {
        root_span.fail(message);
        return 1;
    };

    auto perms_result = validate_file_permissions(bundle_path, false);
    if (!perms_result) {
        logger().log(SLOG_ERROR("Policy file permission check failed")
                         .field("path", bundle_path)
                         .field("error", perms_result.error().to_string()));
        return fail(perms_result.error().to_string());
    }

    std::ifstream in(bundle_path);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open bundle file").field("path", bundle_path));
        return fail("Failed to open bundle file");
    }

    std::stringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    if (content.starts_with("AEGIS-POLICY-BUNDLE")) {
        auto bundle_result = parse_signed_bundle(content);
        if (!bundle_result) {
            logger().log(SLOG_ERROR("Failed to parse signed bundle").field("error", bundle_result.error().to_string()));
            return fail(bundle_result.error().to_string());
        }
        SignedPolicyBundle bundle = *bundle_result;

        auto keys_result = load_trusted_keys();
        if (!keys_result) {
            logger().log(SLOG_ERROR("Failed to load trusted keys").field("error", keys_result.error().to_string()));
            return fail(keys_result.error().to_string());
        }
        const auto& trusted_keys = *keys_result;
        if (trusted_keys.empty()) {
            logger().log(SLOG_ERROR("No trusted keys configured - cannot verify signed policy"));
            return fail("No trusted keys configured - cannot verify signed policy");
        }

        auto verify_result = verify_bundle(bundle, trusted_keys);
        if (!verify_result) {
            logger().log(SLOG_ERROR("Bundle verification failed").field("error", verify_result.error().to_string()));
            return fail(verify_result.error().to_string());
        }

        if (!check_version_acceptable(bundle)) {
            logger().log(SLOG_ERROR("Policy version rollback rejected")
                             .field("bundle_version", static_cast<int64_t>(bundle.policy_version))
                             .field("current_version", static_cast<int64_t>(read_version_counter())));
            return fail("Policy version rollback rejected");
        }

        std::string temp_path = "/tmp/aegisbpf_policy_" + std::to_string(getpid()) + ".conf";
        {
            std::ofstream temp_out(temp_path);
            if (!temp_out.is_open()) {
                logger().log(SLOG_ERROR("Failed to create temp policy file").field("path", temp_path));
                return fail("Failed to create temp policy file");
            }
            temp_out << bundle.policy_content;
        }

        auto apply_result = policy_apply(temp_path, false, bundle.policy_sha256, "", true, trace_id);
        std::remove(temp_path.c_str());
        if (!apply_result) {
            return fail(apply_result.error().to_string());
        }

        auto write_result = write_version_counter(bundle.policy_version);
        if (!write_result) {
            logger().log(
                SLOG_WARN("Failed to update version counter").field("error", write_result.error().to_string()));
        }

        return 0;
    }

    if (require_signature) {
        logger().log(SLOG_ERROR("Unsigned policy rejected (--require-signature specified)"));
        return fail("Unsigned policy rejected (--require-signature specified)");
    }

    auto apply_result = policy_apply(bundle_path, false, "", "", true, trace_id);
    if (!apply_result) {
        return fail(apply_result.error().to_string());
    }
    return 0;
}

int cmd_policy_sign(const std::string& policy_path, const std::string& key_path, const std::string& output_path)
{
    const std::string trace_id = make_span_id("trace-policy-sign");
    ScopedSpan span("cli.policy_sign", trace_id);
    auto fail = [&](const std::string& message) -> int {
        span.fail(message);
        return 1;
    };

    auto policy_perms = validate_file_permissions(policy_path, false);
    if (!policy_perms) {
        logger().log(SLOG_ERROR("Policy file permission check failed")
                         .field("path", policy_path)
                         .field("error", policy_perms.error().to_string()));
        return fail(policy_perms.error().to_string());
    }
    auto key_perms = validate_file_permissions(key_path, false);
    if (!key_perms) {
        logger().log(SLOG_ERROR("Signing key permission check failed")
                         .field("path", key_path)
                         .field("error", key_perms.error().to_string()));
        return fail(key_perms.error().to_string());
    }

    std::ifstream policy_in(policy_path);
    if (!policy_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open policy file").field("path", policy_path));
        return fail("Failed to open policy file");
    }
    std::stringstream policy_ss;
    policy_ss << policy_in.rdbuf();
    std::string policy_content = policy_ss.str();

    std::ifstream key_in(key_path);
    if (!key_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open private key file").field("path", key_path));
        return fail("Failed to open private key file");
    }
    std::string key_hex;
    std::getline(key_in, key_hex);

    if (key_hex.size() != 128) {
        logger().log(SLOG_ERROR("Invalid private key format (expected 128 hex chars)"));
        return fail("Invalid private key format");
    }

    auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };

    SecretKey secret_key{};
    for (size_t i = 0; i < secret_key.size(); ++i) {
        int hi = hex_value(key_hex[2 * i]);
        int lo = hex_value(key_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            logger().log(SLOG_ERROR("Invalid private key format (non-hex character)"));
            return fail("Invalid private key format");
        }
        secret_key[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    uint64_t version = read_version_counter() + 1;
    auto bundle_result = create_signed_bundle(policy_content, secret_key, version, 0);
    if (!bundle_result) {
        logger().log(SLOG_ERROR("Failed to create signed bundle").field("error", bundle_result.error().to_string()));
        return fail(bundle_result.error().to_string());
    }

    std::ofstream out(output_path);
    if (!out.is_open()) {
        logger().log(SLOG_ERROR("Failed to create output file").field("path", output_path));
        return fail("Failed to create output file");
    }

    out << *bundle_result;
    logger().log(SLOG_INFO("Policy signed successfully")
                     .field("output", output_path)
                     .field("version", static_cast<int64_t>(version)));
    return 0;
}

int cmd_policy_export(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-policy-export");
    ScopedSpan span("cli.policy_export", trace_id);
    auto result = policy_export(path);
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_show()
{
    const std::string trace_id = make_span_id("trace-policy-show");
    ScopedSpan span("cli.policy_show", trace_id);
    auto result = policy_show();
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_rollback()
{
    const std::string trace_id = make_span_id("trace-policy-rollback");
    ScopedSpan span("cli.policy_rollback", trace_id);
    auto result = policy_rollback();
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

} // namespace aegis
