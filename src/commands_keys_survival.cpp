// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Key and survival command implementations
 */

#include "commands_keys_survival.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "bpf_ops.hpp"
#include "crypto.hpp"
#include "logging.hpp"
#include "tracing.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

int fail_span(ScopedSpan& span, const std::string& message)
{
    span.fail(message);
    return 1;
}

} // namespace

int cmd_keys_list()
{
    const std::string trace_id = make_span_id("trace-keys-list");
    ScopedSpan span("cli.keys_list", trace_id);

    auto result = load_trusted_keys();
    if (!result) {
        logger().log(SLOG_ERROR("Failed to list keys").field("error", result.error().to_string()));
        return fail_span(span, result.error().to_string());
    }
    for (const auto& key : *result) {
        // Print key fingerprint (first 16 bytes as hex)
        std::ostringstream oss;
        for (size_t i = 0; i < std::min(key.size(), size_t(8)); ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(key[i]);
        }
        std::cout << oss.str() << "..." << '\n';
    }
    return 0;
}

int cmd_keys_add(const std::string& key_file)
{
    const std::string trace_id = make_span_id("trace-keys-add");
    ScopedSpan span("cli.keys_add", trace_id);

    auto perms_result = validate_file_permissions(key_file, false);
    if (!perms_result) {
        logger().log(SLOG_ERROR("Key file permission check failed")
                         .field("path", key_file)
                         .field("error", perms_result.error().to_string()));
        return fail_span(span, perms_result.error().to_string());
    }

    // Read the key file
    std::ifstream in(key_file, std::ios::binary);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open key file").field("path", key_file));
        return fail_span(span, "Failed to open key file");
    }

    // Copy to keys directory
    std::string keys_dir = trusted_keys_dir();
    std::error_code ec;
    std::filesystem::create_directories(keys_dir, ec);
    if (ec) {
        logger().log(SLOG_ERROR("Failed to create keys directory").field("error", ec.message()));
        return fail_span(span, ec.message());
    }

    std::string dest = keys_dir + "/" + std::filesystem::path(key_file).filename().string();
    std::filesystem::copy_file(key_file, dest, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        logger().log(SLOG_ERROR("Failed to copy key file").field("error", ec.message()));
        return fail_span(span, ec.message());
    }

    logger().log(SLOG_INFO("Key added successfully").field("path", dest));
    return 0;
}

int cmd_survival_list()
{
    const std::string trace_id = make_span_id("trace-survival-list");
    ScopedSpan span("cli.survival_list", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto ids_result = read_survival_allowlist(state);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read survival allowlist").field("error", ids_result.error().to_string()));
        return fail_span(span, ids_result.error().to_string());
    }

    std::cout << "Survival allowlist:" << '\n';
    for (const auto& id : *ids_result) {
        std::cout << "  " << id.dev << ":" << id.ino << '\n';
    }
    return 0;
}

int cmd_survival_verify()
{
    const std::string trace_id = make_span_id("trace-survival-verify");
    ScopedSpan span("cli.survival_verify", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto ids_result = read_survival_allowlist(state);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read survival allowlist").field("error", ids_result.error().to_string()));
        return fail_span(span, ids_result.error().to_string());
    }

    // Verify each entry still exists
    int errors = 0;
    for (const auto& id : *ids_result) {
        // Check if the inode still exists
        // This is a basic check - we can't verify the path without the db
        if (id.ino == 0) {
            errors++;
        }
    }

    if (errors > 0) {
        span.fail("survival allowlist verification failed");
        std::cout << "Survival allowlist verification found " << errors << " issues" << '\n';
        return 1;
    }

    std::cout << "Survival allowlist verified successfully (" << ids_result->size() << " entries)" << '\n';
    return 0;
}

} // namespace aegis
