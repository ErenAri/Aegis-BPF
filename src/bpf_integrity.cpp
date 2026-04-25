// cppcheck-suppress-file missingIncludeSystem
#include "bpf_integrity.hpp"

#include <limits.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "bpf_signing.hpp"
#include "logging.hpp"
#include "sha256.hpp"
#include "utils.hpp"

#ifndef AEGIS_BPF_OBJ_PATH
#    define AEGIS_BPF_OBJ_PATH ""
#endif

namespace aegis {

namespace {

constexpr const char* kBpfObjPath = AEGIS_BPF_OBJ_PATH;

std::string env_path_or_default(const char* env_name, const char* fallback)
{
    const char* value = std::getenv(env_name);
    if (value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::string(fallback);
}

bool env_flag_enabled(const char* env_name)
{
    const char* value = std::getenv(env_name);
    if (value == nullptr || *value == '\0') {
        return false;
    }

    std::string normalized(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

std::string configured_hash_paths_text()
{
    const std::string primary = env_path_or_default("AEGIS_BPF_OBJ_HASH_PATH", kBpfObjHashPath);
    const std::string secondary = env_path_or_default("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", kBpfObjHashInstallPath);
    return primary + ", " + secondary;
}

std::string adjacent_hash_path_for_object(const std::string& object_path)
{
    if (object_path.empty()) {
        return {};
    }
    std::filesystem::path obj(object_path);
    std::filesystem::path parent = obj.has_parent_path() ? obj.parent_path() : std::filesystem::path(".");
    return (parent / "aegis.bpf.sha256").string();
}

} // namespace

std::string resolve_bpf_obj_path()
{
    const char* env = std::getenv("AEGIS_BPF_OBJ");
    if (env && *env) {
        return std::string(env);
    }

    auto exe_in_system_prefix = []() -> bool {
        char buf[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len <= 0) {
            return false;
        }
        buf[len] = '\0';
        std::string exe(buf);
        return exe.rfind("/usr/", 0) == 0 || exe.rfind("/usr/local/", 0) == 0;
    };

    std::error_code ec;
    if (exe_in_system_prefix()) {
        if (std::filesystem::exists(kBpfObjInstallPath, ec)) {
            return kBpfObjInstallPath;
        }
        if (std::filesystem::exists(kBpfObjPath, ec)) {
            return kBpfObjPath;
        }
    } else {
        if (std::filesystem::exists(kBpfObjPath, ec)) {
            return kBpfObjPath;
        }
        if (std::filesystem::exists(kBpfObjInstallPath, ec)) {
            return kBpfObjInstallPath;
        }
    }
    return kBpfObjPath;
}

bool allow_unsigned_bpf_enabled()
{
    return env_flag_enabled("AEGIS_ALLOW_UNSIGNED_BPF");
}

bool require_bpf_hash_enabled()
{
    return env_flag_enabled("AEGIS_REQUIRE_BPF_HASH");
}

bool require_bpf_sig_enabled()
{
    return env_flag_enabled("AEGIS_REQUIRE_BPF_SIG");
}

Result<BpfIntegrityStatus> evaluate_bpf_integrity(bool require_hash, bool allow_unsigned)
{
    BpfIntegrityStatus status{};
    status.require_hash = require_hash;
    status.allow_unsigned = allow_unsigned;
    status.object_path = resolve_bpf_obj_path();

    std::error_code ec;
    status.object_exists = std::filesystem::exists(status.object_path, ec);
    if (!status.object_exists) {
        return Error(ErrorCode::ResourceNotFound, "BPF object file not found", status.object_path);
    }

    const std::string hash_path_primary = env_path_or_default("AEGIS_BPF_OBJ_HASH_PATH", kBpfObjHashPath);
    const std::string hash_path_secondary =
        env_path_or_default("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", kBpfObjHashInstallPath);
    const std::string hash_path_adjacent = adjacent_hash_path_for_object(status.object_path);

    if (std::filesystem::exists(hash_path_primary, ec)) {
        status.hash_path = hash_path_primary;
        status.hash_exists = true;
    } else if (std::filesystem::exists(hash_path_secondary, ec)) {
        status.hash_path = hash_path_secondary;
        status.hash_exists = true;
    } else if (!hash_path_adjacent.empty() && std::filesystem::exists(hash_path_adjacent, ec)) {
        status.hash_path = hash_path_adjacent;
        status.hash_exists = true;
    }

    if (!status.hash_exists) {
        status.reason = "bpf_hash_missing";
        if (require_hash && !allow_unsigned) {
            return Error(ErrorCode::BpfLoadFailed, "BPF object hash file is required but not found",
                         configured_hash_paths_text());
        }
        return status;
    }

    std::string expected_hash;
    if (!read_sha256_file(status.hash_path, expected_hash)) {
        return Error(ErrorCode::InvalidArgument, "Failed to read BPF hash file", status.hash_path);
    }

    std::string actual_hash;
    if (!sha256_file_hex(status.object_path, actual_hash)) {
        return Error(ErrorCode::IoError, "Failed to compute hash of BPF object", status.object_path);
    }

    if (!constant_time_hex_compare(expected_hash, actual_hash)) {
        status.reason = "bpf_hash_mismatch";
        if (!allow_unsigned) {
            return Error(ErrorCode::BpfLoadFailed,
                         "BPF object integrity verification failed - file may have been tampered with",
                         "expected=" + expected_hash + " actual=" + actual_hash);
        }
        return status;
    }

    status.hash_verified = true;
    return status;
}

Result<void> verify_bpf_integrity(const std::string& obj_path)
{
#ifndef NDEBUG
    const char* skip_verify = std::getenv("AEGIS_SKIP_BPF_VERIFY");
    if (skip_verify && std::string(skip_verify) == "1") {
        logger().log(SLOG_WARN("BPF verification disabled via AEGIS_SKIP_BPF_VERIFY (DEBUG BUILD ONLY)"));
        return {};
    }
#endif

    const bool allow_unsigned = allow_unsigned_bpf_enabled();
    const bool require_hash = require_bpf_hash_enabled();

    auto integrity_result = evaluate_bpf_integrity(require_hash, allow_unsigned);
    if (!integrity_result) {
        return integrity_result.error();
    }
    const auto& status = *integrity_result;

    if (status.reason == "bpf_hash_missing") {
        std::string checked_paths = configured_hash_paths_text();
        const std::string adjacent_hash = adjacent_hash_path_for_object(obj_path);
        if (!adjacent_hash.empty()) {
            checked_paths += ", " + adjacent_hash;
        }
        logger().log(SLOG_WARN("BPF object hash file not found")
                         .field("checked", checked_paths)
                         .field("require_hash", require_hash)
                         .field("allow_unsigned_bpf", allow_unsigned));
        return {};
    }

    if (status.reason == "bpf_hash_mismatch") {
        logger().log(SLOG_WARN("BPF object hash mismatch accepted by break-glass")
                         .field("path", obj_path)
                         .field("allow_unsigned_bpf", allow_unsigned));
        return {};
    }

    logger().log(
        SLOG_INFO("BPF object integrity verified").field("path", obj_path).field("hash_path", status.hash_path));

    // Hash verified. Now run the optional Ed25519 signature check. The
    // helper is no-op if no .sig file exists and AEGIS_REQUIRE_BPF_SIG is
    // not set, which preserves backward compatibility for hash-only
    // deployments.
    auto sig_result = verify_bpf_signature(obj_path);
    if (!sig_result) {
        if (allow_unsigned) {
            logger().log(SLOG_WARN("BPF signature verification failed, allowed by break-glass")
                             .field("path", obj_path)
                             .field("error", sig_result.error().to_string()));
            return {};
        }
        return sig_result.error();
    }
    return {};
}

} // namespace aegis
