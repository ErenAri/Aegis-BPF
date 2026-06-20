// cppcheck-suppress-file missingIncludeSystem
#include "binary_hash.hpp"

#include <sys/stat.h>

#include <cerrno>
#include <filesystem>

#include "logging.hpp"
#include "sha256.hpp"

namespace aegis {

Result<std::string> compute_binary_sha256(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + path);
    }

    if (!S_ISREG(st.st_mode)) {
        return Error(ErrorCode::InvalidArgument, "Not a regular file", path);
    }

    std::string hash_hex;
    if (!sha256_file_hex(path, hash_hex)) {
        return Error(ErrorCode::IoError, "Failed to compute SHA-256", path);
    }
    return hash_hex;
}

Result<bool> verify_binary_hash(const std::string& path, const std::string& expected_sha256)
{
    auto hash_result = compute_binary_sha256(path);
    if (!hash_result) {
        return hash_result.error();
    }
    return *hash_result == expected_sha256;
}

Result<std::vector<BinaryHashEntry>> scan_binary_hashes(const std::vector<std::string>& paths)
{
    std::vector<BinaryHashEntry> entries;

    for (const auto& scan_path : paths) {
        std::error_code ec;
        if (!std::filesystem::exists(scan_path, ec))
            continue;

        if (std::filesystem::is_regular_file(scan_path, ec)) {
            auto hash = compute_binary_sha256(scan_path);
            if (hash) {
                struct stat st {};
                if (stat(scan_path.c_str(), &st) == 0) {
                    InodeId inode{};
                    inode.ino = st.st_ino;
                    inode.dev = static_cast<uint32_t>(st.st_dev);
                    entries.push_back({inode, scan_path, *hash});
                }
            }
            continue;
        }

        if (!std::filesystem::is_directory(scan_path, ec))
            continue;

        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 scan_path, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (ec)
                break;
            if (!entry.is_regular_file(ec))
                continue;

            struct stat st {};
            if (stat(entry.path().c_str(), &st) != 0)
                continue;

            if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
                continue;

            auto hash = compute_binary_sha256(entry.path().string());
            if (hash) {
                InodeId inode{};
                inode.ino = st.st_ino;
                inode.dev = static_cast<uint32_t>(st.st_dev);
                entries.push_back({inode, entry.path().string(), *hash});
            }
        }
    }

    logger().log(SLOG_INFO("Binary hash scan complete").field("entries", static_cast<int64_t>(entries.size())));
    return entries;
}

Result<uint32_t> verify_allowlist_hashes(const std::vector<BinaryHashEntry>& entries)
{
    uint32_t verified = 0;
    for (const auto& entry : entries) {
        auto result = verify_binary_hash(entry.path, entry.sha256_hex);
        if (result && *result) {
            verified++;
        } else {
            logger().log(
                SLOG_WARN("Binary hash mismatch").field("path", entry.path).field("expected", entry.sha256_hex));
        }
    }
    return verified;
}

} // namespace aegis
