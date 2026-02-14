// cppcheck-suppress-file missingIncludeSystem
#include "binary_scan.hpp"

#include <sys/stat.h>

#include <filesystem>
#include <unordered_set>

#include "logging.hpp"
#include "sha256.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

// Default directories to scan for binaries
static const std::vector<std::string> kDefaultScanDirs = {
    "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin",
};

} // namespace

Result<std::string> sha256_file(const std::string& path)
{
    std::string hex;
    if (!sha256_file_hex(path, hex)) {
        return Error(ErrorCode::IoError, "Failed to compute SHA-256", path);
    }
    return hex;
}

Result<std::vector<BinaryScanResult>> scan_for_binary_hashes(const std::vector<std::string>& target_hashes,
                                                             const std::vector<std::string>& extra_scan_paths)
{
    if (target_hashes.empty()) {
        return std::vector<BinaryScanResult>{};
    }

    // Build lookup set for O(1) matching
    std::unordered_set<std::string> hash_set(target_hashes.begin(), target_hashes.end());

    // Collect all directories to scan
    std::vector<std::string> dirs = kDefaultScanDirs;
    dirs.insert(dirs.end(), extra_scan_paths.begin(), extra_scan_paths.end());

    std::vector<BinaryScanResult> results;
    size_t files_scanned = 0;

    for (const auto& dir : dirs) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) {
            continue;
        }

        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (ec) {
                break;
            }

            std::error_code stat_ec;
            if (!entry.is_regular_file(stat_ec) || stat_ec) {
                continue;
            }

            const auto& path = entry.path().string();
            ++files_scanned;

            std::string hex;
            if (!sha256_file_hex(path, hex)) {
                continue; // Skip files we can't hash (permissions, etc.)
            }

            if (hash_set.count(hex)) {
                struct stat st {};
                if (stat(path.c_str(), &st) != 0) {
                    continue;
                }

                BinaryScanResult result;
                result.hash = hex;
                result.path = path;
                result.inode.ino = st.st_ino;
                result.inode.dev = encode_dev(st.st_dev);
                result.inode.pad = 0;
                results.push_back(std::move(result));

                logger().log(SLOG_INFO("Binary hash match found")
                                 .field("path", path)
                                 .field("hash", hex)
                                 .field("inode", static_cast<int64_t>(st.st_ino)));
            }
        }
    }

    logger().log(SLOG_INFO("Binary hash scan complete")
                     .field("files_scanned", static_cast<int64_t>(files_scanned))
                     .field("matches", static_cast<int64_t>(results.size()))
                     .field("target_hashes", static_cast<int64_t>(target_hashes.size())));

    return results;
}

} // namespace aegis
