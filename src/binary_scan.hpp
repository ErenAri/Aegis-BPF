// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>
#include <vector>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

struct BinaryScanResult {
    std::string hash; // SHA-256 hex digest
    std::string path; // Filesystem path where found
    InodeId inode;    // Device + inode
};

/**
 * Scan filesystem directories for binaries matching the given SHA-256 hashes.
 *
 * Searches default system binary directories (/usr/bin, /usr/sbin, etc.)
 * plus any additional paths provided. For each regular file found, computes
 * SHA-256 and checks against the target hash set.
 *
 * @param target_hashes Set of lowercase hex SHA-256 digests to search for
 * @param extra_scan_paths Additional directories to scan beyond defaults
 * @return Vector of matches (hash, path, inode)
 */
Result<std::vector<BinaryScanResult>> scan_for_binary_hashes(const std::vector<std::string>& target_hashes,
                                                             const std::vector<std::string>& extra_scan_paths = {});

/**
 * Compute SHA-256 hash of a file.
 *
 * @param path Path to the file
 * @return Lowercase hex SHA-256 digest, or error
 */
Result<std::string> sha256_file(const std::string& path);

} // namespace aegis
