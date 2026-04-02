// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

struct BinaryHashEntry {
    InodeId inode;
    std::string path;
    std::string sha256_hex;
};

// Compute SHA-256 hash of a binary file
Result<std::string> compute_binary_sha256(const std::string& path);

// Verify a binary's hash matches the expected value
Result<bool> verify_binary_hash(const std::string& path, const std::string& expected_sha256);

// Scan paths and compute hashes for all executables
Result<std::vector<BinaryHashEntry>> scan_binary_hashes(const std::vector<std::string>& paths);

// Verify all entries in an allow-list against on-disk hashes
Result<uint32_t> verify_allowlist_hashes(const std::vector<BinaryHashEntry>& entries);

} // namespace aegis
