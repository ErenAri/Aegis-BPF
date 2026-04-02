// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "result.hpp"

namespace aegis {

struct BpfSignature {
    uint32_t format_version = 1;
    std::array<uint8_t, 32> sha256_hash{};   // SHA-256 of the .bpf.o file
    std::array<uint8_t, 32> signer_key_id{}; // Key identifier
    std::array<uint8_t, 64> signature{};     // Ed25519 signature (placeholder)
    uint64_t timestamp = 0;
    std::string signer_name;
};

// Verify BPF object signature before loading.
// Returns Ok if:
//   1. Signature file exists and is valid, OR
//   2. AEGIS_ALLOW_UNSIGNED_BPF is set (break-glass)
// Returns Error if signature is missing/invalid in enforce mode.
Result<void> verify_bpf_signature(const std::string& obj_path);

// Compute SHA-256 of a file (used for signing and verification)
Result<std::array<uint8_t, 32>> compute_file_sha256(const std::string& path);

// Write signature file (.sig) alongside the BPF object
Result<void> write_bpf_signature(const std::string& obj_path, const BpfSignature& sig);

// Read and parse signature file
Result<BpfSignature> read_bpf_signature(const std::string& obj_path);

} // namespace aegis
