// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "crypto.hpp"
#include "result.hpp"

namespace aegis {

struct BpfSignature {
    uint32_t format_version = 1;
    std::array<uint8_t, 32> sha256_hash{};   // SHA-256 of the .bpf.o file
    std::array<uint8_t, 32> signer_key_id{}; // Key identifier
    std::array<uint8_t, 64> signature{};     // Ed25519 signature over SHA-256 hash
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

// Sign a BPF object with an Ed25519 secret key: computes the object's SHA-256,
// signs the digest, and writes the `.sig` sidecar that verify_bpf_signature()
// consumes (the `sha256:` + `signature:` fields). Used by `aegisbpf bpf sign`.
Result<void> sign_bpf_object(const std::string& obj_path, const SecretKey& secret_key, const std::string& signer_name);

} // namespace aegis
