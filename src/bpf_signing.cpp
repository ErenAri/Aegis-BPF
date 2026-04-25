// cppcheck-suppress-file missingIncludeSystem
#include "bpf_signing.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "logging.hpp"

namespace aegis {

namespace {

std::string hex_encode(const uint8_t* data, size_t len)
{
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

bool hex_decode(const std::string& hex, uint8_t* out, size_t out_len)
{
    if (hex.size() != out_len * 2)
        return false;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int val;
        if (sscanf(hex.c_str() + i * 2, "%2x", &val) != 1) // NOLINT
            return false;
        out[i] = static_cast<uint8_t>(val);
    }
    return true;
}

bool env_flag_truthy(const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return false;
    }
    std::string normalized(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

// Strip leading/trailing whitespace and any trailing CR/LF.
std::string strip(const std::string& in)
{
    size_t start = 0;
    while (start < in.size() && std::isspace(static_cast<unsigned char>(in[start]))) {
        ++start;
    }
    size_t end = in.size();
    while (end > start && std::isspace(static_cast<unsigned char>(in[end - 1]))) {
        --end;
    }
    return in.substr(start, end - start);
}

} // namespace

Result<std::array<uint8_t, 32>> compute_file_sha256(const std::string& path)
{
    // Use sha256sum for portability (avoids external crypto library dependency)
    std::string cmd = "sha256sum '" + path + "' 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r"); // NOLINT
    if (!pipe) {
        return Error(ErrorCode::IoError, "Failed to run sha256sum", path);
    }

    char buf[128] = {};
    if (fgets(buf, sizeof(buf), pipe) == nullptr) {
        pclose(pipe);
        return Error(ErrorCode::IoError, "sha256sum produced no output", path);
    }
    pclose(pipe);

    std::string hex(buf, 64);
    std::array<uint8_t, 32> hash{};
    if (!hex_decode(hex, hash.data(), 32)) {
        return Error(ErrorCode::IoError, "Failed to parse sha256sum output");
    }

    return hash;
}

Result<void> verify_bpf_signature(const std::string& obj_path)
{
    const bool unsigned_allowed = env_flag_truthy("AEGIS_ALLOW_UNSIGNED_BPF");
    const bool require_sig = env_flag_truthy("AEGIS_REQUIRE_BPF_SIG");

    const std::string sig_path = obj_path + ".sig";
    std::ifstream sig_file(sig_path);

    if (!sig_file.is_open()) {
        if (unsigned_allowed) {
            logger().log(
                SLOG_WARN("BPF signature file not found, unsigned allowed via break-glass").field("path", sig_path));
            return {};
        }
        if (require_sig) {
            return Error(ErrorCode::IntegrityCheckFailed,
                         "BPF signature file required but not found",
                         sig_path);
        }
        // Legacy / unsigned deployments: not present, not required, not break-glass.
        // verify_bpf_integrity() already logged the hash result; nothing more to do.
        return {};
    }

    // Parse the .sig file. Recognised fields:
    //   sha256:<hex>                 (32 bytes / 64 hex chars)   - required (legacy)
    //   signer_pubkey:<hex>          (32 bytes / 64 hex chars)   - optional (Ed25519)
    //   signature:<hex>              (64 bytes / 128 hex chars)  - optional (Ed25519)
    //   signer:<freeform>                                        - optional (display)
    //   timestamp:<unix>                                         - optional
    //   key_id:<hex>                                             - optional / display
    //   format_version:<int>                                     - optional
    std::string sha256_hex;
    std::string signer_pubkey_hex;
    std::string signature_hex;
    std::string signer_name;
    std::string line;
    while (std::getline(sig_file, line)) {
        line = strip(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line.rfind("sha256:", 0) == 0) {
            sha256_hex = strip(line.substr(7));
        } else if (line.rfind("signer_pubkey:", 0) == 0) {
            signer_pubkey_hex = strip(line.substr(14));
        } else if (line.rfind("signature:", 0) == 0) {
            signature_hex = strip(line.substr(10));
        } else if (line.rfind("signer:", 0) == 0) {
            signer_name = strip(line.substr(7));
        }
    }

    if (sha256_hex.empty()) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("BPF signature file missing sha256 field, unsigned allowed").field("path", sig_path));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed, "Signature file missing sha256 field", sig_path);
    }

    // Recompute the hash of the object and compare against the .sig sha256 line.
    auto hash_result = compute_file_sha256(obj_path);
    if (!hash_result) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("Cannot compute BPF object hash, unsigned allowed"));
            return {};
        }
        return hash_result.error();
    }
    const std::string actual_hex = hex_encode(hash_result->data(), 32);

    if (actual_hex != sha256_hex) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("BPF object hash mismatch, unsigned allowed")
                             .field("expected", sha256_hex)
                             .field("actual", actual_hex));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed, "BPF object hash mismatch",
                     "expected=" + sha256_hex + " actual=" + actual_hex);
    }

    // Hash matches. If the .sig file does not carry an Ed25519 signature, treat
    // it as the legacy hash-only format. Pass unless REQUIRE_BPF_SIG is set.
    const bool has_ed25519 = !signer_pubkey_hex.empty() && !signature_hex.empty();
    if (!has_ed25519) {
        if (require_sig && !unsigned_allowed) {
            return Error(ErrorCode::IntegrityCheckFailed,
                         "BPF .sig file does not carry an Ed25519 signature (legacy hash-only format)",
                         sig_path);
        }
        logger().log(SLOG_INFO("BPF hash verified (legacy .sig, no Ed25519 signature)")
                         .field("hash", actual_hex));
        return {};
    }

    // Decode pubkey + signature and verify the Ed25519 signature is over the
    // 32-byte hash of the BPF object.
    auto pubkey_res = decode_public_key(signer_pubkey_hex);
    if (!pubkey_res) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("Invalid signer_pubkey hex in .sig, unsigned allowed").field("path", sig_path));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed, "Invalid signer_pubkey hex in .sig file",
                     pubkey_res.error().to_string());
    }
    auto signature_res = decode_signature(signature_hex);
    if (!signature_res) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("Invalid signature hex in .sig, unsigned allowed").field("path", sig_path));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed, "Invalid signature hex in .sig file",
                     signature_res.error().to_string());
    }

    // The signer key must be in the trusted keys directory. Reject otherwise.
    auto trusted_res = load_trusted_keys();
    if (!trusted_res) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("Failed to load trusted keys, unsigned allowed")
                             .field("error", trusted_res.error().to_string()));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed, "Failed to load trusted keys for BPF signature verification",
                     trusted_res.error().to_string());
    }
    const auto& trusted = *trusted_res;
    const bool trusted_match = std::any_of(trusted.begin(), trusted.end(),
                                           [&](const PublicKey& k) { return k == *pubkey_res; });
    if (!trusted_match) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("BPF signer pubkey not in trusted keys dir, unsigned allowed")
                             .field("signer_pubkey", signer_pubkey_hex)
                             .field("keys_dir", trusted_keys_dir()));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed,
                     "BPF signer pubkey is not present in trusted keys directory",
                     "signer_pubkey=" + signer_pubkey_hex + " keys_dir=" + trusted_keys_dir());
    }

    if (!verify_bytes(hash_result->data(), hash_result->size(), *signature_res, *pubkey_res)) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("Ed25519 verification of BPF object failed, unsigned allowed")
                             .field("path", sig_path));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed,
                     "Ed25519 signature verification failed for BPF object",
                     sig_path);
    }

    logger().log(SLOG_INFO("BPF Ed25519 signature verified")
                     .field("hash", actual_hex)
                     .field("signer_pubkey", signer_pubkey_hex)
                     .field("signer", signer_name));
    return {};
}

Result<void> write_bpf_signature(const std::string& obj_path, const BpfSignature& sig)
{
    std::string sig_path = obj_path + ".sig";
    std::ofstream f(sig_path);
    if (!f.is_open()) {
        return Error(ErrorCode::IoError, "Failed to write signature file", sig_path);
    }

    f << "sha256:" << hex_encode(sig.sha256_hash.data(), 32) << "\n";
    f << "signer:" << sig.signer_name << "\n";
    f << "timestamp:" << sig.timestamp << "\n";
    f << "key_id:" << hex_encode(sig.signer_key_id.data(), 32) << "\n";
    f << "format_version:" << sig.format_version << "\n";

    return {};
}

Result<BpfSignature> read_bpf_signature(const std::string& obj_path)
{
    std::string sig_path = obj_path + ".sig";
    std::ifstream f(sig_path);
    if (!f.is_open()) {
        return Error(ErrorCode::IoError, "Signature file not found", sig_path);
    }

    BpfSignature sig;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("sha256:", 0) == 0) {
            hex_decode(line.substr(7), sig.sha256_hash.data(), 32);
        } else if (line.rfind("signer:", 0) == 0) {
            sig.signer_name = line.substr(7);
        } else if (line.rfind("timestamp:", 0) == 0) {
            sig.timestamp = std::stoull(line.substr(10));
        } else if (line.rfind("key_id:", 0) == 0) {
            hex_decode(line.substr(7), sig.signer_key_id.data(), 32);
        } else if (line.rfind("signature:", 0) == 0) {
            hex_decode(line.substr(10), sig.signature.data(), 64);
        }
    }

    return sig;
}

} // namespace aegis
