// cppcheck-suppress-file missingIncludeSystem
#include "bpf_signing.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

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
    const char* allow_unsigned = std::getenv("AEGIS_ALLOW_UNSIGNED_BPF");
    bool unsigned_allowed = (allow_unsigned != nullptr && std::string(allow_unsigned) == "1");

    const char* require_sig_env = std::getenv("AEGIS_REQUIRE_BPF_SIGNATURE");
    bool require_signature = (require_sig_env != nullptr && std::string(require_sig_env) == "1");

    std::string sig_path = obj_path + ".sig";
    std::ifstream sig_file(sig_path);

    if (!sig_file.is_open()) {
        if (unsigned_allowed) {
            logger().log(
                SLOG_WARN("BPF signature file not found, unsigned allowed via break-glass").field("path", sig_path));
            return {};
        }

        if (require_signature) {
            return Error(ErrorCode::SignatureInvalid,
                         "BPF signature file not found and AEGIS_REQUIRE_BPF_SIGNATURE is set", sig_path);
        }

        const char* require_hash = std::getenv("AEGIS_REQUIRE_BPF_HASH");
        if (require_hash == nullptr || std::string(require_hash) != "1") {
            return {};
        }

        logger().log(SLOG_INFO("BPF signature file not found, using hash-only verification").field("path", sig_path));
        return {};
    }

    auto hash_result = compute_file_sha256(obj_path);
    if (!hash_result) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("Cannot compute BPF object hash, unsigned allowed"));
            return {};
        }
        return hash_result.error();
    }

    std::string expected_hex;
    std::string signature_hex;
    std::string line;
    while (std::getline(sig_file, line)) {
        if (line.rfind("sha256:", 0) == 0) {
            expected_hex = line.substr(7);
        } else if (line.rfind("signature:", 0) == 0) {
            signature_hex = line.substr(10);
        }
    }

    if (expected_hex.empty()) {
        if (unsigned_allowed)
            return {};
        return Error(ErrorCode::IntegrityCheckFailed, "Signature file missing sha256 field", sig_path);
    }

    std::string actual_hex = hex_encode(hash_result->data(), 32);
    if (actual_hex != expected_hex) {
        if (unsigned_allowed) {
            logger().log(SLOG_WARN("BPF object hash mismatch, unsigned allowed")
                             .field("expected", expected_hex)
                             .field("actual", actual_hex));
            return {};
        }
        return Error(ErrorCode::IntegrityCheckFailed, "BPF object hash mismatch",
                     "expected=" + expected_hex + " actual=" + actual_hex);
    }

    logger().log(SLOG_INFO("BPF object hash verified").field("hash", actual_hex));

    // Ed25519 signature verification
    if (require_signature) {
        if (signature_hex.empty()) {
            if (unsigned_allowed) {
                logger().log(SLOG_WARN("BPF signature missing but unsigned allowed via break-glass"));
                return {};
            }
            return Error(ErrorCode::SignatureInvalid,
                         "BPF .sig file lacks Ed25519 signature and AEGIS_REQUIRE_BPF_SIGNATURE is set", sig_path);
        }

        // Decode the signature from hex
        auto sig_result = decode_signature(signature_hex);
        if (!sig_result) {
            return Error(ErrorCode::SignatureInvalid, "Failed to decode BPF Ed25519 signature",
                         sig_result.error().message());
        }
        const Signature& ed_sig = *sig_result;

        // Load trusted keys
        auto keys_result = load_trusted_keys();
        if (!keys_result) {
            return Error(ErrorCode::SignatureInvalid, "Failed to load trusted keys", keys_result.error().message());
        }
        const auto& trusted_keys = *keys_result;

        if (trusted_keys.empty()) {
            return Error(ErrorCode::SignatureInvalid, "No trusted keys found; cannot verify BPF signature");
        }

        // Verify signature over the SHA-256 hash bytes
        bool verified = false;
        for (const auto& key : trusted_keys) {
            if (verify_bytes(hash_result->data(), hash_result->size(), ed_sig, key)) {
                logger().log(SLOG_INFO("BPF Ed25519 signature verified")
                                 .field("key", encode_hex(key))
                                 .field("hash", actual_hex));
                verified = true;
                break;
            }
        }

        if (!verified) {
            return Error(ErrorCode::SignatureInvalid, "BPF Ed25519 signature did not match any trusted key", sig_path);
        }
    } else if (!signature_hex.empty()) {
        // Signature present but not required -- opportunistically verify and log
        auto sig_result = decode_signature(signature_hex);
        if (sig_result) {
            auto keys_result = load_trusted_keys();
            if (keys_result && !keys_result->empty()) {
                bool verified = false;
                for (const auto& key : *keys_result) {
                    if (verify_bytes(hash_result->data(), hash_result->size(), *sig_result, key)) {
                        verified = true;
                        break;
                    }
                }
                if (verified) {
                    logger().log(SLOG_INFO("BPF Ed25519 signature verified (advisory)").field("hash", actual_hex));
                } else {
                    logger().log(SLOG_WARN("BPF Ed25519 signature present but did not match any trusted key")
                                     .field("hash", actual_hex));
                }
            }
        }
    }

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

    // Write Ed25519 signature if present (non-zero)
    static constexpr std::array<uint8_t, 64> zero_sig{};
    if (sig.signature != zero_sig) {
        f << "signature:" << hex_encode(sig.signature.data(), 64) << "\n";
    }

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

Result<void> sign_bpf_object(const std::string& obj_path, const SecretKey& secret_key, const std::string& signer_name)
{
    auto hash_result = compute_file_sha256(obj_path);
    if (!hash_result) {
        return hash_result.error();
    }

    // Sign the SHA-256 digest bytes -- exactly what verify_bpf_signature()
    // checks via verify_bytes(hash, sig, key).
    auto sig_result = sign_bytes(hash_result->data(), hash_result->size(), secret_key);
    if (!sig_result) {
        return Error(ErrorCode::CryptoError, "Failed to sign BPF object hash", sig_result.error().message());
    }

    BpfSignature sig;
    sig.format_version = 1;
    sig.sha256_hash = *hash_result;
    sig.signature = *sig_result;
    sig.timestamp = static_cast<uint64_t>(std::time(nullptr));
    sig.signer_name = signer_name;
    // The Ed25519 secret key's trailing 32 bytes are its public half; record it
    // as the signer key id so operators can identify the signer in the sidecar.
    if (secret_key.size() >= sig.signer_key_id.size()) {
        std::copy(secret_key.end() - static_cast<std::ptrdiff_t>(sig.signer_key_id.size()), secret_key.end(),
                  sig.signer_key_id.begin());
    }

    return write_bpf_signature(obj_path, sig);
}

} // namespace aegis
