// cppcheck-suppress-file missingIncludeSystem
#include "crypto.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "logging.hpp"
#include "sha256.hpp"
#include "utils.hpp"

extern "C" {
#include "tweetnacl.h"
}
#include "tweetnacl_safe.hpp"

namespace aegis {

namespace {

constexpr const char* kDefaultKeysDir = "/etc/aegisbpf/keys";
constexpr const char* kBundleHeader = "AEGIS-POLICY-BUNDLE-V1";
constexpr const char* kBundleSeparator = "---";

uint8_t hex_digit_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return 0xff;
}

std::string bytes_to_hex(const uint8_t* data, size_t len)
{
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hex_chars[(data[i] >> 4) & 0xf];
        result += hex_chars[data[i] & 0xf];
    }
    return result;
}

bool hex_to_bytes(const std::string& hex, uint8_t* out, size_t out_len)
{
    if (hex.size() != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; ++i) {
        uint8_t hi = hex_digit_value(hex[2 * i]);
        uint8_t lo = hex_digit_value(hex[2 * i + 1]);
        if (hi == 0xff || lo == 0xff) {
            return false;
        }
        out[i] = (hi << 4) | lo;
    }
    return true;
}

std::string trim_string(const std::string& s)
{
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

bool parse_header_line(const std::string& line, std::string& key, std::string& value)
{
    size_t pos = line.find(':');
    if (pos == std::string::npos) {
        return false;
    }
    key = trim_string(line.substr(0, pos));
    value = trim_string(line.substr(pos + 1));
    return !key.empty();
}

} // anonymous namespace

std::string trusted_keys_dir()
{
    const char* env = std::getenv("AEGIS_KEYS_DIR");
    if (env && *env) {
        return std::string(env);
    }
    return kDefaultKeysDir;
}

std::string version_counter_path()
{
    const char* env = std::getenv("AEGIS_VERSION_COUNTER_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kVersionCounterPath;
}

// cppcheck-suppress unusedFunction
Result<std::pair<PublicKey, SecretKey>> generate_keypair()
{
    PublicKey pk{};
    SecretKey sk{};
    if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
        return Error(ErrorCode::CryptoError, "Failed to generate Ed25519 keypair");
    }
    return std::make_pair(pk, sk);
}

Result<Signature> sign_message(const std::string& message, const SecretKey& secret_key)
{
    return sign_bytes(reinterpret_cast<const uint8_t*>(message.data()), message.size(), secret_key);
}

Result<Signature> sign_bytes(const uint8_t* data, size_t data_len, const SecretKey& secret_key)
{
    Signature sig{};
    // Use safe wrapper that prevents memory exhaustion attacks
    if (crypto_safe::crypto_sign_detached_safe(sig.data(), data, data_len, secret_key.data()) != 0) {
        return Error(ErrorCode::CryptoError, "Failed to sign message (message may be too large)");
    }
    return sig;
}

bool verify_signature(const std::string& message, const Signature& signature, const PublicKey& public_key)
{
    return verify_bytes(reinterpret_cast<const uint8_t*>(message.data()), message.size(), signature, public_key);
}

bool verify_bytes(const uint8_t* data, size_t data_len, const Signature& signature, const PublicKey& public_key)
{
    // Use safe wrapper that prevents memory exhaustion attacks
    return crypto_safe::crypto_sign_verify_detached_safe(signature.data(), data, data_len, public_key.data()) == 0;
}

std::string encode_hex(const PublicKey& key)
{
    return bytes_to_hex(key.data(), key.size());
}

std::string encode_hex(const Signature& sig)
{
    return bytes_to_hex(sig.data(), sig.size());
}

Result<PublicKey> decode_public_key(const std::string& hex)
{
    std::string trimmed = trim_string(hex);
    PublicKey key{};
    if (!hex_to_bytes(trimmed, key.data(), key.size())) {
        return Error(ErrorCode::InvalidArgument, "Invalid public key hex string",
                     "expected 64 hex characters, got " + std::to_string(trimmed.size()));
    }
    return key;
}

Result<Signature> decode_signature(const std::string& hex)
{
    std::string trimmed = trim_string(hex);
    Signature sig{};
    if (!hex_to_bytes(trimmed, sig.data(), sig.size())) {
        return Error(ErrorCode::InvalidArgument, "Invalid signature hex string",
                     "expected 128 hex characters, got " + std::to_string(trimmed.size()));
    }
    return sig;
}

Result<SignedPolicyBundle> parse_signed_bundle(const std::string& content)
{
    SignedPolicyBundle bundle{};

    // Find the separator
    size_t sep_pos = content.find(kBundleSeparator);
    if (sep_pos == std::string::npos) {
        return Error(ErrorCode::PolicyParseFailed, "Bundle missing separator line (---)");
    }

    std::string header_section = content.substr(0, sep_pos);
    std::string policy_section = content.substr(sep_pos + strlen(kBundleSeparator));

    // Trim leading newline from policy section
    while (!policy_section.empty() && (policy_section[0] == '\n' || policy_section[0] == '\r')) {
        policy_section.erase(0, 1);
    }
    bundle.policy_content = policy_section;

    // Parse header lines
    std::istringstream iss(header_section);
    std::string line;
    bool found_header = false;

    while (std::getline(iss, line)) {
        line = trim_string(line);
        if (line.empty())
            continue;

        if (!found_header) {
            if (line != kBundleHeader) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid bundle header",
                             "expected '" + std::string(kBundleHeader) + "'");
            }
            found_header = true;
            continue;
        }

        std::string key, value;
        if (!parse_header_line(line, key, value)) {
            continue;
        }

        if (key == "format_version") {
            try {
                bundle.format_version = static_cast<uint32_t>(std::stoul(value));
            } catch (const std::exception& e) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid format_version", value);
            }
        } else if (key == "policy_version") {
            try {
                bundle.policy_version = std::stoull(value);
            } catch (const std::exception& e) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid policy_version", value);
            }
        } else if (key == "timestamp") {
            try {
                bundle.timestamp = std::stoull(value);
            } catch (const std::exception& e) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid timestamp", value);
            }
        } else if (key == "expires") {
            try {
                bundle.expires = std::stoull(value);
            } catch (const std::exception& e) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid expires", value);
            }
        } else if (key == "signer_key") {
            auto key_result = decode_public_key(value);
            if (!key_result) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid signer_key", key_result.error().message());
            }
            bundle.signer_key = *key_result;
        } else if (key == "signature") {
            auto sig_result = decode_signature(value);
            if (!sig_result) {
                return Error(ErrorCode::PolicyParseFailed, "Invalid signature", sig_result.error().message());
            }
            bundle.signature = *sig_result;
        } else if (key == "policy_sha256") {
            bundle.policy_sha256 = value;
        }
    }

    if (!found_header) {
        return Error(ErrorCode::PolicyParseFailed, "Bundle header not found");
    }

    if (bundle.format_version == 0) {
        return Error(ErrorCode::PolicyParseFailed, "Missing format_version in bundle");
    }

    return bundle;
}

Result<std::string> create_signed_bundle(const std::string& policy_content, const SecretKey& secret_key,
                                         uint64_t policy_version, uint64_t expires)
{
    // Compute SHA256 of policy content
    std::string policy_sha256 = Sha256::hash_hex(policy_content);

    // Get public key from secret key
    PublicKey public_key;
    std::memcpy(public_key.data(), secret_key.data() + 32, 32);

    // Get current timestamp
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));

    // Create the data to sign: sha256 + version + timestamp + expires
    std::ostringstream sign_data;
    sign_data << policy_sha256 << policy_version << timestamp << expires;
    std::string sign_str = sign_data.str();

    // Sign the data
    auto sig_result = sign_message(sign_str, secret_key);
    if (!sig_result) {
        return sig_result.error();
    }
    Signature signature = *sig_result;

    // Build the bundle
    std::ostringstream oss;
    oss << kBundleHeader << "\n";
    oss << "format_version: 1\n";
    oss << "policy_version: " << policy_version << "\n";
    oss << "timestamp: " << timestamp << "\n";
    oss << "expires: " << expires << "\n";
    oss << "signer_key: " << encode_hex(public_key) << "\n";
    oss << "signature: " << encode_hex(signature) << "\n";
    oss << "policy_sha256: " << policy_sha256 << "\n";
    oss << kBundleSeparator << "\n";
    oss << policy_content;

    return oss.str();
}

Result<void> verify_bundle(const SignedPolicyBundle& bundle, const std::vector<PublicKey>& trusted_keys)
{
    // Check format version
    if (bundle.format_version != 1) {
        return Error(ErrorCode::PolicyParseFailed, "Unsupported bundle format version",
                     std::to_string(bundle.format_version));
    }

    // Check expiration
    if (bundle.expires > 0) {
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        if (now > bundle.expires) {
            return Error(ErrorCode::PolicyExpired, "Policy bundle has expired");
        }
    }

    // Verify SHA256 (constant-time comparison to prevent timing attacks)
    std::string computed_sha256 = Sha256::hash_hex(bundle.policy_content);
    if (!constant_time_hex_compare(computed_sha256, bundle.policy_sha256)) {
        return Error(ErrorCode::IntegrityCheckFailed, "Policy SHA256 mismatch",
                     "expected " + bundle.policy_sha256 + ", got " + computed_sha256);
    }

    // Check if signer key is trusted
    bool key_trusted = std::any_of(trusted_keys.begin(), trusted_keys.end(),
                                   [&bundle](const auto& trusted) { return trusted == bundle.signer_key; });
    if (!key_trusted) {
        return Error(ErrorCode::SignatureInvalid, "Signer key is not trusted", encode_hex(bundle.signer_key));
    }

    // Verify signature
    std::ostringstream sign_data;
    sign_data << bundle.policy_sha256 << bundle.policy_version << bundle.timestamp << bundle.expires;
    std::string sign_str = sign_data.str();

    if (!verify_signature(sign_str, bundle.signature, bundle.signer_key)) {
        return Error(ErrorCode::SignatureInvalid, "Signature verification failed");
    }

    return {};
}

Result<std::vector<PublicKey>> load_trusted_keys()
{
    std::vector<PublicKey> keys;
    const std::string keys_dir = trusted_keys_dir();

    std::error_code ec;
    if (!std::filesystem::exists(keys_dir, ec)) {
        // No keys directory - return empty list
        return keys;
    }

    // Validate key directory ownership and permissions (only enforced when running as root)
    if (geteuid() == 0) {
        auto perm_result = validate_config_directory_permissions(keys_dir);
        if (!perm_result) {
            return Error(ErrorCode::PermissionDenied, "Trusted keys directory failed permission check",
                         perm_result.error().to_string());
        }
    }

    for (const auto& entry : std::filesystem::directory_iterator(keys_dir, ec)) {
        if (entry.path().extension() != ".pub") {
            continue;
        }

        // Reject symlinks in key directory
        struct stat lst {};
        if (lstat(entry.path().c_str(), &lst) != 0) {
            continue;
        }
        if (S_ISLNK(lst.st_mode)) {
            logger().log(SLOG_WARN("Skipping symlinked key file").field("path", entry.path().string()));
            continue;
        }

        // Validate individual key file permissions (root-owned check only when running as root)
        auto file_perm = validate_file_permissions(entry.path().string(), geteuid() == 0);
        if (!file_perm) {
            logger().log(SLOG_WARN("Skipping key file with bad permissions")
                             .field("path", entry.path().string())
                             .field("error", file_perm.error().to_string()));
            continue;
        }

        std::ifstream in(entry.path());
        if (!in.is_open()) {
            continue;
        }

        std::string line;
        if (std::getline(in, line)) {
            auto key_result = decode_public_key(line);
            if (key_result) {
                keys.push_back(*key_result);
            }
        }
    }

    return keys;
}

uint64_t read_version_counter()
{
    std::ifstream in(version_counter_path());
    if (!in.is_open()) {
        return 0;
    }

    uint64_t version = 0;
    in >> version;
    return version;
}

Result<void> write_version_counter(uint64_t version)
{
    const std::filesystem::path version_path_val = version_counter_path();
    const std::filesystem::path version_parent = version_path_val.parent_path();

    std::error_code ec;
    if (!version_parent.empty()) {
        std::filesystem::create_directories(version_parent, ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to create version directory", ec.message());
        }
    }

    return atomic_write_file(version_path_val.string(), std::to_string(version));
}

bool check_version_acceptable(const SignedPolicyBundle& bundle)
{
    uint64_t current = read_version_counter();
    return bundle.policy_version > current;
}

bool validate_break_glass_token(const std::string& token, const std::vector<PublicKey>& keys)
{
    if (token.empty() || keys.empty()) {
        return false;
    }

    // Token format: "<unix_timestamp>:<signature_hex>"
    size_t colon_pos = token.find(':');
    if (colon_pos == std::string::npos || colon_pos == 0) {
        return false;
    }

    std::string timestamp_str = trim_string(token.substr(0, colon_pos));
    std::string sig_hex = trim_string(token.substr(colon_pos + 1));

    // Parse and validate timestamp
    uint64_t token_timestamp = 0;
    try {
        token_timestamp = std::stoull(timestamp_str);
    } catch (const std::exception&) {
        return false;
    }

    // Reject expired tokens (older than 24 hours)
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    constexpr uint64_t kMaxTokenAge = uint64_t{24} * 60 * 60; // 24 hours
    if (token_timestamp + kMaxTokenAge < now) {
        logger().log(SLOG_WARN("Break-glass token expired")
                         .field("token_time", static_cast<int64_t>(token_timestamp))
                         .field("now", static_cast<int64_t>(now)));
        return false;
    }
    // Reject future timestamps (more than 5 minutes ahead)
    if (token_timestamp > now + 300) {
        return false;
    }

    // Decode signature
    auto sig_result = decode_signature(sig_hex);
    if (!sig_result) {
        return false;
    }
    const Signature& sig = *sig_result;

    // Verify signature over timestamp string with any trusted key
    for (const auto& key : keys) {
        if (verify_signature(timestamp_str, sig, key)) {
            return true;
        }
    }

    return false;
}

} // namespace aegis
