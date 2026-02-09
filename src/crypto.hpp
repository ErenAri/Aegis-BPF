// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <array>
#include <string>
#include <vector>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

// Ed25519 key sizes
constexpr size_t kPublicKeySize = 32;
constexpr size_t kSecretKeySize = 64;
constexpr size_t kSignatureSize = 64;

/**
 * Ed25519 public key.
 */
using PublicKey = std::array<uint8_t, kPublicKeySize>;

/**
 * Ed25519 secret key.
 */
using SecretKey = std::array<uint8_t, kSecretKeySize>;

/**
 * Ed25519 signature.
 */
using Signature = std::array<uint8_t, kSignatureSize>;

/**
 * Generate a new Ed25519 keypair.
 *
 * @return Pair of (public_key, secret_key) or error
 */
Result<std::pair<PublicKey, SecretKey>> generate_keypair();

/**
 * Sign a message using Ed25519.
 *
 * @param message Message to sign
 * @param secret_key Ed25519 secret key
 * @return 64-byte signature or error
 */
Result<Signature> sign_message(const std::string& message, const SecretKey& secret_key);

/**
 * Sign raw bytes using Ed25519.
 *
 * @param data Data to sign
 * @param data_len Length of data
 * @param secret_key Ed25519 secret key
 * @return 64-byte signature or error
 */
Result<Signature> sign_bytes(const uint8_t* data, size_t data_len, const SecretKey& secret_key);

/**
 * Verify an Ed25519 signature.
 *
 * @param message Message that was signed
 * @param signature 64-byte signature to verify
 * @param public_key Ed25519 public key
 * @return true if valid, false if invalid
 */
bool verify_signature(const std::string& message, const Signature& signature, const PublicKey& public_key);

/**
 * Verify an Ed25519 signature on raw bytes.
 *
 * @param data Data that was signed
 * @param data_len Length of data
 * @param signature 64-byte signature to verify
 * @param public_key Ed25519 public key
 * @return true if valid, false if invalid
 */
bool verify_bytes(const uint8_t* data, size_t data_len, const Signature& signature, const PublicKey& public_key);

/**
 * Encode a public key as hexadecimal.
 *
 * @param key Public key to encode
 * @return 64-character hex string
 */
std::string encode_hex(const PublicKey& key);

/**
 * Encode a signature as hexadecimal.
 *
 * @param sig Signature to encode
 * @return 128-character hex string
 */
std::string encode_hex(const Signature& sig);

/**
 * Decode a hexadecimal string to a public key.
 *
 * @param hex 64-character hex string
 * @return Public key or error
 */
Result<PublicKey> decode_public_key(const std::string& hex);

/**
 * Decode a hexadecimal string to a signature.
 *
 * @param hex 128-character hex string
 * @return Signature or error
 */
Result<Signature> decode_signature(const std::string& hex);

/**
 * Parse a signed policy bundle from file content.
 *
 * Bundle format:
 * ```
 * AEGIS-POLICY-BUNDLE-V1
 * format_version: 1
 * policy_version: <monotonic counter>
 * timestamp: <unix timestamp>
 * expires: <unix timestamp or 0>
 * signer_key: <hex public key>
 * signature: <hex signature>
 * policy_sha256: <hex sha256>
 * ---
 * <policy content>
 * ```
 *
 * @param content Raw file content
 * @return SignedPolicyBundle or error
 */
Result<SignedPolicyBundle> parse_signed_bundle(const std::string& content);

/**
 * Create a signed policy bundle.
 *
 * @param policy_content Policy file content
 * @param secret_key Signing key
 * @param policy_version Monotonic version counter
 * @param expires Expiration timestamp (0 = no expiration)
 * @return Serialized bundle content or error
 */
Result<std::string> create_signed_bundle(const std::string& policy_content, const SecretKey& secret_key,
                                         uint64_t policy_version, uint64_t expires = 0);

/**
 * Verify a signed policy bundle.
 *
 * Checks:
 * - Signature validity
 * - SHA256 matches policy content
 * - Not expired
 *
 * @param bundle Parsed bundle
 * @param trusted_keys List of trusted public keys
 * @return Success or error with reason
 */
Result<void> verify_bundle(const SignedPolicyBundle& bundle, const std::vector<PublicKey>& trusted_keys);

/**
 * Load trusted public keys from directory.
 *
 * Reads all .pub files from /etc/aegisbpf/keys/
 *
 * @return List of public keys or error
 */
Result<std::vector<PublicKey>> load_trusted_keys();

/**
 * Resolve the trusted keys directory.
 *
 * Uses AEGIS_KEYS_DIR when set, otherwise /etc/aegisbpf/keys.
 */
std::string trusted_keys_dir();

/**
 * Read the current policy version counter.
 *
 * @return Current version or 0 if not set
 */
uint64_t read_version_counter();

/**
 * Resolve the policy version counter path.
 *
 * Uses AEGIS_VERSION_COUNTER_PATH when set, otherwise /var/lib/aegisbpf/version_counter.
 */
std::string version_counter_path();

/**
 * Write the policy version counter.
 *
 * @param version New version number
 * @return Success or error
 */
Result<void> write_version_counter(uint64_t version);

/**
 * Check if a bundle's version is acceptable (anti-rollback).
 *
 * @param bundle Bundle to check
 * @return true if version > current, false otherwise
 */
bool check_version_acceptable(const SignedPolicyBundle& bundle);

/**
 * Validate a break-glass token.
 *
 * Token format: "<unix_timestamp>:<signature_hex>"
 * The signature is verified over the timestamp string using any trusted key.
 * The token is rejected if the timestamp is older than 24 hours.
 *
 * @param token Token content (first line of break_glass.token file)
 * @param keys Trusted public keys
 * @return true if token is valid and not expired
 */
bool validate_break_glass_token(const std::string& token, const std::vector<PublicKey>& keys);

} // namespace aegis
