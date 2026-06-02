// cppcheck-suppress-file missingIncludeSystem
#include "cli_bpf.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#include "bpf_integrity.hpp"
#include "bpf_signing.hpp"
#include "cli_common.hpp"
#include "crypto.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

std::string bytes_to_hex(const uint8_t* data, size_t len)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

// Generate an Ed25519 signer keypair and write <prefix>.key (128-hex secret,
// mode 0600) and <prefix>.pub (64-hex public). Install the .pub in the trusted
// keystore with `aegisbpf keys add <prefix>.pub`, then sign with `bpf sign`.
int cmd_bpf_keygen(const std::string& out_prefix)
{
    auto kp = generate_keypair();
    if (!kp) {
        logger().log(SLOG_ERROR("Failed to generate keypair").field("error", kp.error().to_string()));
        return 1;
    }
    const PublicKey& pub = kp->first;
    const SecretKey& sec = kp->second;

    const std::string key_path = out_prefix + ".key";
    const std::string pub_path = out_prefix + ".pub";

    // Create the secret key file with 0600 from the start (never world-readable).
    int fd = ::open(key_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600); // NOLINT
    if (fd < 0) {
        logger().log(SLOG_ERROR("Failed to create secret key file").field("path", key_path).error_code(errno));
        return 1;
    }
    const std::string sec_hex = bytes_to_hex(sec.data(), sec.size()) + "\n";
    bool write_ok = ::write(fd, sec_hex.data(), sec_hex.size()) == static_cast<ssize_t>(sec_hex.size());
    ::close(fd);
    if (!write_ok) {
        logger().log(SLOG_ERROR("Failed to write secret key file").field("path", key_path));
        return 1;
    }

    std::ofstream pub_out(pub_path);
    if (!pub_out.is_open()) {
        logger().log(SLOG_ERROR("Failed to write public key file").field("path", pub_path));
        return 1;
    }
    pub_out << encode_hex(pub) << "\n";
    pub_out.close();

    logger().log(SLOG_INFO("Generated BPF signer keypair").field("secret", key_path).field("public", pub_path));
    printf("Wrote %s (secret, 0600) and %s (public).\n", key_path.c_str(), pub_path.c_str());
    printf("Install the public key:  aegisbpf keys add %s\n", pub_path.c_str());
    return 0;
}

int cmd_bpf_sign(const std::string& key_path, const std::string& obj_override, const std::string& signer_name)
{
    const std::string obj_path = obj_override.empty() ? resolve_bpf_obj_path() : obj_override;

    auto key_perms = validate_file_permissions(key_path, false);
    if (!key_perms) {
        logger().log(SLOG_ERROR("Signing key permission check failed")
                         .field("path", key_path)
                         .field("error", key_perms.error().to_string()));
        return 1;
    }

    std::ifstream key_in(key_path);
    if (!key_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open private key file").field("path", key_path));
        return 1;
    }
    std::string key_hex;
    std::getline(key_in, key_hex);
    if (key_hex.size() != kSecretKeySize * 2) {
        logger().log(SLOG_ERROR("Invalid private key format (expected 128 hex chars)").field("path", key_path));
        return 1;
    }

    auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };

    SecretKey secret_key{};
    for (size_t i = 0; i < secret_key.size(); ++i) {
        int hi = hex_value(key_hex[2 * i]);
        int lo = hex_value(key_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            logger().log(SLOG_ERROR("Invalid private key format (non-hex character)"));
            return 1;
        }
        secret_key[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    auto result = sign_bpf_object(obj_path, secret_key, signer_name);
    if (!result) {
        logger().log(
            SLOG_ERROR("Failed to sign BPF object").field("path", obj_path).field("error", result.error().to_string()));
        return 1;
    }

    logger().log(SLOG_INFO("BPF object signed").field("object", obj_path).field("sidecar", obj_path + ".sig"));
    printf("Signed %s -> %s.sig\n", obj_path.c_str(), obj_path.c_str());
    return 0;
}

} // namespace

int dispatch_bpf_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];

    if (sub == "keygen") {
        std::string out_prefix;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--out") {
                if (i + 1 >= argc)
                    return usage(prog);
                out_prefix = argv[++i];
            } else {
                return usage(prog);
            }
        }
        if (out_prefix.empty())
            return usage(prog);
        return cmd_bpf_keygen(out_prefix);
    }

    if (sub == "sign") {
        std::string key_path;
        std::string obj_override;
        std::string signer_name = "aegisbpf";
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--key") {
                if (i + 1 >= argc)
                    return usage(prog);
                key_path = argv[++i];
            } else if (arg == "--obj") {
                if (i + 1 >= argc)
                    return usage(prog);
                obj_override = argv[++i];
            } else if (arg == "--signer") {
                if (i + 1 >= argc)
                    return usage(prog);
                signer_name = argv[++i];
            } else {
                return usage(prog);
            }
        }
        if (key_path.empty())
            return usage(prog);
        return cmd_bpf_sign(key_path, obj_override, signer_name);
    }

    return usage(prog);
}

} // namespace aegis
