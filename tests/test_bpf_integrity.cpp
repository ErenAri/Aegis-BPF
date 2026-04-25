// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include "bpf_ops.hpp"
#include "bpf_signing.hpp"
#include "crypto.hpp"
#include "sha256.hpp"

namespace aegis {
namespace {

class TempDir {
  public:
    TempDir()
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_integrity_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) + "_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(path_);
    }

    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

  private:
    std::filesystem::path path_;
};

class ScopedEnvVar {
  public:
    ScopedEnvVar(const char* key, const std::string& value) : key_(key)
    {
        const char* existing = std::getenv(key_);
        if (existing != nullptr) {
            had_previous_ = true;
            previous_ = existing;
        }
        ::setenv(key_, value.c_str(), 1);
    }

    ~ScopedEnvVar()
    {
        if (had_previous_) {
            ::setenv(key_, previous_.c_str(), 1);
        } else {
            ::unsetenv(key_);
        }
    }

  private:
    const char* key_;
    bool had_previous_ = false;
    std::string previous_;
};

TEST(BpfIntegrityTest, VerifiesMatchingHashWhenRequired)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    const auto hash_path = temp_dir.path() / "aegis.bpf.sha256";

    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    std::string obj_hash;
    ASSERT_TRUE(sha256_file_hex(obj_path.string(), obj_hash));
    {
        std::ofstream out(hash_path);
        ASSERT_TRUE(out.is_open());
        out << obj_hash << "\n";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", hash_path.string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing.sha256").string());

    auto result = evaluate_bpf_integrity(true, false);
    ASSERT_TRUE(result);
    EXPECT_TRUE(result->object_exists);
    EXPECT_TRUE(result->hash_exists);
    EXPECT_TRUE(result->hash_verified);
    EXPECT_TRUE(result->reason.empty());
}

TEST(BpfIntegrityTest, UsesObjectAdjacentHashWhenConfiguredPathsAreMissing)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    const auto adjacent_hash_path = temp_dir.path() / "aegis.bpf.sha256";

    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    std::string obj_hash;
    ASSERT_TRUE(sha256_file_hex(obj_path.string(), obj_hash));
    {
        std::ofstream out(adjacent_hash_path);
        ASSERT_TRUE(out.is_open());
        out << obj_hash << "\n";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", (temp_dir.path() / "missing.sha256").string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing2.sha256").string());

    auto result = evaluate_bpf_integrity(true, false);
    ASSERT_TRUE(result);
    EXPECT_TRUE(result->object_exists);
    EXPECT_TRUE(result->hash_exists);
    EXPECT_TRUE(result->hash_verified);
    EXPECT_EQ(result->hash_path, adjacent_hash_path.string());
    EXPECT_TRUE(result->reason.empty());
}

TEST(BpfIntegrityTest, FailsWhenHashIsMissingAndRequired)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", (temp_dir.path() / "missing.sha256").string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing2.sha256").string());

    auto result = evaluate_bpf_integrity(true, false);
    EXPECT_FALSE(result);
}

TEST(BpfIntegrityTest, AllowsMissingHashWithBreakGlass)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", (temp_dir.path() / "missing.sha256").string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing2.sha256").string());

    auto result = evaluate_bpf_integrity(true, true);
    ASSERT_TRUE(result);
    EXPECT_TRUE(result->object_exists);
    EXPECT_FALSE(result->hash_exists);
    EXPECT_FALSE(result->hash_verified);
    EXPECT_EQ(result->reason, "bpf_hash_missing");
}

TEST(BpfIntegrityTest, AllowsMismatchWithBreakGlass)
{
    TempDir temp_dir;
    const auto obj_path = temp_dir.path() / "aegis.bpf.o";
    const auto hash_path = temp_dir.path() / "aegis.bpf.sha256";

    {
        std::ofstream out(obj_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "dummy-bpf-object";
    }
    {
        std::ofstream out(hash_path);
        ASSERT_TRUE(out.is_open());
        out << std::string(64, 'a') << "\n";
    }

    ScopedEnvVar env_obj("AEGIS_BPF_OBJ", obj_path.string());
    ScopedEnvVar env_hash("AEGIS_BPF_OBJ_HASH_PATH", hash_path.string());
    ScopedEnvVar env_hash_install("AEGIS_BPF_OBJ_HASH_INSTALL_PATH", (temp_dir.path() / "missing.sha256").string());

    auto strict_result = evaluate_bpf_integrity(true, false);
    EXPECT_FALSE(strict_result);

    auto break_glass_result = evaluate_bpf_integrity(true, true);
    ASSERT_TRUE(break_glass_result);
    EXPECT_TRUE(break_glass_result->hash_exists);
    EXPECT_FALSE(break_glass_result->hash_verified);
    EXPECT_EQ(break_glass_result->reason, "bpf_hash_mismatch");
}

TEST(BpfIntegrityTest, ParsesUnsignedBpfEnvFlag)
{
    ScopedEnvVar env("AEGIS_ALLOW_UNSIGNED_BPF", "yes");
    EXPECT_TRUE(allow_unsigned_bpf_enabled());
}

TEST(BpfIntegrityTest, ParsesRequireHashEnvFlag)
{
    ScopedEnvVar env("AEGIS_REQUIRE_BPF_HASH", "true");
    EXPECT_TRUE(require_bpf_hash_enabled());
}

TEST(BpfIntegrityTest, ParsesRequireBpfSigEnvFlag)
{
    ScopedEnvVar env("AEGIS_REQUIRE_BPF_SIG", "1");
    EXPECT_TRUE(require_bpf_sig_enabled());
}

// ---------------------------------------------------------------------------
// Ed25519 BPF signature verification tests. These exercise verify_bpf_signature
// directly so we don't depend on the full integrity pipeline / hash-file
// resolution paths.

namespace {

// Write a binary blob and return its SHA-256 (32 bytes) and hex form.
struct ObjectFixture {
    std::filesystem::path obj_path;
    std::array<uint8_t, 32> hash_bytes{};
    std::string hash_hex;
};

ObjectFixture make_obj_fixture(const std::filesystem::path& dir, const std::string& contents)
{
    ObjectFixture f;
    f.obj_path = dir / "aegis.bpf.o";
    {
        std::ofstream out(f.obj_path, std::ios::binary);
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }
    auto digest = compute_file_sha256(f.obj_path.string());
    EXPECT_TRUE(static_cast<bool>(digest));
    f.hash_bytes = *digest;
    std::ostringstream oss;
    for (uint8_t b : f.hash_bytes) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    f.hash_hex = oss.str();
    return f;
}

void write_sig_file(const std::filesystem::path& obj_path, const std::string& sha256_hex,
                    const std::string& signer_pubkey_hex, const std::string& signature_hex)
{
    std::ofstream out(obj_path.string() + ".sig");
    out << "format_version:1\n";
    if (!sha256_hex.empty())
        out << "sha256:" << sha256_hex << "\n";
    if (!signer_pubkey_hex.empty())
        out << "signer_pubkey:" << signer_pubkey_hex << "\n";
    if (!signature_hex.empty())
        out << "signature:" << signature_hex << "\n";
    out << "signer:test-signer\n";
}

void write_pubkey_file(const std::filesystem::path& keys_dir, const std::string& name,
                       const PublicKey& pk)
{
    std::filesystem::create_directories(keys_dir);
    std::ofstream out(keys_dir / (name + ".pub"));
    out << encode_hex(pk) << "\n";
}

} // namespace

TEST(BpfSignatureTest, ValidEd25519SignaturePassesWithTrustedKey)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "valid-bpf-blob");

    auto kp = generate_keypair();
    ASSERT_TRUE(kp);
    const auto& [pk, sk] = *kp;

    auto sig = sign_bytes(fx.hash_bytes.data(), fx.hash_bytes.size(), sk);
    ASSERT_TRUE(sig);

    write_sig_file(fx.obj_path, fx.hash_hex, encode_hex(pk), encode_hex(*sig));

    const auto keys_dir = temp.path() / "keys";
    write_pubkey_file(keys_dir, "test", pk);

    ScopedEnvVar env_keys("AEGIS_KEYS_DIR", keys_dir.string());
    ScopedEnvVar env_require("AEGIS_REQUIRE_BPF_SIG", "1");

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_TRUE(result) << (result ? "" : result.error().to_string());
}

TEST(BpfSignatureTest, RejectsTamperedSignature)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "tampered-sig-blob");

    auto kp = generate_keypair();
    ASSERT_TRUE(kp);
    const auto& [pk, sk] = *kp;
    auto sig = sign_bytes(fx.hash_bytes.data(), fx.hash_bytes.size(), sk);
    ASSERT_TRUE(sig);

    // Flip a byte in the signature hex.
    std::string sig_hex = encode_hex(*sig);
    sig_hex[0] = (sig_hex[0] == '0') ? '1' : '0';

    write_sig_file(fx.obj_path, fx.hash_hex, encode_hex(pk), sig_hex);

    const auto keys_dir = temp.path() / "keys";
    write_pubkey_file(keys_dir, "test", pk);

    ScopedEnvVar env_keys("AEGIS_KEYS_DIR", keys_dir.string());

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_FALSE(result);
}

TEST(BpfSignatureTest, RejectsUntrustedPubkey)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "untrusted-key-blob");

    auto signer_kp = generate_keypair();
    auto trusted_kp = generate_keypair();
    ASSERT_TRUE(signer_kp);
    ASSERT_TRUE(trusted_kp);

    auto sig = sign_bytes(fx.hash_bytes.data(), fx.hash_bytes.size(), signer_kp->second);
    ASSERT_TRUE(sig);

    write_sig_file(fx.obj_path, fx.hash_hex, encode_hex(signer_kp->first), encode_hex(*sig));

    // Trusted-keys dir contains a different key.
    const auto keys_dir = temp.path() / "keys";
    write_pubkey_file(keys_dir, "other", trusted_kp->first);

    ScopedEnvVar env_keys("AEGIS_KEYS_DIR", keys_dir.string());

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_FALSE(result);
}

TEST(BpfSignatureTest, RejectsLegacyHashOnlySigWhenRequireBpfSig)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "legacy-sig-blob");

    // Legacy .sig: only the sha256 line, no Ed25519 fields.
    write_sig_file(fx.obj_path, fx.hash_hex, "", "");

    const auto keys_dir = temp.path() / "keys";
    std::filesystem::create_directories(keys_dir);

    ScopedEnvVar env_keys("AEGIS_KEYS_DIR", keys_dir.string());
    ScopedEnvVar env_require("AEGIS_REQUIRE_BPF_SIG", "1");

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_FALSE(result);
}

TEST(BpfSignatureTest, AllowsLegacyHashOnlySigWhenRequireBpfSigOff)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "legacy-sig-blob-2");

    write_sig_file(fx.obj_path, fx.hash_hex, "", "");

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_TRUE(result) << (result ? "" : result.error().to_string());
}

TEST(BpfSignatureTest, MissingSigFailsWhenRequireBpfSig)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "no-sig-blob");

    ScopedEnvVar env_require("AEGIS_REQUIRE_BPF_SIG", "1");

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_FALSE(result);
}

TEST(BpfSignatureTest, BreakGlassOverridesInvalidSignature)
{
    TempDir temp;
    auto fx = make_obj_fixture(temp.path(), "break-glass-blob");

    // Invalid Ed25519 signature: 128 hex chars of zero, untrusted-anyway.
    write_sig_file(fx.obj_path, fx.hash_hex, std::string(64, '0'), std::string(128, '0'));

    ScopedEnvVar env_require("AEGIS_REQUIRE_BPF_SIG", "1");
    ScopedEnvVar env_break("AEGIS_ALLOW_UNSIGNED_BPF", "1");

    auto result = verify_bpf_signature(fx.obj_path.string());
    EXPECT_TRUE(result) << "break-glass should override sig failure";
}

} // namespace
} // namespace aegis
