// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "bpf_signing.hpp"
#include "crypto.hpp"

namespace aegis {
namespace {

class TempDir {
  public:
    TempDir()
    {
        static uint64_t counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("aegisbpf_signing_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) + "_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(path_);
        ::chmod(path_.c_str(), 0700);
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

// Write a dummy "BPF object" with deterministic contents.
void write_object(const std::filesystem::path& obj_path, const std::string& contents)
{
    std::ofstream out(obj_path, std::ios::binary);
    ASSERT_TRUE(out.is_open());
    out << contents;
    out.close();
    ::chmod(obj_path.c_str(), 0600);
}

// Provision a trusted keystore containing `pub` and return the secret half.
// Returns false via fatal assertion on keygen failure.
void install_trusted_key(const std::filesystem::path& keys_dir, const PublicKey& pub)
{
    std::filesystem::create_directories(keys_dir);
    ::chmod(keys_dir.c_str(), 0700);
    const auto pub_path = keys_dir / "signer.pub";
    std::ofstream out(pub_path);
    ASSERT_TRUE(out.is_open());
    out << encode_hex(pub) << "\n";
    out.close();
    ::chmod(pub_path.c_str(), 0600);
}

// A correctly signed object verifies under AEGIS_REQUIRE_BPF_SIGNATURE when the
// signer's public key is in the trusted keystore.
TEST(BpfSigningTest, ValidSignatureVerifiesWhenRequired)
{
    TempDir dir;
    const auto obj = dir.path() / "aegis.bpf.o";
    const auto keys = dir.path() / "keys";
    write_object(obj, "dummy-bpf-object-contents");

    auto kp = generate_keypair();
    ASSERT_TRUE(kp.ok());
    install_trusted_key(keys, kp->first);

    auto signed_result = sign_bpf_object(obj.string(), kp->second, "test-signer");
    ASSERT_TRUE(signed_result.ok()) << signed_result.error().to_string();
    ASSERT_TRUE(std::filesystem::exists(obj.string() + ".sig"));

    ScopedEnvVar keys_env("AEGIS_KEYS_DIR", keys.string());
    ScopedEnvVar require_env("AEGIS_REQUIRE_BPF_SIGNATURE", "1");
    ScopedEnvVar allow_env("AEGIS_ALLOW_UNSIGNED_BPF", "0");

    auto verified = verify_bpf_signature(obj.string());
    EXPECT_TRUE(verified.ok()) << verified.error().to_string();
}

// Tampering with the object after signing breaks the SHA-256 binding, so
// verification fails closed when a signature is required.
TEST(BpfSigningTest, TamperedObjectFailsWhenRequired)
{
    TempDir dir;
    const auto obj = dir.path() / "aegis.bpf.o";
    const auto keys = dir.path() / "keys";
    write_object(obj, "original-contents");

    auto kp = generate_keypair();
    ASSERT_TRUE(kp.ok());
    install_trusted_key(keys, kp->first);
    ASSERT_TRUE(sign_bpf_object(obj.string(), kp->second, "test-signer").ok());

    // Swap the object contents for an attacker-controlled payload.
    write_object(obj, "malicious-payload");

    ScopedEnvVar keys_env("AEGIS_KEYS_DIR", keys.string());
    ScopedEnvVar require_env("AEGIS_REQUIRE_BPF_SIGNATURE", "1");
    ScopedEnvVar allow_env("AEGIS_ALLOW_UNSIGNED_BPF", "0");

    auto verified = verify_bpf_signature(obj.string());
    EXPECT_FALSE(verified.ok());
}

// A signature from a key that is not in the trusted keystore must be rejected
// even though the object hash itself matches (authenticity, not just integrity).
TEST(BpfSigningTest, UntrustedSignerFailsWhenRequired)
{
    TempDir dir;
    const auto obj = dir.path() / "aegis.bpf.o";
    const auto keys = dir.path() / "keys";
    write_object(obj, "dummy-bpf-object-contents");

    auto signer = generate_keypair();  // signs the object
    auto trusted = generate_keypair(); // the only key the daemon trusts
    ASSERT_TRUE(signer.ok());
    ASSERT_TRUE(trusted.ok());
    install_trusted_key(keys, trusted->first);
    ASSERT_TRUE(sign_bpf_object(obj.string(), signer->second, "rogue-signer").ok());

    ScopedEnvVar keys_env("AEGIS_KEYS_DIR", keys.string());
    ScopedEnvVar require_env("AEGIS_REQUIRE_BPF_SIGNATURE", "1");
    ScopedEnvVar allow_env("AEGIS_ALLOW_UNSIGNED_BPF", "0");

    auto verified = verify_bpf_signature(obj.string());
    EXPECT_FALSE(verified.ok());
}

// No signature sidecar at all, with signatures required, must fail closed.
TEST(BpfSigningTest, MissingSignatureFailsWhenRequired)
{
    TempDir dir;
    const auto obj = dir.path() / "aegis.bpf.o";
    write_object(obj, "dummy-bpf-object-contents");

    ScopedEnvVar require_env("AEGIS_REQUIRE_BPF_SIGNATURE", "1");
    ScopedEnvVar allow_env("AEGIS_ALLOW_UNSIGNED_BPF", "0");

    auto verified = verify_bpf_signature(obj.string());
    EXPECT_FALSE(verified.ok());
}

// Break-glass: AEGIS_ALLOW_UNSIGNED_BPF=1 permits a missing signature even when
// AEGIS_REQUIRE_BPF_SIGNATURE is set (escape hatch, logged as a warning).
TEST(BpfSigningTest, BreakGlassAllowsMissingSignature)
{
    TempDir dir;
    const auto obj = dir.path() / "aegis.bpf.o";
    write_object(obj, "dummy-bpf-object-contents");

    ScopedEnvVar require_env("AEGIS_REQUIRE_BPF_SIGNATURE", "1");
    ScopedEnvVar allow_env("AEGIS_ALLOW_UNSIGNED_BPF", "1");

    auto verified = verify_bpf_signature(obj.string());
    EXPECT_TRUE(verified.ok()) << verified.error().to_string();
}

} // namespace
} // namespace aegis
