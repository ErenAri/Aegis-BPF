// Test for safe crypto wrappers that prevent memory exhaustion attacks
#include <gtest/gtest.h>

#include <array>
#include <string>

#include "crypto.hpp"
#include "tweetnacl_safe.hpp"

extern "C" {
#include "tweetnacl.h"
}

namespace {

using aegis::PublicKey;
using aegis::SecretKey;
using aegis::Signature;

class CryptoSafeTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Generate a test keypair
        ASSERT_EQ(crypto_sign_keypair(pk.data(), sk.data()), 0);
    }

    PublicKey pk{};
    SecretKey sk{};
};

TEST_F(CryptoSafeTest, SignSmallMessageSucceeds)
{
    std::string message = "test message";
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk.data());

    EXPECT_EQ(result, 0);
}

TEST_F(CryptoSafeTest, VerifySmallMessageSucceeds)
{
    std::string message = "test message";
    Signature sig{};

    // Sign the message first
    ASSERT_EQ(aegis::crypto_safe::crypto_sign_detached_safe(sig.data(),
                                                             reinterpret_cast<const uint8_t*>(message.data()),
                                                             message.size(), sk.data()),
              0);

    // Verify it
    int result = aegis::crypto_safe::crypto_sign_verify_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), pk.data());

    EXPECT_EQ(result, 0);
}

TEST_F(CryptoSafeTest, SignLargeMessageWithinLimitSucceeds)
{
    // Create a message just under the limit (4096 bytes)
    std::string message(aegis::crypto_safe::kMaxMessageSize - 1, 'A');
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk.data());

    EXPECT_EQ(result, 0);
}

TEST_F(CryptoSafeTest, SignMessageExceedingLimitFails)
{
    // Create a message exceeding the limit (> 4096 bytes)
    std::string message(aegis::crypto_safe::kMaxMessageSize + 1, 'A');
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk.data());

    // Should fail due to size limit
    EXPECT_EQ(result, -1);
}

TEST_F(CryptoSafeTest, VerifyMessageExceedingLimitFails)
{
    // Create a message exceeding the limit
    std::string message(aegis::crypto_safe::kMaxMessageSize + 1, 'A');
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_verify_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), pk.data());

    // Should fail due to size limit
    EXPECT_EQ(result, -1);
}

TEST_F(CryptoSafeTest, PolicySignatureStringsFitWithinLimit)
{
    // Verify that typical policy signature strings fit within the limit
    // Format: sha256(64) + version(~20) + timestamp(~20) + expires(~20) = ~124 bytes
    std::string policy_sha256(64, 'a');
    std::string sign_data = policy_sha256 + "18446744073709551615" + "18446744073709551615" + "18446744073709551615";

    // This should be well under kMaxMessageSize (4096)
    EXPECT_LT(sign_data.size(), aegis::crypto_safe::kMaxMessageSize);
    EXPECT_LT(sign_data.size(), 200); // Should be < 200 bytes
}

TEST_F(CryptoSafeTest, HighLevelAPIUsesSecureWrapper)
{
    // Verify that the high-level API (sign_bytes/verify_bytes) works correctly
    std::string message = "high-level test message";
    auto sig_result = aegis::sign_bytes(reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk);

    ASSERT_TRUE(sig_result);
    Signature sig = *sig_result;

    bool verified = aegis::verify_bytes(reinterpret_cast<const uint8_t*>(message.data()), message.size(), sig, pk);
    EXPECT_TRUE(verified);
}

TEST_F(CryptoSafeTest, HighLevelAPIRejectsOversizedMessage)
{
    // Create a message that exceeds the safe limit
    std::vector<uint8_t> large_message(aegis::crypto_safe::kMaxMessageSize + 1, 0xAA);
    auto sig_result = aegis::sign_bytes(large_message.data(), large_message.size(), sk);

    // Should fail gracefully
    EXPECT_FALSE(sig_result);
    if (!sig_result) {
        EXPECT_EQ(sig_result.error().code(), aegis::ErrorCode::CryptoError);
    }
}

TEST_F(CryptoSafeTest, MemoryIsClearedAfterSigning)
{
    // This test verifies that sensitive data is cleared from the stack
    // Note: This is a best-effort test; actual verification would require
    // memory inspection tools or sanitizers
    std::string message = "sensitive data";
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk.data());

    EXPECT_EQ(result, 0);
    // The function should have zeroed out the stack buffer
    // (verified by code inspection, not runtime check)
}

TEST_F(CryptoSafeTest, SignEmptyMessageSucceeds)
{
    // Edge case: signing a zero-length message should succeed
    std::string message = "";
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk.data());

    EXPECT_EQ(result, 0);

    // Verify the signature
    int verify_result = aegis::crypto_safe::crypto_sign_verify_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), pk.data());

    EXPECT_EQ(verify_result, 0);
}

TEST_F(CryptoSafeTest, VerifyInvalidSignatureFails)
{
    // Test that verification fails with an incorrect signature
    std::string message = "test message";
    Signature sig{};

    // Create a valid signature first
    ASSERT_EQ(aegis::crypto_safe::crypto_sign_detached_safe(sig.data(),
                                                             reinterpret_cast<const uint8_t*>(message.data()),
                                                             message.size(), sk.data()),
              0);

    // Corrupt the signature
    sig[0] ^= 0xFF;

    // Verification should fail
    int result = aegis::crypto_safe::crypto_sign_verify_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), pk.data());

    EXPECT_NE(result, 0);
}

TEST_F(CryptoSafeTest, SignExactlyAtLimitSucceeds)
{
    // Test signing a message exactly at the maximum size limit
    std::string message(aegis::crypto_safe::kMaxMessageSize, 'X');
    Signature sig{};

    int result = aegis::crypto_safe::crypto_sign_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), sk.data());

    EXPECT_EQ(result, 0);

    // Verify the signature
    int verify_result = aegis::crypto_safe::crypto_sign_verify_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), pk.data());

    EXPECT_EQ(verify_result, 0);
}

TEST_F(CryptoSafeTest, VerifyWithWrongPublicKeyFails)
{
    // Test that verification fails when using a different public key
    std::string message = "test message";
    Signature sig{};

    // Sign with original keypair
    ASSERT_EQ(aegis::crypto_safe::crypto_sign_detached_safe(sig.data(),
                                                             reinterpret_cast<const uint8_t*>(message.data()),
                                                             message.size(), sk.data()),
              0);

    // Generate a different keypair
    PublicKey wrong_pk{};
    SecretKey wrong_sk{};
    ASSERT_EQ(crypto_sign_keypair(wrong_pk.data(), wrong_sk.data()), 0);

    // Verification should fail with wrong public key
    int result = aegis::crypto_safe::crypto_sign_verify_detached_safe(
        sig.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), wrong_pk.data());

    EXPECT_NE(result, 0);
}

} // anonymous namespace
