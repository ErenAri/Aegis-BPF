// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <array>
#include <cstdint>
#include <cstring>

extern "C" {
#include "tweetnacl.h"
}

namespace aegis {
namespace crypto_safe {

/**
 * Maximum message size for stack-based signature operations.
 * This is sufficient for all current use cases (signing metadata strings).
 * If you need to sign larger messages, consider streaming/chunking approaches.
 */
constexpr size_t kMaxMessageSize = 4096;

/**
 * Safe wrapper for crypto_sign_detached that uses stack allocation instead of malloc.
 *
 * This prevents memory exhaustion attacks via repeated signature operations.
 *
 * @param sig Output buffer for 64-byte signature
 * @param m Message to sign
 * @param mlen Length of message (must be <= kMaxMessageSize)
 * @param sk Secret key (64 bytes)
 * @return 0 on success, -1 on failure
 */
inline int crypto_sign_detached_safe(uint8_t* sig, const uint8_t* m, unsigned long long mlen, const uint8_t* sk)
{
    // Reject messages that are too large for stack allocation
    if (mlen > kMaxMessageSize) {
        return -1;
    }

    // Use stack-allocated buffer instead of malloc
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
    uint8_t sm[kMaxMessageSize + 64];
    unsigned long long smlen;

    // Call the original crypto_sign function
    int rc = crypto_sign(sm, &smlen, m, mlen, sk);
    if (rc == 0) {
        std::memcpy(sig, sm, 64);
    }

    // Zero out the stack buffer for security
    volatile uint8_t* volatile_sm = sm;
    for (size_t i = 0; i < sizeof(sm); ++i) {
        volatile_sm[i] = 0;
    }

    return rc;
}

/**
 * Safe wrapper for crypto_sign_verify_detached that uses stack allocation instead of malloc.
 *
 * This prevents memory exhaustion attacks via repeated signature verification.
 *
 * @param sig Signature to verify (64 bytes)
 * @param m Message that was signed
 * @param mlen Length of message (must be <= kMaxMessageSize)
 * @param pk Public key (32 bytes)
 * @return 0 on success, -1 on failure
 */
inline int crypto_sign_verify_detached_safe(const uint8_t* sig, const uint8_t* m, unsigned long long mlen,
                                            const uint8_t* pk)
{
    // Reject messages that are too large for stack allocation
    if (mlen > kMaxMessageSize) {
        return -1;
    }

    // Use stack-allocated buffers instead of malloc
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
    uint8_t sm[kMaxMessageSize + 64];
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
    uint8_t tmp[kMaxMessageSize + 64];

    // Prepare the signed message
    std::memcpy(sm, sig, 64);
    std::memcpy(sm + 64, m, mlen);

    // Verify the signature
    unsigned long long tmplen;
    int rc = crypto_sign_open(tmp, &tmplen, sm, mlen + 64, pk);

    // Zero out the stack buffers for security
    volatile uint8_t* volatile_sm = sm;
    volatile uint8_t* volatile_tmp = tmp;
    for (size_t i = 0; i < sizeof(sm); ++i) {
        volatile_sm[i] = 0;
    }
    for (size_t i = 0; i < sizeof(tmp); ++i) {
        volatile_tmp[i] = 0;
    }

    return rc;
}

} // namespace crypto_safe
} // namespace aegis
