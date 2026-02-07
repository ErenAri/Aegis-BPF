// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
/*
 * AegisBPF - Signed Bundle Parser Fuzzer
 *
 * This fuzzer tests the signed policy bundle parser for crashes,
 * memory errors, and other undefined behavior.
 *
 * Compile with:
 *   clang++ -fsanitize=fuzzer,address -I../../src fuzz_signed_bundle.cpp \
 *           ../../src/crypto.cpp ../../src/sha256.cpp ../../src/tweetnacl.c \
 *           -o fuzz_bundle
 *
 * Run with:
 *   ./fuzz_bundle corpus/ -max_total_time=300
 */

#include <cstdint>
#include <string>

#include "crypto.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Convert to string
    std::string content(reinterpret_cast<const char*>(data), size);

    // Test signed bundle parser
    auto result = aegis::parse_signed_bundle(content);

    // We don't care about the result - we're just looking for crashes
    (void)result;

    return 0;
}
