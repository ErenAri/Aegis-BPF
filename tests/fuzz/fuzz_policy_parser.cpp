/*
 * AegisBPF - Policy Parser Fuzzer
 *
 * This fuzzer tests the policy file parser for crashes, memory errors,
 * and other undefined behavior when given malformed input.
 *
 * Compile with:
 *   clang++ -fsanitize=fuzzer,address -I../../src fuzz_policy_parser.cpp \
 *           ../../src/policy.cpp ../../src/utils.cpp ../../src/sha256.cpp \
 *           -lbpf -o fuzz_policy
 *
 * Run with:
 *   ./fuzz_policy corpus/ -max_total_time=300
 */

#include "policy.hpp"
#include "crypto.hpp"
#include "types.hpp"

#include <cstdint>
#include <cstring>
#include <string>

// Forward declarations for functions we want to fuzz
namespace aegis {
extern Result<Policy> parse_policy_content(const std::string& content, PolicyIssues& issues);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Convert to string
    std::string content(reinterpret_cast<const char*>(data), size);

    // Test policy parser
    aegis::PolicyIssues issues;
    auto result = aegis::parse_policy_content(content, issues);

    // We don't care about the result - we're just looking for crashes
    (void)result;
    (void)issues;

    return 0;
}
