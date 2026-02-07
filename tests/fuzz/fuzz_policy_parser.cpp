// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
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

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <string>

#include "policy.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    char path[] = "/tmp/aegisbpf-policy-fuzz-XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }

    size_t remaining = size;
    const uint8_t* cursor = data;
    while (remaining > 0) {
        const ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            std::remove(path);
            return 0;
        }
        cursor += static_cast<size_t>(written);
        remaining -= static_cast<size_t>(written);
    }
    close(fd);

    // Test policy parser
    aegis::PolicyIssues issues;
    auto result = aegis::parse_policy_file(path, issues);
    std::remove(path);

    // We don't care about the result - we're just looking for crashes
    (void)result;
    (void)issues;

    return 0;
}
