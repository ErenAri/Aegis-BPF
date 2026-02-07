// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
/*
 * AegisBPF - Path Validation Fuzzer
 *
 * This fuzzer tests the path validation functions for crashes,
 * memory errors, and other undefined behavior when given malformed input.
 *
 * Run with:
 *   ./fuzz_path corpus/ -max_total_time=300
 */

#include <cstdint>
#include <cstring>
#include <string>

#include "types.hpp"
#include "utils.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    std::string input(reinterpret_cast<const char*>(data), size);

    // Test basic path validation
    auto result = aegis::validate_path(input);
    (void)result;

    // Test inode ID parsing (format: dev:ino)
    aegis::InodeId id{};
    aegis::parse_inode_id(input, id);

    // Test uint64 parsing
    uint64_t val = 0;
    aegis::parse_uint64(input, val);

    // Test key=value parsing
    std::string key, value;
    aegis::parse_key_value(input, key, value);

    // Test string trimming
    std::string trimmed = aegis::trim(input);
    (void)trimmed;

    // Test JSON escaping
    std::string escaped = aegis::json_escape(input);
    (void)escaped;

    // Test Prometheus label escaping
    std::string prom_escaped = aegis::prometheus_escape_label(input);
    (void)prom_escaped;

    return 0;
}
