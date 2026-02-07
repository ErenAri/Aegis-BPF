// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
/*
 * AegisBPF - Network Rules Fuzzer
 *
 * This fuzzer tests the network rule parsing functions for crashes,
 * memory errors, and other undefined behavior when given malformed input.
 *
 * Run with:
 *   ./fuzz_network corpus/ -max_total_time=300
 */

#include <cstdint>
#include <cstring>
#include <string>

#include "network_ops.hpp"
#include "types.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    std::string input(reinterpret_cast<const char*>(data), size);

    // Test IPv4 parsing
    uint32_t ip_be = 0;
    aegis::parse_ipv4(input, ip_be);
    aegis::Ipv6Key ipv6{};
    aegis::parse_ipv6(input, ipv6);

    // Test CIDR parsing
    uint8_t prefix_len = 0;
    aegis::parse_cidr_v4(input, ip_be, prefix_len);
    aegis::parse_cidr_v6(input, ipv6, prefix_len);

    // Test port parsing with various formats
    // Format: port[:protocol[:direction]]
    if (size >= 1) {
        // Try parsing as port number
        try {
            uint16_t port = static_cast<uint16_t>(std::stoul(input.substr(0, std::min(size, size_t(5)))));
            (void)port;
        } catch (...) {  // NOLINT(bugprone-empty-catch)
            // Expected for malformed input - fuzzing intentionally tests error cases
        }
    }

    // Test IP formatting (inverse operation)
    std::string formatted = aegis::format_ipv4(ip_be);
    (void)formatted;
    std::string formatted_v6 = aegis::format_ipv6(ipv6);
    (void)formatted_v6;

    return 0;
}
