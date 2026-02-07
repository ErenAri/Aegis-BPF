// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
/*
 * AegisBPF - Event Handling Fuzzer
 *
 * This fuzzer tests the event handling functions for crashes,
 * memory errors, and other undefined behavior when given malformed event data.
 *
 * Run with:
 *   ./fuzz_event corpus/ -max_total_time=300
 */

#include <cstdint>
#include <cstring>
#include <string>

#include "events.hpp"
#include "types.hpp"
#include "utils.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // First 4 bytes determine event type
    uint32_t event_type = *reinterpret_cast<const uint32_t*>(data);

    // Test based on event type
    if (event_type == aegis::EVENT_EXEC && size >= sizeof(aegis::ExecEvent)) {
        aegis::ExecEvent ev{};
        std::memcpy(&ev, data, std::min(size, sizeof(ev)));
        aegis::print_exec_event(ev);
    } else if (event_type == aegis::EVENT_BLOCK && size >= sizeof(aegis::BlockEvent)) {
        aegis::BlockEvent ev{};
        std::memcpy(&ev, data, std::min(size, sizeof(ev)));
        aegis::print_block_event(ev);
    } else if ((event_type == aegis::EVENT_NET_CONNECT_BLOCK || event_type == aegis::EVENT_NET_BIND_BLOCK) &&
               size >= sizeof(aegis::NetBlockEvent)) {
        aegis::NetBlockEvent ev{};
        std::memcpy(&ev, data, std::min(size, sizeof(ev)));
        aegis::print_net_block_event(ev);
    }

    // Also test utility functions used in event handling
    if (size >= 16) {
        std::string comm(reinterpret_cast<const char*>(data), 16);
        std::string str = aegis::to_string(comm.c_str(), 16);
        (void)str;
    }

    // Test exec_id building with fuzzed data
    if (size >= 12) {
        uint32_t pid = *reinterpret_cast<const uint32_t*>(data);
        uint64_t start_time = *reinterpret_cast<const uint64_t*>(data + 4);
        std::string exec_id = aegis::build_exec_id(pid, start_time);
        (void)exec_id;
    }

    return 0;
}
