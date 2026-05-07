// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Ring buffer overflow policy parsing helpers
 */

#include "ringbuf_policy.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace aegis {

namespace {

std::string normalize_policy_name(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if (c == '_')
            out.push_back('-');
        else
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool is_reserved_policy_name(const std::string& canonical)
{
    return canonical == "sample" || canonical == "spool" || canonical == "spool-to-disk";
}

} // namespace

bool parse_ringbuf_overflow_policy(const std::string& value, RingbufOverflowPolicy& out,
                                   RingbufOverflowPolicyParseError& err)
{
    if (value.empty()) {
        out = RingbufOverflowPolicy::PriorityFallback;
        return true;
    }
    const std::string canonical = normalize_policy_name(value);
    if (canonical == "priority-fallback") {
        out = RingbufOverflowPolicy::PriorityFallback;
        return true;
    }
    if (is_reserved_policy_name(canonical)) {
        err = RingbufOverflowPolicyParseError::Reserved;
        return false;
    }
    err = RingbufOverflowPolicyParseError::Unknown;
    return false;
}

const char* ringbuf_overflow_policy_name(RingbufOverflowPolicy policy)
{
    switch (policy) {
        case RingbufOverflowPolicy::PriorityFallback:
            return "priority-fallback";
    }
    return "unknown";
}

const char* ringbuf_overflow_policy_description(RingbufOverflowPolicy policy)
{
    switch (policy) {
        case RingbufOverflowPolicy::PriorityFallback:
            return "security-critical events use the priority ringbuf and fall back to the main "
                   "ringbuf on pressure; telemetry is shed first";
    }
    return "unknown";
}

} // namespace aegis
