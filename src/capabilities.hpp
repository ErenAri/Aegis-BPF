// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "result.hpp"

namespace aegis {

/// Linux capability identifiers we care about, expressed as the same
/// integer values the kernel uses (`CAP_BPF` = 39, `CAP_PERFMON` = 38,
/// etc.). These mirror <linux/capability.h> but stay portable across
/// libc versions where some constants are not yet defined.
enum CapBit : int {
    AegisCapNone = -1,
    AegisCapDacReadSearch = 2,
    AegisCapNetAdmin = 12,
    AegisCapSysAdmin = 21,
    AegisCapSysPtrace = 19,
    AegisCapSysResource = 24,
    AegisCapPerfmon = 38,
    AegisCapBpf = 39,
};

/// Snapshot of the calling process's capability state.
struct CapabilitySnapshot {
    uint64_t effective = 0;
    uint64_t permitted = 0;
    uint64_t inheritable = 0;
};

/// True when running on a kernel that knows about CAP_BPF / CAP_PERFMON
/// (Linux >= 5.8). The check is done by trying to query the bounding
/// state of CAP_BPF; older kernels return EINVAL.
bool capabilities_split_supported();

/// Read the current effective/permitted/inheritable capability sets.
Result<CapabilitySnapshot> read_capabilities();

/// Drop the listed capabilities from every set the daemon controls:
/// effective, permitted, inheritable, bounding, and ambient. The call is
/// idempotent — caps that are already absent are silently ignored.
///
/// Failure to update one of the underlying sets returns an error and
/// leaves the process in an undefined intermediate state, so callers
/// should treat it as fatal.
Result<void> drop_capabilities(const std::vector<int>& caps_to_drop);

/// Capabilities the daemon retains after BPF programs have been loaded
/// and attached. Anything not in this set is dropped by
/// `apply_post_attach_cap_drop()`.
std::vector<int> default_post_attach_keep_set();

/// Convenience wrapper around `drop_capabilities()` that uses
/// `default_post_attach_keep_set()` to compute the drop list. Returns
/// the list of capability ids that were dropped (for logging).
Result<std::vector<int>> apply_post_attach_cap_drop();

/// Friendly name for a capability id, e.g. 39 -> "CAP_BPF".
const char* cap_name(int cap);

} // namespace aegis
