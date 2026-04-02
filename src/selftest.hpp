// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>

#include "bpf_ops.hpp"
#include "result.hpp"

namespace aegis {

struct SelftestResult {
    bool maps_accessible = false;
    bool ringbuf_writable = false;
    bool config_readable = false;
    bool process_tree_writable = false;
    uint32_t maps_checked = 0;
    uint32_t maps_ok = 0;
    std::string failure_detail;
};

// Run startup self-tests after BPF load and before entering event loop.
// Validates that all critical maps are accessible and writable.
Result<SelftestResult> run_startup_selftests(const BpfState& state);

} // namespace aegis
