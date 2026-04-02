// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>

#include "bpf_ops.hpp"
#include "result.hpp"

namespace aegis {

struct ProcScanResult {
    uint32_t processes_scanned = 0;
    uint32_t processes_added = 0;
    uint32_t processes_skipped = 0; // already in map
    uint32_t errors = 0;
};

// Scan /proc to populate the process_tree BPF map with pre-existing processes.
// This handles processes that started before aegisbpf and would otherwise
// have no entry in the process tree (missed exec events).
Result<ProcScanResult> reconcile_proc_tree(const BpfState& state);

} // namespace aegis
