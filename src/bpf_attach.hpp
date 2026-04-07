// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "result.hpp"

struct bpf_program;

namespace aegis {

class BpfState;

/// Attach a single BPF program (auto-detects LSM vs tracepoint by section name).
/// This is the single authoritative attach helper — all call-sites must use it.
Result<void> attach_prog(bpf_program* prog, BpfState& state);

Result<void> attach_all(BpfState& state, bool lsm_enabled, bool use_inode_permission, bool use_file_open,
                        bool attach_network_hooks);

} // namespace aegis
