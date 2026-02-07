// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "result.hpp"

namespace aegis {

/// Apply seccomp-bpf filter to restrict system calls.
/// This should be called after all initialization is complete (BPF loaded, files opened).
/// Once applied, only allowed syscalls will work - all others will terminate the process.
Result<void> apply_seccomp_filter();

/// Check if seccomp is available on this system
bool seccomp_available();

} // namespace aegis
