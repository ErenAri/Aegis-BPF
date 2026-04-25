// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>
#include <vector>

#include "result.hpp"

namespace aegis {

/// One filesystem path the daemon should retain access to after the
/// Landlock sandbox is applied. `writable` controls whether write-side
/// rights are added on top of the read-side rights.
struct LandlockPath {
    std::string path;
    bool writable = false;
};

struct LandlockConfig {
    std::vector<LandlockPath> paths;
};

/// Build the default sandbox config based on the daemon's known
/// runtime path inventory (BPF maps, /etc/aegisbpf, /var/lib/aegisbpf,
/// /proc, /sys/kernel/btf, etc.). This is a static description; the
/// caller may extend it (for example to add `AEGIS_KEYS_DIR`).
LandlockConfig default_landlock_config();

/// Probe the running kernel for Landlock support.
/// Returns the supported ABI version (>= 1) or -1 if Landlock is not
/// available (CONFIG_SECURITY_LANDLOCK off, kernel < 5.13, or LSM
/// not enabled at boot).
int landlock_abi_version();

/// True when `landlock_abi_version() >= 1`.
bool landlock_available();

/// Apply the sandbox to the calling thread (and via thread-group
/// inheritance, the rest of the daemon). Idempotent in the sense that
/// each call layers further restrictions on top of any previous ones.
///
/// On kernels without Landlock the call returns success and logs an
/// informational message — the daemon is expected to continue with
/// other defences (seccomp, capability-drop, signed BPF, etc.).
Result<void> apply_landlock_sandbox(const LandlockConfig& config);

} // namespace aegis
