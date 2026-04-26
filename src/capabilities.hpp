// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <vector>

#include "result.hpp"

namespace aegis {

/// Capability identifiers we care about. Numeric values match the
/// kernel's `linux/capability.h` macros, but we redeclare them here so
/// the header does not depend on libcap-ng or kernel headers.
///
/// The minimum-runtime set documented in `docs/HARDENING.md` is
/// `{CAP_BPF, CAP_PERFMON, CAP_DAC_READ_SEARCH}`. CAP_SYS_RESOURCE
/// is also retained on kernels that still need it for `setrlimit`
/// memory-lock bumps; on kernel >= 5.11 the bpf() syscall handles
/// memlock automatically and the cap is unnecessary.
namespace cap {
inline constexpr int kDacReadSearch = 2;   // CAP_DAC_READ_SEARCH
inline constexpr int kSetPCap       = 8;   // CAP_SETPCAP
inline constexpr int kSysAdmin      = 21;  // CAP_SYS_ADMIN
inline constexpr int kSysResource   = 24;  // CAP_SYS_RESOURCE
inline constexpr int kSysPtrace     = 19;  // CAP_SYS_PTRACE
inline constexpr int kPerfmon       = 38;  // CAP_PERFMON
inline constexpr int kBpf           = 39;  // CAP_BPF
}  // namespace cap

struct CapabilityConfig {
    /// Capabilities to retain in the effective + permitted sets after
    /// the drop. Everything else is removed from those two sets.
    std::vector<int> retain;

    /// If true, the inheritable set is unconditionally cleared. New
    /// processes the daemon spawns (it does not, but defense in depth)
    /// will then start with no inherited caps.
    bool clear_inheritable = true;

    /// If true, the bounding set is reduced to `retain`. This is the
    /// only set that prevents `execve()` from regaining caps, so
    /// dropping it closes a class of bypass even though the daemon
    /// does not exec.
    bool clear_bounding = true;

    /// If true, the ambient set is unconditionally cleared. Same
    /// rationale as `clear_inheritable`.
    bool clear_ambient = true;
};

/// Build the default minimum-runtime config:
///   retain = {CAP_BPF, CAP_PERFMON, CAP_DAC_READ_SEARCH, CAP_SYS_RESOURCE}
///   clear_inheritable = clear_bounding = clear_ambient = true
CapabilityConfig default_capability_config();

/// True when the running kernel exposes the fine-grained CAP_BPF /
/// CAP_PERFMON split (introduced in Linux 5.8). When this returns
/// false, dropping to the default config would be too aggressive
/// because CAP_SYS_ADMIN is still required for bpf(2) and many BPF
/// helpers — `drop_to_minimum()` then logs a warning and returns
/// success without dropping.
bool capabilities_split_supported();

/// Drop the calling thread's capability sets to the minimum required
/// for AegisBPF runtime operation per `docs/HARDENING.md`.
///
/// Pre-conditions:
///   * Caller holds CAP_SETPCAP (true while running as root).
///   * All BPF programs are already loaded and attached.
///   * All ring buffers are open.
///   * No worker threads have been spawned yet (Linux capabilities
///     are per-thread; pthread_create inherits the calling thread's
///     set, so calling this function before spawning workers
///     guarantees the workers also start with the reduced set).
///
/// Post-conditions on success:
///   * The effective and permitted sets contain only the capabilities
///     listed in `config.retain`.
///   * If `config.clear_inheritable` is true, the inheritable set is
///     empty.
///   * If `config.clear_bounding` is true, the bounding set is the
///     intersection of its previous value with `config.retain`.
///   * If `config.clear_ambient` is true, the ambient set is empty.
///
/// On kernels without CAP_BPF / CAP_PERFMON (Linux < 5.8) this
/// function logs an INFO message and returns success without
/// dropping. The daemon continues with full root caps; other
/// hardening (seccomp, Landlock, signed BPF) is unaffected.
///
/// On any underlying syscall failure the function returns an error
/// and leaves the calling thread's capability state unchanged where
/// possible. Operators are expected to fail-closed on this error
/// during init.
Result<void> drop_to_minimum(const CapabilityConfig& config);

/// Read the current thread's capability sets from the kernel and
/// return them as four 64-bit bitmasks (effective, permitted,
/// inheritable, bounding). Used by tests to verify drop_to_minimum()
/// actually took effect; not intended for runtime use.
struct CapabilitySnapshot {
    uint64_t effective = 0;
    uint64_t permitted = 0;
    uint64_t inheritable = 0;
    uint64_t bounding = 0;
};

Result<CapabilitySnapshot> read_capability_snapshot();

}  // namespace aegis
