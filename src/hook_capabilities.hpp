// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>
#include <vector>

namespace aegis {

/**
 * Per-LSM-hook kernel attachability report.
 *
 * AegisBPF attaches a fixed set of LSM hooks (some required, most optional)
 * to enforce its policy. Whether each hook can actually be attached on a
 * given kernel depends on whether the kernel exposes the matching trampoline
 * symbol via BTF (e.g. `bpf_lsm_socket_listen` for the `socket_listen` hook).
 *
 * `probe_hook_capabilities()` answers, for each hook AegisBPF cares about,
 * "would this kernel let us attach it?" without requiring AegisBPF itself
 * to be running. This complements the runtime attachment status that the
 * daemon writes to `/var/lib/aegisbpf/capabilities.json` after startup.
 */
struct HookCapability {
    std::string name;       // Stable JSON key, e.g. "lsm_socket_listen".
    std::string btf_symbol; // BPF-LSM trampoline symbol, e.g. "bpf_lsm_socket_listen".
    bool required = false;  // True for hooks AegisBPF cannot run without (file_open, inode_permission).
    bool kernel_supported = false;
    std::string description; // One-line human-readable summary.
};

/**
 * Probe `/sys/kernel/btf/vmlinux` (or the AEGIS_BTF_PATH override) for every
 * LSM hook AegisBPF knows about and report whether each one is available on
 * the current kernel.
 *
 * If BTF is unavailable, every entry is reported with `kernel_supported = false`.
 * Callers can detect that case via the parallel `btf_available` out-parameter.
 */
std::vector<HookCapability> probe_hook_capabilities(bool* btf_available = nullptr);

} // namespace aegis
