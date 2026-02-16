// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "result.hpp"

namespace aegis {

/**
 * Kernel feature detection for AegisBPF.
 *
 * Detects available kernel features and determines the enforcement
 * capability level for the current system.
 */
struct KernelFeatures {
    bool bpf_lsm = false;       // BPF LSM support (full enforcement)
    bool ringbuf = false;       // Ring buffer support
    bool cgroup_v2 = false;     // cgroup v2 support
    bool btf = false;           // BTF (BPF Type Format) available
    bool bpf_syscall = false;   // BPF syscall available
    bool tracepoints = false;   // Tracepoints available
    bool sk_storage = false;    // BPF_MAP_TYPE_SK_STORAGE support (kernel 5.2+)
    bool ima = false;           // IMA securityfs availability
    bool ima_appraisal = false; // IMA appraisal policy active
    std::string kernel_version; // Kernel version string (e.g., "6.1.0")
    int kernel_major = 0;       // Major version number
    int kernel_minor = 0;       // Minor version number
    int kernel_patch = 0;       // Patch version number
};

/**
 * Enforcement capability level.
 *
 * Determines what level of enforcement is possible on this system.
 */
enum class EnforcementCapability {
    Full,      // LSM enforcement + all features
    AuditOnly, // Tracepoint only, can log but not block
    Disabled   // Cannot run at all, missing critical requirements
};

/**
 * Detect kernel features available on the current system.
 *
 * @return KernelFeatures struct with detected capabilities
 */
Result<KernelFeatures> detect_kernel_features();

/**
 * Determine enforcement capability based on kernel features.
 *
 * @param features Detected kernel features
 * @return Enforcement capability level
 */
EnforcementCapability determine_capability(const KernelFeatures& features);

/**
 * Get human-readable capability name.
 */
const char* capability_name(EnforcementCapability cap);

/**
 * Get a detailed explanation of why the given capability was determined.
 *
 * @param features Detected kernel features
 * @param cap Determined capability
 * @return Human-readable explanation
 */
std::string capability_explanation(const KernelFeatures& features, EnforcementCapability cap);

/**
 * Check if a specific kernel version meets minimum requirements.
 *
 * @param major Major version required
 * @param minor Minor version required (default 0)
 * @param patch Patch version required (default 0)
 * @return true if current kernel meets requirements
 */
bool kernel_version_at_least(int major, int minor = 0, int patch = 0);

/**
 * Parse kernel version string into major.minor.patch.
 *
 * @param version_str Kernel version string (e.g., "6.1.0-42-generic")
 * @param major Output major version
 * @param minor Output minor version
 * @param patch Output patch version
 * @return true if parsing succeeded
 */
bool parse_kernel_version(const std::string& version_str, int& major, int& minor, int& patch);

/**
 * Get the current kernel version string.
 *
 * @return Kernel version string or empty on error
 */
std::string get_kernel_version();

/**
 * Check if BPF LSM is enabled in the kernel.
 *
 * Reads /sys/kernel/security/lsm to check if 'bpf' is in the list.
 */
bool check_bpf_lsm_enabled();

/**
 * Check if cgroup v2 is available.
 *
 * Checks for /sys/fs/cgroup/cgroup.controllers.
 */
bool check_cgroup_v2();

/**
 * Check if BTF (BPF Type Format) is available.
 *
 * Checks for /sys/kernel/btf/vmlinux.
 */
bool check_btf_available();

/**
 * Check if bpffs is mounted.
 *
 * Checks for /sys/fs/bpf.
 */
bool check_bpffs_mounted();

/**
 * Check if IMA securityfs is available.
 *
 * Checks for /sys/kernel/security/ima.
 */
bool check_ima_available();

/**
 * Check if IMA appraisal policy is enabled.
 *
 * Reads /sys/kernel/security/ima/policy and looks for appraise rules.
 */
bool check_ima_appraisal_enabled();

} // namespace aegis
