// cppcheck-suppress-file missingIncludeSystem
#include "kernel_features.hpp"

#include <sys/utsname.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "logging.hpp"

namespace aegis {

namespace {

std::string env_path_or_default(const char* env_name, const char* fallback)
{
    const char* value = std::getenv(env_name);
    if (value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::string(fallback);
}

} // namespace

std::string get_kernel_version()
{
    struct utsname uts {};
    if (uname(&uts) != 0) {
        return {};
    }
    return std::string(uts.release);
}

bool parse_kernel_version(const std::string& version_str, int& major, int& minor, int& patch)
{
    major = minor = patch = 0;
    if (version_str.empty()) {
        return false;
    }

    // Parse "X.Y.Z-extra" format
    char extra[256] = {0};
    int parsed = std::sscanf(version_str.c_str(), "%d.%d.%d%255s", &major, &minor, &patch, extra);
    return parsed >= 2; // At least major.minor is required
}

bool kernel_version_at_least(int req_major, int req_minor, int req_patch)
{
    std::string version = get_kernel_version();
    int major = 0, minor = 0, patch = 0;
    if (!parse_kernel_version(version, major, minor, patch)) {
        return false;
    }

    if (major > req_major)
        return true;
    if (major < req_major)
        return false;
    if (minor > req_minor)
        return true;
    if (minor < req_minor)
        return false;
    return patch >= req_patch;
}

bool check_bpf_lsm_enabled()
{
    std::ifstream lsm(env_path_or_default("AEGIS_LSM_PATH", "/sys/kernel/security/lsm"));
    std::string line;
    if (!lsm.is_open() || !std::getline(lsm, line)) {
        return false;
    }
    return line.find("bpf") != std::string::npos;
}

bool check_cgroup_v2()
{
    std::error_code ec;
    return std::filesystem::exists(
        env_path_or_default("AEGIS_CGROUP_CONTROLLERS_PATH", "/sys/fs/cgroup/cgroup.controllers"), ec);
}

bool check_btf_available()
{
    std::error_code ec;
    return std::filesystem::exists(env_path_or_default("AEGIS_BTF_VMLINUX_PATH", "/sys/kernel/btf/vmlinux"), ec);
}

bool check_bpffs_mounted()
{
    std::error_code ec;
    return std::filesystem::exists(env_path_or_default("AEGIS_BPFFS_PATH", "/sys/fs/bpf"), ec);
}

static bool check_tracepoints_available()
{
    std::error_code ec;
    // Check for tracepoint infrastructure
    return std::filesystem::exists(env_path_or_default("AEGIS_TRACEFS_DEBUG_PATH", "/sys/kernel/debug/tracing"), ec) ||
           std::filesystem::exists(env_path_or_default("AEGIS_TRACEFS_PATH", "/sys/kernel/tracing"), ec);
}

static bool check_ringbuf_support()
{
    // Ring buffer was added in kernel 5.8
    return kernel_version_at_least(5, 8, 0);
}

static bool check_bpf_syscall()
{
    // BPF syscall check - if we can read /proc/sys/kernel/unprivileged_bpf_disabled
    // or /sys/fs/bpf exists, BPF syscall is available
    std::error_code ec;
    return std::filesystem::exists(
               env_path_or_default("AEGIS_UNPRIV_BPF_DISABLED_PATH", "/proc/sys/kernel/unprivileged_bpf_disabled"),
               ec) ||
           check_bpffs_mounted();
}

Result<KernelFeatures> detect_kernel_features()
{
    KernelFeatures features;

    // Get kernel version
    features.kernel_version = get_kernel_version();
    if (features.kernel_version.empty()) {
        return Error(ErrorCode::ResourceNotFound, "Failed to get kernel version");
    }

    if (!parse_kernel_version(features.kernel_version, features.kernel_major, features.kernel_minor,
                              features.kernel_patch)) {
        return Error(ErrorCode::InvalidArgument, "Failed to parse kernel version", features.kernel_version);
    }

    // Detect individual features
    features.bpf_lsm = check_bpf_lsm_enabled();
    features.cgroup_v2 = check_cgroup_v2();
    features.btf = check_btf_available();
    features.bpf_syscall = check_bpf_syscall();
    features.ringbuf = check_ringbuf_support();
    features.tracepoints = check_tracepoints_available();

    return features;
}

EnforcementCapability determine_capability(const KernelFeatures& features)
{
    // Check critical requirements for any operation
    if (!features.bpf_syscall) {
        return EnforcementCapability::Disabled;
    }

    if (!features.cgroup_v2) {
        return EnforcementCapability::Disabled;
    }

    if (!features.btf) {
        return EnforcementCapability::Disabled;
    }

    // Check for full enforcement
    if (features.bpf_lsm && features.ringbuf) {
        return EnforcementCapability::Full;
    }

    // Check for audit-only mode
    if (features.tracepoints) {
        return EnforcementCapability::AuditOnly;
    }

    return EnforcementCapability::Disabled;
}

const char* capability_name(EnforcementCapability cap)
{
    switch (cap) {
        case EnforcementCapability::Full:
            return "Full";
        case EnforcementCapability::AuditOnly:
            return "AuditOnly";
        case EnforcementCapability::Disabled:
            return "Disabled";
    }
    return "Unknown";
}

std::string capability_explanation(const KernelFeatures& features, EnforcementCapability cap)
{
    std::ostringstream oss;

    switch (cap) {
        case EnforcementCapability::Full:
            oss << "Full enforcement available. BPF LSM is enabled, "
                << "allowing file access to be blocked and processes to be killed.";
            break;

        case EnforcementCapability::AuditOnly:
            oss << "Audit-only mode. ";
            if (!features.bpf_lsm) {
                oss << "BPF LSM is not enabled in the kernel. "
                    << "To enable, add 'lsm=bpf' (or 'lsm=landlock,lockdown,yama,bpf') "
                    << "to kernel boot parameters. ";
            }
            if (!features.ringbuf) {
                oss << "Ring buffer not available (requires kernel 5.8+). ";
            }
            oss << "File access will be logged but not blocked.";
            break;

        case EnforcementCapability::Disabled:
            oss << "Cannot run AegisBPF. Missing requirements: ";
            std::vector<std::string> missing;
            if (!features.bpf_syscall) {
                missing.push_back("BPF syscall (CONFIG_BPF_SYSCALL)");
            }
            if (!features.cgroup_v2) {
                missing.push_back("cgroup v2 (mount with cgroup2)");
            }
            if (!features.btf) {
                missing.push_back("BTF (/sys/kernel/btf/vmlinux)");
            }
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0)
                    oss << ", ";
                oss << missing[i];
            }
            oss << ".";
            break;
    }

    return oss.str();
}

} // namespace aegis
