// cppcheck-suppress-file missingIncludeSystem
#include "kernel_features.hpp"

#include <sys/utsname.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "landlock.hpp"
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

bool version_at_least(int major, int minor, int req_major, int req_minor)
{
    return major > req_major || (major == req_major && minor >= req_minor);
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
    return lsm_list_contains(read_lsm_list(), "bpf");
}

std::string read_lsm_list()
{
    std::ifstream lsm(env_path_or_default("AEGIS_LSM_PATH", "/sys/kernel/security/lsm"));
    std::string line;
    if (!lsm.is_open() || !std::getline(lsm, line)) {
        return {};
    }
    return line;
}

std::vector<std::string> split_lsm_list(const std::string& lsm_list)
{
    std::vector<std::string> tokens;
    std::string current;
    std::istringstream input(lsm_list);
    while (std::getline(input, current, ',')) {
        const auto begin = current.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos) {
            continue;
        }
        const auto end = current.find_last_not_of(" \t\r\n");
        tokens.push_back(current.substr(begin, end - begin + 1));
    }
    return tokens;
}

bool lsm_list_contains(const std::string& lsm_list, const std::string& name)
{
    for (const auto& token : split_lsm_list(lsm_list)) {
        if (token == name) {
            return true;
        }
    }
    return false;
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

bool check_ima_available()
{
    std::error_code ec;
    return std::filesystem::exists(env_path_or_default("AEGIS_IMA_DIR_PATH", "/sys/kernel/security/ima"), ec);
}

bool check_ima_appraisal_enabled()
{
    std::ifstream policy(env_path_or_default("AEGIS_IMA_POLICY_PATH", "/sys/kernel/security/ima/policy"));
    std::string line;
    if (!policy.is_open()) {
        return false;
    }

    while (std::getline(policy, line)) {
        std::istringstream iss(line);
        std::string token;
        while (iss >> token) {
            if (token == "appraise" || token.rfind("appraise_", 0) == 0) {
                return true;
            }
        }
    }
    return false;
}

int check_landlock_abi_version()
{
    const char* override_path = std::getenv("AEGIS_LANDLOCK_ABI_PATH");
    if (override_path != nullptr && *override_path != '\0') {
        std::ifstream input(override_path);
        int abi = -1;
        if (input >> abi) {
            return abi;
        }
        return -1;
    }
    return landlock_abi_version();
}

bool check_ipe_available(const std::string& lsm_list)
{
    const std::string active_lsms = lsm_list.empty() ? read_lsm_list() : lsm_list;
    std::error_code ec;
    return lsm_list_contains(active_lsms, "ipe") ||
           std::filesystem::exists(env_path_or_default("AEGIS_IPE_DIR_PATH", "/sys/kernel/security/ipe"), ec);
}

bool check_fs_verity_available()
{
    std::error_code ec;
    return std::filesystem::exists(
        env_path_or_default("AEGIS_FS_VERITY_SYSCTL_PATH", "/proc/sys/fs/verity/require_signatures"), ec);
}

bool check_bpf_token_supported(int kernel_major, int kernel_minor)
{
    return version_at_least(kernel_major, kernel_minor, 6, 9);
}

bool check_bpf_arena_supported(int kernel_major, int kernel_minor)
{
    return version_at_least(kernel_major, kernel_minor, 6, 9);
}

bool check_user_ringbuf_supported(int kernel_major, int kernel_minor)
{
    return version_at_least(kernel_major, kernel_minor, 6, 1);
}

bool check_sched_ext_available()
{
    std::error_code ec;
    return std::filesystem::exists(env_path_or_default("AEGIS_SCHED_EXT_PATH", "/sys/kernel/sched_ext"), ec);
}

bool check_open_coded_iterators_supported(int kernel_major, int kernel_minor)
{
    return version_at_least(kernel_major, kernel_minor, 6, 4);
}

bool check_bpf_xattr_kfuncs_supported(int kernel_major, int kernel_minor, bool bpf_lsm)
{
    return bpf_lsm && version_at_least(kernel_major, kernel_minor, 6, 8);
}

bool check_bpf_send_signal_task_supported(int kernel_major, int kernel_minor)
{
    return version_at_least(kernel_major, kernel_minor, 6, 13);
}

bool check_binary_auth_supported(bool fs_verity, bool bpf_lsm, bool bpf_xattr_kfuncs)
{
    return fs_verity && bpf_lsm && bpf_xattr_kfuncs;
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
    features.lsm_list = read_lsm_list();
    features.bpf_lsm = check_bpf_lsm_enabled();
    features.cgroup_v2 = check_cgroup_v2();
    features.btf = check_btf_available();
    features.bpf_syscall = check_bpf_syscall();
    features.ringbuf = check_ringbuf_support();
    features.tracepoints = check_tracepoints_available();
    features.ima = check_ima_available();
    features.ima_appraisal = features.ima && check_ima_appraisal_enabled();
    features.bpf_ima_helpers = features.kernel_major > 6 || (features.kernel_major == 6 && features.kernel_minor >= 1);
    features.landlock_abi = check_landlock_abi_version();
    features.landlock = features.landlock_abi >= 1;
    features.ipe = check_ipe_available(features.lsm_list);
    features.fs_verity = check_fs_verity_available();
    features.bpf_token = check_bpf_token_supported(features.kernel_major, features.kernel_minor);
    features.bpf_arena = check_bpf_arena_supported(features.kernel_major, features.kernel_minor);
    features.user_ringbuf = check_user_ringbuf_supported(features.kernel_major, features.kernel_minor);
    features.sched_ext = check_sched_ext_available();
    features.open_coded_iterators = check_open_coded_iterators_supported(features.kernel_major, features.kernel_minor);
    features.bpf_xattr_kfuncs =
        check_bpf_xattr_kfuncs_supported(features.kernel_major, features.kernel_minor, features.bpf_lsm);
    features.bpf_send_signal_task = check_bpf_send_signal_task_supported(features.kernel_major, features.kernel_minor);
    features.binary_auth = check_binary_auth_supported(features.fs_verity, features.bpf_lsm, features.bpf_xattr_kfuncs);

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

    // The shipped BPF object uses ring buffer maps for event delivery, so
    // ring buffer support is required for both enforce and audit operation.
    if (!features.ringbuf) {
        return EnforcementCapability::Disabled;
    }

    // Check for full enforcement
    if (features.bpf_lsm) {
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
            if (!features.ringbuf) {
                missing.push_back("ring buffer support (kernel 5.8+)");
            }
            if (!features.bpf_lsm && !features.tracepoints) {
                missing.push_back("either BPF LSM or tracepoints");
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
