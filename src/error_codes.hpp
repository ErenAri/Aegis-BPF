// cppcheck-suppress-file missingIncludeSystem
#pragma once
/*
 * AegisBPF - Structured Error Codes
 *
 * Provides stable error codes for programmatic error handling and
 * user-friendly error messages.
 */

#include <string>

namespace aegis {

/**
 * Structured error codes for AegisBPF operations.
 *
 * These codes are stable across versions and can be used for:
 * - Programmatic error handling in automation
 * - User-friendly error messages
 * - Documentation and troubleshooting
 */
enum class AegisErrorCode {
    // Success (0)
    Success = 0,

    // Kernel compatibility (1000-1099)
    KernelTooOld = 1000,
    BpfLsmNotAvailable = 1001,
    BtfNotAvailable = 1002,
    CgroupV2NotAvailable = 1003,
    BpffsNotMounted = 1004,

    // BPF operations (1100-1199)
    BpfLoadFailed = 1100,
    BpfAttachFailed = 1101,
    BpfMapFull = 1102,
    BpfMapNotFound = 1103,
    BpfVerifierRejected = 1104,

    // Policy errors (1200-1299)
    PolicyFileNotFound = 1200,
    PolicyParseError = 1201,
    PolicyValidationError = 1202,
    PolicySignatureInvalid = 1203,
    PolicyVersionMismatch = 1204,

    // File operations (1300-1399)
    FileNotFound = 1300,
    FilePermissionDenied = 1301,
    FileReadError = 1302,
    FileWriteError = 1303,

    // Network errors (1400-1499)
    InvalidIpAddress = 1400,
    InvalidPort = 1401,
    InvalidCidr = 1402,

    // Daemon errors (1500-1599)
    DaemonAlreadyRunning = 1500,
    DaemonNotRunning = 1501,
    DaemonCommunicationError = 1502,

    // Resource errors (1600-1699)
    InsufficientMemory = 1600,
    ResourceLimitReached = 1601,
    Timeout = 1602,

    // Generic errors (1900-1999)
    InvalidArgument = 1900,
    OperationNotSupported = 1901,
    InternalError = 1999,
};

/**
 * Get user-friendly error message for an error code.
 *
 * @param code Error code
 * @param verbose Include technical details
 * @return User-friendly error message
 */
inline std::string error_message(AegisErrorCode code, bool verbose = false)
{
    switch (code) {
        // Kernel compatibility
        case AegisErrorCode::KernelTooOld:
            return verbose ? "Kernel version too old (minimum 5.10 required with BPF LSM support)"
                           : "Kernel version not supported. Upgrade to kernel 5.10 or newer.";
        case AegisErrorCode::BpfLsmNotAvailable:
            return verbose ? "BPF LSM not available. Enable with kernel parameter: lsm=...,bpf"
                           : "BPF LSM not enabled. Contact your system administrator.";
        case AegisErrorCode::BtfNotAvailable:
            return verbose ? "Kernel BTF information not available. Build kernel with CONFIG_DEBUG_INFO_BTF=y"
                           : "Kernel lacks required BTF support.";
        case AegisErrorCode::CgroupV2NotAvailable:
            return "Cgroup v2 not available. Mount with: mount -t cgroup2 none /sys/fs/cgroup";
        case AegisErrorCode::BpffsNotMounted:
            return "BPF filesystem not mounted. Mount with: mount -t bpf bpffs /sys/fs/bpf";

        // BPF operations
        case AegisErrorCode::BpfLoadFailed:
            return verbose ? "Failed to load BPF program. Check kernel logs for verifier errors."
                           : "Failed to load security enforcement. Check system logs.";
        case AegisErrorCode::BpfAttachFailed:
            return verbose ? "Failed to attach BPF program to LSM hooks" : "Failed to activate security enforcement.";
        case AegisErrorCode::BpfMapFull:
            return "BPF map capacity reached. Remove unused deny rules or increase map size.";
        case AegisErrorCode::BpfMapNotFound:
            return verbose ? "BPF map not found at pinned path. Daemon may not be running."
                           : "Security enforcement not active. Start the daemon first.";
        case AegisErrorCode::BpfVerifierRejected:
            return verbose ? "BPF verifier rejected program. Check kernel version and BTF availability."
                           : "Kernel rejected security program. May need kernel upgrade.";

        // Policy errors
        case AegisErrorCode::PolicyFileNotFound:
            return "Policy file not found. Specify a valid policy file path.";
        case AegisErrorCode::PolicyParseError:
            return verbose ? "Failed to parse policy file. Check YAML syntax."
                           : "Policy file format error. Check syntax and try again.";
        case AegisErrorCode::PolicyValidationError:
            return "Policy validation failed. Review policy rules and fix errors.";
        case AegisErrorCode::PolicySignatureInvalid:
            return verbose ? "Policy signature verification failed. File may be tampered or untrusted key."
                           : "Policy signature invalid. Use only trusted policy files.";
        case AegisErrorCode::PolicyVersionMismatch:
            return "Policy version incompatible with this AegisBPF version.";

        // File operations
        case AegisErrorCode::FileNotFound:
            return "File not found.";
        case AegisErrorCode::FilePermissionDenied:
            return "Permission denied. Run with sudo or check file permissions.";
        case AegisErrorCode::FileReadError:
            return "Failed to read file.";
        case AegisErrorCode::FileWriteError:
            return "Failed to write file.";

        // Network errors
        case AegisErrorCode::InvalidIpAddress:
            return "Invalid IP address format. Use IPv4 (x.x.x.x) or IPv6 format.";
        case AegisErrorCode::InvalidPort:
            return "Invalid port number. Must be between 1 and 65535.";
        case AegisErrorCode::InvalidCidr:
            return "Invalid CIDR notation. Use format: IP/prefix (e.g., 192.168.1.0/24)";

        // Daemon errors
        case AegisErrorCode::DaemonAlreadyRunning:
            return "Daemon already running. Stop existing instance first.";
        case AegisErrorCode::DaemonNotRunning:
            return "Daemon not running. Start with: sudo aegisbpf run";
        case AegisErrorCode::DaemonCommunicationError:
            return "Failed to communicate with daemon. Check if daemon is running.";

        // Resource errors
        case AegisErrorCode::InsufficientMemory:
            return "Insufficient memory. Free up system resources and try again.";
        case AegisErrorCode::ResourceLimitReached:
            return "System resource limit reached. Check ulimits and kernel parameters.";
        case AegisErrorCode::Timeout:
            return "Operation timed out. Try again or increase timeout.";

        // Generic errors
        case AegisErrorCode::InvalidArgument:
            return "Invalid argument. Check command syntax with --help.";
        case AegisErrorCode::OperationNotSupported:
            return "Operation not supported on this system.";
        case AegisErrorCode::InternalError:
            return verbose ? "Internal error occurred. Report this bug with logs."
                           : "Internal error. Check logs for details.";

        case AegisErrorCode::Success:
        default:
            return "";
    }
}

/**
 * Get error code from an error code number.
 *
 * Useful for parsing error codes from external systems.
 */
inline AegisErrorCode error_code_from_int(int code)
{
    if (code >= static_cast<int>(AegisErrorCode::KernelTooOld) &&
        code <= static_cast<int>(AegisErrorCode::InternalError)) {
        return static_cast<AegisErrorCode>(code);
    }
    return AegisErrorCode::InternalError;
}

/**
 * Get remediation steps for an error code.
 *
 * Returns actionable steps the user can take to resolve the error.
 */
inline std::string error_remediation(AegisErrorCode code)
{
    switch (code) {
        case AegisErrorCode::KernelTooOld:
            return "Upgrade to kernel 5.10 or newer with BPF LSM support.";
        case AegisErrorCode::BpfLsmNotAvailable:
            return "Add 'lsm=...,bpf' to kernel command line and reboot.";
        case AegisErrorCode::BtfNotAvailable:
            return "Rebuild kernel with CONFIG_DEBUG_INFO_BTF=y or upgrade to newer kernel.";
        case AegisErrorCode::CgroupV2NotAvailable:
            return "Mount cgroup v2: sudo mount -t cgroup2 none /sys/fs/cgroup";
        case AegisErrorCode::BpffsNotMounted:
            return "Mount bpffs: sudo mount -t bpf bpffs /sys/fs/bpf";
        case AegisErrorCode::BpfMapFull:
            return "Run 'sudo aegisbpf block clear' to remove old entries, or increase map size in BPF code.";
        case AegisErrorCode::BpfMapNotFound:
            return "Start daemon: sudo aegisbpf run --enforce";
        case AegisErrorCode::PolicyFileNotFound:
            return "Create policy file or specify correct path with --policy flag.";
        case AegisErrorCode::PolicyParseError:
            return "Validate YAML syntax: yamllint policy.yml";
        case AegisErrorCode::FilePermissionDenied:
            return "Run with sudo or check file ownership and permissions.";
        case AegisErrorCode::DaemonAlreadyRunning:
            return "Stop daemon: sudo systemctl stop aegisbpf";
        case AegisErrorCode::DaemonNotRunning:
            return "Start daemon: sudo aegisbpf run --enforce &";
        default:
            return "Check documentation: https://github.com/yourusername/aegisbpf";
    }
}

} // namespace aegis
