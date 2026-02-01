#include "seccomp.hpp"
#include "logging.hpp"

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

// Architecture-specific audit value
#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture for seccomp"
#endif

namespace aegis {

namespace {

// BPF macros for seccomp filter construction
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }

// Syscall allowlist - these are the only syscalls aegisbpf needs
// Organized by category for maintainability
constexpr unsigned int ALLOWED_SYSCALLS[] = {
    // BPF operations (core functionality)
    SYS_bpf,
    SYS_perf_event_open,

    // Memory management
    SYS_brk,
    SYS_mmap,
    SYS_munmap,
    SYS_mprotect,
    SYS_mremap,

    // File operations (for policy files, proc, sysfs)
    SYS_openat,
    SYS_close,
    SYS_read,
    SYS_write,
    SYS_pread64,
    SYS_pwrite64,
    SYS_lseek,
    SYS_fstat,
#ifdef SYS_newfstatat
    SYS_newfstatat,
#endif
#ifdef SYS_statx
    SYS_statx,
#endif
    SYS_readlinkat,
    SYS_getdents64,
    SYS_fcntl,
    SYS_ioctl,
    SYS_flock,

    // Directory operations
    SYS_mkdirat,
    SYS_unlinkat,
    SYS_renameat,
#ifdef SYS_renameat2
    SYS_renameat2,
#endif

    // Process info (for cgroup resolution)
    SYS_getpid,
    SYS_gettid,
    SYS_getuid,
    SYS_geteuid,
    SYS_getgid,
    SYS_getegid,

    // Signal handling
    SYS_rt_sigprocmask,
    SYS_rt_sigaction,
    SYS_rt_sigreturn,

    // Event polling (for ring buffer)
    SYS_epoll_create1,
    SYS_epoll_ctl,
    SYS_epoll_wait,
    SYS_epoll_pwait,
#ifdef SYS_epoll_pwait2
    SYS_epoll_pwait2,
#endif
    SYS_poll,
    SYS_ppoll,

    // Socket operations (for journald sd_journal_* API)
    SYS_socket,
    SYS_connect,
    SYS_sendto,
    SYS_sendmsg,
    SYS_recvmsg,

    // Time operations
    SYS_clock_gettime,
    SYS_gettimeofday,
    SYS_nanosleep,
    SYS_clock_nanosleep,

    // Thread operations (for std::mutex, etc.)
    SYS_futex,
    SYS_set_robust_list,
    SYS_get_robust_list,
    SYS_clone,
#ifdef SYS_clone3
    SYS_clone3,
#endif
    SYS_set_tid_address,
    SYS_rseq,

    // Memory locking (for BPF map access)
    SYS_mlock,
    SYS_munlock,

    // Process termination
    SYS_exit,
    SYS_exit_group,

    // Capabilities and permissions
    SYS_capget,
    SYS_capset,
    SYS_prctl,

    // Misc required
    SYS_getrandom,
    SYS_arch_prctl,
    SYS_access,
    SYS_faccessat,
#ifdef SYS_faccessat2
    SYS_faccessat2,
#endif
    SYS_prlimit64,
    SYS_sched_getaffinity,
    SYS_sched_yield,

    // For popen() in utils.cpp (kernel config check)
    SYS_pipe2,
    SYS_dup2,
    SYS_dup3,
    SYS_execve,
    SYS_wait4,
    SYS_vfork,
};

constexpr size_t NUM_ALLOWED = sizeof(ALLOWED_SYSCALLS) / sizeof(ALLOWED_SYSCALLS[0]);

} // anonymous namespace

bool seccomp_available()
{
    // Check if seccomp is available via prctl
    int ret = prctl(PR_GET_SECCOMP);
    if (ret == -1 && errno == EINVAL) {
        return false;
    }
    return true;
}

Result<void> apply_seccomp_filter()
{
    if (!seccomp_available()) {
        return Error(ErrorCode::PermissionDenied, "seccomp not available on this system");
    }

    // Build BPF filter program
    // Structure:
    // 1. Load architecture and validate
    // 2. Load syscall number
    // 3. Compare against each allowed syscall
    // 4. If matched, allow; otherwise kill

    // Calculate filter size: arch check (3) + load syscall (1) + comparisons (2*N) + default deny (1)
    const size_t filter_len = 3 + 1 + (NUM_ALLOWED * 2) + 1;
    std::vector<sock_filter> filter;
    filter.reserve(filter_len);

    // Validate architecture
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Load syscall number
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    // For each allowed syscall, jump to allow if matched
    // We need to calculate jump offsets: remaining comparisons + 1 (for default deny)
    for (size_t i = 0; i < NUM_ALLOWED; ++i) {
        size_t remaining = NUM_ALLOWED - i - 1;
        // Jump to ALLOW (skip remaining*2 + 1 instructions) if equal
        // Jump offset for true: skip all remaining comparisons (remaining * 2) + default deny (1) - 1 = remaining*2
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ALLOWED_SYSCALLS[i],
                                   static_cast<uint8_t>(remaining * 2 + 1), 0));
    }

    // Default: kill process for disallowed syscalls
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Allow instruction (jumped to from successful comparisons)
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // Set up the BPF program
    struct sock_fprog prog = {
        .len = static_cast<unsigned short>(filter.size()),
        .filter = filter.data()
    };

    // Set NO_NEW_PRIVS first (required for unprivileged seccomp)
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        return Error::system(errno, "prctl(PR_SET_NO_NEW_PRIVS)");
    }

    // Apply the seccomp filter
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        return Error::system(errno, "prctl(PR_SET_SECCOMP)");
    }

    logger().log(SLOG_INFO("Seccomp filter applied").field("allowed_syscalls", NUM_ALLOWED));
    return {};
}

} // namespace aegis
