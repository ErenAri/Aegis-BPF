// cppcheck-suppress-file missingIncludeSystem
#include "landlock.hpp"

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#if __has_include(<linux/landlock.h>)
#    include <linux/landlock.h>
#    define AEGIS_HAS_LANDLOCK_HEADER 1
#else
#    define AEGIS_HAS_LANDLOCK_HEADER 0
#endif

#include "logging.hpp"
#include "types.hpp"

namespace aegis {

#if AEGIS_HAS_LANDLOCK_HEADER

namespace {

// Glibc < 2.36 does not expose syscall numbers for Landlock yet, so fall
// back to the architecture-independent constants from <linux/landlock.h>
// via direct syscall(2) wrappers. These match the kernel man page.
#    ifndef __NR_landlock_create_ruleset
#        define __NR_landlock_create_ruleset 444
#    endif
#    ifndef __NR_landlock_add_rule
#        define __NR_landlock_add_rule 445
#    endif
#    ifndef __NR_landlock_restrict_self
#        define __NR_landlock_restrict_self 446
#    endif

inline int sys_landlock_create_ruleset(const struct landlock_ruleset_attr* attr, size_t size, uint32_t flags) noexcept
{
    return static_cast<int>(::syscall(__NR_landlock_create_ruleset, attr, size, flags));
}

inline int sys_landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void* rule_attr,
                                 uint32_t flags) noexcept
{
    return static_cast<int>(::syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags));
}

inline int sys_landlock_restrict_self(int ruleset_fd, uint32_t flags) noexcept
{
    return static_cast<int>(::syscall(__NR_landlock_restrict_self, ruleset_fd, flags));
}

// Aggregated per-ABI access masks. ABI 1 (kernel 5.13) defines the
// initial set of LANDLOCK_ACCESS_FS_* bits; later ABIs extend it
// (REFER on ABI 2, TRUNCATE on ABI 3). We compute the supported
// subset from the kernel-reported ABI version so we can keep adding
// stricter rights on newer kernels without breaking older ones.
struct AccessMasks {
    uint64_t read_mask = 0;
    uint64_t write_mask = 0;
};

AccessMasks compute_access_masks(int abi)
{
    AccessMasks m;
    if (abi < 1) {
        return m;
    }

    // ABI 1 (Linux 5.13)
    m.read_mask = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    m.write_mask = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                   LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                   LANDLOCK_ACCESS_FS_MAKE_SYM;
    // Execute on read paths (BPF object, /proc/self/exe, etc.).
    m.read_mask |= LANDLOCK_ACCESS_FS_EXECUTE;

#    ifdef LANDLOCK_ACCESS_FS_REFER
    if (abi >= 2) {
        m.write_mask |= LANDLOCK_ACCESS_FS_REFER;
    }
#    endif
#    ifdef LANDLOCK_ACCESS_FS_TRUNCATE
    if (abi >= 3) {
        m.write_mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
#    endif

    return m;
}

} // namespace

int landlock_abi_version()
{
    int abi = sys_landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        return -1;
    }
    return abi;
}

bool landlock_available()
{
    return landlock_abi_version() >= 1;
}

Result<void> apply_landlock_sandbox(const LandlockConfig& config)
{
    const int abi = landlock_abi_version();
    if (abi < 1) {
        logger().log(SLOG_INFO("Landlock unavailable, skipping sandbox").field("errno", static_cast<int64_t>(errno)));
        return {};
    }

    const AccessMasks masks = compute_access_masks(abi);
    if (masks.read_mask == 0) {
        logger().log(SLOG_WARN("Landlock available but no usable access flags for this ABI")
                         .field("abi", static_cast<int64_t>(abi)));
        return {};
    }

    struct landlock_ruleset_attr ruleset_attr {};
    ruleset_attr.handled_access_fs = masks.read_mask | masks.write_mask;

    const int ruleset_fd = sys_landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        return Error::system(errno, "landlock_create_ruleset");
    }

    int allowed_paths = 0;
    int skipped_paths = 0;
    for (const auto& entry : config.paths) {
        if (entry.path.empty()) {
            continue;
        }
        // Open the path read-only; Landlock only inspects the inode,
        // not the open mode, but we must hold an fd while adding rules.
        const int path_fd = ::open(entry.path.c_str(), O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            // Missing optional paths (e.g. /var/lib/aegisbpf on a
            // first-boot host) just skip. Log at debug to keep
            // production logs quiet.
            logger().log(SLOG_INFO("Landlock allowlist path not present, skipping")
                             .field("path", entry.path)
                             .field("errno", static_cast<int64_t>(errno)));
            ++skipped_paths;
            continue;
        }

        struct landlock_path_beneath_attr path_attr {};
        path_attr.allowed_access = masks.read_mask;
        if (entry.writable) {
            path_attr.allowed_access |= masks.write_mask;
        }
        path_attr.parent_fd = path_fd;

        const int rc = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
        const int saved_errno = errno;
        ::close(path_fd);
        if (rc != 0) {
            ::close(ruleset_fd);
            return Error::system(saved_errno, std::string("landlock_add_rule for ") + entry.path);
        }
        ++allowed_paths;
    }

    // NO_NEW_PRIVS is required by landlock_restrict_self() unless the
    // process holds CAP_SYS_ADMIN. The seccomp path also sets this; it
    // is idempotent.
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        const int saved_errno = errno;
        ::close(ruleset_fd);
        return Error::system(saved_errno, "prctl(PR_SET_NO_NEW_PRIVS) for landlock");
    }

    if (sys_landlock_restrict_self(ruleset_fd, 0) != 0) {
        const int saved_errno = errno;
        ::close(ruleset_fd);
        return Error::system(saved_errno, "landlock_restrict_self");
    }

    ::close(ruleset_fd);

    logger().log(SLOG_INFO("Landlock sandbox applied")
                     .field("abi_version", static_cast<int64_t>(abi))
                     .field("allowed_paths", static_cast<int64_t>(allowed_paths))
                     .field("skipped_paths", static_cast<int64_t>(skipped_paths)));
    return {};
}

#else // !AEGIS_HAS_LANDLOCK_HEADER

int landlock_abi_version()
{
    return -1;
}
bool landlock_available()
{
    return false;
}

Result<void> apply_landlock_sandbox(const LandlockConfig& /*config*/)
{
    logger().log(SLOG_INFO("Landlock support not compiled in (linux/landlock.h missing at build time)"));
    return {};
}

#endif // AEGIS_HAS_LANDLOCK_HEADER

LandlockConfig default_landlock_config()
{
    LandlockConfig cfg;

    // Read-only system paths the daemon needs throughout its lifetime.
    cfg.paths.push_back({"/etc/aegisbpf", false});
    cfg.paths.push_back({"/usr/lib/aegisbpf", false});
    cfg.paths.push_back({"/proc", false});
    cfg.paths.push_back({"/sys/kernel/btf", false});

    // Read-write state and pinned-map directories.
    cfg.paths.push_back({"/var/lib/aegisbpf", true});
    cfg.paths.push_back({"/sys/fs/bpf", true});

    // Caller-overridable trusted-keys and BPF object directories.
    if (const char* keys_dir = std::getenv("AEGIS_KEYS_DIR")) {
        if (keys_dir[0] != '\0') {
            cfg.paths.push_back({keys_dir, false});
        }
    }
    if (const char* bpf_obj = std::getenv("AEGIS_BPF_OBJ")) {
        if (bpf_obj[0] != '\0') {
            std::string p(bpf_obj);
            const auto slash = p.find_last_of('/');
            if (slash != std::string::npos && slash > 0) {
                cfg.paths.push_back({p.substr(0, slash), false});
            }
        }
    }

    return cfg;
}

} // namespace aegis
