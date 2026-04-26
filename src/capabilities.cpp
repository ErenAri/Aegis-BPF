// cppcheck-suppress-file missingIncludeSystem
#include "capabilities.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <linux/capability.h>
#include <sstream>
#include <string>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "logging.hpp"

namespace aegis {

namespace {

// Linux capability-set syscall wrappers. We don't depend on libcap or
// libcap-ng so that the daemon binary stays self-contained and the
// hardening posture matches the Landlock module's pattern of using
// raw syscalls.

#ifndef _LINUX_CAPABILITY_VERSION_3
#    define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif

inline int sys_capget(struct __user_cap_header_struct* header,
                      struct __user_cap_data_struct* data) noexcept
{
    return static_cast<int>(::syscall(SYS_capget, header, data));
}

inline int sys_capset(struct __user_cap_header_struct* header,
                      const struct __user_cap_data_struct* data) noexcept
{
    return static_cast<int>(::syscall(SYS_capset, header, data));
}

constexpr uint64_t cap_bit(int cap) noexcept
{
    return uint64_t{1} << static_cast<unsigned>(cap);
}

uint64_t bitmask_from(const std::vector<int>& caps) noexcept
{
    uint64_t mask = 0;
    for (int c : caps) {
        if (c >= 0 && c < 64) {
            mask |= cap_bit(c);
        }
    }
    return mask;
}

// Parse a "/proc/self/status" CapXxx hex value (the file uses the
// Linux text format: "CapEff:\t<16-hex>\n"). Returns 0 on parse
// failure.
uint64_t parse_status_cap_line(const std::string& line) noexcept
{
    auto pos = line.find(':');
    if (pos == std::string::npos) {
        return 0;
    }
    std::string hex = line.substr(pos + 1);
    while (!hex.empty() && (hex.front() == ' ' || hex.front() == '\t')) {
        hex.erase(hex.begin());
    }
    while (!hex.empty() && (hex.back() == '\n' || hex.back() == ' ' || hex.back() == '\t')) {
        hex.pop_back();
    }
    try {
        return std::stoull(hex, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

// Parse "X.Y[.Z]" from /proc/sys/kernel/osrelease and return X*1000+Y.
// Returns 0 on parse failure (caller treats as "old kernel").
uint32_t kernel_major_minor() noexcept
{
    struct utsname uts {};
    if (::uname(&uts) != 0) {
        return 0;
    }
    uint32_t major = 0;
    uint32_t minor = 0;
    const char* p = uts.release;
    while (*p >= '0' && *p <= '9') {
        major = major * 10 + static_cast<uint32_t>(*p - '0');
        ++p;
    }
    if (*p != '.') {
        return 0;
    }
    ++p;
    while (*p >= '0' && *p <= '9') {
        minor = minor * 10 + static_cast<uint32_t>(*p - '0');
        ++p;
    }
    return major * 1000 + minor;
}

}  // namespace

CapabilityConfig default_capability_config()
{
    CapabilityConfig cfg;
    cfg.retain = {
        cap::kBpf,
        cap::kPerfmon,
        cap::kDacReadSearch,
        cap::kSysResource,
    };
    cfg.clear_inheritable = true;
    cfg.clear_bounding    = true;
    cfg.clear_ambient     = true;
    return cfg;
}

bool capabilities_split_supported()
{
    // CAP_BPF (39) and CAP_PERFMON (38) landed together in Linux 5.8.
    // Below that, dropping to {CAP_BPF, CAP_PERFMON, ...} would strand
    // the daemon -- it would lose CAP_SYS_ADMIN which is still required
    // for bpf(2) and most BPF helpers on those older kernels.
    return kernel_major_minor() >= 5008;
}

Result<CapabilitySnapshot> read_capability_snapshot()
{
    // Prefer /proc/self/status for human-friendly cross-checking.
    // capget(2) is the authoritative source but we also expose what's
    // visible to operators via /proc.
    CapabilitySnapshot snap{};
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) {
        return Error::system(errno, "open /proc/self/status");
    }
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("CapEff:", 0) == 0) {
            snap.effective = parse_status_cap_line(line);
        } else if (line.rfind("CapPrm:", 0) == 0) {
            snap.permitted = parse_status_cap_line(line);
        } else if (line.rfind("CapInh:", 0) == 0) {
            snap.inheritable = parse_status_cap_line(line);
        } else if (line.rfind("CapBnd:", 0) == 0) {
            snap.bounding = parse_status_cap_line(line);
        }
    }
    return snap;
}

Result<void> drop_to_minimum(const CapabilityConfig& config)
{
    if (!capabilities_split_supported()) {
        const uint32_t kver = kernel_major_minor();
        logger().log(SLOG_INFO("Skipping capability drop: kernel < 5.8 lacks CAP_BPF / CAP_PERFMON")
                         .field("kernel_version_x1000", static_cast<int64_t>(kver)));
        return {};
    }

    if (config.retain.empty()) {
        return Error::invalid_argument("capability retain set must not be empty");
    }

    const uint64_t want_mask = bitmask_from(config.retain);
    if (want_mask == 0) {
        return Error::invalid_argument("capability retain mask is zero (no valid caps in retain list)");
    }

    // Step 1: clear ambient set BEFORE shrinking permitted, since
    // PR_CAP_AMBIENT_RAISE requires the cap in permitted+inheritable.
    if (config.clear_ambient) {
        if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == -1) {
            // Older kernels may not support PR_CAP_AMBIENT (added 4.3).
            // Treat ENOTSUP / EINVAL as best-effort and continue; we
            // log but do not fail.
            const int e = errno;
            if (e != EINVAL && e != ENOSYS) {
                return Error::system(e, "prctl(PR_CAP_AMBIENT, CLEAR_ALL)");
            }
            logger().log(SLOG_INFO("Ambient capability set unsupported on this kernel; continuing")
                             .field("errno", static_cast<int64_t>(e)));
        }
    }

    // Step 2: shrink the bounding set FIRST, while we still have
    // CAP_SETPCAP in the effective set. PR_CAPBSET_DROP requires
    // CAP_SETPCAP, so we cannot drop bounding caps after we've
    // reduced effective+permitted to the retain mask (which excludes
    // CAP_SETPCAP). Bounding is dropped one cap at a time and
    // permanently removes the cap for the calling thread and any
    // future fork/exec descendants -- it is the only set that
    // prevents execve() from regaining caps.
    if (config.clear_bounding) {
        for (int c = 0; c < 64; ++c) {
            const uint64_t bit = cap_bit(c);
            if ((want_mask & bit) != 0) {
                continue;  // keep
            }
            if (::prctl(PR_CAPBSET_READ, c, 0, 0, 0) <= 0) {
                continue;  // already not in bounding set, or unknown cap
            }
            if (::prctl(PR_CAPBSET_DROP, c, 0, 0, 0) == -1) {
                const int e = errno;
                // EINVAL on caps the kernel doesn't know about -- fine.
                if (e != EINVAL) {
                    return Error::system(e, "prctl(PR_CAPBSET_DROP)");
                }
            }
        }
    }

    // Step 3: read current sets via capget (authoritative) and compute
    // what the new effective/permitted/inheritable should look like.
    struct __user_cap_header_struct header {};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid     = 0;  // self
    struct __user_cap_data_struct data[2] {};

    if (sys_capget(&header, data) != 0) {
        return Error::system(errno, "capget");
    }

    // The version-3 layout is two __user_cap_data_struct entries; the
    // 32-bit `effective`/`permitted`/`inheritable` fields together
    // form the 64-bit mask.
    auto split_lo = static_cast<uint32_t>(want_mask & 0xFFFFFFFFu);
    auto split_hi = static_cast<uint32_t>((want_mask >> 32) & 0xFFFFFFFFu);

    data[0].effective   = split_lo;
    data[0].permitted   = split_lo;
    data[0].inheritable = config.clear_inheritable ? 0u : data[0].inheritable;
    data[1].effective   = split_hi;
    data[1].permitted   = split_hi;
    data[1].inheritable = config.clear_inheritable ? 0u : data[1].inheritable;

    if (sys_capset(&header, data) != 0) {
        return Error::system(errno, "capset (drop effective + permitted)");
    }

    // Step 4: prove it. Read back via /proc/self/status and log so
    // operators can verify in journald that the drop succeeded. This
    // also catches kernels that silently mask requested caps.
    auto snap_result = read_capability_snapshot();
    if (snap_result) {
        const auto& snap = snap_result.value();
        const uint64_t leaked_eff = snap.effective & ~want_mask;
        const uint64_t leaked_prm = snap.permitted & ~want_mask;
        if (leaked_eff != 0 || leaked_prm != 0) {
            logger().log(SLOG_WARN("Capability drop incomplete: kernel retained caps outside retain set")
                             .field("requested_mask", want_mask)
                             .field("effective_after", snap.effective)
                             .field("permitted_after", snap.permitted)
                             .field("bounding_after", snap.bounding));
        } else {
            logger().log(SLOG_INFO("Capability drop applied")
                             .field("retain_mask", want_mask)
                             .field("effective", snap.effective)
                             .field("permitted", snap.permitted)
                             .field("inheritable", snap.inheritable)
                             .field("bounding", snap.bounding));
        }
    }

    return {};
}

}  // namespace aegis
