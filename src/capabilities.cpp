// cppcheck-suppress-file missingIncludeSystem
#include "capabilities.hpp"

#include <linux/capability.h>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "logging.hpp"

namespace aegis {

namespace {

// glibc does not expose capget(2) / capset(2) wrappers. Use the syscall
// numbers directly — they are stable across all supported architectures.
inline int sys_capget(struct __user_cap_header_struct* hdr, struct __user_cap_data_struct* data) noexcept
{
    return static_cast<int>(::syscall(SYS_capget, hdr, data));
}

inline int sys_capset(struct __user_cap_header_struct* hdr, const struct __user_cap_data_struct* data) noexcept
{
    return static_cast<int>(::syscall(SYS_capset, hdr, data));
}

constexpr int kCapVersion = _LINUX_CAPABILITY_VERSION_3;
constexpr int kCapU32Words = _LINUX_CAPABILITY_U32S_3;

uint64_t pack(uint32_t low, uint32_t high)
{
    return static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);
}

void unpack(uint64_t value, uint32_t& low, uint32_t& high)
{
    low = static_cast<uint32_t>(value & 0xFFFFFFFFu);
    high = static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFu);
}

} // namespace

bool capabilities_split_supported()
{
    // PR_CAPBSET_READ on a kernel that doesn't know CAP_BPF returns
    // -1 / EINVAL. On supported kernels it returns 0 or 1.
    const int rc = ::prctl(PR_CAPBSET_READ, AegisCapBpf, 0, 0, 0);
    return rc >= 0;
}

Result<CapabilitySnapshot> read_capabilities()
{
    struct __user_cap_header_struct hdr {};
    hdr.version = kCapVersion;
    hdr.pid = 0;
    struct __user_cap_data_struct data[kCapU32Words]{};

    if (sys_capget(&hdr, data) != 0) {
        return Error::system(errno, "capget");
    }

    CapabilitySnapshot snap;
    snap.effective = pack(data[0].effective, data[1].effective);
    snap.permitted = pack(data[0].permitted, data[1].permitted);
    snap.inheritable = pack(data[0].inheritable, data[1].inheritable);
    return snap;
}

Result<void> drop_capabilities(const std::vector<int>& caps_to_drop)
{
    if (caps_to_drop.empty()) {
        return {};
    }

    // 1. Read the current cap state.
    struct __user_cap_header_struct hdr {};
    hdr.version = kCapVersion;
    hdr.pid = 0;
    struct __user_cap_data_struct data[kCapU32Words]{};
    if (sys_capget(&hdr, data) != 0) {
        return Error::system(errno, "capget");
    }

    uint64_t eff = pack(data[0].effective, data[1].effective);
    uint64_t prm = pack(data[0].permitted, data[1].permitted);
    uint64_t inh = pack(data[0].inheritable, data[1].inheritable);

    // 2. Lower from ambient (children won't inherit) and compute the
    //    narrowed effective / permitted / inheritable masks.
    for (int cap : caps_to_drop) {
        if (cap < 0) {
            continue;
        }
        const uint64_t bit = 1ULL << cap;

        // Ambient: PR_CAP_AMBIENT_LOWER may return EINVAL when the
        // capability isn't present in the ambient set already; ignore.
        const int amb_rc = ::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0);
        if (amb_rc != 0 && errno != EINVAL && errno != ENOENT) {
            return Error::system(errno, std::string("prctl(PR_CAP_AMBIENT_LOWER, ") + cap_name(cap) + ")");
        }

        eff &= ~bit;
        prm &= ~bit;
        inh &= ~bit;
    }

    // 3. Drop from the bounding set FIRST, while CAP_SETPCAP is still
    //    in our effective set. PR_CAPBSET_DROP requires CAP_SETPCAP in
    //    the caller's effective set, so we must do this before the
    //    capset() shrink in step 4 -- otherwise CAP_SETPCAP itself
    //    (which is in the drop list when starting as root) gets cleared
    //    from effective and the subsequent PR_CAPBSET_DROP calls fail
    //    with EPERM, leaking the bounding bits.
    for (int cap : caps_to_drop) {
        if (cap < 0) {
            continue;
        }
        const int bs_rc = ::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
        if (bs_rc != 0) {
            // EPERM here means the caller never had CAP_SETPCAP to
            // begin with (unprivileged container); EINVAL means the
            // kernel doesn't know this cap number. Both are non-fatal:
            // the capset() in step 4 still narrows effective/permitted
            // for this process, even if the bounding bit survives.
            const int err = errno;
            if (err == EPERM || err == EINVAL) {
                continue;
            }
            return Error::system(err, std::string("prctl(PR_CAPBSET_DROP, ") + cap_name(cap) + ")");
        }
    }

    // 4. Push the narrowed effective/permitted/inheritable set back in
    //    one capset() call. After this point CAP_SETPCAP is gone, so
    //    no further PR_CAPBSET_DROP is possible -- which is fine because
    //    step 3 already shrank the bounding set.
    unpack(eff, data[0].effective, data[1].effective);
    unpack(prm, data[0].permitted, data[1].permitted);
    unpack(inh, data[0].inheritable, data[1].inheritable);
    if (sys_capset(&hdr, data) != 0) {
        return Error::system(errno, "capset");
    }

    return {};
}

std::vector<int> default_post_attach_keep_set()
{
    // Once BPF objects and LSM/tracepoint/cgroup hooks are attached, the
    // daemon does not need to load new programs or attach new hooks
    // through the rest of its lifetime. Map updates use file
    // descriptors that were already opened with the appropriate caps,
    // so they continue to work without CAP_BPF.
    //
    // We retain `CAP_NET_ADMIN` because:
    //   - cgroup socket hook updates may still be needed when policies
    //     change at runtime, and
    //   - some socket-related BPF map operations on cgroup-scoped maps
    //     check for it on the syscall path.
    //
    // We retain `CAP_DAC_READ_SEARCH` so the agent can keep reading
    // `/proc/<pid>/{exe,cgroup,ns/*}` even when the running uid lacks
    // discretionary access to those nodes (e.g. PID owned by another
    // namespace).
    return {AegisCapNetAdmin, AegisCapDacReadSearch};
}

Result<std::vector<int>> apply_post_attach_cap_drop()
{
    // Build the drop list as "every cap currently set in permitted,
    // minus the keep set". We deliberately do not enumerate the entire
    // CAP_LAST_CAP space — that would race with newly added caps in
    // future kernels. Working from the live snapshot keeps us correct.
    auto snapshot = read_capabilities();
    if (!snapshot) {
        return snapshot.error();
    }

    const std::vector<int> keep = default_post_attach_keep_set();
    uint64_t keep_mask = 0;
    for (int cap : keep) {
        if (cap >= 0) {
            keep_mask |= (1ULL << cap);
        }
    }

    std::vector<int> drop_list;
    for (int cap = 0; cap < 64; ++cap) {
        const uint64_t bit = 1ULL << cap;
        if (((snapshot->permitted | snapshot->effective | snapshot->inheritable) & bit) == 0) {
            continue;
        }
        if (keep_mask & bit) {
            continue;
        }
        drop_list.push_back(cap);
    }

    auto rc = drop_capabilities(drop_list);
    if (!rc) {
        return rc.error();
    }
    return drop_list;
}

const char* cap_name(int cap)
{
    switch (cap) {
        case 0:
            return "CAP_CHOWN";
        case 1:
            return "CAP_DAC_OVERRIDE";
        case 2:
            return "CAP_DAC_READ_SEARCH";
        case 3:
            return "CAP_FOWNER";
        case 4:
            return "CAP_FSETID";
        case 5:
            return "CAP_KILL";
        case 6:
            return "CAP_SETGID";
        case 7:
            return "CAP_SETUID";
        case 8:
            return "CAP_SETPCAP";
        case 9:
            return "CAP_LINUX_IMMUTABLE";
        case 10:
            return "CAP_NET_BIND_SERVICE";
        case 11:
            return "CAP_NET_BROADCAST";
        case 12:
            return "CAP_NET_ADMIN";
        case 13:
            return "CAP_NET_RAW";
        case 14:
            return "CAP_IPC_LOCK";
        case 15:
            return "CAP_IPC_OWNER";
        case 16:
            return "CAP_SYS_MODULE";
        case 17:
            return "CAP_SYS_RAWIO";
        case 18:
            return "CAP_SYS_CHROOT";
        case 19:
            return "CAP_SYS_PTRACE";
        case 20:
            return "CAP_SYS_PACCT";
        case 21:
            return "CAP_SYS_ADMIN";
        case 22:
            return "CAP_SYS_BOOT";
        case 23:
            return "CAP_SYS_NICE";
        case 24:
            return "CAP_SYS_RESOURCE";
        case 25:
            return "CAP_SYS_TIME";
        case 26:
            return "CAP_SYS_TTY_CONFIG";
        case 27:
            return "CAP_MKNOD";
        case 28:
            return "CAP_LEASE";
        case 29:
            return "CAP_AUDIT_WRITE";
        case 30:
            return "CAP_AUDIT_CONTROL";
        case 31:
            return "CAP_SETFCAP";
        case 32:
            return "CAP_MAC_OVERRIDE";
        case 33:
            return "CAP_MAC_ADMIN";
        case 34:
            return "CAP_SYSLOG";
        case 35:
            return "CAP_WAKE_ALARM";
        case 36:
            return "CAP_BLOCK_SUSPEND";
        case 37:
            return "CAP_AUDIT_READ";
        case 38:
            return "CAP_PERFMON";
        case 39:
            return "CAP_BPF";
        case 40:
            return "CAP_CHECKPOINT_RESTORE";
        default:
            return "CAP_UNKNOWN";
    }
}

} // namespace aegis
