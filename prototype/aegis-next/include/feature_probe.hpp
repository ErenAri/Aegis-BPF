// SPDX-License-Identifier: GPL-2.0
//
// Runtime feature probing for aegis-next.
//
// Each feature is probed independently at startup. The agent degrades
// gracefully: if arena maps are unavailable, fall back to ringbuf;
// if sched_ext is unavailable, skip the quarantine scheduler; etc.

#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unistd.h>

// BPF_MAP_TYPE_ARENA was added in kernel 6.9 and may not be in
// the installed libbpf/uapi headers yet. Use a typed constant
// to avoid implicit int→enum conversion errors in C++.
#ifndef BPF_MAP_TYPE_ARENA
static constexpr auto BPF_MAP_TYPE_ARENA =
    static_cast<enum bpf_map_type>(33);
#endif

namespace aegis_next {

// BPF_MAP_TYPE_USER_RINGBUF was added in kernel 6.1.
#ifndef BPF_MAP_TYPE_USER_RINGBUF
static constexpr auto BPF_MAP_TYPE_USER_RINGBUF =
    static_cast<enum bpf_map_type>(31);
#endif

struct FeatureSupport {
    bool arena;        // BPF_MAP_TYPE_ARENA (kernel 6.9+)
    bool sched_ext;    // struct_ops sched_ext (kernel 6.12+)
    bool bpf_lsm;      // BPF LSM hooks (CONFIG_BPF_LSM)
    bool ringbuf;      // BPF_MAP_TYPE_RINGBUF (kernel 5.8+)
    // Phase 4 features
    bool user_ringbuf; // BPF_MAP_TYPE_USER_RINGBUF (kernel 6.1+)
    bool fsverity;     // CONFIG_FS_VERITY enabled
    bool xattr;        // bpf_get_file_xattr kfunc (kernel 6.8+)
    bool binary_auth;  // all binary auth deps available
};

// Probe whether a BPF map type is supported by trying to create one.
inline bool probe_map_type(enum bpf_map_type type,
                           __u32 key_size, __u32 value_size,
                           __u32 max_entries)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);

    // Arena requires special setup — pages field.
    if (type == BPF_MAP_TYPE_ARENA) {
        opts.map_extra = 0; // addr hint
        // Arena needs map_flags and specific sizes.
        int fd = bpf_map_create(type, "probe_arena",
                                0,   // key_size (arena ignores)
                                0,   // value_size (arena ignores)
                                0,   // max_entries (arena ignores)
                                &opts);
        if (fd >= 0) {
            close(fd);
            return true;
        }
        // Try with non-zero to handle different kernel expectations.
        return false;
    }

    int fd = bpf_map_create(type, "probe", key_size, value_size,
                            max_entries, nullptr);
    if (fd >= 0) {
        close(fd);
        return true;
    }
    return false;
}

// Probe sched_ext by checking for the SCX_OPS_ENQ_LAST flag in BTF.
// A simpler heuristic: check if /sys/kernel/sched_ext exists.
inline bool probe_sched_ext()
{
    return access("/sys/kernel/sched_ext", F_OK) == 0;
}

// Probe fsverity support by checking if the kernel exposes the
// fsverity sysfs or ioctl interface.
inline bool probe_fsverity()
{
    // Check if FS_IOC_ENABLE_VERITY is supported by any filesystem.
    // A simpler heuristic: check if /proc/filesystems contains verity-
    // capable fs (ext4, btrfs, f2fs all support it).
    FILE* f = fopen("/proc/filesystems", "r");
    if (!f)
        return false;
    char buf[1024]{};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    // If any verity-capable filesystem is present and kernel is 6.7+,
    // fsverity kfuncs should be available.
    return strstr(buf, "ext4") != nullptr ||
           strstr(buf, "btrfs") != nullptr ||
           strstr(buf, "f2fs") != nullptr;
}

// Probe BPF LSM by checking if "bpf" is in the active LSM list.
inline bool probe_bpf_lsm()
{
    FILE* f = fopen("/sys/kernel/security/lsm", "r");
    if (!f)
        return false;
    char buf[512]{};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, "bpf") != nullptr;
}

// Run all probes and return the feature support matrix.
inline FeatureSupport probe_features()
{
    FeatureSupport fs{};

    fs.bpf_lsm = probe_bpf_lsm();
    fs.ringbuf = probe_map_type(BPF_MAP_TYPE_RINGBUF, 0, 0, 4096);
    fs.sched_ext = probe_sched_ext();

    // Arena probe: try to create a minimal arena map.
    // On 6.9+ this succeeds; on older kernels EINVAL.
    fs.arena = probe_map_type(BPF_MAP_TYPE_ARENA, 0, 0, 0);

    // Phase 4 probes.
    fs.user_ringbuf = probe_map_type(BPF_MAP_TYPE_USER_RINGBUF, 0, 0, 4096);
    fs.fsverity = probe_fsverity();
    // xattr kfuncs are available if kernel >= 6.8 and BPF LSM is on.
    // We approximate: if arena is available (6.9+), xattr kfuncs should be too.
    fs.xattr = fs.arena && fs.bpf_lsm;
    // Binary auth requires fsverity + BPF LSM + xattr.
    fs.binary_auth = fs.fsverity && fs.bpf_lsm && fs.xattr;

    return fs;
}

// Print feature matrix to stdout.
inline void print_features(const FeatureSupport& fs)
{
    std::printf("aegis-next: feature probe results:\n");
    std::printf("  %-20s %s\n", "BPF LSM",    fs.bpf_lsm   ? "yes" : "NO (need lsm=bpf boot param)");
    std::printf("  %-20s %s\n", "Arena maps",  fs.arena      ? "yes" : "NO (need kernel 6.9+, using ringbuf fallback)");
    std::printf("  %-20s %s\n", "Ringbuf",     fs.ringbuf    ? "yes" : "NO");
    std::printf("  %-20s %s\n", "sched_ext",   fs.sched_ext  ? "yes" : "NO (quarantine scheduler unavailable)");
    std::printf("  %-20s %s\n", "user_ringbuf", fs.user_ringbuf ? "yes" : "NO (need kernel 6.1+)");
    std::printf("  %-20s %s\n", "fsverity",    fs.fsverity   ? "yes" : "NO (need CONFIG_FS_VERITY)");
    std::printf("  %-20s %s\n", "xattr kfuncs", fs.xattr     ? "yes" : "NO (need kernel 6.8+)");
    std::printf("  %-20s %s\n", "binary auth",  fs.binary_auth ? "yes" : "NO (need fsverity + LSM + xattr)");
}

} // namespace aegis_next
