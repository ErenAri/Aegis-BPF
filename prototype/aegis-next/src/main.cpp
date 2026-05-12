// SPDX-License-Identifier: GPL-2.0
//
// aegis-next userspace driver (proof-of-concept).
//
// Loads provenance.bpf.o, attaches the lsm/bprm_check_security
// program, mmaps the BPF arena, and on SIGINT prints the recorded
// provenance nodes.
//
// This is a scaffold. It does NOT integrate with the mainline
// aegisbpf daemon. It runs as a standalone binary so the prototype
// can iterate without touching the shipped agent.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/mman.h>
#include <sys/resource.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>

#include "provenance.skel.h"

namespace {

// Must match prototype/aegis-next/bpf/provenance.bpf.c exactly.
constexpr std::size_t kArenaPages = 16384;
constexpr std::size_t kArenaBytes = kArenaPages * 4096ULL;
constexpr std::size_t kMaxNodes = 1ULL << 20;

struct ProvHeader {
    std::uint64_t magic;
    std::uint64_t next_index;
    std::uint64_t dropped;
    std::uint64_t reserved;
};

struct ProvNode {
    std::uint64_t ts_ns;
    std::uint32_t pid;
    std::uint32_t ppid;
    std::uint32_t tgid;
    std::uint32_t uid;
    std::uint64_t cgid;
    std::uint64_t exec_inode;
    std::uint64_t prev_index;
    char          comm[16];
};

static_assert(sizeof(ProvHeader) == 32, "ProvHeader layout drift");
static_assert(sizeof(ProvNode) == 64, "ProvNode layout drift");

struct ProvLayout {
    ProvHeader hdr;
    ProvNode   nodes[kMaxNodes];
};

std::atomic<bool> g_stop{false};

void on_sigint(int)
{
    g_stop.store(true, std::memory_order_relaxed);
}

int libbpf_print(enum libbpf_print_level level, const char* fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0; // suppress noisy debug
    }
    return std::vfprintf(stderr, fmt, args);
}

void bump_memlock_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        std::fprintf(stderr,
                     "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
                     std::strerror(errno));
    }
}

void print_node_row(const ProvNode& n, const char* lineage_marker)
{
    char safe_comm[17] = {};
    std::memcpy(safe_comm, n.comm, sizeof(n.comm));
    std::printf("  %-19lu %-7u %-7u %-7u %-16s %-12lu %s\n",
                (unsigned long)n.ts_ns,
                n.pid,
                n.ppid,
                n.uid,
                safe_comm,
                (unsigned long)n.exec_inode,
                lineage_marker);
}

void dump(const ProvLayout* layout)
{
    constexpr std::uint64_t kSentinel = static_cast<std::uint64_t>(-1);
    const std::uint64_t total = layout->hdr.next_index;
    const std::uint64_t shown = total < 32 ? total : 32;
    std::printf("\naegis-next: arena header\n");
    std::printf("  magic       = 0x%016lx\n", (unsigned long)layout->hdr.magic);
    std::printf("  next_index  = %lu\n", (unsigned long)total);
    std::printf("  dropped     = %lu\n", (unsigned long)layout->hdr.dropped);

    std::printf("\nlast %lu exec node(s):\n", (unsigned long)shown);
    std::printf("  %-19s %-7s %-7s %-7s %-16s %-12s %s\n",
                "ts_ns", "pid", "ppid", "uid", "comm", "exec_inode", "prev_slot");

    const std::uint64_t start = (total > shown) ? (total - shown) : 0;
    for (std::uint64_t i = start; i < total; ++i) {
        const ProvNode& n = layout->nodes[i % kMaxNodes];
        char marker[32];
        if (n.prev_index == kSentinel) {
            std::snprintf(marker, sizeof(marker), "(root)");
        } else {
            std::snprintf(marker, sizeof(marker), "%lu",
                          (unsigned long)n.prev_index);
        }
        print_node_row(n, marker);
    }

    // Walk lineage backwards from the most recent exec to demonstrate
    // the hash-indexed parent lookup is wired end-to-end.
    if (total == 0) {
        return;
    }
    std::printf("\nlineage of most recent exec (walking prev_index):\n");
    std::printf("  %-19s %-7s %-7s %-7s %-16s %-12s %s\n",
                "ts_ns", "pid", "ppid", "uid", "comm", "exec_inode", "depth");
    std::uint64_t cursor = (total - 1) % kMaxNodes;
    int depth = 0;
    constexpr int kMaxDepth = 64;
    while (depth < kMaxDepth) {
        const ProvNode& n = layout->nodes[cursor];
        char depth_str[16];
        std::snprintf(depth_str, sizeof(depth_str), "%d", depth);
        print_node_row(n, depth_str);
        if (n.prev_index == kSentinel) {
            break;
        }
        cursor = n.prev_index % kMaxNodes;
        ++depth;
    }
    if (depth == kMaxDepth) {
        std::printf("  (truncated at depth %d)\n", kMaxDepth);
    }
}

} // namespace

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    libbpf_set_print(libbpf_print);
    bump_memlock_rlimit();

    provenance_bpf* skel = provenance_bpf__open_and_load();
    if (!skel) {
        std::fprintf(stderr, "failed to open+load provenance skeleton: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "hint: requires kernel >= 6.9 and CAP_BPF + CAP_SYS_ADMIN\n");
        return 1;
    }

    int arena_fd = bpf_map__fd(skel->maps.aegis_next_arena);
    if (arena_fd < 0) {
        std::fprintf(stderr, "arena map fd unavailable\n");
        provenance_bpf__destroy(skel);
        return 1;
    }

    void* arena = mmap(nullptr, kArenaBytes, PROT_READ,
                       MAP_SHARED, arena_fd, 0);
    if (arena == MAP_FAILED) {
        std::fprintf(stderr, "mmap(arena) failed: %s\n", std::strerror(errno));
        provenance_bpf__destroy(skel);
        return 1;
    }

    if (provenance_bpf__attach(skel) != 0) {
        std::fprintf(stderr, "failed to attach LSM program: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "hint: kernel must be built with CONFIG_BPF_LSM=y and\n"
                     "      lsm= boot param must include bpf\n");
        munmap(arena, kArenaBytes);
        provenance_bpf__destroy(skel);
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::printf("aegis-next: attached. exec events recorded into arena.\n");
    std::printf("press Ctrl-C to dump and exit.\n");

    auto* layout = static_cast<const ProvLayout*>(arena);
    std::uint64_t last_seen = 0;
    while (!g_stop.load(std::memory_order_relaxed)) {
        sleep(2);
        const std::uint64_t cur = layout->hdr.next_index;
        if (cur != last_seen) {
            std::printf("  ... recorded %lu exec(s) total\n",
                        (unsigned long)cur);
            last_seen = cur;
        }
    }

    dump(layout);

    munmap(arena, kArenaBytes);
    provenance_bpf__destroy(skel);
    return 0;
}
