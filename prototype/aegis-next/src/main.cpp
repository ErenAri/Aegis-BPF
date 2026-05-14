// SPDX-License-Identifier: GPL-2.0
//
// aegis-next userspace driver (proof-of-concept).
//
// Subcommands:
//   aegisbpf-next attach          — load, pin maps, attach LSM, loop
//   aegisbpf-next graph dump      — print recent exec nodes
//   aegisbpf-next graph lineage <pid> — walk lineage for a pid
//   aegisbpf-next graph stats     — print arena header stats
//
// The "attach" subcommand pins the arena map in bpffs so the
// "graph" subcommands can open it from a separate process.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

#include "aegis_next_prov.hpp"
#include "prov_walk.hpp"
#include "provenance.skel.h"

namespace {

using aegis_next::kArenaBytes;
using aegis_next::kMaxLineageDepth;
using aegis_next::kMaxNodes;
using aegis_next::kRootSentinel;
using aegis_next::LineageEntry;
using aegis_next::ProvHeader;
using aegis_next::ProvLayout;
using aegis_next::ProvNode;

// Default bpffs pin directory. Overridable via AEGIS_NEXT_PIN_DIR.
constexpr const char* kDefaultPinDir = "/sys/fs/bpf/aegis_next";

std::string pin_dir()
{
    const char* env = std::getenv("AEGIS_NEXT_PIN_DIR");
    if (env && env[0] != '\0') {
        return env;
    }
    return kDefaultPinDir;
}

std::string arena_pin_path() { return pin_dir() + "/arena"; }

std::atomic<bool> g_stop{false};

void on_sigint(int)
{
    g_stop.store(true, std::memory_order_relaxed);
}

int libbpf_print(enum libbpf_print_level level, const char* fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0;
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

void print_node_row(const ProvNode& n, const char* tag)
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
                tag);
}

void print_table_header()
{
    std::printf("  %-19s %-7s %-7s %-7s %-16s %-12s %s\n",
                "ts_ns", "pid", "ppid", "uid", "comm", "exec_inode", "info");
}

// ---- arena open helpers ----

// Open an already-pinned arena map via bpf_obj_get and mmap it.
// Returns nullptr on failure (with stderr diagnostics).
const ProvLayout* open_pinned_arena()
{
    std::string path = arena_pin_path();
    int fd = bpf_obj_get(path.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned arena at %s: %s\n"
                     "hint: run 'aegisbpf-next attach' first\n",
                     path.c_str(), std::strerror(errno));
        return nullptr;
    }
    void* arena = mmap(nullptr, kArenaBytes, PROT_READ,
                       MAP_SHARED, fd, 0);
    close(fd);
    if (arena == MAP_FAILED) {
        std::fprintf(stderr, "mmap(arena) failed: %s\n",
                     std::strerror(errno));
        return nullptr;
    }
    return static_cast<const ProvLayout*>(arena);
}

aegis_next::SlotReader make_reader(const ProvLayout* layout)
{
    return [layout](std::uint64_t slot) -> ProvNode {
        return layout->nodes[slot];
    };
}

// ---- subcommands ----

void usage(const char* prog)
{
    std::fprintf(stderr,
                 "usage: %s <command>\n"
                 "\n"
                 "commands:\n"
                 "  attach                 load BPF, pin maps, attach LSM, loop\n"
                 "  graph dump             print recent exec nodes from arena\n"
                 "  graph lineage <pid>    walk exec lineage for a process\n"
                 "  graph stats            print arena header statistics\n",
                 prog);
}

int cmd_attach()
{
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

    // Pin arena map in bpffs so graph subcommands can reach it.
    std::string dir = pin_dir();
    (void)::mkdir(dir.c_str(), 0700);
    std::string path = arena_pin_path();
    int err = bpf_map__pin(skel->maps.aegis_next_arena, path.c_str());
    if (err && errno != EEXIST) {
        std::fprintf(stderr, "failed to pin arena at %s: %s\n",
                     path.c_str(), std::strerror(errno));
        std::fprintf(stderr,
                     "hint: is bpffs mounted at /sys/fs/bpf?\n");
        provenance_bpf__destroy(skel);
        return 1;
    }
    std::printf("aegis-next: arena pinned at %s\n", path.c_str());

    int arena_fd = bpf_map__fd(skel->maps.aegis_next_arena);
    if (arena_fd < 0) {
        std::fprintf(stderr, "arena map fd unavailable\n");
        provenance_bpf__destroy(skel);
        return 1;
    }

    void* arena = mmap(nullptr, kArenaBytes, PROT_READ,
                       MAP_SHARED, arena_fd, 0);
    if (arena == MAP_FAILED) {
        std::fprintf(stderr, "mmap(arena) failed: %s\n",
                     std::strerror(errno));
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
    std::printf("press Ctrl-C to stop.\n");

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

    std::printf("\naegis-next: detaching. arena pin remains at %s\n",
                path.c_str());

    munmap(arena, kArenaBytes);
    provenance_bpf__destroy(skel);
    return 0;
}

int cmd_graph_stats()
{
    const ProvLayout* layout = open_pinned_arena();
    if (!layout) return 1;

    const ProvHeader& hdr = layout->hdr;
    std::printf("aegis-next arena stats\n");
    std::printf("  magic       = 0x%016lx\n", (unsigned long)hdr.magic);
    std::printf("  next_index  = %lu\n", (unsigned long)hdr.next_index);
    std::printf("  dropped     = %lu\n", (unsigned long)hdr.dropped);

    const std::uint64_t total = hdr.next_index;
    const std::uint64_t occupied =
        (total < kMaxNodes) ? total : kMaxNodes;
    std::printf("  slots used  = %lu / %lu (%.1f%%)\n",
                (unsigned long)occupied,
                (unsigned long)kMaxNodes,
                occupied * 100.0 / kMaxNodes);

    munmap(const_cast<void*>(static_cast<const void*>(layout)),
           kArenaBytes);
    return 0;
}

int cmd_graph_dump()
{
    const ProvLayout* layout = open_pinned_arena();
    if (!layout) return 1;

    const std::uint64_t total = layout->hdr.next_index;
    const std::uint64_t shown = total < 32 ? total : 32;
    std::printf("last %lu of %lu exec node(s):\n",
                (unsigned long)shown, (unsigned long)total);
    print_table_header();

    const std::uint64_t start = (total > shown) ? (total - shown) : 0;
    for (std::uint64_t i = start; i < total; ++i) {
        const ProvNode& n = layout->nodes[i % kMaxNodes];
        char marker[32];
        if (n.prev_index == kRootSentinel) {
            std::snprintf(marker, sizeof(marker), "(root)");
        } else {
            std::snprintf(marker, sizeof(marker), "parent@%lu",
                          (unsigned long)n.prev_index);
        }
        print_node_row(n, marker);
    }

    munmap(const_cast<void*>(static_cast<const void*>(layout)),
           kArenaBytes);
    return 0;
}

int cmd_graph_lineage(std::uint32_t target_pid)
{
    const ProvLayout* layout = open_pinned_arena();
    if (!layout) return 1;

    const std::uint64_t total = layout->hdr.next_index;
    auto reader = make_reader(layout);

    std::uint64_t slot = aegis_next::find_slot_by_pid(
        target_pid, total, kMaxNodes, reader);

    if (slot == kRootSentinel) {
        std::fprintf(stderr,
                     "pid %u not found in the arena (%lu nodes scanned)\n",
                     target_pid, (unsigned long)total);
        munmap(const_cast<void*>(static_cast<const void*>(layout)),
               kArenaBytes);
        return 1;
    }

    std::printf("lineage for pid %u (most recent exec at slot %lu):\n",
                target_pid, (unsigned long)slot);
    print_table_header();

    const std::size_t visited = aegis_next::walk_lineage(
        slot, kMaxNodes, reader,
        [](const LineageEntry& e) {
            char depth_str[16];
            std::snprintf(depth_str, sizeof(depth_str), "depth=%d", e.depth);
            print_node_row(e.node, depth_str);
        });

    if (visited == static_cast<std::size_t>(kMaxLineageDepth)) {
        std::printf("  (truncated at depth %d)\n", kMaxLineageDepth);
    }

    munmap(const_cast<void*>(static_cast<const void*>(layout)),
           kArenaBytes);
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const std::string cmd = argv[1];

    if (cmd == "attach") {
        return cmd_attach();
    }

    if (cmd == "graph") {
        if (argc < 3) {
            std::fprintf(stderr, "graph requires a subcommand: dump, lineage, stats\n");
            return 1;
        }
        const std::string sub = argv[2];
        if (sub == "dump") {
            return cmd_graph_dump();
        }
        if (sub == "stats") {
            return cmd_graph_stats();
        }
        if (sub == "lineage") {
            if (argc < 4) {
                std::fprintf(stderr, "usage: %s graph lineage <pid>\n", argv[0]);
                return 1;
            }
            char* end = nullptr;
            const unsigned long pid_arg = std::strtoul(argv[3], &end, 10);
            if (!end || *end != '\0' || pid_arg == 0 || pid_arg > UINT32_MAX) {
                std::fprintf(stderr, "invalid pid: %s\n", argv[3]);
                return 1;
            }
            return cmd_graph_lineage(static_cast<std::uint32_t>(pid_arg));
        }
        std::fprintf(stderr, "unknown graph subcommand: %s\n", sub.c_str());
        return 1;
    }

    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        usage(argv[0]);
        return 0;
    }

    std::fprintf(stderr, "unknown command: %s\n", cmd.c_str());
    usage(argv[0]);
    return 1;
}
