// SPDX-License-Identifier: GPL-2.0
//
// aegis-next userspace driver (proof-of-concept).
//
// Subcommands:
//   aegisbpf-next attach [--deny <name>]...  — load, pin maps, attach LSM, loop
//   aegisbpf-next graph dump      — print recent exec nodes
//   aegisbpf-next graph lineage <pid> — walk lineage for a pid
//   aegisbpf-next graph stats     — print arena header stats
//   aegisbpf-next sched start     — load sched_ext quarantine scheduler
//   aegisbpf-next sched quarantine <cgid> <level> — set quarantine level
//   aegisbpf-next sched status    — list quarantined cgroups
//
// The "attach" subcommand pins the arena map in bpffs so the
// "graph" subcommands can open it from a separate process.
// With --deny flags, attach auto-quarantines cgroups that exec
// deny-listed binaries (writes to the pinned quarantine map).

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <atomic>
#include <cerrno>
#include <type_traits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>
#include <unistd.h>

#include "aegis_next_prov.hpp"
#include "prov_walk.hpp"
#include "prov_arena_types.h"  // C struct defs for skeleton arena globals
#include "provenance.skel.h"
#include "quarantine.skel.h"

// Verify that our computed hash table offset matches the skeleton layout.
static_assert(offsetof(provenance_bpf::provenance_bpf__arena, arena_ht) ==
              aegis_next::kHtOffset,
              "arena hash table offset mismatch — update kHtOffset");

namespace {

using aegis_next::arena_ht_from_mmap;
using aegis_next::HtEntry;
using aegis_next::kArenaBytes;
using aegis_next::kMaxLineageDepth;
using aegis_next::kMaxNodes;
using aegis_next::kRootSentinel;
using aegis_next::LineageEntry;
using aegis_next::ProvHeader;
using aegis_next::ProvLayout;
using aegis_next::ProvNode;

// Format a NetFlow 5-tuple into a human-readable string.
std::string format_flow(const aegis_next::NetFlow* flow)
{
    if (!flow)
        return "-";

    const char* proto_str = "?";
    switch (flow->proto) {
    case 6:  proto_str = "tcp"; break;
    case 17: proto_str = "udp"; break;
    case 1:  proto_str = "icmp"; break;
    }

    char src_buf[INET6_ADDRSTRLEN] = {};
    char dst_buf[INET6_ADDRSTRLEN] = {};

    if (flow->family == 2 /* AF_INET */) {
        inet_ntop(AF_INET, &flow->src_v4, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &flow->dst_v4, dst_buf, sizeof(dst_buf));
    } else if (flow->family == 10 /* AF_INET6 */) {
        inet_ntop(AF_INET6, flow->src_v6, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, flow->dst_v6, dst_buf, sizeof(dst_buf));
    }

    char buf[256];
    if (flow->dst_port != 0) {
        std::snprintf(buf, sizeof(buf), "%s %s:%u->%s:%u",
                      proto_str, src_buf, flow->src_port,
                      dst_buf, flow->dst_port);
    } else {
        std::snprintf(buf, sizeof(buf), "%s %s:%u",
                      proto_str, src_buf, flow->src_port);
    }
    return buf;
}

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
std::string quarantine_pin_path() { return pin_dir() + "/quarantine"; }
std::string gc_state_pin_path() { return pin_dir() + "/gc_state"; }

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

void print_node_row(const ProvNode& n, const char* tag,
                    const char* path = nullptr)
{
    char safe_comm[13] = {};
    std::memcpy(safe_comm, n.comm, sizeof(n.comm));
    std::printf("  %-19lu %-5s %-7u %-7u %-7u %-12s %-12lu %-16s %s\n",
                (unsigned long)n.ts_ns,
                aegis_next::kind_name(n.kind),
                n.pid,
                n.ppid,
                n.uid,
                safe_comm,
                (unsigned long)n.object_id,
                (path && path[0]) ? path : "-",
                tag);
}

void print_table_header()
{
    std::printf("  %-19s %-5s %-7s %-7s %-7s %-12s %-12s %-16s %s\n",
                "ts_ns", "kind", "pid", "ppid", "uid", "comm",
                "object_id", "path", "info");
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
    void* arena = mmap(nullptr, kArenaBytes, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
    close(fd);
    if (arena == MAP_FAILED) {
        std::fprintf(stderr, "mmap(arena) failed: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "note: on kernel 6.17+, BPF arenas can only be mmapped\n"
                     "      by one process. Use 'graph' subcommands from the\n"
                     "      attach process (future: Unix socket query API).\n");
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
                 "  attach [--deny <name>]... load BPF, pin maps, attach LSM, loop\n"
                 "  graph dump             print recent exec nodes from arena\n"
                 "  graph lineage <pid>    walk exec lineage for a process\n"
                 "  graph stats            print arena header statistics\n"
                 "  graph gc               print GC timer statistics\n"
                 "  sched start            load sched_ext quarantine scheduler\n"
                 "  sched quarantine <cgid> <level>  set quarantine level for cgroup\n"
                 "  sched status           list quarantined cgroups\n",
                 prog);
}

int cmd_attach(const std::unordered_set<std::string>& deny_list)
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

    // Pin GC state map for the `graph gc` subcommand.
    std::string gc_path = gc_state_pin_path();
    int gc_pin_err = bpf_map__pin(skel->maps.aegis_next_gc_state, gc_path.c_str());
    if (gc_pin_err && errno != EEXIST) {
        std::fprintf(stderr, "warning: failed to pin gc_state at %s: %s\n",
                     gc_path.c_str(), std::strerror(errno));
    }

    int arena_fd = bpf_map__fd(skel->maps.aegis_next_arena);
    if (arena_fd < 0) {
        std::fprintf(stderr, "arena map fd unavailable\n");
        provenance_bpf__destroy(skel);
        return 1;
    }

    // Arena init + catch-up scan MUST run before attach. The catchup
    // SEC("syscall") program calls bpf_arena_alloc_pages (sleepable
    // kfunc since 6.12+) and seeds the arena with existing processes.
    // LSM hooks will find the arena ready once they fire after attach.
    int catchup_fd = bpf_program__fd(skel->progs.aegis_next_catchup);
    if (catchup_fd >= 0) {
        LIBBPF_OPTS(bpf_test_run_opts, run_opts);
        int rc = bpf_prog_test_run_opts(catchup_fd, &run_opts);
        if (rc != 0 || run_opts.retval != 0) {
            std::fprintf(stderr,
                         "arena init / catch-up failed (rc=%d retval=%d): %s\n",
                         rc, run_opts.retval, std::strerror(errno));
            provenance_bpf__destroy(skel);
            return 1;
        }
    }

    // libbpf 1.6+ automatically mmaps the arena for skeleton globals.
    // Access the arena data through skel->arena instead of manual mmap.
    if (!skel->arena) {
        std::fprintf(stderr, "arena not mapped by libbpf\n");
        provenance_bpf__destroy(skel);
        return 1;
    }

    std::printf("aegis-next: catch-up scan seeded %lu process(es)\n",
                (unsigned long)skel->arena->arena_hdr.next_index);

    if (provenance_bpf__attach(skel) != 0) {
        std::fprintf(stderr, "failed to attach LSM program: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "hint: kernel must be built with CONFIG_BPF_LSM=y and\n"
                     "      lsm= boot param must include bpf\n");
        provenance_bpf__destroy(skel);
        return 1;
    }

    // Arm the in-kernel GC timer for pid_slot sweep.
    int gc_fd = bpf_program__fd(skel->progs.aegis_next_gc_start);
    if (gc_fd >= 0) {
        LIBBPF_OPTS(bpf_test_run_opts, gc_opts);
        int gc_rc = bpf_prog_test_run_opts(gc_fd, &gc_opts);
        if (gc_rc == 0 && gc_opts.retval == 0) {
            std::printf("aegis-next: GC timer armed (30s interval)\n");
        } else {
            std::fprintf(stderr,
                         "warning: GC timer arm failed (rc=%d retval=%d): %s\n",
                         gc_rc, gc_opts.retval, std::strerror(errno));
        }
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    // If a deny list is active, try to open the pinned quarantine map
    // for auto-quarantine writes. Not fatal if missing — just log.
    int quarantine_fd = -1;
    if (!deny_list.empty()) {
        std::string qpath = quarantine_pin_path();
        quarantine_fd = bpf_obj_get(qpath.c_str());
        if (quarantine_fd < 0) {
            std::fprintf(stderr,
                         "warning: deny list active but quarantine map not pinned at %s\n"
                         "  run 'aegisbpf-next sched start' to enable auto-quarantine.\n",
                         qpath.c_str());
        } else {
            std::printf("aegis-next: deny list active (%zu entries), "
                        "auto-quarantine via pinned map.\n",
                        deny_list.size());
        }
    }

    std::printf("aegis-next: attached. events recorded into arena.\n");

    // Access arena through the skeleton's auto-mapped globals.
    auto* arena_view = skel->arena;

    // Quick check: hash table was populated by the catch-up scan.
    {
        const auto* ht = reinterpret_cast<const aegis_next::HtEntry*>(
            arena_view->arena_ht);
        std::uint64_t occupied = 0;
        for (std::size_t i = 0; i < aegis_next::kHtBuckets; ++i) {
            if (ht[i].key != 0)
                ++occupied;
        }
        std::printf("aegis-next: arena hash table: %lu / %lu buckets used (%.1f%%)\n",
                    (unsigned long)occupied,
                    (unsigned long)aegis_next::kHtBuckets,
                    occupied * 100.0 / aegis_next::kHtBuckets);
    }

    // Set up ringbuf for real-time alert processing.
    struct ring_ctx {
        const std::remove_pointer_t<decltype(arena_view)>* arena;
        const std::unordered_set<std::string>* deny;
        int quar_fd;
        std::uint64_t events;
        std::uint64_t quarantine_hits;
        std::uint64_t last_print;
    };

    ring_ctx rctx{};
    rctx.arena = arena_view;
    rctx.deny = &deny_list;
    rctx.quar_fd = quarantine_fd;

    int rb_fd = bpf_map__fd(skel->maps.aegis_next_ringbuf);
    struct ring_buffer* rb = ring_buffer__new(
        rb_fd,
        [](void* ctx, void* data, size_t /*sz*/) -> int {
            auto* c = static_cast<ring_ctx*>(ctx);
            auto* alert = static_cast<const aegis_alert*>(data);
            ++c->events;

            // Deny-list check for exec events.
            if (alert->kind == PROV_KIND_EXEC &&
                c->quar_fd >= 0 && !c->deny->empty()) {
                const auto& node =
                    c->arena->arena_nodes[alert->slot % kMaxNodes];
                std::string comm(node.comm,
                                 strnlen(node.comm, sizeof(node.comm)));
                if (c->deny->count(comm) && node.cgid != 0) {
                    __u32 level = 1;
                    if (bpf_map_update_elem(c->quar_fd, &node.cgid,
                                            &level, BPF_ANY) == 0) {
                        std::printf("  ** auto-quarantined cgid %lu "
                                    "(exec '%s', pid %u)\n",
                                    (unsigned long)node.cgid,
                                    comm.c_str(), node.pid);
                        ++c->quarantine_hits;
                    }
                }
            }

            // Periodic progress line (every 100 events).
            if (c->events - c->last_print >= 100) {
                std::printf("  ... %lu events processed via ringbuf\n",
                            (unsigned long)c->events);
                c->last_print = c->events;
            }
            return 0;
        },
        &rctx, nullptr);

    if (!rb) {
        std::fprintf(stderr, "failed to create ring_buffer: %s\n",
                     std::strerror(errno));
        provenance_bpf__destroy(skel);
        return 1;
    }

    std::printf("aegis-next: ringbuf polling active (sub-ms latency).\n");
    std::printf("press Ctrl-C to stop.\n");

    while (!g_stop.load(std::memory_order_relaxed)) {
        int err = ring_buffer__poll(rb, 1000 /* ms timeout */);
        if (err < 0 && err != -EINTR)
            break;
    }

    ring_buffer__free(rb);

    if (rctx.quarantine_hits > 0) {
        std::printf("aegis-next: auto-quarantined %lu cgroup(s) this session.\n",
                    (unsigned long)rctx.quarantine_hits);
    }
    std::printf("aegis-next: processed %lu events via ringbuf.\n",
                (unsigned long)rctx.events);

    // Report hash table stats on exit.
    {
        const auto* ht = reinterpret_cast<const aegis_next::HtEntry*>(
            arena_view->arena_ht);
        std::uint64_t occupied = 0;
        for (std::size_t i = 0; i < aegis_next::kHtBuckets; ++i) {
            if (ht[i].key != 0)
                ++occupied;
        }
        std::printf("aegis-next: arena hash table at exit: %lu / %lu buckets occupied\n",
                    (unsigned long)occupied,
                    (unsigned long)aegis_next::kHtBuckets);
    }

    // Show last few events with resolved paths and network flows.
    {
        const auto* pslab = reinterpret_cast<const aegis_next::PathSlabEntry*>(
            arena_view->path_slab);
        const auto* nslab = reinterpret_cast<const aegis_next::NetFlow*>(
            arena_view->net_slab);
        const std::uint64_t cur = arena_view->arena_hdr.next_index;
        const std::uint64_t shown = cur < 16 ? cur : 16;
        std::printf("aegis-next: last %lu events:\n", (unsigned long)shown);
        print_table_header();
        for (std::uint64_t i = cur - shown; i < cur; ++i) {
            const auto& n = reinterpret_cast<const ProvNode&>(
                arena_view->arena_nodes[i % kMaxNodes]);
            const char* path = aegis_next::path_from_slab(pslab, n.path_slab_idx);
            // For socket events, show 5-tuple in the path column.
            std::string flow_str;
            if (n.net_slab_idx != 0) {
                const auto* flow = aegis_next::net_from_slab(nslab, n.net_slab_idx);
                flow_str = format_flow(flow);
                path = flow_str.c_str();
            }
            char marker[32];
            if (n.prev_index == kRootSentinel) {
                std::snprintf(marker, sizeof(marker), "(root)");
            } else {
                std::snprintf(marker, sizeof(marker), "parent@%lu",
                              (unsigned long)n.prev_index);
            }
            print_node_row(n, marker, path);
        }
    }

    std::printf("\naegis-next: detaching. arena pin remains at %s\n",
                path.c_str());

    // libbpf manages the arena mmap — no manual munmap needed.
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
    std::printf("  generation  = %lu\n", (unsigned long)hdr.generation);

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

int cmd_graph_gc()
{
    std::string path = gc_state_pin_path();
    int fd = bpf_obj_get(path.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned gc_state at %s: %s\n"
                     "hint: run 'aegisbpf-next attach' first.\n",
                     path.c_str(), std::strerror(errno));
        return 1;
    }

    // gc_state layout: bpf_timer (opaque, skip), then u64 runs, u64 evicted.
    // bpf_timer is 16 bytes on most kernels. We read the full value
    // and extract the trailing stats fields.
    // The struct in BPF is: { bpf_timer(16B), u64 runs, u64 evicted }
    // Total: 32 bytes.
    struct {
        char timer_opaque[16]; // bpf_timer is opaque to userspace
        std::uint64_t runs;
        std::uint64_t evicted;
    } state{};

    __u32 key = 0;
    if (bpf_map_lookup_elem(fd, &key, &state) != 0) {
        std::fprintf(stderr, "failed to read gc_state: %s\n",
                     std::strerror(errno));
        close(fd);
        return 1;
    }

    std::printf("aegis-next GC stats\n");
    std::printf("  gc passes   = %lu\n", (unsigned long)state.runs);
    std::printf("  evicted     = %lu\n", (unsigned long)state.evicted);
    close(fd);
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

    // Try O(1) hash lookup first, fall back to linear scan.
    const HtEntry* ht = arena_ht_from_mmap(layout);
    std::uint64_t slot = aegis_next::find_slot_by_pid_ht(
        target_pid, ht, kMaxNodes, reader);

    if (slot == kRootSentinel) {
        // Hash miss (stale or never inserted) — fall back to linear scan.
        slot = aegis_next::find_slot_by_pid(
            target_pid, total, kMaxNodes, reader);
    }

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

    const std::uint64_t gen = layout->hdr.generation;
    bool hit_stale = false;
    const std::size_t visited = aegis_next::walk_lineage(
        slot, kMaxNodes, reader,
        [&](const LineageEntry& e) {
            char depth_str[32];
            if (e.stale) {
                std::snprintf(depth_str, sizeof(depth_str),
                              "depth=%d (stale)", e.depth);
                hit_stale = true;
            } else {
                std::snprintf(depth_str, sizeof(depth_str),
                              "depth=%d", e.depth);
            }
            print_node_row(e.node, depth_str);
        },
        gen);

    if (hit_stale) {
        std::printf("  (walk stopped: stale node detected — arena has wrapped)\n");
    } else if (visited == static_cast<std::size_t>(kMaxLineageDepth)) {
        std::printf("  (truncated at depth %d)\n", kMaxLineageDepth);
    }

    munmap(const_cast<void*>(static_cast<const void*>(layout)),
           kArenaBytes);
    return 0;
}

// ---- sched_ext subcommands ------------------------------------

int cmd_sched_start()
{
    libbpf_set_print(libbpf_print);
    bump_memlock_rlimit();

    quarantine_bpf* skel = quarantine_bpf__open_and_load();
    if (!skel) {
        std::fprintf(stderr, "failed to open+load quarantine scheduler: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "hint: requires kernel >= 6.12 with CONFIG_SCHED_CLASS_EXT=y\n");
        return 1;
    }

    // Pin quarantine map in bpffs so CLI commands can reach it.
    std::string dir = pin_dir();
    (void)::mkdir(dir.c_str(), 0700);
    std::string qpath = quarantine_pin_path();
    int pin_err = bpf_map__pin(skel->maps.aegis_next_quarantine, qpath.c_str());
    if (pin_err && errno != EEXIST) {
        std::fprintf(stderr, "failed to pin quarantine map at %s: %s\n",
                     qpath.c_str(), std::strerror(errno));
        std::fprintf(stderr,
                     "hint: is bpffs mounted at /sys/fs/bpf?\n");
        quarantine_bpf__destroy(skel);
        return 1;
    }
    std::printf("aegis-next: quarantine map pinned at %s\n", qpath.c_str());

    struct bpf_link* link = bpf_map__attach_struct_ops(skel->maps.aegis_next_sched);
    if (!link) {
        std::fprintf(stderr, "failed to attach sched_ext scheduler: %s\n",
                     std::strerror(errno));
        quarantine_bpf__destroy(skel);
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::printf("aegis-next: sched_ext scheduler 'aegis_next' attached.\n");
    std::printf("  throttled slice: 1ms, default slice: 5ms\n");
    std::printf("press Ctrl-C to detach.\n");

    while (!g_stop.load(std::memory_order_relaxed)) {
        sleep(2);
    }

    std::printf("\naegis-next: detaching sched_ext scheduler.\n");
    std::printf("  quarantine pin remains at %s\n", qpath.c_str());
    bpf_link__destroy(link);
    quarantine_bpf__destroy(skel);
    return 0;
}

int open_pinned_quarantine_fd()
{
    std::string path = quarantine_pin_path();
    int fd = bpf_obj_get(path.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned quarantine map at %s: %s\n"
                     "hint: run 'aegisbpf-next sched start' first.\n",
                     path.c_str(), std::strerror(errno));
    }
    return fd;
}

int cmd_sched_quarantine(std::uint64_t cgid, std::uint32_t level)
{
    int map_fd = open_pinned_quarantine_fd();
    if (map_fd < 0)
        return 1;

    int err;
    if (level == 0) {
        err = bpf_map_delete_elem(map_fd, &cgid);
        if (err && errno != ENOENT) {
            std::fprintf(stderr, "failed to clear quarantine for cgid %lu: %s\n",
                         (unsigned long)cgid, std::strerror(errno));
            close(map_fd);
            return 1;
        }
        std::printf("quarantine cleared for cgid %lu\n", (unsigned long)cgid);
    } else {
        err = bpf_map_update_elem(map_fd, &cgid, &level, BPF_ANY);
        if (err) {
            std::fprintf(stderr, "failed to set quarantine for cgid %lu: %s\n",
                         (unsigned long)cgid, std::strerror(errno));
            close(map_fd);
            return 1;
        }
        std::printf("quarantine set for cgid %lu: level=%u\n",
                    (unsigned long)cgid, level);
    }

    close(map_fd);
    return 0;
}

int cmd_sched_status()
{
    int map_fd = open_pinned_quarantine_fd();
    if (map_fd < 0)
        return 1;

    std::printf("quarantined cgroups:\n");
    std::printf("  %-20s %s\n", "CGROUP_ID", "LEVEL");

    __u64 key = 0;
    __u64 next_key = 0;
    __u32 value = 0;
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            const char* label = (value >= 2) ? "pin"
                              : (value >= 1) ? "throttle"
                              : "none";
            std::printf("  %-20lu %u (%s)\n",
                        (unsigned long)next_key, value, label);
            ++count;
        }
        key = next_key;
    }

    if (count == 0) {
        std::printf("  (none)\n");
    }
    std::printf("total: %d\n", count);

    close(map_fd);
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
        std::unordered_set<std::string> deny_list;
        for (int i = 2; i < argc; ++i) {
            if (std::strcmp(argv[i], "--deny") == 0 && i + 1 < argc) {
                deny_list.insert(argv[++i]);
            }
        }
        return cmd_attach(deny_list);
    }

    if (cmd == "graph") {
        if (argc < 3) {
            std::fprintf(stderr, "graph requires a subcommand: dump, lineage, stats, gc\n");
            return 1;
        }
        const std::string sub = argv[2];
        if (sub == "dump") {
            return cmd_graph_dump();
        }
        if (sub == "stats") {
            return cmd_graph_stats();
        }
        if (sub == "gc") {
            return cmd_graph_gc();
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

    if (cmd == "sched") {
        if (argc < 3) {
            std::fprintf(stderr, "sched requires a subcommand: start, quarantine, status\n");
            return 1;
        }
        const std::string sub = argv[2];
        if (sub == "start") {
            return cmd_sched_start();
        }
        if (sub == "status") {
            return cmd_sched_status();
        }
        if (sub == "quarantine") {
            if (argc < 5) {
                std::fprintf(stderr, "usage: %s sched quarantine <cgid> <level>\n", argv[0]);
                return 1;
            }
            const auto cgid = static_cast<std::uint64_t>(std::strtoull(argv[3], nullptr, 0));
            const auto level = static_cast<std::uint32_t>(std::strtoul(argv[4], nullptr, 0));
            return cmd_sched_quarantine(cgid, level);
        }
        std::fprintf(stderr, "unknown sched subcommand: %s\n", sub.c_str());
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
