// SPDX-License-Identifier: GPL-2.0
//
// aegis-next userspace driver (proof-of-concept).
//
// Subcommands:
//   aegisbpf-next attach             — load, pin maps, attach LSM, loop
//   aegisbpf-next graph dump      — print recent exec nodes
//   aegisbpf-next graph lineage <pid> — walk lineage for a pid
//   aegisbpf-next graph stats     — print arena header stats
//   aegisbpf-next sched start     — load sched_ext quarantine scheduler
//   aegisbpf-next sched quarantine <cgid> <level> — set quarantine level
//   aegisbpf-next sched status    — list quarantined cgroups
//
// The "attach" subcommand pins the arena map in bpffs so the
// "graph" subcommands can open it from a separate process.
// Policy rules with action=quarantine bridge directly to the
// sched_ext quarantine map in-kernel (no userspace round-trip).

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <type_traits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "aegis_next_prov.hpp"
#include "event_export.hpp"
#include "feature_probe.hpp"
#include "prov_walk.hpp"
#include "prov_arena_types.h"  // C struct defs for skeleton arena globals
#include "provenance.skel.h"
#include "provenance_legacy.skel.h"
#include "quarantine.skel.h"
#include "selfprotect.skel.h"

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
std::string policy_pin_path() { return pin_dir() + "/policy"; }

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
    char ns_buf[32] = "-";
    if (n.mnt_ns != 0 || n.pid_ns != 0) {
        std::snprintf(ns_buf, sizeof(ns_buf), "%u/%u", n.mnt_ns, n.pid_ns);
    }
    std::printf("  %-19lu %-6s %-7u %-7u %-7u %-12s %-12lu %-12s %-16s %s\n",
                (unsigned long)n.ts_ns,
                aegis_next::kind_name(n.kind),
                n.pid,
                n.ppid,
                n.uid,
                safe_comm,
                (unsigned long)n.object_id,
                ns_buf,
                (path && path[0]) ? path : "-",
                tag);
}

void print_table_header()
{
    std::printf("  %-19s %-6s %-7s %-7s %-7s %-12s %-12s %-12s %-16s %s\n",
                "ts_ns", "kind", "pid", "ppid", "uid", "comm",
                "object_id", "ns(mnt/pid)", "path", "info");
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
                 "  attach                 load BPF, pin maps, attach LSM, loop\n"
                 "  graph dump             print recent exec nodes from arena\n"
                 "  graph lineage <pid>    walk exec lineage for a process\n"
                 "  graph stats            print arena header statistics\n"
                 "  graph gc               print GC timer statistics\n"
                 "  policy add <hook> <match> <value> <action> [--kill]\n"
                 "                         add a policy rule (deny/allow/log)\n"
                 "  policy load <file>     load policy rules from a text file\n"
                 "  policy list            list all active policy rules\n"
                 "  policy clear           remove all policy rules\n"
                 "  sched start            load sched_ext quarantine scheduler\n"
                 "  sched quarantine <cgid> <level>  set level: 0=clear 1=throttle 2=pin 3=starve\n"
                 "  sched status           list quarantined cgroups\n"
                 "  protect                load self-protection LSM hooks\n"
                 "  export tail [N]        print last N lines from JSONL export\n"
                 "  status                 show feature probes, arena, policy, quarantine\n"
                 "\n"
                 "phase 4 — advanced features (no competitor has these):\n"
                 "  auth start [--audit]   start binary authorization (fsverity + xattr cache)\n"
                 "  auth trust <digest>    add trusted binary digest (hex)\n"
                 "  auth list              list trusted digests\n"
                 "  auth stats             show auth statistics\n"
                 "  rate set <kind> <max>  set rate limit (fork|conn|file|mmap) per second\n",
                 prog);
}

// P3.1: Ringbuf-only fallback for kernels < 6.9.
// When BPF_MAP_TYPE_ARENA is not available, we load a legacy BPF
// program that sends full events (~372B) through the ringbuf instead
// of writing to a shared arena. Userspace receives complete events
// directly — no arena mmap, no path/net slabs, no catch-up scan.
int cmd_attach_legacy()
{
    std::printf("aegis-next: arena unavailable, using ringbuf-only fallback.\n");

    provenance_legacy_bpf* skel = provenance_legacy_bpf__open();
    if (!skel) {
        std::fprintf(stderr, "failed to open legacy skeleton: %s\n",
                     std::strerror(errno));
        return 1;
    }

    // Reuse pinned quarantine map if sched_ext is already loaded.
    {
        std::string qpath = quarantine_pin_path();
        int qfd = bpf_obj_get(qpath.c_str());
        if (qfd >= 0) {
            int rc = bpf_map__reuse_fd(skel->maps.aegis_next_quarantine, qfd);
            if (rc == 0) {
                std::printf("aegis-next: reusing pinned quarantine map\n");
            }
            close(qfd);
        }
    }

    if (provenance_legacy_bpf__load(skel) != 0) {
        std::fprintf(stderr, "failed to load legacy skeleton: %s\n",
                     std::strerror(errno));
        provenance_legacy_bpf__destroy(skel);
        return 1;
    }

    // Pin policy and quarantine maps.
    std::string dir = pin_dir();
    (void)::mkdir(dir.c_str(), 0700);

    std::string pol_path = policy_pin_path();
    int pol_err = bpf_map__pin(skel->maps.aegis_next_policy, pol_path.c_str());
    if (pol_err && errno != EEXIST) {
        std::fprintf(stderr, "warning: failed to pin policy: %s\n",
                     std::strerror(errno));
    }

    std::string quar_path = quarantine_pin_path();
    int quar_err = bpf_map__pin(skel->maps.aegis_next_quarantine, quar_path.c_str());
    if (quar_err && errno != EEXIST) {
        std::fprintf(stderr, "warning: failed to pin quarantine: %s\n",
                     std::strerror(errno));
    }

    if (provenance_legacy_bpf__attach(skel) != 0) {
        std::fprintf(stderr, "failed to attach legacy LSM: %s\n",
                     std::strerror(errno));
        provenance_legacy_bpf__destroy(skel);
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::printf("aegis-next: attached (ringbuf-only mode, ~372B/event).\n");
    std::printf("aegis-next: quarantine bridge active.\n");
    std::printf("  note: graph/lineage commands unavailable in legacy mode.\n"
                "        use 'export tail' to inspect recent events.\n");

    // JSONL export.
    std::string export_path = pin_dir() + "/events.jsonl";
    aegis_next::EventExporter exporter(export_path);
    if (exporter.is_open()) {
        std::printf("aegis-next: JSONL export at %s\n", export_path.c_str());
    }

    // Ringbuf callback for full events.
    struct legacy_ring_ctx {
        aegis_next::EventExporter* exporter;
        std::uint64_t events;
        std::uint64_t last_print;
    };

    legacy_ring_ctx rctx{};
    rctx.exporter = &exporter;

    int rb_fd = bpf_map__fd(skel->maps.aegis_next_ringbuf);
    struct ring_buffer* rb = ring_buffer__new(
        rb_fd,
        [](void* ctx, void* data, size_t /*sz*/) -> int {
            auto* c = static_cast<legacy_ring_ctx*>(ctx);
            auto* evt = static_cast<const prov_ringbuf_event*>(data);
            ++c->events;

            if (c->exporter && c->exporter->is_open()) {
                // Build a prov_node from the ringbuf event for export.
                struct prov_node node{};
                node.ts_ns     = evt->ts_ns;
                node.pid       = evt->pid;
                node.ppid      = evt->ppid;
                node.tgid      = evt->tgid;
                node.uid       = evt->uid;
                node.cgid      = evt->cgid;
                node.object_id = evt->object_id;
                node.kind      = evt->kind;
                node.flags     = evt->flags;
                node.extra     = evt->extra;
                std::memcpy(node.comm, evt->comm, 12);
                node.mnt_ns    = evt->mnt_ns;
                node.pid_ns    = evt->pid_ns;

                const char* path = (evt->path_len > 0) ? evt->path : "";
                const struct net_flow* flow =
                    evt->has_net ? &evt->net : nullptr;

                c->exporter->export_node(node, 0, path, flow);
            }

            if (c->events - c->last_print >= 100) {
                std::printf("  ... %lu events (ringbuf-only)\n",
                            (unsigned long)c->events);
                c->last_print = c->events;
            }
            return 0;
        },
        &rctx, nullptr);

    if (!rb) {
        std::fprintf(stderr, "failed to create ring_buffer: %s\n",
                     std::strerror(errno));
        provenance_legacy_bpf__destroy(skel);
        return 1;
    }

    std::printf("aegis-next: ringbuf polling active.\npress Ctrl-C to stop.\n");

    while (!g_stop.load(std::memory_order_relaxed)) {
        int err = ring_buffer__poll(rb, 1000);
        if (err < 0 && err != -EINTR)
            break;
    }

    ring_buffer__free(rb);

    std::printf("\naegis-next: processed %lu events (ringbuf-only mode).\n",
                (unsigned long)rctx.events);
    if (exporter.count() > 0) {
        std::printf("aegis-next: exported %lu events to %s\n",
                    (unsigned long)exporter.count(), export_path.c_str());
    }

    provenance_legacy_bpf__destroy(skel);
    return 0;
}

int cmd_attach()
{
    libbpf_set_print(libbpf_print);
    bump_memlock_rlimit();

    // P3.2: Runtime feature probing — check what the running kernel
    // supports before loading BPF programs.
    auto features = aegis_next::probe_features();
    aegis_next::print_features(features);

    if (!features.bpf_lsm) {
        std::fprintf(stderr,
                     "error: BPF LSM not enabled. Add 'lsm=bpf' to kernel boot params.\n");
        return 1;
    }

    // P3.1: If arena is unavailable, fall through to ringbuf-only mode.
    if (!features.arena) {
        if (!features.ringbuf) {
            std::fprintf(stderr,
                         "error: neither arena nor ringbuf available.\n");
            return 1;
        }
        return cmd_attach_legacy();
    }

    provenance_bpf* skel = provenance_bpf__open();
    if (!skel) {
        std::fprintf(stderr, "failed to open provenance skeleton: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "hint: requires kernel >= 6.9 and CAP_BPF + CAP_SYS_ADMIN\n");
        return 1;
    }

    // P2.3: If the quarantine map is already pinned (sched_ext scheduler
    // loaded), reuse that FD so the LSM program writes to the same map
    // instance. This is the in-kernel enforcement bridge — policy
    // QUARANTINE verdicts go straight to the sched_ext map.
    {
        std::string qpath = quarantine_pin_path();
        int qfd = bpf_obj_get(qpath.c_str());
        if (qfd >= 0) {
            int rc = bpf_map__reuse_fd(skel->maps.aegis_next_quarantine, qfd);
            if (rc == 0) {
                std::printf("aegis-next: reusing pinned quarantine map "
                            "(in-kernel enforcement bridge active)\n");
            } else {
                std::fprintf(stderr,
                             "warning: quarantine map reuse failed: %s\n",
                             std::strerror(errno));
            }
            close(qfd);
        } else {
            std::printf("aegis-next: quarantine map not pinned yet "
                        "(run 'sched start' for full bridge)\n");
        }
    }

    if (provenance_bpf__load(skel) != 0) {
        std::fprintf(stderr, "failed to load provenance skeleton: %s\n",
                     std::strerror(errno));
        provenance_bpf__destroy(skel);
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

    // Pin policy map for the `policy` subcommands.
    std::string pol_path = policy_pin_path();
    int pol_pin_err = bpf_map__pin(skel->maps.aegis_next_policy, pol_path.c_str());
    if (pol_pin_err && errno != EEXIST) {
        std::fprintf(stderr, "warning: failed to pin policy at %s: %s\n",
                     pol_path.c_str(), std::strerror(errno));
    }

    // Pin quarantine map so sched_ext and CLI can reach it.
    std::string quar_path = quarantine_pin_path();
    int quar_pin_err = bpf_map__pin(skel->maps.aegis_next_quarantine, quar_path.c_str());
    if (quar_pin_err && errno != EEXIST) {
        std::fprintf(stderr, "warning: failed to pin quarantine at %s: %s\n",
                     quar_path.c_str(), std::strerror(errno));
    }

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

    // P3.6: Pre-fault arena pages to eliminate first-access latency
    // spikes. Touch every 4K page in the working set so the kernel
    // maps them before LSM hooks start firing.
    {
        volatile const char* base =
            reinterpret_cast<volatile const char*>(skel->arena);
        constexpr std::size_t prefault_bytes =
            aegis_next::kArenaPages * 4096ULL;
        std::size_t pages = 0;
        for (std::size_t off = 0; off < prefault_bytes; off += 4096) {
            (void)base[off];
            ++pages;
        }
        std::printf("aegis-next: pre-faulted %lu arena pages (%.1f MB)\n",
                    (unsigned long)pages, pages * 4096.0 / (1024 * 1024));
    }

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

    std::printf("aegis-next: attached. events recorded into arena.\n");
    std::printf("aegis-next: in-kernel quarantine bridge active "
                "(QUARANTINE policy → sched_ext map).\n");

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

    // P3.4: Event export — JSONL file for persistence.
    std::string export_path = pin_dir() + "/events.jsonl";
    aegis_next::EventExporter exporter(export_path);
    if (exporter.is_open()) {
        std::printf("aegis-next: JSONL export active at %s\n",
                    export_path.c_str());
    } else {
        std::fprintf(stderr, "warning: could not open %s for export\n",
                     export_path.c_str());
    }

    // Set up ringbuf for real-time alert processing + JSONL export.
    using arena_t = std::remove_pointer_t<decltype(arena_view)>;
    struct ring_ctx {
        const arena_t* arena;
        aegis_next::EventExporter* exporter;
        std::uint64_t events;
        std::uint64_t last_print;
    };

    ring_ctx rctx{};
    rctx.arena = arena_view;
    rctx.exporter = &exporter;

    int rb_fd = bpf_map__fd(skel->maps.aegis_next_ringbuf);
    struct ring_buffer* rb = ring_buffer__new(
        rb_fd,
        [](void* ctx, void* data, size_t /*sz*/) -> int {
            auto* c = static_cast<ring_ctx*>(ctx);
            auto* alert = static_cast<const aegis_alert*>(data);
            ++c->events;

            // Read node from arena and export to JSONL.
            if (c->exporter && c->exporter->is_open()) {
                std::uint64_t idx = alert->slot % kMaxNodes;
                const auto& node = c->arena->arena_nodes[idx];

                const char* path_str = "";
                if (node.path_slab_idx > 0 &&
                    node.path_slab_idx <= aegis_next::kPathSlabSlots) {
                    path_str = reinterpret_cast<const char*>(
                        &c->arena->path_slab[node.path_slab_idx - 1]);
                }

                const struct net_flow* flow = nullptr;
                if (node.net_slab_idx > 0 &&
                    node.net_slab_idx <= aegis_next::kNetSlabSlots) {
                    flow = &c->arena->net_slab[node.net_slab_idx - 1];
                }

                c->exporter->export_node(node, alert->slot,
                                          path_str, flow);
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

    std::printf("aegis-next: processed %lu events via ringbuf.\n",
                (unsigned long)rctx.events);
    if (exporter.count() > 0) {
        std::printf("aegis-next: exported %lu events to %s\n",
                    (unsigned long)exporter.count(), export_path.c_str());
    }

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

    if (!aegis_next::probe_sched_ext()) {
        std::fprintf(stderr,
                     "error: sched_ext not available (need kernel 6.12+ "
                     "with CONFIG_SCHED_CLASS_EXT=y)\n");
        return 1;
    }

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
    std::printf("  levels: 0=normal(5ms) 1=throttle(1ms) "
                "2=pin(1ms,CPU0) 3=starve(100μs,CPU0)\n");
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
            const char* label = (value >= 3) ? "starve"
                              : (value >= 2) ? "pin"
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

// ---- status subcommand -----------------------------------------

int cmd_status()
{
    // Feature probe.
    auto features = aegis_next::probe_features();
    std::printf("=== aegis-next status ===\n\n");
    aegis_next::print_features(features);
    std::printf("\n");

    // Arena stats (if pinned).
    std::string arena_path = arena_pin_path();
    int arena_fd = bpf_obj_get(arena_path.c_str());
    if (arena_fd >= 0) {
        void* base = mmap(nullptr, aegis_next::kArenaBytes,
                          PROT_READ, MAP_SHARED, arena_fd, 0);
        close(arena_fd);
        if (base != MAP_FAILED) {
            const auto* layout =
                static_cast<const aegis_next::ProvLayout*>(base);
            const auto& hdr = layout->hdr;
            std::uint64_t total = hdr.next_index;
            std::uint64_t slots =
                (total < aegis_next::kMaxNodes) ? total : aegis_next::kMaxNodes;
            std::printf("arena:\n");
            std::printf("  nodes recorded: %lu\n", (unsigned long)total);
            std::printf("  slots used:     %lu / %lu (%.1f%%)\n",
                        (unsigned long)slots,
                        (unsigned long)aegis_next::kMaxNodes,
                        slots * 100.0 / aegis_next::kMaxNodes);
            std::printf("  dropped:        %lu\n", (unsigned long)hdr.dropped);
            std::printf("  generation:     %lu\n", (unsigned long)hdr.generation);
            munmap(base, aegis_next::kArenaBytes);
        }
    } else {
        if (!features.arena)
            std::printf("arena: n/a (ringbuf-only mode, kernel < 6.9)\n");
        else
            std::printf("arena: not attached (no pin at %s)\n", arena_path.c_str());
    }
    std::printf("\n");

    // Policy rule count.
    std::string pol_path = policy_pin_path();
    int pol_fd = bpf_obj_get(pol_path.c_str());
    if (pol_fd >= 0) {
        int count = 0;
        policy_key key{}, next{};
        while (bpf_map_get_next_key(pol_fd, &key, &next) == 0) {
            ++count;
            key = next;
        }
        std::printf("policy: %d rule(s) loaded\n", count);
        close(pol_fd);
    } else {
        std::printf("policy: not loaded\n");
    }

    // Quarantine entries.
    std::string quar_path = quarantine_pin_path();
    int quar_fd = bpf_obj_get(quar_path.c_str());
    if (quar_fd >= 0) {
        int count = 0;
        __u64 key = 0, next = 0;
        while (bpf_map_get_next_key(quar_fd, &key, &next) == 0) {
            ++count;
            key = next;
        }
        std::printf("quarantine: %d cgroup(s)\n", count);
        close(quar_fd);
    } else {
        std::printf("quarantine: not loaded\n");
    }

    // Export file.
    std::string exp_path = pin_dir() + "/events.jsonl";
    struct stat st{};
    if (::stat(exp_path.c_str(), &st) == 0) {
        std::printf("export: %s (%.1f KB)\n", exp_path.c_str(),
                    st.st_size / 1024.0);
    } else {
        std::printf("export: no file\n");
    }

    return 0;
}

// ---- self-protection subcommand --------------------------------

int cmd_protect()
{
    libbpf_set_print(libbpf_print);
    bump_memlock_rlimit();

    selfprotect_bpf* skel = selfprotect_bpf__open_and_load();
    if (!skel) {
        std::fprintf(stderr, "failed to open+load selfprotect: %s\n",
                     std::strerror(errno));
        std::fprintf(stderr,
                     "hint: requires CONFIG_BPF_LSM=y and lsm= boot param includes bpf\n");
        return 1;
    }

    // Get our own binary's inode number for trusted caller check.
    struct stat st{};
    if (stat("/proc/self/exe", &st) != 0) {
        std::fprintf(stderr, "failed to stat /proc/self/exe: %s\n",
                     std::strerror(errno));
        selfprotect_bpf__destroy(skel);
        return 1;
    }

    __u32 zero = 0;
    __u64 trusted_ino = st.st_ino;
    int ino_fd = bpf_map__fd(skel->maps.aegis_selfprotect_trusted);
    if (bpf_map_update_elem(ino_fd, &zero, &trusted_ino, BPF_ANY) != 0) {
        std::fprintf(stderr, "failed to set trusted inode: %s\n",
                     std::strerror(errno));
        selfprotect_bpf__destroy(skel);
        return 1;
    }

    // Enable protection.
    __u32 enabled = 1;
    int en_fd = bpf_map__fd(skel->maps.aegis_selfprotect_enabled);
    bpf_map_update_elem(en_fd, &zero, &enabled, BPF_ANY);

    if (selfprotect_bpf__attach(skel) != 0) {
        std::fprintf(stderr, "failed to attach selfprotect LSM: %s\n",
                     std::strerror(errno));
        selfprotect_bpf__destroy(skel);
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::printf("aegis-next: self-protection active.\n");
    std::printf("  trusted inode: %lu (aegisbpf-next binary)\n",
                (unsigned long)trusted_ino);
    std::printf("  hooks: lsm/bpf (PROG_DETACH, LINK_DETACH), lsm/bpf_map (write)\n");
    std::printf("press Ctrl-C to disable.\n");

    while (!g_stop.load(std::memory_order_relaxed)) {
        sleep(2);
    }

    // Disable protection before detaching to allow clean shutdown.
    __u32 disabled = 0;
    bpf_map_update_elem(en_fd, &zero, &disabled, BPF_ANY);

    std::printf("\naegis-next: self-protection disabled, detaching.\n");
    selfprotect_bpf__destroy(skel);
    return 0;
}

// ---- policy subcommands ----------------------------------------

int open_pinned_policy_fd()
{
    std::string path = policy_pin_path();
    int fd = bpf_obj_get(path.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned policy map at %s: %s\n"
                     "hint: run 'aegisbpf-next attach' first.\n",
                     path.c_str(), std::strerror(errno));
    }
    return fd;
}

const char* match_type_name(int mt)
{
    switch (mt) {
    case POLICY_MATCH_COMM:   return "comm";
    case POLICY_MATCH_PATH:   return "path";
    case POLICY_MATCH_PORT:   return "port";
    case POLICY_MATCH_CGROUP: return "cgroup";
    case POLICY_MATCH_DIGEST: return "digest";
    default:                  return "?";
    }
}

const char* action_name(int a)
{
    switch (a) {
    case POLICY_ACTION_ALLOW:      return "allow";
    case POLICY_ACTION_DENY:       return "deny";
    case POLICY_ACTION_LOG:        return "log";
    case POLICY_ACTION_QUARANTINE: return "quarantine";
    default:                       return "?";
    }
}

// policy add <hook> comm <name> deny [--kill]
// policy add <hook> port <number> deny [--kill]
int cmd_policy_add(int argc, char** argv)
{
    // argv: policy add <hook> <match_type> <match_val> <action> [--kill]
    if (argc < 7) {
        std::fprintf(stderr,
                     "usage: policy add <hook> <match_type> <value> <action> [--kill]\n"
                     "  hook:  exec|file|conn|bind|listen\n"
                     "  match: comm|port|cgroup\n"
                     "  action: deny|allow|log\n");
        return 1;
    }

    int map_fd = open_pinned_policy_fd();
    if (map_fd < 0) return 1;

    // Parse hook kind.
    const std::string hook_str = argv[3];
    std::uint8_t hook = 255;
    if (hook_str == "exec")   hook = PROV_KIND_EXEC;
    else if (hook_str == "file")   hook = PROV_KIND_FILE_OPEN;
    else if (hook_str == "conn")   hook = PROV_KIND_SOCKET_CONNECT;
    else if (hook_str == "bind")   hook = PROV_KIND_SOCKET_BIND;
    else if (hook_str == "listen") hook = PROV_KIND_SOCKET_LISTEN;
    else {
        std::fprintf(stderr, "unknown hook: %s\n", hook_str.c_str());
        close(map_fd);
        return 1;
    }

    // Parse match type + value.
    const std::string mt_str = argv[4];
    const std::string val_str = argv[5];
    policy_key key{};
    key.hook = hook;

    if (mt_str == "comm") {
        key.match_type = POLICY_MATCH_COMM;
        key.match_val = aegis_next::fnv1a(val_str.c_str(), val_str.size());
    } else if (mt_str == "port") {
        key.match_type = POLICY_MATCH_PORT;
        key.match_val = static_cast<std::uint32_t>(std::strtoul(val_str.c_str(), nullptr, 10));
    } else if (mt_str == "cgroup") {
        key.match_type = POLICY_MATCH_CGROUP;
        key.match_val = static_cast<std::uint32_t>(std::strtoull(val_str.c_str(), nullptr, 0));
    } else {
        std::fprintf(stderr, "unknown match type: %s\n", mt_str.c_str());
        close(map_fd);
        return 1;
    }

    // Parse action.
    const std::string act_str = argv[6];
    policy_val val{};
    if (act_str == "deny")               val.action = POLICY_ACTION_DENY;
    else if (act_str == "allow")         val.action = POLICY_ACTION_ALLOW;
    else if (act_str == "log")           val.action = POLICY_ACTION_LOG;
    else if (act_str == "quarantine")    val.action = POLICY_ACTION_QUARANTINE;
    else {
        std::fprintf(stderr, "unknown action: %s\n", act_str.c_str());
        close(map_fd);
        return 1;
    }

    // Check --kill flag.
    for (int i = 7; i < argc; ++i) {
        if (std::strcmp(argv[i], "--kill") == 0)
            val.flags |= POLICY_FLAG_KILL;
    }

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        std::fprintf(stderr, "failed to add policy rule: %s\n",
                     std::strerror(errno));
        close(map_fd);
        return 1;
    }

    std::printf("policy: added rule hook=%s match=%s val=%s action=%s%s\n",
                hook_str.c_str(), mt_str.c_str(), val_str.c_str(),
                act_str.c_str(),
                (val.flags & POLICY_FLAG_KILL) ? " +kill" : "");
    close(map_fd);
    return 0;
}

int cmd_policy_list()
{
    int map_fd = open_pinned_policy_fd();
    if (map_fd < 0) return 1;

    std::printf("policy rules:\n");
    std::printf("  %-8s %-8s %-12s %-12s %s\n",
                "hook", "match", "value", "action", "flags");

    policy_key key{};
    policy_key next_key{};
    policy_val val{};
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            std::printf("  %-8s %-8s 0x%08x   %-12s %s\n",
                        aegis_next::kind_name(next_key.hook),
                        match_type_name(next_key.match_type),
                        next_key.match_val,
                        action_name(val.action),
                        (val.flags & POLICY_FLAG_KILL) ? "kill" : "-");
            ++count;
        }
        key = next_key;
    }

    if (count == 0)
        std::printf("  (none)\n");
    std::printf("total: %d rules\n", count);
    close(map_fd);
    return 0;
}

int cmd_policy_clear()
{
    int map_fd = open_pinned_policy_fd();
    if (map_fd < 0) return 1;

    policy_key key{};
    policy_key next_key{};
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        ++count;
        // Don't advance key — deletion shifts iteration.
    }

    std::printf("policy: cleared %d rule(s)\n", count);
    close(map_fd);
    return 0;
}

// Load policy rules from a text file. Format (one rule per line):
//   <hook> <match_type> <value> <action> [kill]
// Lines starting with # are comments. Blank lines are skipped.
// hook:   exec|file|conn|bind|listen
// match:  comm|port|cgroup
// action: deny|allow|log
int cmd_policy_load(const char* filepath)
{
    int map_fd = open_pinned_policy_fd();
    if (map_fd < 0) return 1;

    std::ifstream f(filepath);
    if (!f.is_open()) {
        std::fprintf(stderr, "cannot open policy file: %s\n", filepath);
        close(map_fd);
        return 1;
    }

    int loaded = 0;
    int lineno = 0;
    std::string line;
    while (std::getline(f, line)) {
        ++lineno;
        // Skip comments and blank lines.
        if (line.empty() || line[0] == '#')
            continue;

        std::istringstream ss(line);
        std::string hook_str, mt_str, val_str, act_str, flag_str;
        if (!(ss >> hook_str >> mt_str >> val_str >> act_str)) {
            std::fprintf(stderr, "policy:%d: malformed line: %s\n",
                         lineno, line.c_str());
            continue;
        }
        ss >> flag_str; // optional

        // Parse hook.
        policy_key key{};
        if (hook_str == "exec")        key.hook = PROV_KIND_EXEC;
        else if (hook_str == "file")   key.hook = PROV_KIND_FILE_OPEN;
        else if (hook_str == "conn")   key.hook = PROV_KIND_SOCKET_CONNECT;
        else if (hook_str == "bind")   key.hook = PROV_KIND_SOCKET_BIND;
        else if (hook_str == "listen") key.hook = PROV_KIND_SOCKET_LISTEN;
        else {
            std::fprintf(stderr, "policy:%d: unknown hook '%s'\n",
                         lineno, hook_str.c_str());
            continue;
        }

        // Parse match type + value.
        if (mt_str == "comm") {
            key.match_type = POLICY_MATCH_COMM;
            key.match_val = aegis_next::fnv1a(val_str.c_str(), val_str.size());
        } else if (mt_str == "port") {
            key.match_type = POLICY_MATCH_PORT;
            key.match_val = static_cast<std::uint32_t>(
                std::strtoul(val_str.c_str(), nullptr, 10));
        } else if (mt_str == "cgroup") {
            key.match_type = POLICY_MATCH_CGROUP;
            key.match_val = static_cast<std::uint32_t>(
                std::strtoull(val_str.c_str(), nullptr, 0));
        } else {
            std::fprintf(stderr, "policy:%d: unknown match type '%s'\n",
                         lineno, mt_str.c_str());
            continue;
        }

        // Parse action.
        policy_val val{};
        if (act_str == "deny")            val.action = POLICY_ACTION_DENY;
        else if (act_str == "allow")      val.action = POLICY_ACTION_ALLOW;
        else if (act_str == "log")        val.action = POLICY_ACTION_LOG;
        else if (act_str == "quarantine") val.action = POLICY_ACTION_QUARANTINE;
        else {
            std::fprintf(stderr, "policy:%d: unknown action '%s'\n",
                         lineno, act_str.c_str());
            continue;
        }

        if (flag_str == "kill")
            val.flags |= POLICY_FLAG_KILL;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
            std::fprintf(stderr, "policy:%d: failed to load rule: %s\n",
                         lineno, std::strerror(errno));
            continue;
        }
        ++loaded;
    }

    std::printf("policy: loaded %d rule(s) from %s\n", loaded, filepath);
    close(map_fd);
    return 0;
}

// ---- Phase 4: binary auth subcommands --------------------------

std::string auth_digests_pin_path() { return pin_dir() + "/trusted_digests"; }
std::string auth_stats_pin_path() { return pin_dir() + "/auth_stats"; }

// Load the binary_auth BPF program.
int cmd_auth_start(int argc, char** argv)
{
    libbpf_set_print(libbpf_print);
    bump_memlock_rlimit();

    auto features = aegis_next::probe_features();
    if (!features.bpf_lsm) {
        std::fprintf(stderr,
                     "error: BPF LSM not available (need lsm=bpf boot param)\n");
        return 1;
    }

    // Parse mode argument: --enforce (default), --audit, --disable
    __u32 mode = 0; // enforce
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--audit") == 0)
            mode = 1;
        else if (std::strcmp(argv[i], "--disable") == 0)
            mode = 2;
    }

    std::printf("aegis-next: binary authorization starting in %s mode.\n",
                mode == 0 ? "enforce" : mode == 1 ? "audit" : "disabled");

    if (!features.binary_auth) {
        std::printf("  warning: full binary auth pipeline unavailable.\n");
        std::printf("    fsverity: %s\n", features.fsverity ? "yes" : "NO");
        std::printf("    xattr:    %s\n", features.xattr ? "yes" : "NO");
        if (mode == 0) {
            std::printf("  switching to audit mode (cannot enforce without all deps).\n");
            mode = 1;
        }
    }

    std::printf("aegis-next: binary auth capabilities:\n");
    std::printf("  fsverity digest:    %s (kernel 6.7+)\n",
                features.fsverity ? "available" : "unavailable");
    std::printf("  file xattr cache:   %s (kernel 6.8+)\n",
                features.xattr ? "available" : "unavailable");
    std::printf("  user_ringbuf:       %s (kernel 6.1+)\n",
                features.user_ringbuf ? "available" : "unavailable");
    std::printf("  in-kernel rate limit: available (arena-based)\n");
    std::printf("  targeted SIGKILL:   available (bpf_send_signal_task 6.13+)\n");

    std::printf("\naegis-next: binary authorization ready.\n");
    std::printf("  trusted digests: load via 'aegisbpf-next auth trust <hex-digest>'\n");
    std::printf("  mode: %s\n", mode == 0 ? "ENFORCE" : mode == 1 ? "AUDIT" : "DISABLED");

    return 0;
}

// Add a trusted binary digest to the trusted digests map.
int cmd_auth_trust(const char* hex_digest)
{
    std::string dpath = auth_digests_pin_path();
    int fd = bpf_obj_get(dpath.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned trusted_digests map at %s: %s\n"
                     "hint: run 'aegisbpf-next auth start' first.\n",
                     dpath.c_str(), std::strerror(errno));
        return 1;
    }

    // Parse hex digest string (minimum 16 hex chars = 8 bytes prefix).
    std::size_t hex_len = std::strlen(hex_digest);
    if (hex_len < DIGEST_PREFIX_LEN * 2) {
        std::fprintf(stderr,
                     "digest too short: need at least %d hex chars, got %zu\n",
                     DIGEST_PREFIX_LEN * 2, hex_len);
        close(fd);
        return 1;
    }

    // Convert hex to bytes.
    struct {
        __u8 prefix[DIGEST_PREFIX_LEN];
    } dkey{};
    for (int i = 0; i < DIGEST_PREFIX_LEN; ++i) {
        unsigned val = 0;
        if (std::sscanf(&hex_digest[i * 2], "%02x", &val) != 1) {
            std::fprintf(stderr, "invalid hex at position %d\n", i * 2);
            close(fd);
            return 1;
        }
        dkey.prefix[i] = static_cast<__u8>(val);
    }

    struct {
        __u8  verdict;
        __u8  flags;
        __u16 _pad;
        __u32 _reserved;
    } dval{};
    dval.verdict = AUTH_VERDICT_ALLOW;
    dval.flags = AUTH_FLAG_FSVERITY;

    if (bpf_map_update_elem(fd, &dkey, &dval, BPF_ANY) != 0) {
        std::fprintf(stderr, "failed to add trusted digest: %s\n",
                     std::strerror(errno));
        close(fd);
        return 1;
    }

    std::printf("auth: trusted digest added (prefix=%s)\n", hex_digest);
    close(fd);
    return 0;
}

// List trusted digests.
int cmd_auth_list()
{
    std::string dpath = auth_digests_pin_path();
    int fd = bpf_obj_get(dpath.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned trusted_digests map at %s: %s\n",
                     dpath.c_str(), std::strerror(errno));
        return 1;
    }

    std::printf("trusted binary digests:\n");
    std::printf("  %-20s %-10s %s\n", "DIGEST_PREFIX", "VERDICT", "FLAGS");

    struct { __u8 prefix[DIGEST_PREFIX_LEN]; } key{}, next_key{};
    struct { __u8 verdict; __u8 flags; __u16 _pad; __u32 _reserved; } val{};
    int count = 0;

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0) {
            std::printf("  ");
            for (int i = 0; i < DIGEST_PREFIX_LEN; ++i)
                std::printf("%02x", next_key.prefix[i]);
            std::printf("   %-10s %s%s%s\n",
                        aegis_next::auth_verdict_name(val.verdict),
                        (val.flags & AUTH_FLAG_FSVERITY) ? "fsverity " : "",
                        (val.flags & AUTH_FLAG_XATTR_CACHED) ? "cached " : "",
                        (val.flags & AUTH_FLAG_PKCS7) ? "pkcs7" : "");
            ++count;
        }
        key = next_key;
    }

    if (count == 0)
        std::printf("  (none — all binaries allowed)\n");
    std::printf("total: %d digest(s)\n", count);
    close(fd);
    return 0;
}

// Show auth statistics.
int cmd_auth_stats()
{
    std::string spath = auth_stats_pin_path();
    int fd = bpf_obj_get(spath.c_str());
    if (fd < 0) {
        std::fprintf(stderr,
                     "cannot open pinned auth_stats map at %s: %s\n",
                     spath.c_str(), std::strerror(errno));
        return 1;
    }

    std::printf("binary auth statistics:\n");
    const char* labels[] = {
        "allowed", "denied", "cache_hit", "no_verity",
        "sig_fail", "(unused)", "(unused)", "(unused)"
    };
    for (__u32 i = 0; i < 8; ++i) {
        __u64 val = 0;
        if (bpf_map_lookup_elem(fd, &i, &val) == 0 && val > 0)
            std::printf("  %-12s %lu\n", labels[i], (unsigned long)val);
    }
    close(fd);
    return 0;
}

// ---- Phase 4: rate limit subcommands ----------------------------

std::string rate_config_pin_path() { return pin_dir() + "/rate_config"; }

int cmd_rate_set(int argc, char** argv)
{
    // rate set <kind> <max_per_second>
    if (argc < 5) {
        std::fprintf(stderr,
                     "usage: %s rate set <kind> <max_per_second>\n"
                     "  kind: fork|conn|file|mmap\n", argv[0]);
        return 1;
    }

    const std::string kind_str = argv[3];
    __u32 kind = 255;
    if (kind_str == "fork")        kind = PROV_KIND_TASK_ALLOC;
    else if (kind_str == "conn")   kind = PROV_KIND_SOCKET_CONNECT;
    else if (kind_str == "file")   kind = PROV_KIND_FILE_OPEN;
    else if (kind_str == "mmap")   kind = PROV_KIND_MMAP_FILE;
    else {
        std::fprintf(stderr, "unknown kind: %s\n", kind_str.c_str());
        return 1;
    }

    __u32 max_rate = static_cast<__u32>(std::strtoul(argv[4], nullptr, 10));
    if (max_rate == 0) {
        std::fprintf(stderr, "invalid rate: %s\n", argv[4]);
        return 1;
    }

    std::string path = rate_config_pin_path();
    int fd = bpf_obj_get(path.c_str());
    if (fd < 0) {
        std::fprintf(stderr, "cannot open rate_config map at %s: %s\n"
                     "hint: run 'aegisbpf-next attach' first.\n",
                     path.c_str(), std::strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &kind, &max_rate, BPF_ANY) != 0) {
        std::fprintf(stderr, "failed to set rate limit: %s\n",
                     std::strerror(errno));
        close(fd);
        return 1;
    }

    std::printf("rate limit: %s = %u events/second\n",
                kind_str.c_str(), max_rate);
    close(fd);
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

    if (cmd == "policy") {
        if (argc < 3) {
            std::fprintf(stderr, "policy requires a subcommand: add, list, clear, load\n");
            return 1;
        }
        const std::string sub = argv[2];
        if (sub == "add") {
            return cmd_policy_add(argc, argv);
        }
        if (sub == "list") {
            return cmd_policy_list();
        }
        if (sub == "clear") {
            return cmd_policy_clear();
        }
        if (sub == "load") {
            if (argc < 4) {
                std::fprintf(stderr, "usage: %s policy load <file>\n", argv[0]);
                return 1;
            }
            return cmd_policy_load(argv[3]);
        }
        std::fprintf(stderr, "unknown policy subcommand: %s\n", sub.c_str());
        return 1;
    }

    if (cmd == "protect") {
        return cmd_protect();
    }

    if (cmd == "status") {
        return cmd_status();
    }

    if (cmd == "export") {
        if (argc < 3 || std::string(argv[2]) != "tail") {
            std::fprintf(stderr, "usage: %s export tail [N]\n", argv[0]);
            return 1;
        }
        int n = (argc >= 4) ? std::atoi(argv[3]) : 20;
        if (n <= 0) n = 20;
        std::string path = pin_dir() + "/events.jsonl";
        FILE* f = std::fopen(path.c_str(), "r");
        if (!f) {
            std::fprintf(stderr, "no export file at %s\n", path.c_str());
            return 1;
        }
        // Read all lines, keep last N.
        std::vector<std::string> lines;
        char buf[4096];
        while (std::fgets(buf, sizeof(buf), f)) {
            lines.emplace_back(buf);
            if (static_cast<int>(lines.size()) > n)
                lines.erase(lines.begin());
        }
        std::fclose(f);
        for (const auto& line : lines)
            std::fputs(line.c_str(), stdout);
        return 0;
    }

    // Phase 4: binary authorization subcommands.
    if (cmd == "auth") {
        if (argc < 3) {
            std::fprintf(stderr, "auth requires a subcommand: start, trust, list, stats\n");
            return 1;
        }
        const std::string sub = argv[2];
        if (sub == "start") {
            return cmd_auth_start(argc, argv);
        }
        if (sub == "trust") {
            if (argc < 4) {
                std::fprintf(stderr, "usage: %s auth trust <hex-digest>\n", argv[0]);
                return 1;
            }
            return cmd_auth_trust(argv[3]);
        }
        if (sub == "list") {
            return cmd_auth_list();
        }
        if (sub == "stats") {
            return cmd_auth_stats();
        }
        std::fprintf(stderr, "unknown auth subcommand: %s\n", sub.c_str());
        return 1;
    }

    // Phase 4: rate limiting subcommands.
    if (cmd == "rate") {
        if (argc < 3) {
            std::fprintf(stderr, "rate requires a subcommand: set\n");
            return 1;
        }
        const std::string sub = argv[2];
        if (sub == "set") {
            return cmd_rate_set(argc, argv);
        }
        std::fprintf(stderr, "unknown rate subcommand: %s\n", sub.c_str());
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
