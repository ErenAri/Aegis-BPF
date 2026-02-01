/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * Main entry point for the userspace daemon and CLI commands.
 */

#include "bpf_ops.hpp"
#include "events.hpp"
#include "logging.hpp"
#include "policy.hpp"
#include "seccomp.hpp"
#include "sha256.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <bpf/libbpf.h>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace aegis {

static volatile sig_atomic_t g_exiting = 0;

static void handle_signal(int)
{
    g_exiting = 1;
}

static Result<void> setup_agent_cgroup(BpfState &state)
{
    static constexpr const char *kAgentCgroup = "/sys/fs/cgroup/aegis_agent";

    std::error_code ec;
    std::filesystem::create_directories(kAgentCgroup, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to create cgroup", ec.message());
    }

    std::ofstream procs(std::string(kAgentCgroup) + "/cgroup.procs", std::ios::out | std::ios::trunc);
    if (!procs.is_open()) {
        return Error(ErrorCode::IoError, "Failed to open cgroup.procs", kAgentCgroup);
    }
    procs << getpid();
    procs.close();

    struct stat st{};
    if (stat(kAgentCgroup, &st) != 0) {
        return Error::system(errno, "stat failed for " + std::string(kAgentCgroup));
    }

    uint64_t cgid = static_cast<uint64_t>(st.st_ino);

    TRY(bump_memlock_rlimit());

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_cgroup_map");
    }

    return {};
}

static int run(bool audit_only)
{
    auto prereqs_result = check_prereqs();
    if (!prereqs_result) {
        logger().log(SLOG_ERROR("Prerequisites check failed")
            .field("error", prereqs_result.error().to_string()));
        return 1;
    }
    bool lsm_enabled = *prereqs_result;

    if (!lsm_enabled) {
        if (!audit_only) {
            logger().log(SLOG_WARN("BPF LSM not enabled; falling back to tracepoint audit-only mode"));
            audit_only = true;
        } else {
            logger().log(SLOG_INFO("BPF LSM not enabled; running in tracepoint audit-only mode"));
        }
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
            .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        logger().log(SLOG_ERROR("Layout version check failed")
            .field("error", version_result.error().to_string()));
        return 1;
    }

    auto config_result = set_agent_config(state, audit_only);
    if (!config_result) {
        logger().log(SLOG_ERROR("Failed to set agent config")
            .field("error", config_result.error().to_string()));
        return 1;
    }

    auto cgroup_result = setup_agent_cgroup(state);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to setup agent cgroup")
            .field("error", cgroup_result.error().to_string()));
        return 1;
    }

    auto attach_result = attach_all(state, lsm_enabled);
    if (!attach_result) {
        logger().log(SLOG_ERROR("Failed to attach programs")
            .field("error", attach_result.error().to_string()));
        return 1;
    }

    RingBufferGuard rb(ring_buffer__new(bpf_map__fd(state.events), handle_event, nullptr, nullptr));
    if (!rb) {
        logger().log(SLOG_ERROR("Failed to create ring buffer"));
        return 1;
    }

    logger().log(SLOG_INFO("Agent started")
        .field("audit_only", audit_only)
        .field("lsm_enabled", lsm_enabled));

    int err = 0;
    while (!g_exiting) {
        err = ring_buffer__poll(rb.get(), 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            logger().log(SLOG_ERROR("Ring buffer poll failed").error_code(-err));
            break;
        }
    }

    logger().log(SLOG_INFO("Agent stopped"));
    return err < 0 ? 1 : 0;
}

static int block_file(const std::string &path)
{
    // Validate path before processing
    auto validated = validate_existing_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
            .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto entries = read_deny_db();
    auto add_result = add_deny_path(state, *validated, entries);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny path")
            .field("error", add_result.error().to_string()));
        return 1;
    }

    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database")
            .field("error", write_result.error().to_string()));
        return 1;
    }

    return 0;
}

static int block_add(const std::string &path)
{
    return block_file(path);
}

static int block_del(const std::string &path)
{
    auto inode_result = path_to_inode(path);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to get inode")
            .field("error", inode_result.error().to_string()));
        return 1;
    }
    InodeId id = *inode_result;

    int map_fd = bpf_obj_get(kDenyInodePin);
    if (map_fd < 0) {
        logger().log(SLOG_ERROR("deny_inode_map not found"));
        return 1;
    }
    bpf_map_delete_elem(map_fd, &id);
    close(map_fd);

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    std::string resolved_path = ec ? path : resolved.string();
    PathKey path_key{};
    fill_path_key(resolved_path, path_key);
    int path_fd = bpf_obj_get(kDenyPathPin);
    if (path_fd >= 0) {
        bpf_map_delete_elem(path_fd, &path_key);
        if (resolved_path != path) {
            PathKey raw_key{};
            fill_path_key(path, raw_key);
            bpf_map_delete_elem(path_fd, &raw_key);
        }
        close(path_fd);
    } else {
        logger().log(SLOG_WARN("deny_path_map not found"));
    }

    auto entries = read_deny_db();
    entries.erase(id);
    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database")
            .field("error", write_result.error().to_string()));
        return 1;
    }
    return 0;
}

static int block_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto db = read_deny_db();
    InodeId key{};
    InodeId next_key{};
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end() && !it->second.empty()) {
            std::cout << it->second << " (" << inode_to_string(key) << ")" << std::endl;
        } else {
            std::cout << inode_to_string(key) << std::endl;
        }
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), &key, &next_key);
        key = next_key;
    }

    return 0;
}

static int block_clear()
{
    std::remove(kDenyInodePin);
    std::remove(kDenyPathPin);
    std::remove(kAllowCgroupPin);
    std::remove(kDenyCgroupStatsPin);
    std::remove(kDenyInodeStatsPin);
    std::remove(kDenyPathStatsPin);
    std::remove(kAgentMetaPin);
    std::filesystem::remove(kDenyDbPath);
    std::filesystem::remove(kPolicyAppliedPath);
    std::filesystem::remove(kPolicyAppliedPrevPath);
    std::filesystem::remove(kPolicyAppliedHashPath);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
            .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to reload BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }
    if (state.block_stats) {
        auto reset_result = reset_block_stats_map(state.block_stats);
        if (!reset_result) {
            logger().log(SLOG_WARN("Failed to reset block stats")
                .field("error", reset_result.error().to_string()));
        }
    }
    return 0;
}

static int allow_add(const std::string &path)
{
    // Validate cgroup path
    auto validated = validate_cgroup_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid cgroup path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
            .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto add_result = add_allow_cgroup_path(state, *validated);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add allow cgroup")
            .field("error", add_result.error().to_string()));
        return 1;
    }

    return 0;
}

static int allow_del(const std::string &path)
{
    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to get cgroup ID")
            .field("error", cgid_result.error().to_string()));
        return 1;
    }
    uint64_t cgid = *cgid_result;

    int fd = bpf_obj_get(kAllowCgroupPin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("allow_cgroup_map not found"));
        return 1;
    }
    bpf_map_delete_elem(fd, &cgid);
    close(fd);
    return 0;
}

static int allow_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto ids_result = read_allow_cgroup_ids(state.allow_cgroup);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read allow cgroup IDs")
            .field("error", ids_result.error().to_string()));
        return 1;
    }

    for (uint64_t id : *ids_result) {
        std::cout << id << std::endl;
    }

    return 0;
}

static int health()
{
    bool ok = true;
    std::error_code ec;
    bool cgroup_ok = path_exists("/sys/fs/cgroup/cgroup.controllers", ec);
    bool bpffs_ok = path_exists("/sys/fs/bpf", ec);
    bool btf_ok = path_exists("/sys/kernel/btf/vmlinux", ec);
    std::string obj_path = resolve_bpf_obj_path();
    bool obj_ok = path_exists(obj_path.c_str(), ec);

    if (!cgroup_ok || !bpffs_ok || !btf_ok || !obj_ok) {
        ok = false;
    }

    bool is_root = geteuid() == 0;
    std::cout << "euid: " << geteuid() << "\n";
    std::cout << "cgroup_v2: " << (cgroup_ok ? "ok" : "missing") << "\n";
    std::cout << "bpffs: " << (bpffs_ok ? "ok" : "missing") << "\n";
    std::cout << "btf: " << (btf_ok ? "ok" : "missing") << "\n";
    std::cout << "bpf_obj_path: " << obj_path << (obj_ok ? "" : " (missing)") << "\n";

    bool lsm_enabled = kernel_bpf_lsm_enabled();
    std::cout << "bpf_lsm_enabled: " << (lsm_enabled ? "yes" : "no") << "\n";

    std::string lsm_list = read_file_first_line("/sys/kernel/security/lsm");
    if (!lsm_list.empty()) {
        std::cout << "lsm_list: " << lsm_list << "\n";
    }

    struct KernelConfigCheck {
        const char *key;
        const char *label;
    };
    const KernelConfigCheck config_checks[] = {
        {"CONFIG_BPF", "kernel_config_bpf"},
        {"CONFIG_BPF_SYSCALL", "kernel_config_bpf_syscall"},
        {"CONFIG_BPF_JIT", "kernel_config_bpf_jit"},
        {"CONFIG_BPF_LSM", "kernel_config_bpf_lsm"},
        {"CONFIG_CGROUPS", "kernel_config_cgroups"},
        {"CONFIG_CGROUP_BPF", "kernel_config_cgroup_bpf"},
    };
    for (const auto &check : config_checks) {
        std::string value = kernel_config_value(check.key);
        if (value.empty()) {
            value = "unknown";
        }
        std::cout << check.label << ": " << value << "\n";
    }

    struct PinInfo {
        const char *name;
        const char *path;
    };
    const PinInfo pins[] = {
        {"deny_inode", kDenyInodePin},
        {"deny_path", kDenyPathPin},
        {"allow_cgroup", kAllowCgroupPin},
        {"block_stats", kBlockStatsPin},
        {"deny_cgroup_stats", kDenyCgroupStatsPin},
        {"deny_inode_stats", kDenyInodeStatsPin},
        {"deny_path_stats", kDenyPathStatsPin},
        {"agent_meta", kAgentMetaPin},
    };

    if (is_root) {
        std::vector<std::string> present;
        std::vector<std::string> missing;
        std::vector<std::string> unreadable;
        for (const auto &pin : pins) {
            bool exists = path_exists(pin.path, ec);
            if (ec) {
                unreadable.emplace_back(pin.name);
            } else if (exists) {
                present.emplace_back(pin.name);
            } else {
                missing.emplace_back(pin.name);
            }
        }
        if (!present.empty()) {
            std::cout << "pins_present: " << join_list(present) << "\n";
        }
        if (!missing.empty()) {
            std::cout << "pins_missing: " << join_list(missing) << "\n";
        }
        if (!unreadable.empty()) {
            std::cout << "pins_unreadable: " << join_list(unreadable) << "\n";
        }

        if (path_exists(kAgentMetaPin, ec)) {
            int fd = bpf_obj_get(kAgentMetaPin);
            if (fd < 0) {
                std::cout << "layout_version: unreadable (" << std::strerror(errno) << ")\n";
            } else {
                uint32_t key = 0;
                AgentMeta meta{};
                if (bpf_map_lookup_elem(fd, &key, &meta) == 0) {
                    if (meta.layout_version == kLayoutVersion) {
                        std::cout << "layout_version: ok (" << meta.layout_version << ")\n";
                    } else {
                        std::cout << "layout_version: mismatch (found " << meta.layout_version
                                  << ", expected " << kLayoutVersion << ")\n";
                    }
                } else {
                    std::cout << "layout_version: unavailable (" << std::strerror(errno) << ")\n";
                }
                close(fd);
            }
        }
    } else {
        std::cout << "pins_present: skipped (requires root)\n";
        std::cout << "layout_version: skipped (requires root)\n";
    }

    return ok ? 0 : 1;
}

static int print_metrics(const std::string &out_path)
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
            .field("error", stats_result.error().to_string()));
        return 1;
    }
    BlockStats stats = *stats_result;

    auto cgroup_result = read_cgroup_block_counts(state.deny_cgroup_stats);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to read cgroup block counts")
            .field("error", cgroup_result.error().to_string()));
        return 1;
    }
    auto cgroup_blocks = *cgroup_result;

    auto inode_result = read_inode_block_counts(state.deny_inode_stats);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to read inode block counts")
            .field("error", inode_result.error().to_string()));
        return 1;
    }
    auto inode_blocks = *inode_result;

    auto path_result = read_path_block_counts(state.deny_path_stats);
    if (!path_result) {
        logger().log(SLOG_ERROR("Failed to read path block counts")
            .field("error", path_result.error().to_string()));
        return 1;
    }
    auto path_blocks = *path_result;

    size_t deny_sz = map_entry_count(state.deny_inode);
    size_t deny_path_sz = map_entry_count(state.deny_path);
    size_t allow_sz = map_entry_count(state.allow_cgroup);

    std::ostringstream oss;
    oss << "# HELP aegisbpf_blocks_total Total number of block events.\n";
    oss << "# TYPE aegisbpf_blocks_total counter\n";
    oss << "aegisbpf_blocks_total " << stats.blocks << "\n";
    oss << "# HELP aegisbpf_ringbuf_drops_total Total ringbuf drops.\n";
    oss << "# TYPE aegisbpf_ringbuf_drops_total counter\n";
    oss << "aegisbpf_ringbuf_drops_total " << stats.ringbuf_drops << "\n";
    oss << "# HELP aegisbpf_deny_inode_entries Number of deny inode entries.\n";
    oss << "# TYPE aegisbpf_deny_inode_entries gauge\n";
    oss << "aegisbpf_deny_inode_entries " << deny_sz << "\n";
    oss << "# HELP aegisbpf_deny_path_entries Number of deny path entries.\n";
    oss << "# TYPE aegisbpf_deny_path_entries gauge\n";
    oss << "aegisbpf_deny_path_entries " << deny_path_sz << "\n";
    oss << "# HELP aegisbpf_allow_cgroup_entries Number of allow cgroup entries.\n";
    oss << "# TYPE aegisbpf_allow_cgroup_entries gauge\n";
    oss << "aegisbpf_allow_cgroup_entries " << allow_sz << "\n";

    if (!cgroup_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_cgroup_total Block events by cgroup.\n";
        oss << "# TYPE aegisbpf_blocks_by_cgroup_total counter\n";
        for (const auto &kv : cgroup_blocks) {
            std::string cgpath = resolve_cgroup_path(kv.first);
            oss << "aegisbpf_blocks_by_cgroup_total{cgid=\"" << kv.first << "\",cgroup_path=\""
                << prometheus_escape_label(cgpath) << "\"} " << kv.second << "\n";
        }
    }
    if (!inode_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_inode_total Block events by inode.\n";
        oss << "# TYPE aegisbpf_blocks_by_inode_total counter\n";
        for (const auto &kv : inode_blocks) {
            oss << "aegisbpf_blocks_by_inode_total{dev=\"" << kv.first.dev << "\",ino=\""
                << kv.first.ino << "\"} " << kv.second << "\n";
        }
    }
    if (!path_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_path_total Block events by path.\n";
        oss << "# TYPE aegisbpf_blocks_by_path_total counter\n";
        for (const auto &kv : path_blocks) {
            if (kv.first.empty()) {
                continue;
            }
            oss << "aegisbpf_blocks_by_path_total{path=\"" << prometheus_escape_label(kv.first)
                << "\"} " << kv.second << "\n";
        }
    }

    if (out_path.empty() || out_path == "-") {
        std::cout << oss.str();
    } else {
        std::ofstream out(out_path, std::ios::trunc);
        if (!out.is_open()) {
            logger().log(SLOG_ERROR("Failed to write metrics").field("path", out_path));
            return 1;
        }
        out << oss.str();
    }

    return 0;
}

static int print_stats()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
            .field("error", load_result.error().to_string()));
        return 1;
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
            .field("error", stats_result.error().to_string()));
        return 1;
    }
    BlockStats stats = *stats_result;

    auto cgroup_result = read_cgroup_block_counts(state.deny_cgroup_stats);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to read cgroup block counts")
            .field("error", cgroup_result.error().to_string()));
        return 1;
    }
    auto cgroup_blocks = *cgroup_result;

    auto inode_result = read_inode_block_counts(state.deny_inode_stats);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to read inode block counts")
            .field("error", inode_result.error().to_string()));
        return 1;
    }
    auto inode_blocks = *inode_result;

    auto path_result = read_path_block_counts(state.deny_path_stats);
    if (!path_result) {
        logger().log(SLOG_ERROR("Failed to read path block counts")
            .field("error", path_result.error().to_string()));
        return 1;
    }
    auto path_blocks = *path_result;

    size_t deny_sz = map_entry_count(state.deny_inode);
    size_t deny_path_sz = map_entry_count(state.deny_path);
    size_t allow_sz = map_entry_count(state.allow_cgroup);

    std::cout << "deny_inode entries: " << deny_sz << "\n"
              << "deny_path entries: " << deny_path_sz << "\n"
              << "allow_cgroup entries: " << allow_sz << "\n"
              << "blocks: " << stats.blocks << "\n"
              << "ringbuf_drops: " << stats.ringbuf_drops << std::endl;

    if (!cgroup_blocks.empty()) {
        std::cout << "blocks_by_cgroup:\n";
        for (const auto &kv : cgroup_blocks) {
            std::string cgpath = resolve_cgroup_path(kv.first);
            if (!cgpath.empty()) {
                std::cout << "  " << cgpath << " (" << kv.first << "): " << kv.second << "\n";
            } else {
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
            }
        }
    }
    if (!inode_blocks.empty()) {
        auto db = read_deny_db();
        std::cout << "blocks_by_inode:\n";
        for (const auto &kv : inode_blocks) {
            auto it = db.find(kv.first);
            if (it != db.end() && !it->second.empty()) {
                std::cout << "  " << it->second << " (" << inode_to_string(kv.first) << "): " << kv.second << "\n";
            } else {
                std::cout << "  " << inode_to_string(kv.first) << ": " << kv.second << "\n";
            }
        }
    }
    if (!path_blocks.empty()) {
        std::cout << "blocks_by_path:\n";
        for (const auto &kv : path_blocks) {
            if (!kv.first.empty()) {
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
            }
        }
    }

    return 0;
}

static LogLevel parse_log_level(const std::string &level)
{
    if (level == "debug") return LogLevel::Debug;
    if (level == "info") return LogLevel::Info;
    if (level == "warn" || level == "warning") return LogLevel::Warn;
    if (level == "error") return LogLevel::Error;
    if (level == "fatal") return LogLevel::Fatal;
    return LogLevel::Info;
}

static int usage(const char *prog)
{
    std::cerr << "Usage: " << prog
              << " run [--audit|--enforce] [--log=stdout|journald|both] [--log-level=debug|info|warn|error] [--log-format=text|json]"
              << " | block {add|del|list|clear} [path]"
              << " | allow {add|del} <cgroup_path> | allow list"
              << " | policy {lint|apply|export} <file> [--reset] [--sha256 <hex>|--sha256-file <path>] [--no-rollback]"
              << " | policy {show|rollback}"
              << " | stats"
              << " | metrics [--out <path>]"
              << " | health" << std::endl;
    return 1;
}

} // namespace aegis

int main(int argc, char **argv)
{
    using namespace aegis;

    // Parse global logging options first
    LogLevel log_level = LogLevel::Info;
    bool json_format = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--log-level=", 0) == 0) {
            log_level = parse_log_level(arg.substr(12));
        } else if (arg.rfind("--log-format=", 0) == 0) {
            json_format = (arg.substr(13) == "json");
        }
    }

    logger().set_level(log_level);
    logger().set_json_format(json_format);

    if (argc == 1) {
        return run(false);
    }

    std::string cmd = argv[1];

    if (cmd == "run") {
        bool audit_only = false;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--audit" || arg == "--mode=audit") {
                audit_only = true;
            } else if (arg == "--enforce" || arg == "--mode=enforce") {
                audit_only = false;
            } else if (arg.rfind("--log=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--log="));
                if (!set_event_log_sink(value)) {
                    return usage(argv[0]);
                }
            } else if (arg == "--log") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                std::string value = argv[++i];
                if (!set_event_log_sink(value)) {
                    return usage(argv[0]);
                }
            } else if (arg.rfind("--log-level=", 0) == 0 || arg.rfind("--log-format=", 0) == 0) {
                // Already processed
            } else {
                return usage(argv[0]);
            }
        }
        return run(audit_only);
    }

    if (cmd == "block") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return block_add(argv[3]);
        }
        if (sub == "del") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return block_del(argv[3]);
        }
        if (sub == "list") {
            return block_list();
        }
        if (sub == "clear") {
            return block_clear();
        }
        return usage(argv[0]);
    }

    if (cmd == "allow") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return allow_add(argv[3]);
        }
        if (sub == "del") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return allow_del(argv[3]);
        }
        if (sub == "list") {
            if (argc > 3) {
                return usage(argv[0]);
            }
            return allow_list();
        }
        return usage(argv[0]);
    }

    if (cmd == "policy") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "lint") {
            if (argc != 4) {
                return usage(argv[0]);
            }
            auto result = policy_lint(argv[3]);
            return result ? 0 : 1;
        }
        if (sub == "apply") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            bool reset = false;
            bool rollback_on_failure = true;
            std::string sha256;
            std::string sha256_file;
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--reset") {
                    reset = true;
                } else if (arg == "--no-rollback") {
                    rollback_on_failure = false;
                } else if (arg == "--sha256") {
                    if (i + 1 >= argc) {
                        return usage(argv[0]);
                    }
                    sha256 = argv[++i];
                } else if (arg == "--sha256-file") {
                    if (i + 1 >= argc) {
                        return usage(argv[0]);
                    }
                    sha256_file = argv[++i];
                } else {
                    return usage(argv[0]);
                }
            }
            auto result = policy_apply(argv[3], reset, sha256, sha256_file, rollback_on_failure);
            return result ? 0 : 1;
        }
        if (sub == "export") {
            if (argc != 4) {
                return usage(argv[0]);
            }
            auto result = policy_export(argv[3]);
            return result ? 0 : 1;
        }
        if (sub == "show") {
            if (argc != 3) {
                return usage(argv[0]);
            }
            auto result = policy_show();
            return result ? 0 : 1;
        }
        if (sub == "rollback") {
            if (argc != 3) {
                return usage(argv[0]);
            }
            auto result = policy_rollback();
            return result ? 0 : 1;
        }
        return usage(argv[0]);
    }

    if (cmd == "health") {
        if (argc > 2) {
            return usage(argv[0]);
        }
        return health();
    }

    if (cmd == "metrics") {
        std::string out_path;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--out") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                out_path = argv[++i];
            } else {
                return usage(argv[0]);
            }
        }
        return print_metrics(out_path);
    }

    if (cmd == "stats") {
        if (argc > 2) {
            return usage(argv[0]);
        }
        return print_stats();
    }

    return usage(argv[0]);
}
