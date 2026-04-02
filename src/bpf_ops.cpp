// cppcheck-suppress-file missingIncludeSystem
#include "bpf_ops.hpp"

#include <bpf/btf.h>

#include <dirent.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <numeric>
#include <set>
#include <vector>

#include "bpf_attach.hpp"
#include "bpf_integrity.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "tracing.hpp"
#include "utils.hpp"

namespace aegis {

namespace {
std::atomic<uint32_t> g_ringbuf_bytes{0};
std::atomic<uint32_t> g_max_deny_inodes{0};
std::atomic<uint32_t> g_max_deny_paths{0};
std::atomic<uint32_t> g_max_network_entries{0};

std::set<std::string> detect_missing_optional_lsm_hooks()
{
    static constexpr std::array<const char*, 7> kOptionalHooks = {
        "bprm_check_security", "file_mmap",     "socket_connect", "socket_bind",
        "socket_listen",       "socket_accept", "socket_sendmsg",
    };

    std::set<std::string> missing;
    struct btf* vmlinux = btf__load_vmlinux_btf();
    long btf_err = libbpf_get_error(vmlinux);
    if (btf_err != 0) {
        logger().log(SLOG_WARN("Failed to load vmlinux BTF; disabling optional LSM programs")
                         .field("error", static_cast<int64_t>(-btf_err)));
        for (const char* hook : kOptionalHooks) {
            missing.insert(hook);
        }
        return missing;
    }

    for (const char* hook : kOptionalHooks) {
        if (btf__find_by_name_kind(vmlinux, hook, BTF_KIND_FUNC) < 0) {
            missing.insert(hook);
        }
    }
    btf__free(vmlinux);
    return missing;
}
} // namespace

bool kernel_bpf_lsm_enabled()
{
    return check_bpf_lsm_enabled();
}

Result<void> bump_memlock_rlimit()
{
    rlimit rlim{};
    std::memset(&rlim, 0, sizeof(rlim));
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        return Error::system(errno, "Failed to raise memlock rlimit");
    }
    return {};
}

Result<void> ensure_pin_dir()
{
    if (mkdir(kPinRoot, 0755) && errno != EEXIST) {
        return Error::system(errno, "Failed to create pin directory");
    }
    return {};
}

Result<void> ensure_db_dir()
{
    std::error_code ec;
    std::filesystem::create_directories(kDenyDbDir, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to create database directory", ec.message());
    }
    return {};
}

Result<void> reuse_pinned_map(bpf_map* map, const char* path, bool& reused)
{
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        return {};
    }
    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        close(fd);
        return Error::bpf_error(err, "Failed to reuse pinned map");
    }
    reused = true;
    return {};
}

Result<void> pin_map(bpf_map* map, const char* path)
{
    int err = bpf_map__pin(map, path);
    if (err) {
        return Error::bpf_error(err, "Failed to pin map");
    }
    return {};
}

void cleanup_bpf(BpfState& state)
{
    for (auto* link : state.links) {
        bpf_link__destroy(link);
    }
    if (state.obj) {
        bpf_object__close(state.obj);
    }
    state.obj = nullptr;
    state.links.clear();
}

void BpfState::cleanup()
{
    cleanup_bpf(*this);
}

void set_ringbuf_bytes(uint32_t bytes)
{
    g_ringbuf_bytes.store(bytes, std::memory_order_relaxed);
}

void set_max_deny_inodes(uint32_t count)
{
    g_max_deny_inodes.store(count, std::memory_order_relaxed);
}

void set_max_deny_paths(uint32_t count)
{
    g_max_deny_paths.store(count, std::memory_order_relaxed);
}

void set_max_network_entries(uint32_t count)
{
    g_max_network_entries.store(count, std::memory_order_relaxed);
}

Result<void> load_bpf(bool reuse_pins, bool attach_links, BpfState& state)
{
    const std::string inherited_trace_id = current_trace_id();
    const std::string trace_id = inherited_trace_id.empty() ? make_span_id("trace") : inherited_trace_id;
    ScopedSpan root_span("bpf.load", trace_id, current_span_id());

    auto fail = [&root_span](const Error& error) -> Result<void> {
        root_span.fail(error.to_string());
        return error;
    };

    std::string obj_path;
    {
        ScopedSpan span("bpf.resolve_obj_path", trace_id, root_span.span_id());
        obj_path = resolve_bpf_obj_path();
    }

    {
        ScopedSpan span("bpf.verify_integrity", trace_id, root_span.span_id());
        auto verify_result = verify_bpf_integrity(obj_path);
        if (!verify_result) {
            span.fail(verify_result.error().to_string());
            return fail(verify_result.error());
        }
    }

    {
        ScopedSpan span("bpf.open_object", trace_id, root_span.span_id());

        // Check for custom BTF path when kernel doesn't have built-in BTF.
        // This enables CO-RE on older kernels using BTFHub-generated minimized BTFs.
        struct bpf_object_open_opts open_opts = {};
        open_opts.sz = sizeof(open_opts);
        std::string btf_custom_path;

        if (access("/sys/kernel/btf/vmlinux", F_OK) != 0) {
            // Try to find a matching BTF file for this kernel
            struct utsname uname_buf = {};
            if (uname(&uname_buf) == 0) {
                const std::string kernel_release = uname_buf.release;
                const std::vector<std::string> btf_search_paths = {
                    "/usr/lib/aegisbpf/btfs/" + kernel_release + ".btf",
                    "/etc/aegisbpf/btfs/" + kernel_release + ".btf",
                };
                for (const auto& path : btf_search_paths) {
                    if (access(path.c_str(), R_OK) == 0) {
                        btf_custom_path = path;
                        open_opts.btf_custom_path = btf_custom_path.c_str();
                        logger().log(LogLevel::Info, "Using custom BTF: " + btf_custom_path);
                        break;
                    }
                }
                if (btf_custom_path.empty()) {
                    logger().log(LogLevel::Warn, "No kernel BTF at /sys/kernel/btf/vmlinux and no custom BTF "
                                                 "found for kernel " +
                                                     kernel_release);
                }
            }
        }

        state.obj = bpf_object__open_file(obj_path.c_str(), &open_opts);
        const int open_err = libbpf_get_error(state.obj);
        if (open_err) {
            state.obj = nullptr;
            Error error = Error::bpf_error(open_err, "Failed to open BPF object file: " + obj_path);
            span.fail(error.to_string());
            return fail(error);
        }
        if (!state.obj) {
            Error error(ErrorCode::BpfLoadFailed, "Failed to open BPF object file", obj_path);
            span.fail(error.to_string());
            return fail(error);
        }
    }

    // Store kernel features for later reference
    KernelFeatures kernel_features;
    {
        ScopedSpan span("bpf.check_kernel_features", trace_id, root_span.span_id());
        auto features_result = detect_kernel_features();
        if (!features_result) {
            cleanup_bpf(state);
            Error error(ErrorCode::BpfLoadFailed, "Failed to detect kernel features",
                        features_result.error().to_string());
            span.fail(error.to_string());
            return fail(error);
        }
        kernel_features = features_result.value();
    }

    {
        ScopedSpan span("bpf.find_maps", trace_id, root_span.span_id());

        state.events = bpf_object__find_map_by_name(state.obj, "events");
        state.deny_inode = bpf_object__find_map_by_name(state.obj, "deny_inode_map");
        state.deny_path = bpf_object__find_map_by_name(state.obj, "deny_path_map");
        state.allow_cgroup = bpf_object__find_map_by_name(state.obj, "allow_cgroup_map");
        state.allow_exec_inode = bpf_object__find_map_by_name(state.obj, "allow_exec_inode_map");
        state.exec_identity_mode = bpf_object__find_map_by_name(state.obj, "exec_identity_mode_map");
        state.block_stats = bpf_object__find_map_by_name(state.obj, "block_stats");
        state.deny_cgroup_stats = bpf_object__find_map_by_name(state.obj, "deny_cgroup_stats");
        state.deny_inode_stats = bpf_object__find_map_by_name(state.obj, "deny_inode_stats");
        state.deny_path_stats = bpf_object__find_map_by_name(state.obj, "deny_path_stats");
        state.agent_meta = bpf_object__find_map_by_name(state.obj, "agent_meta_map");
        // Agent config is stored as a BPF global (fast-path reads from BPF side),
        // which libbpf exposes as a data map.
        state.config_map = bpf_object__find_map_by_name(state.obj, ".data");
        if (!state.config_map) {
            state.config_map = bpf_object__find_map_by_name(state.obj, ".bss");
        }
        state.survival_allowlist = bpf_object__find_map_by_name(state.obj, "survival_allowlist");
        state.policy_generation_map = bpf_object__find_map_by_name(state.obj, "policy_generation");

        // Cgroup-scoped deny maps
        state.deny_cgroup_inode = bpf_object__find_map_by_name(state.obj, "deny_cgroup_inode");
        state.deny_cgroup_ipv4 = bpf_object__find_map_by_name(state.obj, "deny_cgroup_ipv4");
        state.deny_cgroup_port = bpf_object__find_map_by_name(state.obj, "deny_cgroup_port");

        // Diagnostics and process cache maps (optional)
        state.diagnostics = bpf_object__find_map_by_name(state.obj, "diagnostics");
        state.dead_processes = bpf_object__find_map_by_name(state.obj, "dead_processes");

        // Quality improvement maps (optional)
        state.hook_latency = bpf_object__find_map_by_name(state.obj, "hook_latency");
        state.event_approver_inode = bpf_object__find_map_by_name(state.obj, "event_approver_inode");
        state.event_approver_path = bpf_object__find_map_by_name(state.obj, "event_approver_path");
        state.priority_events = bpf_object__find_map_by_name(state.obj, "priority_events");

        // Network maps (optional)
        state.deny_ipv4 = bpf_object__find_map_by_name(state.obj, "deny_ipv4");
        state.deny_ipv6 = bpf_object__find_map_by_name(state.obj, "deny_ipv6");
        state.deny_port = bpf_object__find_map_by_name(state.obj, "deny_port");
        state.deny_ip_port_v4 = bpf_object__find_map_by_name(state.obj, "deny_ip_port_v4");
        state.deny_ip_port_v6 = bpf_object__find_map_by_name(state.obj, "deny_ip_port_v6");
        state.deny_cidr_v4 = bpf_object__find_map_by_name(state.obj, "deny_cidr_v4");
        state.deny_cidr_v6 = bpf_object__find_map_by_name(state.obj, "deny_cidr_v6");
        state.net_block_stats = bpf_object__find_map_by_name(state.obj, "net_block_stats");
        state.net_ip_stats = bpf_object__find_map_by_name(state.obj, "net_ip_stats");
        state.net_port_stats = bpf_object__find_map_by_name(state.obj, "net_port_stats");
        state.backpressure = bpf_object__find_map_by_name(state.obj, "backpressure");

        if (!state.events || !state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.block_stats ||
            !state.deny_cgroup_stats || !state.deny_inode_stats || !state.deny_path_stats || !state.agent_meta ||
            !state.config_map || !state.survival_allowlist || !state.allow_exec_inode || !state.exec_identity_mode) {
            cleanup_bpf(state);
            Error error(ErrorCode::BpfLoadFailed, "Required BPF maps not found in object file");
            span.fail(error.to_string());
            return fail(error);
        }

        if (bpf_map__key_size(state.config_map) != sizeof(uint32_t) || bpf_map__max_entries(state.config_map) != 1 ||
            bpf_map__value_size(state.config_map) != sizeof(AgentConfig)) {
            cleanup_bpf(state);
            Error error(ErrorCode::BpfLoadFailed, "Config map layout mismatch",
                        "key_size=" + std::to_string(bpf_map__key_size(state.config_map)) +
                            " value_size=" + std::to_string(bpf_map__value_size(state.config_map)) +
                            " max_entries=" + std::to_string(bpf_map__max_entries(state.config_map)));
            span.fail(error.to_string());
            return fail(error);
        }
    }

    {
        ScopedSpan span("bpf.configure_ringbuf", trace_id, root_span.span_id());
        uint32_t ringbuf_bytes = g_ringbuf_bytes.load(std::memory_order_relaxed);
        if (ringbuf_bytes > 0) {
            int err = bpf_map__set_max_entries(state.events, ringbuf_bytes);
            if (err) {
                cleanup_bpf(state);
                Error error = Error::bpf_error(err, "Failed to set ring buffer size");
                span.fail(error.to_string());
                return fail(error);
            }
        }
    }

    // Configure map sizes if overridden at runtime
    {
        ScopedSpan span("bpf.configure_map_sizes", trace_id, root_span.span_id());
        auto try_set_max = [&](bpf_map* map, uint32_t max_entries, const char* name) -> Result<void> {
            if (max_entries > 0 && map) {
                int err = bpf_map__set_max_entries(map, max_entries);
                if (err) {
                    cleanup_bpf(state);
                    return Error::bpf_error(err, std::string("Failed to set max entries for ") + name);
                }
                logger().log(SLOG_INFO("Configured map size")
                                 .field("map", name)
                                 .field("max_entries", static_cast<int64_t>(max_entries)));
            }
            return {};
        };

        uint32_t max_inodes = g_max_deny_inodes.load(std::memory_order_relaxed);
        uint32_t max_paths = g_max_deny_paths.load(std::memory_order_relaxed);
        uint32_t max_net = g_max_network_entries.load(std::memory_order_relaxed);

        auto r = try_set_max(state.deny_inode, max_inodes, "deny_inode");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.allow_exec_inode, max_inodes, "allow_exec_inode");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.deny_path, max_paths, "deny_path");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.deny_ipv4, max_net, "deny_ipv4");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.deny_ipv6, max_net, "deny_ipv6");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.deny_port, max_net, "deny_port");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.deny_ip_port_v4, max_net, "deny_ip_port_v4");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
        r = try_set_max(state.deny_ip_port_v6, max_net, "deny_ip_port_v6");
        if (!r) {
            span.fail(r.error().to_string());
            return fail(r.error());
        }
    }

    if (reuse_pins) {
        ScopedSpan span("bpf.reuse_pinned_maps", trace_id, root_span.span_id());

        auto try_reuse = [&state](bpf_map* map, const char* path, bool& reused) -> Result<void> {
            auto result = reuse_pinned_map(map, path, reused);
            if (!result) {
                cleanup_bpf(state);
                return result.error();
            }
            return {};
        };
        auto try_reuse_optional = [](bpf_map* map, const char* path, bool& reused) -> Result<void> {
            if (!map) {
                return {};
            }
            auto result = reuse_pinned_map(map, path, reused);
            if (result) {
                return {};
            }

            logger().log(SLOG_WARN("Failed to reuse optional pinned map; recreating map")
                             .field("path", path)
                             .field("error", result.error().to_string()));
            reused = false;
            std::error_code ec;
            std::filesystem::remove(path, ec);
            if (ec) {
                logger().log(SLOG_WARN("Failed to remove stale optional pinned map")
                                 .field("path", path)
                                 .field("error", ec.message()));
            }
            return {};
        };

        auto check = [&span, &fail](const Result<void>& result) -> Result<void> {
            if (result) {
                return {};
            }
            span.fail(result.error().to_string());
            return fail(result.error());
        };

        TRY(check(try_reuse(state.deny_inode, kDenyInodePin, state.inode_reused)));
        TRY(check(try_reuse(state.deny_path, kDenyPathPin, state.deny_path_reused)));
        TRY(check(try_reuse(state.allow_cgroup, kAllowCgroupPin, state.cgroup_reused)));
        TRY(check(try_reuse(state.allow_exec_inode, kAllowExecInodePin, state.allow_exec_inode_reused)));
        TRY(check(try_reuse(state.exec_identity_mode, kExecIdentityModePin, state.exec_identity_mode_reused)));
        TRY(check(try_reuse(state.block_stats, kBlockStatsPin, state.block_stats_reused)));
        TRY(check(try_reuse(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused)));
        TRY(check(try_reuse(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused)));
        TRY(check(try_reuse(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused)));
        TRY(check(try_reuse(state.agent_meta, kAgentMetaPin, state.agent_meta_reused)));
        TRY(check(try_reuse_optional(state.config_map, kAgentConfigPin, state.config_map_reused)));
        TRY(check(try_reuse(state.survival_allowlist, kSurvivalAllowlistPin, state.survival_allowlist_reused)));

        // Network maps (optional - don't fail if not found)
        TRY(check(try_reuse_optional(state.deny_ipv4, kDenyIpv4Pin, state.deny_ipv4_reused)));
        TRY(check(try_reuse_optional(state.deny_ipv6, kDenyIpv6Pin, state.deny_ipv6_reused)));
        TRY(check(try_reuse_optional(state.deny_port, kDenyPortPin, state.deny_port_reused)));
        TRY(check(try_reuse_optional(state.deny_ip_port_v4, kDenyIpPortV4Pin, state.deny_ip_port_v4_reused)));
        TRY(check(try_reuse_optional(state.deny_ip_port_v6, kDenyIpPortV6Pin, state.deny_ip_port_v6_reused)));
        TRY(check(try_reuse_optional(state.deny_cidr_v4, kDenyCidrV4Pin, state.deny_cidr_v4_reused)));
        TRY(check(try_reuse_optional(state.deny_cidr_v6, kDenyCidrV6Pin, state.deny_cidr_v6_reused)));
        TRY(check(try_reuse_optional(state.net_block_stats, kNetBlockStatsPin, state.net_block_stats_reused)));
        TRY(check(try_reuse_optional(state.net_ip_stats, kNetIpStatsPin, state.net_ip_stats_reused)));
        TRY(check(try_reuse_optional(state.net_port_stats, kNetPortStatsPin, state.net_port_stats_reused)));

        // Cgroup-scoped deny maps (optional — reuse flags are not tracked in BpfState
        // because these maps are always rebuilt from policy; the pins exist purely for
        // post-crash introspection via bpftool)
        {
            bool dummy = false;
            try_reuse_optional(state.deny_cgroup_inode, kDenyCgroupInodePin, dummy);
            try_reuse_optional(state.deny_cgroup_ipv4, kDenyCgroupIpv4Pin, dummy);
            try_reuse_optional(state.deny_cgroup_port, kDenyCgroupPortPin, dummy);
        }
    }

    {
        ScopedSpan span("bpf.configure_autoload", trace_id, root_span.span_id());
        if (!kernel_bpf_lsm_enabled()) {
            bpf_program* lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_inode_permission");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_bprm_check_security");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            // Disable network LSM hooks when LSM is not available
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_connect");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_bind");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_listen");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_accept");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_sendmsg");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
        } else {
            const std::set<std::string> missing_hooks = detect_missing_optional_lsm_hooks();
            const auto disable_optional_program = [&](const char* prog_name, const char* hook_name) {
                if (missing_hooks.find(hook_name) == missing_hooks.end()) {
                    return;
                }
                bpf_program* prog = bpf_object__find_program_by_name(state.obj, prog_name);
                if (!prog) {
                    return;
                }
                bpf_program__set_autoload(prog, false);
                logger().log(SLOG_WARN("Disabling optional LSM program; kernel hook not available")
                                 .field("program", prog_name)
                                 .field("hook", hook_name));
            };

            disable_optional_program("handle_bprm_check_security", "bprm_check_security");
            disable_optional_program("handle_file_mmap", "file_mmap");
            disable_optional_program("handle_socket_connect", "socket_connect");
            disable_optional_program("handle_socket_bind", "socket_bind");
            disable_optional_program("handle_socket_listen", "socket_listen");
            disable_optional_program("handle_socket_accept", "socket_accept");
            disable_optional_program("handle_socket_sendmsg", "socket_sendmsg");
        }
    }

    {
        ScopedSpan span("bpf.load_object", trace_id, root_span.span_id());
        int err = bpf_object__load(state.obj);
        if (err) {
            cleanup_bpf(state);

            std::string error_msg = "Failed to load BPF object";

            Error error = Error::bpf_error(err, error_msg);
            span.fail(error.to_string());
            return fail(error);
        }
    }

    bool need_pins =
        !state.inode_reused || !state.deny_path_reused || !state.cgroup_reused || !state.allow_exec_inode_reused ||
        !state.exec_identity_mode_reused || !state.block_stats_reused || !state.deny_cgroup_stats_reused ||
        !state.deny_inode_stats_reused || !state.deny_path_stats_reused || !state.agent_meta_reused ||
        (state.config_map && !state.config_map_reused) || !state.survival_allowlist_reused ||
        (state.deny_ipv4 && !state.deny_ipv4_reused) || (state.deny_ipv6 && !state.deny_ipv6_reused) ||
        (state.deny_port && !state.deny_port_reused) || (state.deny_ip_port_v4 && !state.deny_ip_port_v4_reused) ||
        (state.deny_ip_port_v6 && !state.deny_ip_port_v6_reused) ||
        (state.deny_cidr_v4 && !state.deny_cidr_v4_reused) || (state.deny_cidr_v6 && !state.deny_cidr_v6_reused) ||
        (state.net_block_stats && !state.net_block_stats_reused) ||
        (state.net_ip_stats && !state.net_ip_stats_reused) || (state.net_port_stats && !state.net_port_stats_reused);

    if (need_pins) {
        ScopedSpan span("bpf.pin_maps", trace_id, root_span.span_id());

        auto pin_result = ensure_pin_dir();
        if (!pin_result) {
            cleanup_bpf(state);
            span.fail(pin_result.error().to_string());
            return fail(pin_result.error());
        }

        auto try_pin = [&state](bpf_map* map, const char* path, bool reused) -> Result<void> {
            if (!reused) {
                auto result = pin_map(map, path);
                if (!result) {
                    cleanup_bpf(state);
                    return result.error();
                }
            }
            return {};
        };

        auto check = [&span, &fail](const Result<void>& result) -> Result<void> {
            if (result) {
                return {};
            }
            span.fail(result.error().to_string());
            return fail(result.error());
        };

        TRY(check(try_pin(state.deny_inode, kDenyInodePin, state.inode_reused)));
        TRY(check(try_pin(state.deny_path, kDenyPathPin, state.deny_path_reused)));
        TRY(check(try_pin(state.allow_cgroup, kAllowCgroupPin, state.cgroup_reused)));
        TRY(check(try_pin(state.allow_exec_inode, kAllowExecInodePin, state.allow_exec_inode_reused)));
        TRY(check(try_pin(state.exec_identity_mode, kExecIdentityModePin, state.exec_identity_mode_reused)));
        TRY(check(try_pin(state.block_stats, kBlockStatsPin, state.block_stats_reused)));
        TRY(check(try_pin(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused)));
        TRY(check(try_pin(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused)));
        TRY(check(try_pin(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused)));
        TRY(check(try_pin(state.agent_meta, kAgentMetaPin, state.agent_meta_reused)));
        TRY(check(try_pin(state.config_map, kAgentConfigPin, state.config_map_reused)));
        TRY(check(try_pin(state.survival_allowlist, kSurvivalAllowlistPin, state.survival_allowlist_reused)));

        // Network maps (optional)
        if (state.deny_ipv4) {
            TRY(check(try_pin(state.deny_ipv4, kDenyIpv4Pin, state.deny_ipv4_reused)));
        }
        if (state.deny_ipv6) {
            TRY(check(try_pin(state.deny_ipv6, kDenyIpv6Pin, state.deny_ipv6_reused)));
        }
        if (state.deny_port) {
            TRY(check(try_pin(state.deny_port, kDenyPortPin, state.deny_port_reused)));
        }
        if (state.deny_ip_port_v4) {
            TRY(check(try_pin(state.deny_ip_port_v4, kDenyIpPortV4Pin, state.deny_ip_port_v4_reused)));
        }
        if (state.deny_ip_port_v6) {
            TRY(check(try_pin(state.deny_ip_port_v6, kDenyIpPortV6Pin, state.deny_ip_port_v6_reused)));
        }
        if (state.deny_cidr_v4) {
            TRY(check(try_pin(state.deny_cidr_v4, kDenyCidrV4Pin, state.deny_cidr_v4_reused)));
        }
        if (state.deny_cidr_v6) {
            TRY(check(try_pin(state.deny_cidr_v6, kDenyCidrV6Pin, state.deny_cidr_v6_reused)));
        }
        if (state.net_block_stats) {
            TRY(check(try_pin(state.net_block_stats, kNetBlockStatsPin, state.net_block_stats_reused)));
        }
        if (state.net_ip_stats) {
            TRY(check(try_pin(state.net_ip_stats, kNetIpStatsPin, state.net_ip_stats_reused)));
        }
        if (state.net_port_stats) {
            TRY(check(try_pin(state.net_port_stats, kNetPortStatsPin, state.net_port_stats_reused)));
        }

        // Cgroup-scoped deny maps (best-effort pin; use a dummy reuse flag since
        // these are rebuilt from policy on every apply)
        {
            bool dummy = false;
            if (state.deny_cgroup_inode) {
                try_pin(state.deny_cgroup_inode, kDenyCgroupInodePin, dummy);
            }
            if (state.deny_cgroup_ipv4) {
                try_pin(state.deny_cgroup_ipv4, kDenyCgroupIpv4Pin, dummy);
            }
            if (state.deny_cgroup_port) {
                try_pin(state.deny_cgroup_port, kDenyCgroupPortPin, dummy);
            }
        }
    }

    if (attach_links) {
        ScopedSpan span("bpf.attach_core_programs", trace_id, root_span.span_id());
        const char* progs[] = {"handle_execve", "handle_file_open", "handle_fork", "handle_exit"};
        for (const char* prog_name : progs) {
            bpf_program* prog = bpf_object__find_program_by_name(state.obj, prog_name);
            if (!prog) {
                cleanup_bpf(state);
                Error error(ErrorCode::BpfLoadFailed, std::string("BPF program not found: ") + prog_name);
                span.fail(error.to_string());
                return fail(error);
            }
            auto result = attach_prog(prog, state);
            if (!result) {
                cleanup_bpf(state);
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
    }

    return {};
}

// --- FD-accepting overloads for shadow population ---

Result<void> add_rule_inode_to_fd(int inode_fd, const InodeId& id, uint8_t flags, DenyEntries& entries)
{
    uint8_t merged = flags;
    uint8_t existing = 0;
    if (bpf_map_lookup_elem(inode_fd, &id, &existing) == 0) {
        merged = static_cast<uint8_t>(merged | existing);
    }
    if (bpf_map_update_elem(inode_fd, &id, &merged, BPF_ANY)) {
        return Error::system(errno, "Failed to update rule inode map");
    }
    entries.try_emplace(id, "");
    return {};
}

Result<void> add_rule_path_to_fds(int inode_fd, int path_fd, const std::string& path, uint8_t flags,
                                  DenyEntries& entries)
{
    if (path.empty()) {
        return Error(ErrorCode::InvalidArgument, "Path is empty");
    }
    if (path.find('\0') != std::string::npos) {
        return Error(ErrorCode::InvalidArgument, "Path contains null bytes", path);
    }

    struct stat lstat_buf {};
    bool is_symlink = (lstat(path.c_str(), &lstat_buf) == 0) && S_ISLNK(lstat_buf.st_mode);
    if (is_symlink) {
        logger().log(SLOG_INFO("Deny path is symlink, will resolve to target").field("symlink", path));
    }

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        return Error(ErrorCode::PathResolutionFailed, "Failed to resolve path", path + ": " + ec.message());
    }
    std::string resolved_str = resolved.string();

    if (resolved_str.size() >= kDenyPathMax) {
        return Error(ErrorCode::PathTooLong, "Resolved path exceeds maximum length",
                     resolved_str + " (" + std::to_string(resolved_str.size()) + " >= " + std::to_string(kDenyPathMax) +
                         ")");
    }

    struct stat st {};
    if (stat(resolved_str.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + resolved_str);
    }

    InodeId id{};
    id.ino = st.st_ino;
    id.dev = encode_dev(st.st_dev);
    id.pad = 0;

    TRY(add_rule_inode_to_fd(inode_fd, id, flags, entries));

    uint8_t merged = flags;
    PathKey path_key{};
    fill_path_key(resolved_str, path_key);
    uint8_t existing = 0;
    if (bpf_map_lookup_elem(path_fd, &path_key, &existing) == 0) {
        merged = static_cast<uint8_t>(merged | existing);
    }
    if (bpf_map_update_elem(path_fd, &path_key, &merged, BPF_ANY)) {
        return Error::system(errno, "Failed to update rule path map");
    }

    if (path != resolved_str && path.size() < kDenyPathMax) {
        merged = flags;
        PathKey raw_key{};
        fill_path_key(path, raw_key);
        existing = 0;
        if (bpf_map_lookup_elem(path_fd, &raw_key, &existing) == 0) {
            merged = static_cast<uint8_t>(merged | existing);
        }
        if (bpf_map_update_elem(path_fd, &raw_key, &merged, BPF_ANY)) {
            return Error::system(errno, "Failed to update rule path map (raw path)");
        }
    }

    if (is_symlink) {
        logger().log(SLOG_INFO("Deny rule added for symlink target")
                         .field("original", path)
                         .field("resolved", resolved_str)
                         .field("dev", static_cast<int64_t>(id.dev))
                         .field("ino", static_cast<int64_t>(id.ino)));
    }

    entries[id] = resolved_str;
    return {};
}

Result<void> add_deny_inode_to_fd(int inode_fd, const InodeId& id, DenyEntries& entries)
{
    return add_rule_inode_to_fd(inode_fd, id, kRuleFlagDenyAlways, entries);
}

Result<void> add_deny_path_to_fds(int inode_fd, int path_fd, const std::string& path, DenyEntries& entries)
{
    return add_rule_path_to_fds(inode_fd, path_fd, path, kRuleFlagDenyAlways, entries);
}

Result<void> add_allow_cgroup_to_fd(int cgroup_fd, uint64_t cgid)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(cgroup_fd, &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update shadow allow_cgroup_map");
    }
    return {};
}

Result<void> add_allow_cgroup_path_to_fd(int cgroup_fd, const std::string& path)
{
    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        return cgid_result.error();
    }
    return add_allow_cgroup_to_fd(cgroup_fd, *cgid_result);
}

Result<void> add_allow_exec_inode_to_fd(int allow_exec_inode_fd, const InodeId& id)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(allow_exec_inode_fd, &id, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update shadow allow_exec_inode_map");
    }
    return {};
}

// --- Cgroup-scoped deny operations ---

Result<uint64_t> resolve_cgroup_identifier(const std::string& cgroup_str)
{
    if (cgroup_str.rfind("cgid:", 0) == 0) {
        std::string id_str = cgroup_str.substr(5);
        uint64_t cgid = 0;
        if (!parse_uint64(id_str, cgid)) {
            return Error(ErrorCode::InvalidArgument, "Invalid cgid value", id_str);
        }
        return cgid;
    }
    return path_to_cgid(cgroup_str);
}

Result<void> add_cgroup_deny_inode_to_fd(int map_fd, uint64_t cgid, const InodeId& inode)
{
    CgroupInodeKey key{};
    key.cgid = cgid;
    key.inode = inode;
    uint8_t one = 1;
    if (bpf_map_update_elem(map_fd, &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_cgroup_inode map");
    }
    return {};
}

Result<void> add_cgroup_deny_ipv4_to_fd(int map_fd, uint64_t cgid, const std::string& ip)
{
    uint32_t ip_be = 0;
    if (!parse_ipv4(ip, ip_be)) {
        return Error(ErrorCode::InvalidArgument, "Invalid IPv4 address for cgroup deny", ip);
    }
    CgroupIpv4Key key{};
    key.cgid = cgid;
    key.addr = ip_be;
    key._pad = 0;
    uint8_t one = 1;
    if (bpf_map_update_elem(map_fd, &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_cgroup_ipv4 map");
    }
    return {};
}

Result<void> add_cgroup_deny_port_to_fd(int map_fd, uint64_t cgid, const PortRule& rule)
{
    CgroupPortKey key{};
    key.cgid = cgid;
    key.port = rule.port;
    key.protocol = rule.protocol;
    key.direction = rule.direction;
    key._pad = 0;
    uint8_t one = 1;
    if (bpf_map_update_elem(map_fd, &key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_cgroup_port map");
    }
    return {};
}

// --- End shadow map support ---

Result<BlockStats> read_block_stats_map(bpf_map* map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<BlockStats> vals(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data())) {
        return Error::system(errno, "Failed to read block_stats");
    }
    BlockStats out{};
    for (const auto& v : vals) {
        out.blocks += v.blocks;
        out.ringbuf_drops += v.ringbuf_drops;
    }
    return out;
}

Result<BackpressureStats> read_backpressure_stats(BpfState& state)
{
    if (!state.backpressure) {
        return BackpressureStats{};
    }
    int fd = bpf_map__fd(state.backpressure);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<BackpressureStats> vals(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data())) {
        if (errno == ENOENT) {
            return BackpressureStats{};
        }
        return Error::system(errno, "Failed to read backpressure stats");
    }
    BackpressureStats out{};
    for (const auto& v : vals) {
        out.seq_total += v.seq_total;
        out.priority_submitted += v.priority_submitted;
        out.priority_drops += v.priority_drops;
        out.telemetry_drops += v.telemetry_drops;
    }
    return out;
}

Result<std::vector<std::pair<uint32_t, HookLatencyEntry>>> read_hook_latency_entries(BpfState& state)
{
    if (!state.hook_latency) {
        return std::vector<std::pair<uint32_t, HookLatencyEntry>>{};
    }
    int fd = bpf_map__fd(state.hook_latency);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<HookLatencyEntry> vals(cpu_cnt);
    std::vector<std::pair<uint32_t, HookLatencyEntry>> out;

    for (uint32_t hook = 0; hook < static_cast<uint32_t>(HOOK_MAX); ++hook) {
        if (bpf_map_lookup_elem(fd, &hook, vals.data())) {
            continue; // Hook not active or not yet recorded
        }
        HookLatencyEntry agg{};
        agg.min_ns = UINT64_MAX;
        for (const auto& v : vals) {
            agg.total_ns += v.total_ns;
            agg.count += v.count;
            if (v.max_ns > agg.max_ns) {
                agg.max_ns = v.max_ns;
            }
            if (v.count > 0 && v.min_ns < agg.min_ns) {
                agg.min_ns = v.min_ns;
            }
        }
        if (agg.count == 0) {
            continue;
        }
        if (agg.min_ns == UINT64_MAX) {
            agg.min_ns = 0;
        }
        out.emplace_back(hook, agg);
    }
    return out;
}

Result<std::vector<std::pair<uint64_t, uint64_t>>> read_cgroup_block_counts(bpf_map* map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<uint64_t> vals(cpu_cnt);
    uint64_t key = 0;
    uint64_t next_key = 0;
    std::vector<std::pair<uint64_t, uint64_t>> out;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            return Error::system(errno, "Failed to read deny_cgroup_stats");
        }
        uint64_t sum = std::accumulate(vals.begin(), vals.end(), uint64_t{0});
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<std::pair<InodeId, uint64_t>>> read_inode_block_counts(bpf_map* map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<uint64_t> vals(cpu_cnt);
    InodeId key{};
    InodeId next_key{};
    std::vector<std::pair<InodeId, uint64_t>> out;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            return Error::system(errno, "Failed to read deny_inode_stats");
        }
        uint64_t sum = std::accumulate(vals.begin(), vals.end(), uint64_t{0});
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<std::pair<std::string, uint64_t>>> read_path_block_counts(bpf_map* map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<uint64_t> vals(cpu_cnt);
    PathKey key{};
    PathKey next_key{};
    std::vector<std::pair<std::string, uint64_t>> out;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            return Error::system(errno, "Failed to read deny_path_stats");
        }
        uint64_t sum = std::accumulate(vals.begin(), vals.end(), uint64_t{0});
        std::string path(key.path, strnlen(key.path, sizeof(key.path)));
        out.emplace_back(path, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<uint64_t>> read_allow_cgroup_ids(bpf_map* map)
{
    int fd = bpf_map__fd(map);
    uint64_t key = 0;
    uint64_t next_key = 0;
    std::vector<uint64_t> out;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        out.push_back(key);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<void> reset_block_stats_map(bpf_map* map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Failed to get CPU count");
    }
    std::vector<BlockStats> zeros(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_update_elem(fd, &key, zeros.data(), BPF_ANY)) {
        return Error::system(errno, "Failed to reset block_stats");
    }
    return {};
}

// cppcheck-suppress unusedFunction
Result<bool> check_prereqs()
{
    if (!std::filesystem::exists("/sys/fs/cgroup/cgroup.controllers")) {
        return Error(ErrorCode::ResourceNotFound, "cgroup v2 is required at /sys/fs/cgroup");
    }
    if (!std::filesystem::exists("/sys/fs/bpf")) {
        return Error(ErrorCode::ResourceNotFound, "bpffs is not mounted at /sys/fs/bpf");
    }
    return kernel_bpf_lsm_enabled();
}

Result<void> add_deny_inode(BpfState& state, const InodeId& id, DenyEntries& entries)
{
    return add_rule_inode_to_fd(bpf_map__fd(state.deny_inode), id, kRuleFlagDenyAlways, entries);
}

Result<void> add_deny_path(BpfState& state, const std::string& path, DenyEntries& entries)
{
    return add_rule_path_to_fds(bpf_map__fd(state.deny_inode), bpf_map__fd(state.deny_path), path, kRuleFlagDenyAlways,
                                entries);
}

Result<void> add_allow_cgroup(BpfState& state, uint64_t cgid)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_cgroup_map");
    }
    return {};
}

Result<void> add_allow_cgroup_path(BpfState& state, const std::string& path)
{
    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        return cgid_result.error();
    }
    return add_allow_cgroup(state, *cgid_result);
}

Result<void> add_allow_exec_inode(BpfState& state, const InodeId& id)
{
    if (!state.allow_exec_inode) {
        return Error(ErrorCode::BpfMapOperationFailed, "allow_exec_inode map not found");
    }
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_exec_inode), &id, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_exec_inode_map");
    }
    return {};
}

Result<void> set_exec_identity_mode(BpfState& state, bool enabled)
{
    if (!state.exec_identity_mode) {
        return Error(ErrorCode::BpfMapOperationFailed, "exec_identity_mode map not found");
    }
    uint32_t key = 0;
    uint8_t value = enabled ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(state.exec_identity_mode), &key, &value, BPF_ANY)) {
        return Error::system(errno, "Failed to update exec_identity_mode_map");
    }
    return {};
}

// Critical binary name patterns to discover via /proc scan
// These match against basename(exe) to find binaries regardless of installation path
static const char* kSurvivalBinaryNames[] = {"init", "systemd", "kubelet", "sshd",     "ssh",     "containerd",
                                             "runc", "crio",    "dockerd", "apt",      "apt-get", "dpkg",
                                             "yum",  "dnf",     "rpm",     "sh",       "bash",    "dash",
                                             "sudo", "su",      "reboot",  "shutdown", nullptr};

Result<void> add_survival_entry(BpfState& state, const InodeId& id)
{
    if (!state.survival_allowlist) {
        return Error(ErrorCode::BpfMapOperationFailed, "Survival allowlist map not found");
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.survival_allowlist), &id, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update survival_allowlist");
    }
    return {};
}

static bool is_survival_binary_name(const std::string& basename)
{
    for (int i = 0; kSurvivalBinaryNames[i] != nullptr; ++i) {
        if (basename == kSurvivalBinaryNames[i]) {
            return true;
        }
    }
    return false;
}

static Result<std::vector<std::pair<pid_t, std::string>>> discover_survival_processes()
{
    std::vector<std::pair<pid_t, std::string>> processes;
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return Error::system(errno, "Failed to open /proc");
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Skip non-numeric entries
        if (!isdigit(entry->d_name[0])) {
            continue;
        }

        pid_t pid = atoi(entry->d_name);
        std::string exe_path = std::string("/proc/") + entry->d_name + "/exe";

        char target[PATH_MAX] = {};
        ssize_t len = readlink(exe_path.c_str(), target, sizeof(target) - 1);
        if (len <= 0) {
            continue; // Process may have exited or we don't have permission
        }
        target[len] = '\0';

        // Extract basename
        const char* basename_ptr = strrchr(target, '/');
        std::string basename = basename_ptr ? std::string(basename_ptr + 1) : std::string(target);

        if (is_survival_binary_name(basename)) {
            processes.emplace_back(pid, std::string(target));
        }
    }

    closedir(proc_dir);
    return processes;
}

Result<void> populate_survival_allowlist(BpfState& state)
{
    if (!state.survival_allowlist) {
        return Error(ErrorCode::BpfMapOperationFailed, "Survival allowlist map not found");
    }

    // Discover survival binaries from running processes
    auto proc_result = discover_survival_processes();
    if (!proc_result) {
        logger().log(SLOG_WARN("Failed to discover survival processes from /proc")
                         .field("error", proc_result.error().to_string()));
        // Continue anyway, don't fail the entire operation
    }

    std::set<InodeId> added_inodes; // Deduplicate by inode
    int count = 0;

    if (proc_result) {
        for (const auto& [pid, exe_path] : proc_result.value()) {
            // Stat through /proc/[pid]/exe to handle mount namespace differences
            // The exe_path from readlink might not be accessible from host namespace
            std::string proc_exe_path = "/proc/" + std::to_string(pid) + "/exe";
            struct stat st {};
            if (stat(proc_exe_path.c_str(), &st) != 0) {
                // Fallback: try the resolved path (for same-namespace binaries)
                if (stat(exe_path.c_str(), &st) != 0) {
                    continue;
                }
            }

            InodeId id{};
            id.ino = st.st_ino;
            id.dev = encode_dev(st.st_dev);
            id.pad = 0;

            // Deduplicate: same binary may be running in multiple processes
            if (added_inodes.find(id) != added_inodes.end()) {
                continue;
            }

            auto result = add_survival_entry(state, id);
            if (result) {
                added_inodes.insert(id);
                ++count;
                logger().log(SLOG_DEBUG("Added survival binary")
                                 .field("path", exe_path)
                                 .field("pid", static_cast<int64_t>(pid))
                                 .field("inode", static_cast<int64_t>(id.ino)));
            }
        }
    }

    // Also add PID 1 (init) as a failsafe, regardless of what it's called
    struct stat st {};
    if (stat("/proc/1/exe", &st) == 0) {
        char target[PATH_MAX] = {};
        ssize_t len = readlink("/proc/1/exe", target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            if (stat(target, &st) == 0) {
                InodeId id{};
                id.ino = st.st_ino;
                id.dev = encode_dev(st.st_dev);
                id.pad = 0;

                if (added_inodes.find(id) == added_inodes.end()) {
                    auto result = add_survival_entry(state, id);
                    if (result) {
                        ++count;
                        logger().log(SLOG_INFO("Added PID 1 to survival allowlist").field("path", std::string(target)));
                    }
                }
            }
        }
    }

    logger().log(SLOG_INFO("Populated survival allowlist via /proc scan").field("count", static_cast<int64_t>(count)));
    return {};
}

Result<std::vector<InodeId>> read_survival_allowlist(BpfState& state)
{
    if (!state.survival_allowlist) {
        return Error(ErrorCode::BpfMapOperationFailed, "Survival allowlist map not found");
    }

    std::vector<InodeId> entries;
    int fd = bpf_map__fd(state.survival_allowlist);
    InodeId key{};
    InodeId next_key{};

    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        entries.push_back(key);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return entries;
}

} // namespace aegis
