// cppcheck-suppress-file missingIncludeSystem
#include "bpf_ops.hpp"

#include <dirent.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <set>

#include "logging.hpp"
#include "sha256.hpp"
#include "tracing.hpp"
#include "utils.hpp"

#ifndef AEGIS_BPF_OBJ_PATH
#    define AEGIS_BPF_OBJ_PATH ""
#endif

namespace aegis {

namespace {
constexpr const char* kBpfObjPath = AEGIS_BPF_OBJ_PATH;
std::atomic<uint32_t> g_ringbuf_bytes{0};
} // namespace

bool kernel_bpf_lsm_enabled()
{
    std::ifstream lsm("/sys/kernel/security/lsm");
    std::string line;
    if (!lsm.is_open() || !std::getline(lsm, line)) {
        return false;
    }
    return line.find("bpf") != std::string::npos;
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

std::string resolve_bpf_obj_path()
{
    const char* env = std::getenv("AEGIS_BPF_OBJ");
    if (env && *env) {
        return std::string(env);
    }

    auto exe_in_system_prefix = []() -> bool {
        char buf[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len <= 0) {
            return false;
        }
        buf[len] = '\0';
        std::string exe(buf);
        return exe.rfind("/usr/", 0) == 0 || exe.rfind("/usr/local/", 0) == 0;
    };

    std::error_code ec;
    if (exe_in_system_prefix()) {
        if (std::filesystem::exists(kBpfObjInstallPath, ec)) {
            return kBpfObjInstallPath;
        }
        if (std::filesystem::exists(kBpfObjPath, ec)) {
            return kBpfObjPath;
        }
    } else {
        if (std::filesystem::exists(kBpfObjPath, ec)) {
            return kBpfObjPath;
        }
        if (std::filesystem::exists(kBpfObjInstallPath, ec)) {
            return kBpfObjInstallPath;
        }
    }
    return kBpfObjPath;
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

static Result<void> attach_prog(bpf_program* prog, BpfState& state)
{
    const char* sec = bpf_program__section_name(prog);
    const bool is_lsm = sec && (std::strncmp(sec, "lsm/", 4) == 0 || std::strncmp(sec, "lsm.s/", 6) == 0);

    bpf_link* link = is_lsm ? bpf_program__attach_lsm(prog) : bpf_program__attach(prog);
    int err = libbpf_get_error(link);
    if (err || !link) {
        if (err == 0) {
            err = -EINVAL;
        }
        return Error::bpf_error(err, "Failed to attach BPF program");
    }
    state.links.push_back(link);
    return {};
}

void set_ringbuf_bytes(uint32_t bytes)
{
    g_ringbuf_bytes.store(bytes, std::memory_order_relaxed);
}

// Verify BPF object file integrity before loading
static Result<void> verify_bpf_integrity(const std::string& obj_path)
{
    // Check if verification is disabled (for development only)
    // SECURITY: This bypass is disabled in Release builds to prevent tampering
#ifndef NDEBUG
    const char* skip_verify = std::getenv("AEGIS_SKIP_BPF_VERIFY");
    if (skip_verify && std::string(skip_verify) == "1") {
        logger().log(SLOG_WARN("BPF verification disabled via AEGIS_SKIP_BPF_VERIFY (DEBUG BUILD ONLY)"));
        return {};
    }
#endif

    // Find the expected hash file
    std::string hash_path;
    std::error_code ec;

    // Try /etc/aegisbpf first (admin override), then installed path
    if (std::filesystem::exists(kBpfObjHashPath, ec)) {
        hash_path = kBpfObjHashPath;
    } else if (std::filesystem::exists(kBpfObjHashInstallPath, ec)) {
        hash_path = kBpfObjHashInstallPath;
    } else {
        // No hash file found - in production this should be an error
        // For development/testing, warn and continue
        logger().log(SLOG_WARN("BPF object hash file not found, verification skipped")
                         .field("checked", std::string(kBpfObjHashPath) + ", " + kBpfObjHashInstallPath));
        return {};
    }

    // Read expected hash
    std::string expected_hash;
    if (!read_sha256_file(hash_path, expected_hash)) {
        return Error(ErrorCode::InvalidArgument, "Failed to read BPF hash file", hash_path);
    }

    // Compute actual hash
    std::string actual_hash;
    if (!sha256_file_hex(obj_path, actual_hash)) {
        return Error(ErrorCode::IoError, "Failed to compute hash of BPF object", obj_path);
    }

    // Constant-time comparison to prevent timing side-channel attacks
    if (!constant_time_hex_compare(expected_hash, actual_hash)) {
        logger().log(SLOG_ERROR("BPF object integrity verification failed")
                         .field("path", obj_path)
                         .field("expected", expected_hash)
                         .field("actual", actual_hash));
        return Error(ErrorCode::BpfLoadFailed,
                     "BPF object integrity verification failed - file may have been tampered with",
                     "expected=" + expected_hash + " actual=" + actual_hash);
    }

    logger().log(SLOG_INFO("BPF object integrity verified").field("path", obj_path).field("hash", actual_hash));
    return {};
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
        state.obj = bpf_object__open_file(obj_path.c_str(), nullptr);
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

    {
        ScopedSpan span("bpf.find_maps", trace_id, root_span.span_id());

        state.events = bpf_object__find_map_by_name(state.obj, "events");
        state.deny_inode = bpf_object__find_map_by_name(state.obj, "deny_inode_map");
        state.deny_path = bpf_object__find_map_by_name(state.obj, "deny_path_map");
        state.allow_cgroup = bpf_object__find_map_by_name(state.obj, "allow_cgroup_map");
        state.block_stats = bpf_object__find_map_by_name(state.obj, "block_stats");
        state.deny_cgroup_stats = bpf_object__find_map_by_name(state.obj, "deny_cgroup_stats");
        state.deny_inode_stats = bpf_object__find_map_by_name(state.obj, "deny_inode_stats");
        state.deny_path_stats = bpf_object__find_map_by_name(state.obj, "deny_path_stats");
        state.agent_meta = bpf_object__find_map_by_name(state.obj, "agent_meta_map");
        state.config_map = bpf_object__find_map_by_name(state.obj, "agent_config_map");
        state.survival_allowlist = bpf_object__find_map_by_name(state.obj, "survival_allowlist");

        // Network maps (optional)
        state.deny_ipv4 = bpf_object__find_map_by_name(state.obj, "deny_ipv4");
        state.deny_ipv6 = bpf_object__find_map_by_name(state.obj, "deny_ipv6");
        state.deny_port = bpf_object__find_map_by_name(state.obj, "deny_port");
        state.deny_cidr_v4 = bpf_object__find_map_by_name(state.obj, "deny_cidr_v4");
        state.deny_cidr_v6 = bpf_object__find_map_by_name(state.obj, "deny_cidr_v6");
        state.net_block_stats = bpf_object__find_map_by_name(state.obj, "net_block_stats");
        state.net_ip_stats = bpf_object__find_map_by_name(state.obj, "net_ip_stats");
        state.net_port_stats = bpf_object__find_map_by_name(state.obj, "net_port_stats");

        if (!state.events || !state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.block_stats ||
            !state.deny_cgroup_stats || !state.deny_inode_stats || !state.deny_path_stats || !state.agent_meta ||
            !state.config_map || !state.survival_allowlist) {
            cleanup_bpf(state);
            Error error(ErrorCode::BpfLoadFailed, "Required BPF maps not found in object file");
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
        TRY(check(try_reuse(state.block_stats, kBlockStatsPin, state.block_stats_reused)));
        TRY(check(try_reuse(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused)));
        TRY(check(try_reuse(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused)));
        TRY(check(try_reuse(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused)));
        TRY(check(try_reuse(state.agent_meta, kAgentMetaPin, state.agent_meta_reused)));
        TRY(check(try_reuse(state.survival_allowlist, kSurvivalAllowlistPin, state.survival_allowlist_reused)));

        // Network maps (optional - don't fail if not found)
        TRY(check(try_reuse_optional(state.deny_ipv4, kDenyIpv4Pin, state.deny_ipv4_reused)));
        TRY(check(try_reuse_optional(state.deny_ipv6, kDenyIpv6Pin, state.deny_ipv6_reused)));
        TRY(check(try_reuse_optional(state.deny_port, kDenyPortPin, state.deny_port_reused)));
        TRY(check(try_reuse_optional(state.deny_cidr_v4, kDenyCidrV4Pin, state.deny_cidr_v4_reused)));
        TRY(check(try_reuse_optional(state.deny_cidr_v6, kDenyCidrV6Pin, state.deny_cidr_v6_reused)));
        TRY(check(try_reuse_optional(state.net_block_stats, kNetBlockStatsPin, state.net_block_stats_reused)));
        TRY(check(try_reuse_optional(state.net_ip_stats, kNetIpStatsPin, state.net_ip_stats_reused)));
        TRY(check(try_reuse_optional(state.net_port_stats, kNetPortStatsPin, state.net_port_stats_reused)));
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
            // Disable network LSM hooks when LSM is not available
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_connect");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
            lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_socket_bind");
            if (lsm_prog) {
                bpf_program__set_autoload(lsm_prog, false);
            }
        }
    }

    {
        ScopedSpan span("bpf.load_object", trace_id, root_span.span_id());
        int err = bpf_object__load(state.obj);
        if (err) {
            cleanup_bpf(state);
            Error error = Error::bpf_error(err, "Failed to load BPF object");
            span.fail(error.to_string());
            return fail(error);
        }
    }

    bool need_pins =
        !state.inode_reused || !state.deny_path_reused || !state.cgroup_reused || !state.block_stats_reused ||
        !state.deny_cgroup_stats_reused || !state.deny_inode_stats_reused || !state.deny_path_stats_reused ||
        !state.agent_meta_reused || !state.survival_allowlist_reused || (state.deny_ipv4 && !state.deny_ipv4_reused) ||
        (state.deny_ipv6 && !state.deny_ipv6_reused) || (state.deny_port && !state.deny_port_reused) ||
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
        TRY(check(try_pin(state.block_stats, kBlockStatsPin, state.block_stats_reused)));
        TRY(check(try_pin(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused)));
        TRY(check(try_pin(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused)));
        TRY(check(try_pin(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused)));
        TRY(check(try_pin(state.agent_meta, kAgentMetaPin, state.agent_meta_reused)));
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

Result<void> attach_all(BpfState& state, bool lsm_enabled, bool use_inode_permission, bool use_file_open)
{
    const std::string inherited_trace_id = current_trace_id();
    const std::string trace_id = inherited_trace_id.empty() ? make_span_id("trace") : inherited_trace_id;
    ScopedSpan root_span("bpf.attach_all", trace_id, current_span_id());
    state.attach_contract_valid = false;
    state.file_hooks_expected = 0;
    state.file_hooks_attached = 0;

    auto fail = [&root_span](const Error& error) -> Result<void> {
        root_span.fail(error.to_string());
        return error;
    };

    bpf_program* prog = nullptr;

    {
        ScopedSpan span("bpf.attach.execve", trace_id, root_span.span_id());
        prog = bpf_object__find_program_by_name(state.obj, "handle_execve");
        if (!prog) {
            Error error(ErrorCode::BpfAttachFailed, "BPF program not found: handle_execve");
            span.fail(error.to_string());
            return fail(error);
        }
        auto result = attach_prog(prog, state);
        if (!result) {
            span.fail(result.error().to_string());
            return fail(result.error());
        }
    }

    if (lsm_enabled) {
        ScopedSpan span("bpf.attach.file_hooks_lsm", trace_id, root_span.span_id());
        state.file_hooks_expected = static_cast<uint8_t>((use_inode_permission ? 1 : 0) + (use_file_open ? 1 : 0));
        if (state.file_hooks_expected == 0) {
            Error error(ErrorCode::BpfAttachFailed, "No LSM file hooks requested");
            span.fail(error.to_string());
            return fail(error);
        }
        if (use_inode_permission) {
            prog = bpf_object__find_program_by_name(state.obj, "handle_inode_permission");
            if (!prog) {
                Error error(ErrorCode::BpfAttachFailed, "Requested LSM hook not found: handle_inode_permission");
                span.fail(error.to_string());
                return fail(error);
            }
            auto result = attach_prog(prog, state);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
            ++state.file_hooks_attached;
        }
        if (use_file_open) {
            prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
            if (!prog) {
                Error error(ErrorCode::BpfAttachFailed, "Requested LSM hook not found: handle_file_open");
                span.fail(error.to_string());
                return fail(error);
            }
            auto result = attach_prog(prog, state);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
            ++state.file_hooks_attached;
        }
        if (state.file_hooks_attached != state.file_hooks_expected) {
            Error error(ErrorCode::BpfAttachFailed, "LSM file hook attach contract violated");
            span.fail(error.to_string());
            return fail(error);
        }
    } else {
        ScopedSpan span("bpf.attach.file_hooks_tracepoint", trace_id, root_span.span_id());
        state.file_hooks_expected = 1;
        prog = bpf_object__find_program_by_name(state.obj, "handle_openat");
        if (!prog) {
            Error error(ErrorCode::BpfAttachFailed, "BPF file open program not found");
            span.fail(error.to_string());
            return fail(error);
        }
        auto result = attach_prog(prog, state);
        if (!result) {
            span.fail(result.error().to_string());
            return fail(result.error());
        }
        state.file_hooks_attached = 1;
    }

    {
        ScopedSpan span("bpf.attach.fork", trace_id, root_span.span_id());
        prog = bpf_object__find_program_by_name(state.obj, "handle_fork");
        if (!prog) {
            Error error(ErrorCode::BpfAttachFailed, "BPF program not found: handle_fork");
            span.fail(error.to_string());
            return fail(error);
        }
        auto result = attach_prog(prog, state);
        if (!result) {
            span.fail(result.error().to_string());
            return fail(result.error());
        }
    }

    {
        ScopedSpan span("bpf.attach.exit", trace_id, root_span.span_id());
        prog = bpf_object__find_program_by_name(state.obj, "handle_exit");
        if (!prog) {
            Error error(ErrorCode::BpfAttachFailed, "BPF program not found: handle_exit");
            span.fail(error.to_string());
            return fail(error);
        }
        auto result = attach_prog(prog, state);
        if (!result) {
            span.fail(result.error().to_string());
            return fail(result.error());
        }
    }

    // Attach network LSM hooks if available.
    if (lsm_enabled) {
        ScopedSpan span("bpf.attach.network_hooks", trace_id, root_span.span_id());
        prog = bpf_object__find_program_by_name(state.obj, "handle_socket_connect");
        if (prog) {
            auto result = attach_prog(prog, state);
            if (!result) {
                logger().log(
                    SLOG_WARN("Optional socket_connect hook attach failed").field("error", result.error().to_string()));
            }
        }
        prog = bpf_object__find_program_by_name(state.obj, "handle_socket_bind");
        if (prog) {
            auto result = attach_prog(prog, state);
            if (!result) {
                logger().log(
                    SLOG_WARN("Optional socket_bind hook attach failed").field("error", result.error().to_string()));
            }
        }
    }

    state.attach_contract_valid = true;

    return {};
}

size_t map_entry_count(bpf_map* map)
{
    if (!map) {
        return 0;
    }
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    size_t count = 0;
    int fd = bpf_map__fd(map);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        ++count;
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        key.swap(next_key);
    }
    return count;
}

Result<void> clear_map_entries(bpf_map* map)
{
    if (!map) {
        return Error(ErrorCode::InvalidArgument, "Map is null");
    }
    int fd = bpf_map__fd(map);
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        bpf_map_delete_elem(fd, key.data());
        if (!rc) {
            key.swap(next_key);
        }
    }
    return {};
}

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
Result<void> set_agent_config(BpfState& state, bool audit_only)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    cfg.audit_only = audit_only ? 1 : 0;
    cfg.enforce_signal = kEnforceSignalTerm;
    cfg.event_sample_rate = 1;
    cfg.sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
    cfg.sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    if (bpf_map_update_elem(bpf_map__fd(state.config_map), &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to configure BPF audit mode");
    }
    return {};
}

Result<void> ensure_layout_version(BpfState& state)
{
    if (!state.agent_meta) {
        return Error(ErrorCode::BpfMapOperationFailed, "Agent meta map not found");
    }

    uint32_t key = 0;
    AgentMeta meta{};
    int fd = bpf_map__fd(state.agent_meta);
    if (bpf_map_lookup_elem(fd, &key, &meta) && errno != ENOENT) {
        return Error::system(errno, "Failed to read agent_meta_map");
    }
    if (meta.layout_version == 0) {
        meta.layout_version = kLayoutVersion;
        if (bpf_map_update_elem(fd, &key, &meta, BPF_ANY)) {
            return Error::system(errno, "Failed to set agent layout version");
        }
        return {};
    }
    if (meta.layout_version != kLayoutVersion) {
        return Error(ErrorCode::LayoutVersionMismatch, "Pinned maps layout version mismatch",
                     "found " + std::to_string(meta.layout_version) + ", expected " + std::to_string(kLayoutVersion) +
                         ". Run 'sudo aegisbpf block clear' to reset pins.");
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
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_inode), &id, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_inode_map");
    }
    entries.try_emplace(id, "");
    return {};
}

Result<void> add_deny_path(BpfState& state, const std::string& path, DenyEntries& entries)
{
    if (path.empty()) {
        return Error(ErrorCode::InvalidArgument, "Path is empty");
    }

    // Check for null bytes (potential injection attack)
    if (path.find('\0') != std::string::npos) {
        return Error(ErrorCode::InvalidArgument, "Path contains null bytes", path);
    }

    // Check if the input path is a symlink (for audit logging)
    struct stat lstat_buf {};
    bool is_symlink = (lstat(path.c_str(), &lstat_buf) == 0) && S_ISLNK(lstat_buf.st_mode);
    if (is_symlink) {
        logger().log(SLOG_INFO("Deny path is symlink, will resolve to target").field("symlink", path));
    }

    // Canonicalize path - resolves symlinks, removes . and .., normalizes slashes
    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        return Error(ErrorCode::PathResolutionFailed, "Failed to resolve path", path + ": " + ec.message());
    }

    std::string resolved_str = resolved.string();

    // Check length AFTER canonicalization (resolved path might be longer)
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

    TRY(add_deny_inode(state, id, entries));

    uint8_t one = 1;
    PathKey path_key{};
    fill_path_key(resolved_str, path_key);
    if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &path_key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_path_map");
    }

    // Also add the raw path if different (for direct path matching)
    if (path != resolved_str && path.size() < kDenyPathMax) {
        PathKey raw_key{};
        fill_path_key(path, raw_key);
        if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &raw_key, &one, BPF_ANY)) {
            return Error::system(errno, "Failed to update deny_path_map (raw path)");
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

Result<void> set_agent_config_full(BpfState& state, const AgentConfig& config)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    AgentConfig normalized = config;
    if (normalized.event_sample_rate == 0) {
        normalized.event_sample_rate = 1;
    }
    if (normalized.sigkill_escalation_threshold == 0) {
        normalized.sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
    }
    if (normalized.sigkill_escalation_window_seconds == 0) {
        normalized.sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    }

    uint32_t key = 0;
    if (bpf_map_update_elem(bpf_map__fd(state.config_map), &key, &normalized, BPF_ANY)) {
        return Error::system(errno, "Failed to configure BPF agent config");
    }
    return {};
}

Result<void> update_deadman_deadline(BpfState& state, uint64_t deadline_ns)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);

    // Read current config
    if (bpf_map_lookup_elem(fd, &key, &cfg)) {
        if (errno != ENOENT) {
            return Error::system(errno, "Failed to read agent config");
        }
        cfg.enforce_signal = kEnforceSignalTerm;
        cfg.event_sample_rate = 1;
        cfg.sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
        cfg.sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    }

    // Update deadline
    cfg.deadman_deadline_ns = deadline_ns;

    // Write back
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to update deadman deadline");
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
            struct stat st {};
            if (stat(exe_path.c_str(), &st) != 0) {
                continue;
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
