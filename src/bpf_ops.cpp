#include "bpf_ops.hpp"
#include "logging.hpp"
#include "utils.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef AEGIS_BPF_OBJ_PATH
#define AEGIS_BPF_OBJ_PATH ""
#endif

namespace aegis {

namespace {
constexpr const char *kBpfObjPath = AEGIS_BPF_OBJ_PATH;
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
    const char *env = std::getenv("AEGIS_BPF_OBJ");
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

Result<void> reuse_pinned_map(bpf_map *map, const char *path, bool &reused)
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

Result<void> pin_map(bpf_map *map, const char *path)
{
    int err = bpf_map__pin(map, path);
    if (err) {
        return Error::bpf_error(err, "Failed to pin map");
    }
    return {};
}

void cleanup_bpf(BpfState &state)
{
    for (auto *link : state.links) {
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

static Result<void> attach_prog(bpf_program *prog, BpfState &state)
{
    bpf_link *link = bpf_program__attach(prog);
    int err = libbpf_get_error(link);
    if (err) {
        return Error::bpf_error(err, "Failed to attach BPF program");
    }
    state.links.push_back(link);
    return {};
}

Result<void> load_bpf(bool reuse_pins, bool attach_links, BpfState &state)
{
    std::string obj_path = resolve_bpf_obj_path();
    state.obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    if (!state.obj) {
        return Error::bpf_error(-errno, "Failed to open BPF object file");
    }

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

    if (!state.events || !state.deny_inode || !state.deny_path || !state.allow_cgroup ||
        !state.block_stats || !state.deny_cgroup_stats || !state.deny_inode_stats ||
        !state.deny_path_stats || !state.agent_meta || !state.config_map) {
        cleanup_bpf(state);
        return Error(ErrorCode::BpfLoadFailed, "Required BPF maps not found in object file");
    }

    if (reuse_pins) {
        auto try_reuse = [&state](bpf_map *map, const char *path, bool &reused) -> Result<void> {
            auto result = reuse_pinned_map(map, path, reused);
            if (!result) {
                cleanup_bpf(state);
                return result.error();
            }
            return {};
        };

        TRY(try_reuse(state.deny_inode, kDenyInodePin, state.inode_reused));
        TRY(try_reuse(state.deny_path, kDenyPathPin, state.deny_path_reused));
        TRY(try_reuse(state.allow_cgroup, kAllowCgroupPin, state.cgroup_reused));
        TRY(try_reuse(state.block_stats, kBlockStatsPin, state.block_stats_reused));
        TRY(try_reuse(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused));
        TRY(try_reuse(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused));
        TRY(try_reuse(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused));
        TRY(try_reuse(state.agent_meta, kAgentMetaPin, state.agent_meta_reused));
    }

    if (!kernel_bpf_lsm_enabled()) {
        bpf_program *lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
        if (lsm_prog) {
            bpf_program__set_autoload(lsm_prog, false);
        }
    }

    int err = bpf_object__load(state.obj);
    if (err) {
        cleanup_bpf(state);
        return Error::bpf_error(err, "Failed to load BPF object");
    }

    bool need_pins = !state.inode_reused || !state.deny_path_reused || !state.cgroup_reused ||
                     !state.block_stats_reused || !state.deny_cgroup_stats_reused ||
                     !state.deny_inode_stats_reused || !state.deny_path_stats_reused ||
                     !state.agent_meta_reused;

    if (need_pins) {
        auto pin_result = ensure_pin_dir();
        if (!pin_result) {
            cleanup_bpf(state);
            return pin_result.error();
        }

        auto try_pin = [&state](bpf_map *map, const char *path, bool reused) -> Result<void> {
            if (!reused) {
                auto result = pin_map(map, path);
                if (!result) {
                    cleanup_bpf(state);
                    return result.error();
                }
            }
            return {};
        };

        TRY(try_pin(state.deny_inode, kDenyInodePin, state.inode_reused));
        TRY(try_pin(state.deny_path, kDenyPathPin, state.deny_path_reused));
        TRY(try_pin(state.allow_cgroup, kAllowCgroupPin, state.cgroup_reused));
        TRY(try_pin(state.block_stats, kBlockStatsPin, state.block_stats_reused));
        TRY(try_pin(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused));
        TRY(try_pin(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused));
        TRY(try_pin(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused));
        TRY(try_pin(state.agent_meta, kAgentMetaPin, state.agent_meta_reused));
    }

    if (attach_links) {
        const char* progs[] = {"handle_execve", "handle_file_open", "handle_fork", "handle_exit"};
        for (const char* prog_name : progs) {
            bpf_program *prog = bpf_object__find_program_by_name(state.obj, prog_name);
            if (!prog) {
                cleanup_bpf(state);
                return Error(ErrorCode::BpfLoadFailed, std::string("BPF program not found: ") + prog_name);
            }
            auto result = attach_prog(prog, state);
            if (!result) {
                cleanup_bpf(state);
                return result.error();
            }
        }
    }

    return {};
}

Result<void> attach_all(BpfState &state, bool lsm_enabled)
{
    bpf_program *prog = bpf_object__find_program_by_name(state.obj, "handle_execve");
    if (!prog) {
        return Error(ErrorCode::BpfAttachFailed, "BPF program not found: handle_execve");
    }
    TRY(attach_prog(prog, state));

    if (lsm_enabled) {
        prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
    } else {
        prog = bpf_object__find_program_by_name(state.obj, "handle_openat");
    }
    if (!prog) {
        return Error(ErrorCode::BpfAttachFailed, "BPF file open program not found");
    }
    TRY(attach_prog(prog, state));

    prog = bpf_object__find_program_by_name(state.obj, "handle_fork");
    if (!prog) {
        return Error(ErrorCode::BpfAttachFailed, "BPF program not found: handle_fork");
    }
    TRY(attach_prog(prog, state));

    prog = bpf_object__find_program_by_name(state.obj, "handle_exit");
    if (!prog) {
        return Error(ErrorCode::BpfAttachFailed, "BPF program not found: handle_exit");
    }
    TRY(attach_prog(prog, state));

    return {};
}

size_t map_entry_count(bpf_map *map)
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

Result<void> clear_map_entries(bpf_map *map)
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

Result<BlockStats> read_block_stats_map(bpf_map *map)
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
    for (const auto &v : vals) {
        out.blocks += v.blocks;
        out.ringbuf_drops += v.ringbuf_drops;
    }
    return out;
}

Result<std::vector<std::pair<uint64_t, uint64_t>>> read_cgroup_block_counts(bpf_map *map)
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
        uint64_t sum = 0;
        for (uint64_t v : vals) {
            sum += v;
        }
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<std::pair<InodeId, uint64_t>>> read_inode_block_counts(bpf_map *map)
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
        uint64_t sum = 0;
        for (uint64_t v : vals) {
            sum += v;
        }
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<std::pair<std::string, uint64_t>>> read_path_block_counts(bpf_map *map)
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
        uint64_t sum = 0;
        for (uint64_t v : vals) {
            sum += v;
        }
        std::string path(key.path, strnlen(key.path, sizeof(key.path)));
        out.emplace_back(path, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return out;
}

Result<std::vector<uint64_t>> read_allow_cgroup_ids(bpf_map *map)
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

Result<void> reset_block_stats_map(bpf_map *map)
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

Result<void> set_agent_config(BpfState &state, bool audit_only)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    cfg.audit_only = audit_only ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(state.config_map), &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to configure BPF audit mode");
    }
    return {};
}

Result<void> ensure_layout_version(BpfState &state)
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
        return Error(ErrorCode::LayoutVersionMismatch,
                     "Pinned maps layout version mismatch",
                     "found " + std::to_string(meta.layout_version) +
                     ", expected " + std::to_string(kLayoutVersion) +
                     ". Run 'sudo aegisbpf block clear' to reset pins.");
    }
    return {};
}

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

Result<void> add_deny_inode(BpfState &state, const InodeId &id, DenyEntries &entries)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_inode), &id, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_inode_map");
    }
    if (entries.find(id) == entries.end()) {
        entries[id] = "";
    }
    return {};
}

Result<void> add_deny_path(BpfState &state, const std::string &path, DenyEntries &entries)
{
    if (path.empty()) {
        return Error(ErrorCode::InvalidArgument, "Path is empty");
    }

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        return Error(ErrorCode::PathResolutionFailed, "Failed to resolve path", path + ": " + ec.message());
    }

    struct stat st{};
    if (stat(resolved.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + resolved.string());
    }

    InodeId id{};
    id.ino = st.st_ino;
    id.dev = static_cast<uint32_t>(st.st_dev);

    TRY(add_deny_inode(state, id, entries));

    uint8_t one = 1;
    std::string resolved_str = resolved.string();
    PathKey path_key{};
    fill_path_key(resolved_str, path_key);
    if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &path_key, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update deny_path_map");
    }
    if (path != resolved_str) {
        PathKey raw_key{};
        fill_path_key(path, raw_key);
        if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &raw_key, &one, BPF_ANY)) {
            return Error::system(errno, "Failed to update deny_path_map (raw path)");
        }
    }

    entries[id] = resolved_str;
    return {};
}

Result<void> add_allow_cgroup(BpfState &state, uint64_t cgid)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_cgroup_map");
    }
    return {};
}

Result<void> add_allow_cgroup_path(BpfState &state, const std::string &path)
{
    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        return cgid_result.error();
    }
    return add_allow_cgroup(state, *cgid_result);
}

} // namespace aegis
