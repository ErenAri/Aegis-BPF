#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

static constexpr const char *kPinRoot = "/sys/fs/bpf/aegisbpf";
static constexpr const char *kDenyInodePin = "/sys/fs/bpf/aegisbpf/deny_inode";
static constexpr const char *kDenyPathPin = "/sys/fs/bpf/aegisbpf/deny_path";
static constexpr const char *kAllowCgroupPin = "/sys/fs/bpf/aegisbpf/allow_cgroup";
static constexpr const char *kBlockStatsPin = "/sys/fs/bpf/aegisbpf/block_stats";
static constexpr const char *kDenyCgroupStatsPin = "/sys/fs/bpf/aegisbpf/deny_cgroup_stats";
static constexpr const char *kDenyInodeStatsPin = "/sys/fs/bpf/aegisbpf/deny_inode_stats";
static constexpr const char *kDenyPathStatsPin = "/sys/fs/bpf/aegisbpf/deny_path_stats";
static constexpr const char *kAgentMetaPin = "/sys/fs/bpf/aegisbpf/agent_meta";
static constexpr const char *kBpfObjPath = AEGIS_BPF_OBJ_PATH;
static constexpr const char *kDenyDbDir = "/var/lib/aegisbpf";
static constexpr const char *kDenyDbPath = "/var/lib/aegisbpf/deny.db";
static constexpr uint32_t kLayoutVersion = 1;
static constexpr size_t kDenyPathMax = 256;

enum EventType : uint32_t {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2
};

struct exec_event {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t cgid;
    char comm[16];
};

struct block_event {
    uint32_t ppid;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint32_t pid;
    uint64_t cgid;
    char comm[16];
    uint64_t ino;
    uint32_t dev;
    char path[kDenyPathMax];
    char action[8];
};

struct event {
    uint32_t type;
    union {
        exec_event exec;
        block_event block;
    };
};

struct BlockStats {
    uint64_t blocks;
    uint64_t ringbuf_drops;
};

struct InodeId {
    uint64_t ino;
    uint32_t dev;

    bool operator==(const InodeId &other) const noexcept
    {
        return ino == other.ino && dev == other.dev;
    }
};

struct InodeIdHash {
    std::size_t operator()(const InodeId &id) const noexcept
    {
        return std::hash<uint64_t>{}(id.ino) ^ (std::hash<uint32_t>{}(id.dev) << 1);
    }
};

struct PathKey {
    char path[kDenyPathMax];
};

using DenyEntries = std::unordered_map<InodeId, std::string, InodeIdHash>;

struct AgentConfig {
    uint8_t audit_only;
};

struct AgentMeta {
    uint32_t layout_version;
};

struct BpfState {
    bpf_object *obj = nullptr;
    bpf_map *events = nullptr;
    bpf_map *deny_inode = nullptr;
    bpf_map *deny_path = nullptr;
    bpf_map *allow_cgroup = nullptr;
    bpf_map *block_stats = nullptr;
    bpf_map *deny_cgroup_stats = nullptr;
    bpf_map *deny_inode_stats = nullptr;
    bpf_map *deny_path_stats = nullptr;
    bpf_map *agent_meta = nullptr;
    bpf_map *config_map = nullptr;
    std::vector<bpf_link *> links;
    bool inode_reused = false;
    bool deny_path_reused = false;
    bool cgroup_reused = false;
    bool block_stats_reused = false;
    bool deny_cgroup_stats_reused = false;
    bool deny_inode_stats_reused = false;
    bool deny_path_stats_reused = false;
    bool agent_meta_reused = false;
};

static int setup_agent_cgroup(BpfState &state);

static volatile sig_atomic_t exiting;

static void handle_signal(int)
{
    exiting = 1;
}

static bool kernel_bpf_lsm_enabled()
{
    std::ifstream lsm("/sys/kernel/security/lsm");
    std::string line;
    if (!lsm.is_open() || !std::getline(lsm, line))
        return false;
    return line.find("bpf") != std::string::npos;
}

static int bump_memlock_rlimit()
{
    rlimit rlim;
    std::memset(&rlim, 0, sizeof(rlim));
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int ensure_pin_dir()
{
    if (mkdir(kPinRoot, 0755) && errno != EEXIST)
        return -1;
    return 0;
}

static int ensure_db_dir()
{
    std::error_code ec;
    std::filesystem::create_directories(kDenyDbDir, ec);
    return ec ? -1 : 0;
}

static std::string inode_to_string(const InodeId &id)
{
    std::ostringstream oss;
    oss << id.dev << ":" << id.ino;
    return oss.str();
}

static bool path_to_inode(const std::string &path, InodeId &id)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "stat failed for " << path << ": " << std::strerror(errno) << std::endl;
        return false;
    }
    id.ino = st.st_ino;
    id.dev = static_cast<uint32_t>(st.st_dev);
    return true;
}

static bool path_to_cgid(const std::string &path, uint64_t &cgid)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "stat failed for " << path << ": " << std::strerror(errno) << std::endl;
        return false;
    }
    cgid = static_cast<uint64_t>(st.st_ino);
    return true;
}

static void fill_path_key(const std::string &path, PathKey &key)
{
    std::memset(&key, 0, sizeof(key));
    size_t len = path.size();
    if (len >= sizeof(key.path))
        len = sizeof(key.path) - 1;
    std::memcpy(key.path, path.data(), len);
}

static std::string resolve_cgroup_path(uint64_t cgid)
{
    static std::unordered_map<uint64_t, std::string> cache;
    auto it = cache.find(cgid);
    if (it != cache.end())
        return it->second;

    std::error_code ec;
    std::filesystem::recursive_directory_iterator dir("/sys/fs/cgroup",
                                                      std::filesystem::directory_options::skip_permission_denied, ec);
    std::string found;
    for (; dir != std::filesystem::recursive_directory_iterator(); ++dir) {
        if (!dir->is_directory())
            continue;
        struct stat st {};
        if (stat(dir->path().c_str(), &st) != 0)
            continue;
        if (static_cast<uint64_t>(st.st_ino) == cgid) {
            found = dir->path().string();
            break;
        }
    }
    cache[cgid] = found;
    return found;
}

struct CwdCacheEntry {
    uint64_t start_time;
    std::string cwd;
};

static std::string read_proc_cwd(uint32_t pid)
{
    std::string link = "/proc/" + std::to_string(pid) + "/cwd";
    char buf[PATH_MAX];
    ssize_t len = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (len < 0)
        return {};
    buf[len] = '\0';
    return std::string(buf);
}

static std::string resolve_relative_path(uint32_t pid, uint64_t start_time, const std::string &path)
{
    if (path.empty() || path.front() == '/')
        return path;

    static std::unordered_map<uint32_t, CwdCacheEntry> cache;
    auto it = cache.find(pid);
    if (it == cache.end() || (start_time && it->second.start_time != start_time)) {
        std::string cwd = read_proc_cwd(pid);
        if (cwd.empty())
            return path;
        cache[pid] = {start_time, cwd};
        it = cache.find(pid);
    }

    std::filesystem::path combined = std::filesystem::path(it->second.cwd) / path;
    return combined.lexically_normal().string();
}

static size_t map_entry_count(bpf_map *map)
{
    if (!map)
        return 0;
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

static DenyEntries read_deny_db()
{
    DenyEntries entries;
    std::ifstream in(kDenyDbPath);
    if (!in.is_open())
        return entries;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        uint32_t dev = 0;
        uint64_t ino = 0;
        std::string path;
        if (!(iss >> dev >> ino))
            continue;
        if (!(iss >> path))
            path.clear();
        InodeId id {};
        id.ino = ino;
        id.dev = dev;
        entries[id] = path;
    }
    return entries;
}

static int write_deny_db(const DenyEntries &entries)
{
    if (ensure_db_dir())
        return -1;
    std::ofstream out(kDenyDbPath, std::ios::trunc);
    if (!out.is_open())
        return -1;
    for (const auto &kv : entries) {
        out << kv.first.dev << " " << kv.first.ino;
        if (!kv.second.empty())
            out << " " << kv.second;
        out << "\n";
    }
    return 0;
}

static int reuse_pinned_map(bpf_map *map, const char *path, bool &reused)
{
    int fd = bpf_obj_get(path);
    if (fd < 0)
        return 0;
    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        close(fd);
        return err;
    }
    reused = true;
    return 0;
}

static int pin_map(bpf_map *map, const char *path)
{
    return bpf_map__pin(map, path);
}

static void cleanup_bpf(BpfState &state)
{
    for (auto *link : state.links)
        bpf_link__destroy(link);
    if (state.obj)
        bpf_object__close(state.obj);
    state.obj = nullptr;
}

static int attach_prog(bpf_program *prog, BpfState &state)
{
    bpf_link *link = bpf_program__attach(prog);
    int err = libbpf_get_error(link);
    if (err)
        return err;
    state.links.push_back(link);
    return 0;
}

static int load_bpf(bool reuse_pins, bool attach_links, BpfState &state)
{
    state.obj = bpf_object__open_file(kBpfObjPath, nullptr);
    if (!state.obj)
        return -errno;

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
    if (!state.events || !state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.block_stats ||
        !state.deny_cgroup_stats || !state.deny_inode_stats || !state.deny_path_stats || !state.agent_meta ||
        !state.config_map) {
        cleanup_bpf(state);
        return -ENOENT;
    }

    if (reuse_pins) {
        int err = reuse_pinned_map(state.deny_inode, kDenyInodePin, state.inode_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_path, kDenyPathPin, state.deny_path_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.allow_cgroup, kAllowCgroupPin, state.cgroup_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.block_stats, kBlockStatsPin, state.block_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.agent_meta, kAgentMetaPin, state.agent_meta_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
    }

    if (!kernel_bpf_lsm_enabled()) {
        bpf_program *lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
        if (lsm_prog)
            bpf_program__set_autoload(lsm_prog, false);
    }

    int err = bpf_object__load(state.obj);
    if (err) {
        cleanup_bpf(state);
        return err;
    }

    if (!state.inode_reused || !state.deny_path_reused || !state.cgroup_reused || !state.block_stats_reused ||
        !state.deny_cgroup_stats_reused || !state.deny_inode_stats_reused || !state.deny_path_stats_reused ||
        !state.agent_meta_reused) {
        if (ensure_pin_dir()) {
            cleanup_bpf(state);
            return -errno;
        }
        if (!state.inode_reused) {
            err = pin_map(state.deny_inode, kDenyInodePin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_path_reused) {
            err = pin_map(state.deny_path, kDenyPathPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.cgroup_reused) {
            err = pin_map(state.allow_cgroup, kAllowCgroupPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.block_stats_reused) {
            err = pin_map(state.block_stats, kBlockStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_cgroup_stats_reused) {
            err = pin_map(state.deny_cgroup_stats, kDenyCgroupStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_inode_stats_reused) {
            err = pin_map(state.deny_inode_stats, kDenyInodeStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_path_stats_reused) {
            err = pin_map(state.deny_path_stats, kDenyPathStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.agent_meta_reused) {
            err = pin_map(state.agent_meta, kAgentMetaPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
    }

    if (attach_links) {
        // Legacy path: attach immediately.
        // Prefer using attach_all after any required map seeding.
        bpf_program *prog = bpf_object__find_program_by_name(state.obj, "handle_execve");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }

        prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }

        prog = bpf_object__find_program_by_name(state.obj, "handle_fork");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }

        prog = bpf_object__find_program_by_name(state.obj, "handle_exit");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
    }

    return 0;
}

static int attach_all(BpfState &state, bool lsm_enabled)
{
    int err;
    bpf_program *prog = bpf_object__find_program_by_name(state.obj, "handle_execve");
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    if (lsm_enabled) {
        prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
    } else {
        prog = bpf_object__find_program_by_name(state.obj, "handle_openat");
    }
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    prog = bpf_object__find_program_by_name(state.obj, "handle_fork");
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    prog = bpf_object__find_program_by_name(state.obj, "handle_exit");
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    return 0;
}

static std::string to_string(const char *buf, size_t sz)
{
    return std::string(buf, strnlen(buf, sz));
}

static std::string json_escape(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + 4);
    for (char c : in) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

static void print_exec_event(const exec_event &ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    oss << "{\"type\":\"exec\",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time << ",\"cgid\":" << ev.cgid
        << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\""
        << ",\"comm\":\"" << json_escape(to_string(ev.comm, sizeof(ev.comm))) << "\"}";
    std::cout << oss.str() << std::endl;
}

static void print_block_event(const block_event &ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string path = to_string(ev.path, sizeof(ev.path));
    std::string resolved_path = resolve_relative_path(ev.pid, ev.start_time, path);
    oss << "{\"type\":\"block\",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time << ",\"parent_start_time\":" << ev.parent_start_time
        << ",\"cgid\":" << ev.cgid << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\"";
    if (!path.empty())
        oss << ",\"path\":\"" << json_escape(path) << "\"";
    if (!resolved_path.empty() && resolved_path != path)
        oss << ",\"resolved_path\":\"" << json_escape(resolved_path) << "\"";
    oss << ",\"ino\":" << ev.ino << ",\"dev\":" << ev.dev << ",\"action\":\""
        << json_escape(to_string(ev.action, sizeof(ev.action))) << "\",\"comm\":\""
        << json_escape(to_string(ev.comm, sizeof(ev.comm))) << "\"}";
    std::cout << oss.str() << std::endl;
}

static int handle_event(void *, void *data, size_t)
{
    const auto *e = static_cast<const event *>(data);
    if (e->type == EVENT_EXEC) {
        print_exec_event(e->exec);
    } else if (e->type == EVENT_BLOCK) {
        print_block_event(e->block);
    }
    return 0;
}

static int set_agent_config(BpfState &state, bool audit_only)
{
    if (!state.config_map)
        return -ENOENT;

    uint32_t key = 0;
    AgentConfig cfg {};
    cfg.audit_only = audit_only ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(state.config_map), &key, &cfg, BPF_ANY)) {
        std::cerr << "Failed to configure BPF audit mode: " << std::strerror(errno) << std::endl;
        return -errno;
    }
    return 0;
}

static int ensure_layout_version(BpfState &state)
{
    if (!state.agent_meta)
        return -ENOENT;

    uint32_t key = 0;
    AgentMeta meta {};
    int fd = bpf_map__fd(state.agent_meta);
    if (bpf_map_lookup_elem(fd, &key, &meta) && errno != ENOENT) {
        std::cerr << "Failed to read agent_meta_map: " << std::strerror(errno) << std::endl;
        return -errno;
    }
    if (meta.layout_version == 0) {
        meta.layout_version = kLayoutVersion;
        if (bpf_map_update_elem(fd, &key, &meta, BPF_ANY)) {
            std::cerr << "Failed to set agent layout version: " << std::strerror(errno) << std::endl;
            return -errno;
        }
        return 0;
    }
    if (meta.layout_version != kLayoutVersion) {
        std::cerr << "Pinned maps layout version mismatch (found " << meta.layout_version
                  << ", expected " << kLayoutVersion << "). Run 'sudo ./build/aegisbpf block clear' to reset pins."
                  << std::endl;
        return -EINVAL;
    }
    return 0;
}

static bool check_prereqs(bool &lsm_enabled)
{
    if (!std::filesystem::exists("/sys/fs/cgroup/cgroup.controllers")) {
        std::cerr << "cgroup v2 is required at /sys/fs/cgroup" << std::endl;
        return false;
    }
    if (!std::filesystem::exists("/sys/fs/bpf")) {
        std::cerr << "bpffs is not mounted at /sys/fs/bpf" << std::endl;
        return false;
    }
    lsm_enabled = kernel_bpf_lsm_enabled();
    return true;
}

static int run(bool audit_only)
{
    bool lsm_enabled = false;
    if (!check_prereqs(lsm_enabled))
        return 1;

    if (!lsm_enabled) {
        if (!audit_only) {
            std::cerr << "BPF LSM not enabled; falling back to tracepoint audit-only mode" << std::endl;
            audit_only = true;
        } else {
            std::cerr << "BPF LSM not enabled; running in tracepoint audit-only mode" << std::endl;
        }
    }

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    err = ensure_layout_version(state);
    if (err) {
        cleanup_bpf(state);
        return 1;
    }

    err = set_agent_config(state, audit_only);
    if (err) {
        cleanup_bpf(state);
        return 1;
    }

    if (setup_agent_cgroup(state)) {
        cleanup_bpf(state);
        return 1;
    }

    err = attach_all(state, lsm_enabled);
    if (err) {
        std::cerr << "Failed to attach programs: " << std::strerror(-err) << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    ring_buffer *rb = ring_buffer__new(bpf_map__fd(state.events), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            std::cerr << "Ring buffer poll failed: " << std::strerror(-err) << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    cleanup_bpf(state);
    return err < 0 ? 1 : 0;
}

static int deny_path(const std::string &path)
{
    return 0;
}

// Populate the inode deny map using a real path (symlinks resolved).
static int block_file(const std::string &path)
{
    if (path.empty()) {
        std::cerr << "Path is empty" << std::endl;
        return 1;
    }

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        std::cerr << "Failed to resolve path '" << path << "': " << ec.message() << std::endl;
        return 1;
    }

    struct stat st {};
    if (stat(resolved.c_str(), &st) != 0) {
        std::cerr << "stat failed for " << resolved << ": " << std::strerror(errno) << std::endl;
        return 1;
    }

    InodeId id {};
    id.ino = st.st_ino;
    id.dev = static_cast<uint32_t>(st.st_dev);

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_inode), &id, &one, BPF_ANY)) {
        std::cerr << "Failed to update deny_inode_map: " << std::strerror(errno) << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    std::string resolved_str = resolved.string();
    PathKey path_key {};
    fill_path_key(resolved_str, path_key);
    if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &path_key, &one, BPF_ANY)) {
        std::cerr << "Failed to update deny_path_map: " << std::strerror(errno) << std::endl;
        cleanup_bpf(state);
        return 1;
    }
    if (path != resolved_str) {
        PathKey raw_key {};
        fill_path_key(path, raw_key);
        if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &raw_key, &one, BPF_ANY)) {
            std::cerr << "Failed to update deny_path_map (raw): " << std::strerror(errno) << std::endl;
            cleanup_bpf(state);
            return 1;
        }
    }

    auto entries = read_deny_db();
    entries[id] = resolved_str;
    write_deny_db(entries);

    cleanup_bpf(state);
    return 0;
}

static int read_block_stats_map(bpf_map *map, BlockStats &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<BlockStats> vals(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data())) {
        std::cerr << "Failed to read block_stats: " << std::strerror(errno) << std::endl;
        return 1;
    }
    out = {};
    for (const auto &v : vals) {
        out.blocks += v.blocks;
        out.ringbuf_drops += v.ringbuf_drops;
    }
    return 0;
}

static int read_cgroup_block_counts(bpf_map *map, std::vector<std::pair<uint64_t, uint64_t>> &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<uint64_t> vals(cpu_cnt);
    uint64_t key = 0;
    uint64_t next_key = 0;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            std::cerr << "Failed to read deny_cgroup_stats: " << std::strerror(errno) << std::endl;
            return 1;
        }
        uint64_t sum = 0;
        for (uint64_t v : vals)
            sum += v;
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int read_inode_block_counts(bpf_map *map, std::vector<std::pair<InodeId, uint64_t>> &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<uint64_t> vals(cpu_cnt);
    InodeId key {};
    InodeId next_key {};
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            std::cerr << "Failed to read deny_inode_stats: " << std::strerror(errno) << std::endl;
            return 1;
        }
        uint64_t sum = 0;
        for (uint64_t v : vals)
            sum += v;
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int read_path_block_counts(bpf_map *map, std::vector<std::pair<std::string, uint64_t>> &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<uint64_t> vals(cpu_cnt);
    PathKey key {};
    PathKey next_key {};
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            std::cerr << "Failed to read deny_path_stats: " << std::strerror(errno) << std::endl;
            return 1;
        }
        uint64_t sum = 0;
        for (uint64_t v : vals)
            sum += v;
        std::string path = to_string(key.path, sizeof(key.path));
        out.emplace_back(path, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int reset_block_stats_map(bpf_map *map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<BlockStats> zeros(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_update_elem(fd, &key, zeros.data(), BPF_ANY)) {
        std::cerr << "Failed to reset block_stats: " << std::strerror(errno) << std::endl;
        return 1;
    }
    return 0;
}

static int block_add(const std::string &path)
{
    return block_file(path);
}

// Place current process into a dedicated cgroup v2 and allow that cgroup in the BPF map.
static int setup_agent_cgroup(BpfState &state)
{
    static constexpr const char *kAgentCgroup = "/sys/fs/cgroup/aegis_agent";

    std::error_code ec;
    std::filesystem::create_directories(kAgentCgroup, ec);
    if (ec) {
        std::cerr << "Failed to create cgroup " << kAgentCgroup << ": " << ec.message() << std::endl;
        return 1;
    }

    std::ofstream procs(std::string(kAgentCgroup) + "/cgroup.procs", std::ios::out | std::ios::trunc);
    if (!procs.is_open()) {
        std::cerr << "Failed to open cgroup.procs for " << kAgentCgroup << std::endl;
        return 1;
    }
    procs << getpid();
    procs.close();

    struct stat st {};
    if (stat(kAgentCgroup, &st) != 0) {
        std::cerr << "stat failed for " << kAgentCgroup << ": " << std::strerror(errno) << std::endl;
        return 1;
    }

    uint64_t cgid = static_cast<uint64_t>(st.st_ino);

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        std::cerr << "Failed to update allow_cgroup_map: " << std::strerror(errno) << std::endl;
        return 1;
    }

    return 0;
}

static int block_del(const std::string &path)
{
    InodeId id {};
    if (!path_to_inode(path, id))
        return 1;

    int map_fd = bpf_obj_get(kDenyInodePin);
    if (map_fd < 0) {
        std::cerr << "deny_inode_map not found" << std::endl;
        return 1;
    }
    bpf_map_delete_elem(map_fd, &id);
    close(map_fd);

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    std::string resolved_path = ec ? path : resolved.string();
    PathKey path_key {};
    fill_path_key(resolved_path, path_key);
    int path_fd = bpf_obj_get(kDenyPathPin);
    if (path_fd >= 0) {
        bpf_map_delete_elem(path_fd, &path_key);
        if (resolved_path != path) {
            PathKey raw_key {};
            fill_path_key(path, raw_key);
            bpf_map_delete_elem(path_fd, &raw_key);
        }
        close(path_fd);
    } else {
        std::cerr << "deny_path_map not found" << std::endl;
    }

    auto entries = read_deny_db();
    entries.erase(id);
    write_deny_db(entries);
    return 0;
}

static int block_list()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    auto db = read_deny_db();
    InodeId key {};
    InodeId next_key {};
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end() && !it->second.empty())
            std::cout << it->second << " (" << inode_to_string(key) << ")" << std::endl;
        else
            std::cout << inode_to_string(key) << std::endl;
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), &key, &next_key);
        key = next_key;
    }

    cleanup_bpf(state);
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

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to reload BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }
    if (state.block_stats)
        reset_block_stats_map(state.block_stats);
    cleanup_bpf(state);
    return 0;
}

static int allow_add(const std::string &path)
{
    uint64_t cgid = 0;
    if (!path_to_cgid(path, cgid))
        return 1;

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        std::cerr << "Failed to update allow_cgroup_map: " << std::strerror(errno) << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    cleanup_bpf(state);
    return 0;
}

static int allow_del(const std::string &path)
{
    uint64_t cgid = 0;
    if (!path_to_cgid(path, cgid))
        return 1;

    int fd = bpf_obj_get(kAllowCgroupPin);
    if (fd < 0) {
        std::cerr << "allow_cgroup_map not found" << std::endl;
        return 1;
    }
    bpf_map_delete_elem(fd, &cgid);
    close(fd);
    return 0;
}

static int allow_list()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    uint64_t key = 0;
    uint64_t next_key = 0;
    int rc = bpf_map_get_next_key(bpf_map__fd(state.allow_cgroup), nullptr, &key);
    while (!rc) {
        std::cout << key << std::endl;
        rc = bpf_map_get_next_key(bpf_map__fd(state.allow_cgroup), &key, &next_key);
        key = next_key;
    }

    cleanup_bpf(state);
    return 0;
}

static int print_stats()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    BlockStats stats {};
    if (read_block_stats_map(state.block_stats, stats)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<uint64_t, uint64_t>> cgroup_blocks;
    if (read_cgroup_block_counts(state.deny_cgroup_stats, cgroup_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<InodeId, uint64_t>> inode_blocks;
    if (read_inode_block_counts(state.deny_inode_stats, inode_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<std::string, uint64_t>> path_blocks;
    if (read_path_block_counts(state.deny_path_stats, path_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

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
            std::string path = resolve_cgroup_path(kv.first);
            if (!path.empty())
                std::cout << "  " << path << " (" << kv.first << "): " << kv.second << "\n";
            else
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
        }
    }
    if (!inode_blocks.empty()) {
        auto db = read_deny_db();
        std::cout << "blocks_by_inode:\n";
        for (const auto &kv : inode_blocks) {
            auto it = db.find(kv.first);
            if (it != db.end() && !it->second.empty())
                std::cout << "  " << it->second << " (" << inode_to_string(kv.first) << "): " << kv.second << "\n";
            else
                std::cout << "  " << inode_to_string(kv.first) << ": " << kv.second << "\n";
        }
    }
    if (!path_blocks.empty()) {
        std::cout << "blocks_by_path:\n";
        for (const auto &kv : path_blocks) {
            if (!kv.first.empty())
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
        }
    }

    cleanup_bpf(state);
    return 0;
}

static int usage(const char *prog)
{
    std::cerr << "Usage: " << prog
              << " run [--audit|--enforce]"
              << " | block {add|del|list|clear} [path]"
              << " | allow {add|del} <cgroup_path> | allow list"
              << " | stats" << std::endl;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return run(false);

    std::string cmd = argv[1];
    if (cmd == "run") {
        bool audit_only = false;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--audit" || arg == "--mode=audit") {
                audit_only = true;
            } else if (arg == "--enforce" || arg == "--mode=enforce") {
                audit_only = false;
            } else {
                return usage(argv[0]);
            }
        }
        return run(audit_only);
    }
    if (cmd == "block") {
        if (argc < 3)
            return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4)
                return usage(argv[0]);
            return block_add(argv[3]);
        } else if (sub == "del") {
            if (argc < 4)
                return usage(argv[0]);
            return block_del(argv[3]);
        } else if (sub == "list") {
            return block_list();
        } else if (sub == "clear") {
            return block_clear();
        } else {
            return usage(argv[0]);
        }
    }
    if (cmd == "allow") {
        if (argc < 3)
            return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4)
                return usage(argv[0]);
            return allow_add(argv[3]);
        } else if (sub == "del") {
            if (argc < 4)
                return usage(argv[0]);
            return allow_del(argv[3]);
        } else if (sub == "list") {
            if (argc > 3)
                return usage(argv[0]);
            return allow_list();
        } else {
            return usage(argv[0]);
        }
    }
    if (cmd == "stats") {
        if (argc > 2)
            return usage(argv[0]);
        return print_stats();
    }

    return usage(argv[0]);
}
