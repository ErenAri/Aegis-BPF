#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace aegis {

inline constexpr const char *kPinRoot = "/sys/fs/bpf/aegisbpf";
inline constexpr const char *kDenyInodePin = "/sys/fs/bpf/aegisbpf/deny_inode";
inline constexpr const char *kDenyPathPin = "/sys/fs/bpf/aegisbpf/deny_path";
inline constexpr const char *kAllowCgroupPin = "/sys/fs/bpf/aegisbpf/allow_cgroup";
inline constexpr const char *kBlockStatsPin = "/sys/fs/bpf/aegisbpf/block_stats";
inline constexpr const char *kDenyCgroupStatsPin = "/sys/fs/bpf/aegisbpf/deny_cgroup_stats";
inline constexpr const char *kDenyInodeStatsPin = "/sys/fs/bpf/aegisbpf/deny_inode_stats";
inline constexpr const char *kDenyPathStatsPin = "/sys/fs/bpf/aegisbpf/deny_path_stats";
inline constexpr const char *kAgentMetaPin = "/sys/fs/bpf/aegisbpf/agent_meta";
inline constexpr const char *kBpfObjInstallPath = "/usr/lib/aegisbpf/aegis.bpf.o";
inline constexpr const char *kDenyDbDir = "/var/lib/aegisbpf";
inline constexpr const char *kDenyDbPath = "/var/lib/aegisbpf/deny.db";
inline constexpr const char *kPolicyAppliedPath = "/var/lib/aegisbpf/policy.applied";
inline constexpr const char *kPolicyAppliedPrevPath = "/var/lib/aegisbpf/policy.applied.prev";
inline constexpr const char *kPolicyAppliedHashPath = "/var/lib/aegisbpf/policy.applied.sha256";
inline constexpr uint32_t kLayoutVersion = 1;
inline constexpr size_t kDenyPathMax = 256;

enum EventType : uint32_t {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2
};

enum class EventLogSink {
    Stdout,
    Journald,
    StdoutAndJournald
};

struct ExecEvent {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t cgid;
    char comm[16];
};

struct BlockEvent {
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

struct Event {
    uint32_t type;
    union {
        ExecEvent exec;
        BlockEvent block;
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

struct Policy {
    int version = 0;
    std::vector<std::string> deny_paths;
    std::vector<InodeId> deny_inodes;
    std::vector<std::string> allow_cgroup_paths;
    std::vector<uint64_t> allow_cgroup_ids;
};

struct PolicyIssues {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;

    [[nodiscard]] bool has_errors() const { return !errors.empty(); }
    [[nodiscard]] bool has_warnings() const { return !warnings.empty(); }
};

} // namespace aegis
