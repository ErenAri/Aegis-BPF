#pragma once

#include <array>
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
inline constexpr const char *kSurvivalAllowlistPin = "/sys/fs/bpf/aegisbpf/survival_allowlist";
inline constexpr const char *kBpfObjInstallPath = "/usr/lib/aegisbpf/aegis.bpf.o";

// Break-glass detection paths
inline constexpr const char *kBreakGlassPath = "/etc/aegisbpf/break_glass";
inline constexpr const char *kBreakGlassVarPath = "/var/lib/aegisbpf/break_glass";
inline constexpr const char *kBreakGlassTokenPath = "/etc/aegisbpf/break_glass.token";
inline constexpr const char *kVersionCounterPath = "/var/lib/aegisbpf/version_counter";
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
    uint32_t pad;

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

// Enhanced deny entry with full tracking information
struct DenyEntry {
    InodeId id;
    std::string original_path;    // What user specified
    std::string resolved_path;    // Canonical path
    uint64_t added_timestamp;
    std::string source;           // "policy:/path" or "cli"
};

// Signed policy bundle format
struct SignedPolicyBundle {
    uint32_t format_version;      // Bundle format (1)
    uint64_t policy_version;      // Monotonic counter
    uint64_t timestamp;           // Unix timestamp
    uint64_t expires;             // Expiration (0 = none)
    std::array<uint8_t, 32> signer_key;
    std::array<uint8_t, 64> signature;
    std::string policy_sha256;
    std::string policy_content;
};

struct AgentConfig {
    uint8_t audit_only;
    uint8_t deadman_enabled;
    uint8_t break_glass_active;
    uint8_t _pad;
    uint64_t deadman_deadline_ns;
    uint32_t deadman_ttl_seconds;
    uint32_t _pad2;
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
