// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace aegis {

#ifndef AEGIS_ENABLE_SIGKILL_ENFORCEMENT
#    define AEGIS_ENABLE_SIGKILL_ENFORCEMENT 0
#endif

inline constexpr const char* kPinRoot = "/sys/fs/bpf/aegisbpf";
inline constexpr const char* kDenyInodePin = "/sys/fs/bpf/aegisbpf/deny_inode";
inline constexpr const char* kDenyPathPin = "/sys/fs/bpf/aegisbpf/deny_path";
inline constexpr const char* kAllowCgroupPin = "/sys/fs/bpf/aegisbpf/allow_cgroup";
inline constexpr const char* kBlockStatsPin = "/sys/fs/bpf/aegisbpf/block_stats";
inline constexpr const char* kDenyCgroupStatsPin = "/sys/fs/bpf/aegisbpf/deny_cgroup_stats";
inline constexpr const char* kDenyInodeStatsPin = "/sys/fs/bpf/aegisbpf/deny_inode_stats";
inline constexpr const char* kDenyPathStatsPin = "/sys/fs/bpf/aegisbpf/deny_path_stats";
inline constexpr const char* kAgentMetaPin = "/sys/fs/bpf/aegisbpf/agent_meta";
inline constexpr const char* kSurvivalAllowlistPin = "/sys/fs/bpf/aegisbpf/survival_allowlist";
inline constexpr const char* kBpfObjInstallPath = "/usr/lib/aegisbpf/aegis.bpf.o";

// Network map pin paths
inline constexpr const char* kDenyIpv4Pin = "/sys/fs/bpf/aegisbpf/deny_ipv4";
inline constexpr const char* kDenyIpv6Pin = "/sys/fs/bpf/aegisbpf/deny_ipv6";
inline constexpr const char* kDenyPortPin = "/sys/fs/bpf/aegisbpf/deny_port";
inline constexpr const char* kDenyCidrV4Pin = "/sys/fs/bpf/aegisbpf/deny_cidr_v4";
inline constexpr const char* kDenyCidrV6Pin = "/sys/fs/bpf/aegisbpf/deny_cidr_v6";
inline constexpr const char* kNetBlockStatsPin = "/sys/fs/bpf/aegisbpf/net_block_stats";
inline constexpr const char* kNetIpStatsPin = "/sys/fs/bpf/aegisbpf/net_ip_stats";
inline constexpr const char* kNetPortStatsPin = "/sys/fs/bpf/aegisbpf/net_port_stats";

// Break-glass detection paths
inline constexpr const char* kBreakGlassPath = "/etc/aegisbpf/break_glass";
inline constexpr const char* kBreakGlassVarPath = "/var/lib/aegisbpf/break_glass";
inline constexpr const char* kBreakGlassTokenPath = "/etc/aegisbpf/break_glass.token";
inline constexpr const char* kVersionCounterPath = "/var/lib/aegisbpf/version_counter";
inline constexpr const char* kDenyDbDir = "/var/lib/aegisbpf";
inline constexpr const char* kDenyDbPath = "/var/lib/aegisbpf/deny.db";
inline constexpr const char* kPolicyAppliedPath = "/var/lib/aegisbpf/policy.applied";
inline constexpr const char* kPolicyAppliedPrevPath = "/var/lib/aegisbpf/policy.applied.prev";
inline constexpr const char* kPolicyAppliedHashPath = "/var/lib/aegisbpf/policy.applied.sha256";
inline constexpr const char* kBpfObjHashPath = "/etc/aegisbpf/aegis.bpf.sha256";
inline constexpr const char* kBpfObjHashInstallPath = "/usr/lib/aegisbpf/aegis.bpf.sha256";
inline constexpr uint32_t kLayoutVersion = 1;
inline constexpr size_t kDenyPathMax = 256;
inline constexpr uint8_t kEnforceSignalNone = 0;
inline constexpr uint8_t kEnforceSignalInt = 2;
inline constexpr uint8_t kEnforceSignalKill = 9;
inline constexpr uint8_t kEnforceSignalTerm = 15;
inline constexpr uint32_t kSigkillEscalationThresholdDefault = 5;
inline constexpr uint32_t kSigkillEscalationWindowSecondsDefault = 30;
inline constexpr bool kSigkillEnforcementCompiledIn = (AEGIS_ENABLE_SIGKILL_ENFORCEMENT != 0);

enum EventType : uint32_t {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2,
    EVENT_NET_CONNECT_BLOCK = 10,
    EVENT_NET_BIND_BLOCK = 11,
};

enum class EventLogSink { Stdout, Journald, StdoutAndJournald };

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

struct NetBlockEvent {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint64_t cgid;
    char comm[16];
    uint8_t family;   /* AF_INET=2 or AF_INET6=10 */
    uint8_t protocol; /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t direction; /* 0=egress (connect), 1=bind */
    uint8_t _pad;
    uint32_t remote_ipv4; /* Network byte order */
    uint8_t remote_ipv6[16];
    char action[8];     /* "AUDIT", "TERM", "KILL", or "BLOCK" */
    char rule_type[16]; /* "ip", "port", "cidr" */
};

struct Event {
    uint32_t type;
    union {
        ExecEvent exec;
        BlockEvent block;
        NetBlockEvent net_block;
    };
};

struct BlockStats {
    uint64_t blocks;
    uint64_t ringbuf_drops;
};

struct NetBlockStats {
    uint64_t connect_blocks;
    uint64_t bind_blocks;
    uint64_t ringbuf_drops;
};

struct PortKey {
    uint16_t port;
    uint8_t protocol;  /* 0=any, 6=tcp, 17=udp */
    uint8_t direction; /* 0=egress, 1=bind, 2=both */

    bool operator==(const PortKey& other) const noexcept
    {
        return port == other.port && protocol == other.protocol && direction == other.direction;
    }
};

struct PortKeyHash {
    std::size_t operator()(const PortKey& k) const noexcept
    {
        return std::hash<uint16_t>{}(k.port) ^ (std::hash<uint8_t>{}(k.protocol) << 1) ^
               (std::hash<uint8_t>{}(k.direction) << 2);
    }
};

struct Ipv4LpmKey {
    uint32_t prefixlen;
    uint32_t addr; /* Network byte order */
};

struct Ipv6Key {
    uint8_t addr[16];
};

struct Ipv6LpmKey {
    uint32_t prefixlen;
    uint8_t addr[16];
};

struct NetIpKey {
    uint8_t family; /* AF_INET=2, AF_INET6=10 */
    uint8_t pad[3];
    uint8_t addr[16];
};

struct InodeId {
    uint64_t ino;
    uint32_t dev;
    uint32_t pad;

    bool operator==(const InodeId& other) const noexcept { return ino == other.ino && dev == other.dev; }
    bool operator<(const InodeId& other) const noexcept
    {
        if (dev != other.dev)
            return dev < other.dev;
        return ino < other.ino;
    }
};

struct InodeIdHash {
    std::size_t operator()(const InodeId& id) const noexcept
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
    std::string original_path; // What user specified
    std::string resolved_path; // Canonical path
    uint64_t added_timestamp;
    std::string source; // "policy:/path" or "cli"
};

// Signed policy bundle format
struct SignedPolicyBundle {
    uint32_t format_version; // Bundle format (1)
    uint64_t policy_version; // Monotonic counter
    uint64_t timestamp;      // Unix timestamp
    uint64_t expires;        // Expiration (0 = none)
    std::array<uint8_t, 32> signer_key;
    std::array<uint8_t, 64> signature;
    std::string policy_sha256;
    std::string policy_content;
};

struct AgentConfig {
    uint8_t audit_only;
    uint8_t deadman_enabled;
    uint8_t break_glass_active;
    uint8_t enforce_signal; /* 0=none, 2=SIGINT, 9=SIGKILL, 15=SIGTERM */
    uint64_t deadman_deadline_ns;
    uint32_t deadman_ttl_seconds;
    uint32_t event_sample_rate;
    uint32_t sigkill_escalation_threshold;      /* SIGKILL after N denies in window */
    uint32_t sigkill_escalation_window_seconds; /* Escalation window size */
};

struct AgentMeta {
    uint32_t layout_version;
};

struct PortRule {
    uint16_t port;
    uint8_t protocol;  /* 0=any, 6=tcp, 17=udp */
    uint8_t direction; /* 0=egress, 1=bind, 2=both */
};

struct IpPortRule {
    std::string ip;
    uint16_t port;
    uint8_t protocol;
};

struct NetworkPolicy {
    std::vector<std::string> deny_ips;     /* Exact IPv4/IPv6 addresses */
    std::vector<std::string> deny_cidrs;   /* CIDR ranges */
    std::vector<PortRule> deny_ports;      /* Port rules */
    std::vector<IpPortRule> deny_ip_ports; /* IP:port combos */
    bool enabled = false;
};

struct Policy {
    int version = 0;
    std::vector<std::string> deny_paths;
    std::vector<InodeId> deny_inodes;
    std::vector<std::string> allow_cgroup_paths;
    std::vector<uint64_t> allow_cgroup_ids;
    NetworkPolicy network;
};

struct PolicyIssues {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;

    // cppcheck-suppress unusedFunction
    [[nodiscard]] bool has_errors() const { return !errors.empty(); }
    // cppcheck-suppress unusedFunction
    [[nodiscard]] bool has_warnings() const { return !warnings.empty(); }
};

// Compile-time struct layout assertions.
// These catch silent mismatches between userspace types and BPF map layouts.
// Sizes must match the corresponding BPF-side definitions in aegis.bpf.c.
static_assert(sizeof(ExecEvent) == 40, "ExecEvent size changed — update BPF struct");
static_assert(sizeof(BlockEvent) == 336, "BlockEvent size changed — update BPF struct");
static_assert(sizeof(NetBlockEvent) == 104, "NetBlockEvent size changed — update BPF struct");
static_assert(sizeof(InodeId) == 16, "InodeId size changed — update BPF struct");
static_assert(sizeof(PathKey) == 256, "PathKey size changed — update BPF struct");
static_assert(sizeof(AgentConfig) == 32, "AgentConfig size changed — update BPF struct");
static_assert(sizeof(AgentMeta) == 4, "AgentMeta size changed — update BPF struct");
static_assert(sizeof(BlockStats) == 16, "BlockStats size changed — update BPF struct");
static_assert(sizeof(PortKey) == 4, "PortKey size changed — update BPF struct");
static_assert(sizeof(Ipv4LpmKey) == 8, "Ipv4LpmKey size changed — update BPF struct");
static_assert(sizeof(Ipv6LpmKey) == 20, "Ipv6LpmKey size changed — update BPF struct");
static_assert(sizeof(NetBlockStats) == 24, "NetBlockStats size changed — update BPF struct");

// Critical field offset assertions — ensure wire-compatible layout.
static_assert(offsetof(BlockEvent, path) == 68, "BlockEvent::path offset changed");
static_assert(offsetof(NetBlockEvent, remote_ipv4) == 56, "NetBlockEvent::remote_ipv4 offset changed");
static_assert(offsetof(AgentConfig, deadman_deadline_ns) == 8, "AgentConfig::deadman_deadline_ns offset changed");

} // namespace aegis
