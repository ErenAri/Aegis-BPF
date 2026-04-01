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
inline constexpr const char* kAllowExecInodePin = "/sys/fs/bpf/aegisbpf/allow_exec_inode";
inline constexpr const char* kExecIdentityModePin = "/sys/fs/bpf/aegisbpf/exec_identity_mode";
inline constexpr const char* kBlockStatsPin = "/sys/fs/bpf/aegisbpf/block_stats";
inline constexpr const char* kDenyCgroupStatsPin = "/sys/fs/bpf/aegisbpf/deny_cgroup_stats";
inline constexpr const char* kDenyInodeStatsPin = "/sys/fs/bpf/aegisbpf/deny_inode_stats";
inline constexpr const char* kDenyPathStatsPin = "/sys/fs/bpf/aegisbpf/deny_path_stats";
inline constexpr const char* kAgentMetaPin = "/sys/fs/bpf/aegisbpf/agent_meta";
inline constexpr const char* kAgentConfigPin = "/sys/fs/bpf/aegisbpf/agent_config";
inline constexpr const char* kSurvivalAllowlistPin = "/sys/fs/bpf/aegisbpf/survival_allowlist";
inline constexpr const char* kBpfObjInstallPath = "/usr/lib/aegisbpf/aegis.bpf.o";

// Network map pin paths
inline constexpr const char* kDenyIpv4Pin = "/sys/fs/bpf/aegisbpf/deny_ipv4";
inline constexpr const char* kDenyIpv6Pin = "/sys/fs/bpf/aegisbpf/deny_ipv6";
inline constexpr const char* kDenyPortPin = "/sys/fs/bpf/aegisbpf/deny_port";
inline constexpr const char* kDenyIpPortV4Pin = "/sys/fs/bpf/aegisbpf/deny_ip_port_v4";
inline constexpr const char* kDenyIpPortV6Pin = "/sys/fs/bpf/aegisbpf/deny_ip_port_v6";
inline constexpr const char* kDenyCidrV4Pin = "/sys/fs/bpf/aegisbpf/deny_cidr_v4";
inline constexpr const char* kDenyCidrV6Pin = "/sys/fs/bpf/aegisbpf/deny_cidr_v6";
inline constexpr const char* kNetBlockStatsPin = "/sys/fs/bpf/aegisbpf/net_block_stats";
inline constexpr const char* kNetIpStatsPin = "/sys/fs/bpf/aegisbpf/net_ip_stats";
inline constexpr const char* kNetPortStatsPin = "/sys/fs/bpf/aegisbpf/net_port_stats";
inline constexpr const char* kDiagnosticsPin = "/sys/fs/bpf/aegisbpf/diagnostics";
inline constexpr const char* kDeadProcessesPin = "/sys/fs/bpf/aegisbpf/dead_processes";

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
inline constexpr const char* kCapabilitiesReportPath = "/var/lib/aegisbpf/capabilities.json";
inline constexpr const char* kControlStatePath = "/var/lib/aegisbpf/control_state.json";
inline constexpr const char* kControlLogPath = "/var/lib/aegisbpf/control_log.jsonl";
inline constexpr const char* kControlLockPath = "/var/lib/aegisbpf/control.lock";
inline constexpr const char* kBpfObjHashPath = "/etc/aegisbpf/aegis.bpf.sha256";
inline constexpr const char* kBpfObjHashInstallPath = "/usr/lib/aegisbpf/aegis.bpf.sha256";
inline constexpr const char* kCapabilitiesSchemaSemver = "1.5.0";
inline constexpr uint32_t kLayoutVersion = 1;
inline constexpr size_t kDenyPathMax = 256;
inline constexpr uint8_t kEnforceSignalNone = 0;
inline constexpr uint8_t kEnforceSignalInt = 2;
inline constexpr uint8_t kEnforceSignalKill = 9;
inline constexpr uint8_t kEnforceSignalTerm = 15;
inline constexpr uint32_t kSigkillEscalationThresholdDefault = 5;
inline constexpr uint32_t kSigkillEscalationWindowSecondsDefault = 30;
inline constexpr bool kSigkillEnforcementCompiledIn = (AEGIS_ENABLE_SIGKILL_ENFORCEMENT != 0);
inline constexpr uint8_t kRuleFlagDenyAlways = 1;
inline constexpr uint8_t kRuleFlagProtectByVerifiedExec = 2;
inline constexpr uint8_t kExecIdentityFlagAllowlistEnforce = 1u << 0;
inline constexpr uint8_t kExecIdentityFlagProtectConnect = 1u << 1;
inline constexpr uint8_t kExecIdentityFlagProtectFiles = 1u << 2;
inline constexpr uint8_t kExecIdentityFlagTrustRuntimeDeps = 1u << 3;

enum EventType : uint32_t {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2,
    EVENT_EXEC_ARGV = 3,
    EVENT_FORENSIC_BLOCK = 4,
    EVENT_NET_CONNECT_BLOCK = 10,
    EVENT_NET_BIND_BLOCK = 11,
    EVENT_NET_LISTEN_BLOCK = 12,
    EVENT_NET_ACCEPT_BLOCK = 13,
    EVENT_NET_SENDMSG_BLOCK = 14,
    EVENT_KERNEL_PTRACE_BLOCK = 20,
    EVENT_KERNEL_MODULE_BLOCK = 21,
    EVENT_KERNEL_BPF_BLOCK = 22,
};

enum DiagType : uint32_t {
    DIAG_MAP_PRESSURE = 1,
    DIAG_HOOK_ERROR = 2,
    DIAG_PROCESS_EVICTION = 3,
};

enum HookId : uint32_t {
    HOOK_FILE_OPEN = 0,
    HOOK_INODE_PERMISSION = 1,
    HOOK_BPRM_CHECK = 2,
    HOOK_FILE_MMAP = 3,
    HOOK_SOCKET_CONNECT = 4,
    HOOK_SOCKET_BIND = 5,
    HOOK_SOCKET_LISTEN = 6,
    HOOK_SOCKET_ACCEPT = 7,
    HOOK_SOCKET_SENDMSG = 8,
    HOOK_EXECVE = 9,
    HOOK_PTRACE = 10,
    HOOK_MODULE_LOAD = 11,
    HOOK_BPF = 12,
    HOOK_MAX = 16,
};

enum class EventLogSink { Stdout, Journald, StdoutAndJournald };

inline constexpr size_t kMaxArgvSize = 256;

// New map pin paths for quality improvements
inline constexpr const char* kHookLatencyPin = "/sys/fs/bpf/aegisbpf/hook_latency";
inline constexpr const char* kEventApproverInodePin = "/sys/fs/bpf/aegisbpf/event_approver_inode";
inline constexpr const char* kEventApproverPathPin = "/sys/fs/bpf/aegisbpf/event_approver_path";
inline constexpr const char* kPriorityEventsPin = "/sys/fs/bpf/aegisbpf/priority_events";

struct ExecEvent {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t cgid;
    char comm[16];
};

struct ExecArgvEvent {
    uint32_t pid;
    uint32_t _pad;
    uint64_t start_time;
    uint16_t argc;
    uint16_t total_len;
    uint32_t _pad2;
    char argv[kMaxArgvSize]; /* null-separated argument strings */
};

struct DiagEvent {
    uint32_t type; /* DiagType */
    uint32_t _pad;
    uint64_t timestamp;
    uint32_t data1;
    uint32_t data2;
    char msg[64];
};

struct HookLatencyEntry {
    uint64_t total_ns;
    uint64_t count;
    uint64_t max_ns;
    uint64_t min_ns;
};

struct ForensicEvent {
    uint32_t type; /* EVENT_FORENSIC_BLOCK */
    uint32_t pid;
    uint32_t ppid;
    uint32_t _pad;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint64_t cgid;
    char comm[16];
    uint64_t ino;
    uint32_t dev;
    uint32_t uid;
    uint32_t gid;
    uint32_t _pad2;
    uint64_t exec_ino;
    uint32_t exec_dev;
    uint8_t exec_stage;
    uint8_t verified_exec;
    uint8_t exec_identity_known;
    uint8_t _pad3;
    char action[8];
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
    uint8_t direction; /* 0=egress (connect), 1=bind, 2=listen, 3=accept, 4=send */
    uint8_t _pad;
    uint32_t remote_ipv4; /* Network byte order */
    uint8_t remote_ipv6[16];
    char action[8];     /* "AUDIT", "TERM", "KILL", or "BLOCK" */
    char rule_type[16]; /* "ip", "port", "cidr", "ip_port", "identity" */
};

/// Kernel security block event: ptrace, module load, BPF program load.
struct KernelBlockEvent {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint64_t cgid;
    char comm[16];
    uint32_t target_pid; /* target PID for ptrace, 0 otherwise */
    uint32_t _pad;
    char action[8];     /* "AUDIT", "TERM", "KILL", or "BLOCK" */
    char rule_type[16]; /* "ptrace", "module", "bpf" */
};

struct Event {
    uint32_t type;
    union {
        ExecEvent exec;
        ExecArgvEvent exec_argv;
        BlockEvent block;
        NetBlockEvent net_block;
        ForensicEvent forensic;
        KernelBlockEvent kernel_block;
    };
};

struct BlockStats {
    uint64_t blocks;
    uint64_t ringbuf_drops;
};

struct NetBlockStats {
    uint64_t connect_blocks;
    uint64_t bind_blocks;
    uint64_t listen_blocks;
    uint64_t accept_blocks;
    uint64_t sendmsg_blocks;
    uint64_t ringbuf_drops;
};

/// Dual-path backpressure telemetry (Aquila pattern).
struct BackpressureStats {
    uint64_t seq_total;          ///< Monotonic total events generated
    uint64_t priority_submitted; ///< Events submitted to priority buffer
    uint64_t priority_drops;     ///< Priority buffer reservation failures
    uint64_t telemetry_drops;    ///< Telemetry buffer reservation failures
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

struct IpPortV4Key {
    uint32_t addr; /* Network byte order */
    uint16_t port;
    uint8_t protocol; /* 0=any, 6=tcp, 17=udp */
    uint8_t pad;
};

struct IpPortV6Key {
    uint8_t addr[16];
    uint16_t port;
    uint8_t protocol; /* 0=any, 6=tcp, 17=udp */
    uint8_t pad;
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
    uint8_t enforce_signal;      /* 0=none, 2=SIGINT, 9=SIGKILL, 15=SIGTERM */
    uint8_t emergency_disable;   /* bypass enforcement (force AUDIT) when set */
    uint8_t file_policy_empty;   /* optimization hint: no file deny rules loaded */
    uint8_t net_policy_empty;    /* optimization hint: no network deny rules loaded */
    uint8_t exec_identity_flags; /* bitmask; see kRuleFlag* and exec-identity contract */
    uint64_t deadman_deadline_ns;
    uint32_t deadman_ttl_seconds;
    uint32_t event_sample_rate;
    uint32_t sigkill_escalation_threshold;      /* SIGKILL after N denies in window */
    uint32_t sigkill_escalation_window_seconds; /* Escalation window size */
    uint8_t deny_ptrace;                        /* block ptrace attachment (MITRE T1055.008) */
    uint8_t deny_module_load;                   /* block kernel module loading (MITRE T1547.006) */
    uint8_t deny_bpf;                           /* block unauthorized BPF program load (MITRE T1562) */
    uint8_t _pad_kernel;
    uint64_t policy_generation; /* monotonic generation for atomic policy commits */
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
    uint8_t protocol; /* 0=any, 6=tcp, 17=udp */
};

struct NetworkPolicy {
    std::vector<std::string> deny_ips;     /* Exact IPv4/IPv6 addresses */
    std::vector<std::string> deny_cidrs;   /* CIDR ranges */
    std::vector<PortRule> deny_ports;      /* Port rules */
    std::vector<IpPortRule> deny_ip_ports; /* Exact remote IP:port tuples */
    bool enabled = false;
};

struct Policy {
    int version = 0;
    std::vector<std::string> deny_paths;
    std::vector<InodeId> deny_inodes;
    // "Protected" resources are allowed for VERIFIED_EXEC processes and denied otherwise.
    // This is distinct from deny rules, which always deny regardless of exec identity.
    std::vector<std::string> protect_paths;
    bool protect_connect = false;       // when true, all connect() attempts are protected
    bool protect_runtime_deps = false;  // when true, executable mmaps must remain VERIFIED_EXEC
    bool require_ima_appraisal = false; // when true, enforce only if IMA appraisal is active on node
    std::vector<std::string> allow_cgroup_paths;
    std::vector<uint64_t> allow_cgroup_ids;
    NetworkPolicy network;
    std::vector<std::string> deny_binary_hashes;  // sha256:... entries (v3+)
    std::vector<std::string> allow_binary_hashes; // sha256:... entries (v3+)
    std::vector<std::string> scan_paths;          // Extra paths for binary hash scan (v3+)
    // Kernel security hooks (MITRE ATT&CK coverage)
    bool deny_ptrace = false;      // block ptrace (T1055.008)
    bool deny_module_load = false; // block kernel module loading (T1547.006)
    bool deny_bpf = false;         // block unauthorized BPF program loading (T1562)
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
static_assert(sizeof(AgentConfig) == 48, "AgentConfig size changed — update BPF struct");
static_assert(sizeof(AgentMeta) == 4, "AgentMeta size changed — update BPF struct");
static_assert(sizeof(BlockStats) == 16, "BlockStats size changed — update BPF struct");
static_assert(sizeof(PortKey) == 4, "PortKey size changed — update BPF struct");
static_assert(sizeof(IpPortV4Key) == 8, "IpPortV4Key size changed — update BPF struct");
static_assert(sizeof(IpPortV6Key) == 20, "IpPortV6Key size changed — update BPF struct");
static_assert(sizeof(Ipv4LpmKey) == 8, "Ipv4LpmKey size changed — update BPF struct");
static_assert(sizeof(Ipv6LpmKey) == 20, "Ipv6LpmKey size changed — update BPF struct");
static_assert(sizeof(NetBlockStats) == 48, "NetBlockStats size changed — update BPF struct");
static_assert(sizeof(ExecArgvEvent) == 280, "ExecArgvEvent size changed — update BPF struct");
static_assert(sizeof(DiagEvent) == 88, "DiagEvent size changed — update BPF struct");
static_assert(sizeof(HookLatencyEntry) == 32, "HookLatencyEntry size changed — update BPF struct");
static_assert(sizeof(ForensicEvent) == 104, "ForensicEvent size changed — update BPF struct");

// Critical field offset assertions — ensure wire-compatible layout.
static_assert(offsetof(BlockEvent, path) == 68, "BlockEvent::path offset changed");
static_assert(offsetof(NetBlockEvent, remote_ipv4) == 56, "NetBlockEvent::remote_ipv4 offset changed");
static_assert(offsetof(AgentConfig, deadman_deadline_ns) == 8, "AgentConfig::deadman_deadline_ns offset changed");
static_assert(offsetof(ExecArgvEvent, argv) == 24, "ExecArgvEvent::argv offset changed");

} // namespace aegis
