# AegisBPF API Reference

This document provides a comprehensive reference for the AegisBPF internal APIs, data structures, and BPF maps.

## Table of Contents

- [Core Types](#core-types)
- [Error Handling](#error-handling)
- [BPF Operations](#bpf-operations)
- [Policy Management](#policy-management)
- [Network Operations](#network-operations)
- [Cryptographic Operations](#cryptographic-operations)
- [BPF Maps Reference](#bpf-maps-reference)
- [Event Types](#event-types)
- [Configuration](#configuration)
- [File System Paths](#file-system-paths)

---

## Core Types

### InodeId

Uniquely identifies a file by device and inode number.

```cpp
struct InodeId {
    uint64_t ino;   // Inode number
    uint32_t dev;   // Encoded device number
    uint32_t pad;   // Alignment padding
};
```

**Usage:**
```cpp
InodeId id{};
id.ino = st.st_ino;
id.dev = encode_dev(st.st_dev);  // Use encode_dev() for proper encoding
```

### PathKey

Fixed-size path buffer for BPF map keys.

```cpp
struct PathKey {
    char path[kDenyPathMax];  // kDenyPathMax = 256
};
```

### Policy

Represents a parsed policy file.

```cpp
struct Policy {
    int version;                              // Policy format version (1 or 2)
    std::vector<std::string> deny_paths;      // Paths to block
    std::vector<InodeId> deny_inodes;         // Inodes to block (dev:ino)
    std::vector<std::string> allow_cgroup_paths;  // Allowed cgroup paths
    std::vector<uint64_t> allow_cgroup_ids;   // Allowed cgroup IDs
    NetworkPolicy network;                    // Network rules (version 2)
};
```

### NetworkPolicy

Network blocking rules.

```cpp
struct NetworkPolicy {
    std::vector<std::string> deny_ips;     // IPv4/IPv6 addresses
    std::vector<std::string> deny_cidrs;   // CIDR ranges (e.g., "10.0.0.0/8")
    std::vector<PortRule> deny_ports;      // Port rules
    bool enabled = false;                  // Auto-set when rules added
};
```

### PortRule

Port-based blocking rule.

```cpp
struct PortRule {
    uint16_t port;       // Port number (1-65535)
    uint8_t protocol;    // 0=any, 6=tcp, 17=udp
    uint8_t direction;   // 0=egress, 1=bind, 2=both
};
```

### AgentConfig

Runtime configuration for the BPF agent.

```cpp
struct AgentConfig {
    uint8_t audit_only;              // 1 = audit mode (no blocking)
    uint8_t deadman_enabled;         // 1 = deadman switch active
    uint8_t break_glass_active;      // 1 = break-glass override
    uint8_t enforce_signal;          // Signal: 0=none, 2=INT, 9=KILL, 15=TERM
    uint64_t deadman_deadline_ns;    // Deadline (CLOCK_BOOTTIME ns)
    uint32_t deadman_ttl_seconds;    // TTL for heartbeat refresh
    uint32_t event_sample_rate;      // 1 = all events, N = 1/N sampling
    uint32_t sigkill_escalation_threshold;      // Strikes before SIGKILL
    uint32_t sigkill_escalation_window_seconds; // Window for counting strikes
};
```

### SignedPolicyBundle

Cryptographically signed policy bundle.

```cpp
struct SignedPolicyBundle {
    uint32_t format_version;              // Bundle format (currently 1)
    uint64_t policy_version;              // Monotonic counter (anti-rollback)
    uint64_t timestamp;                   // Creation time (Unix epoch)
    uint64_t expires;                     // Expiration time (0 = never)
    std::array<uint8_t, 32> signer_key;   // Ed25519 public key
    std::array<uint8_t, 64> signature;    // Ed25519 signature
    std::string policy_sha256;            // SHA256 of policy_content
    std::string policy_content;           // Raw policy INI content
};
```

---

## Error Handling

### ErrorCode Enumeration

```cpp
enum class ErrorCode {
    // General
    Success = 0,
    Unknown,
    InvalidArgument,

    // System
    PermissionDenied,
    ResourceNotFound,
    ResourceBusy,
    IoError,

    // BPF
    BpfLoadFailed,
    BpfAttachFailed,
    BpfMapOperationFailed,
    BpfPinFailed,

    // Policy
    PolicyParseFailed,
    PolicyVersionMismatch,
    PolicyHashMismatch,
    PolicyApplyFailed,

    // Path
    PathNotFound,
    PathResolutionFailed,
    PathTooLong,

    // Configuration
    ConfigInvalid,
    LayoutVersionMismatch,

    // Crypto
    CryptoError,
    SignatureInvalid,
    IntegrityCheckFailed,
    PolicyExpired,
    PolicyRollback,
};
```

### Result<T> Template

Monadic error handling type.

```cpp
template <typename T>
class Result {
public:
    // Check success
    bool ok() const;
    explicit operator bool() const;

    // Access value (UB if !ok())
    T& value();
    T& operator*();
    T* operator->();

    // Access error (UB if ok())
    Error& error();

    // Get value or default
    T value_or(T default_value) const;

    // Transform success value
    template <typename F>
    auto map(F&& f) -> Result<decltype(f(std::declval<T>()))>;
};

// Specialization for void
template <>
class Result<void> {
public:
    bool ok() const;
    explicit operator bool() const;
    Error& error();
};
```

### Error Class

```cpp
class Error {
public:
    Error(ErrorCode code, std::string message);
    Error(ErrorCode code, std::string message, std::string context);

    ErrorCode code() const;
    const std::string& message() const;
    const std::string& context() const;
    std::string to_string() const;

    // Factory methods
    static Error system(int errno_val, const std::string& operation);
    static Error not_found(const std::string& what);
    static Error invalid_argument(const std::string& what);
    static Error bpf_error(int err, const std::string& operation);
};
```

### TRY Macro

Early return on error.

```cpp
#define TRY(expr) \
    do { \
        auto _result = (expr); \
        if (!_result) return _result.error(); \
    } while (0)

// Usage:
Result<void> apply_policy(const std::string& path) {
    auto policy = TRY(parse_policy_file(path, issues));
    TRY(add_deny_path(state, policy.deny_paths[0], entries));
    return {};
}
```

---

## BPF Operations

### BpfState Structure

Holds all BPF state (object, maps, links).

```cpp
struct BpfState {
    bpf_object* obj = nullptr;
    std::vector<bpf_link*> links;

    // Core maps
    bpf_map* events = nullptr;
    bpf_map* deny_inode = nullptr;
    bpf_map* deny_path = nullptr;
    bpf_map* allow_cgroup = nullptr;
    bpf_map* block_stats = nullptr;
    bpf_map* deny_cgroup_stats = nullptr;
    bpf_map* deny_inode_stats = nullptr;
    bpf_map* deny_path_stats = nullptr;
    bpf_map* agent_meta = nullptr;
    bpf_map* config_map = nullptr;
    bpf_map* survival_allowlist = nullptr;

    // Network maps
    bpf_map* deny_ipv4 = nullptr;
    bpf_map* deny_ipv6 = nullptr;
    bpf_map* deny_port = nullptr;
    bpf_map* deny_cidr_v4 = nullptr;
    bpf_map* deny_cidr_v6 = nullptr;
    bpf_map* net_block_stats = nullptr;
    bpf_map* net_ip_stats = nullptr;
    bpf_map* net_port_stats = nullptr;

    // Reuse flags (true if map was reused from pin)
    bool inode_reused = false;
    bool deny_path_reused = false;
    // ... (additional reuse flags)

    void cleanup();  // RAII cleanup
};
```

### Core Functions

#### load_bpf

Load BPF object and optionally reuse pinned maps.

```cpp
Result<void> load_bpf(bool reuse_pins, bool attach_links, BpfState& state);
```

**Parameters:**
- `reuse_pins`: If true, attempt to reuse existing pinned maps
- `attach_links`: If true, attach programs after loading
- `state`: Output BpfState (caller owns)

**Returns:** Success or Error

#### attach_all

Attach BPF programs to hooks.

```cpp
Result<void> attach_all(BpfState& state, bool lsm_enabled,
                        bool use_inode_permission, bool use_file_open);
```

**Parameters:**
- `state`: Loaded BPF state
- `lsm_enabled`: Whether BPF LSM is available
- `use_inode_permission`: Attach `inode_permission` LSM hook
- `use_file_open`: Attach `file_open` LSM hook

#### add_deny_path

Add a file path to the deny list.

```cpp
Result<void> add_deny_path(BpfState& state, const std::string& path,
                           DenyEntries& entries);
```

**Behavior:**
1. Validates path (no null bytes, length check)
2. Resolves symlinks via `std::filesystem::canonical()`
3. Stats the file to get inode
4. Adds both inode and path to respective maps
5. Updates the entries cache

#### add_deny_inode

Add an inode directly to the deny list.

```cpp
Result<void> add_deny_inode(BpfState& state, const InodeId& id,
                            DenyEntries& entries);
```

#### add_allow_cgroup

Allow a cgroup to bypass deny rules.

```cpp
Result<void> add_allow_cgroup(BpfState& state, uint64_t cgid);
Result<void> add_allow_cgroup_path(BpfState& state, const std::string& path);
```

#### set_agent_config_full

Configure the BPF agent runtime parameters.

```cpp
Result<void> set_agent_config_full(BpfState& state, const AgentConfig& config);
```

#### populate_survival_allowlist

Populate the survival allowlist with critical system binaries.

```cpp
Result<void> populate_survival_allowlist(BpfState& state);
```

**Protected binaries include:**
- `/sbin/init`, `/lib/systemd/systemd`
- `/usr/bin/kubelet`, `/usr/bin/containerd`
- `/usr/sbin/sshd`, `/bin/bash`, `/bin/sh`
- Package managers: `apt`, `dpkg`, `yum`, `dnf`, `rpm`

### Statistics Functions

#### read_block_stats_map

Read global block statistics.

```cpp
Result<BlockStats> read_block_stats_map(bpf_map* map);

struct BlockStats {
    uint64_t blocks;        // Total blocked operations
    uint64_t ringbuf_drops; // Events dropped due to buffer overflow
};
```

#### read_cgroup_block_counts

Read per-cgroup block counts.

```cpp
Result<std::vector<std::pair<uint64_t, uint64_t>>>
read_cgroup_block_counts(bpf_map* map);
// Returns: [(cgroup_id, block_count), ...]
```

#### read_inode_block_counts

Read per-inode block counts.

```cpp
Result<std::vector<std::pair<InodeId, uint64_t>>>
read_inode_block_counts(bpf_map* map);
```

---

## Policy Management

### parse_policy_file

Parse a policy file in INI format.

```cpp
Result<Policy> parse_policy_file(const std::string& path, PolicyIssues& issues);
```

**Policy File Format:**
```ini
version=1

[deny_path]
/usr/bin/malware
/opt/blocked/binary

[deny_inode]
259:12345
259:67890

[allow_cgroup]
/sys/fs/cgroup/system.slice
cgid:123456789

# Version 2 only:
[deny_ip]
192.168.1.100
2001:db8::1

[deny_cidr]
10.0.0.0/8
fd00::/8

[deny_port]
22:tcp:bind
443:tcp:egress
53:any:both
```

### policy_apply

Apply a policy file with optional integrity verification.

```cpp
Result<void> policy_apply(const std::string& path, bool reset,
                          const std::string& cli_hash,
                          const std::string& cli_hash_file,
                          bool rollback_on_failure);
```

**Parameters:**
- `path`: Policy file path
- `reset`: If true, clear existing rules before applying
- `cli_hash`: Expected SHA256 (hex string)
- `cli_hash_file`: Path to file containing expected SHA256
- `rollback_on_failure`: If true, rollback to previous policy on error

### policy_rollback

Rollback to the previously applied policy.

```cpp
Result<void> policy_rollback();
```

### policy_export

Export current rules to a policy file.

```cpp
Result<void> policy_export(const std::string& path);
```

---

## Network Operations

### IP Address Functions

```cpp
// Parse IPv4 address to network byte order
bool parse_ipv4(const std::string& ip_str, uint32_t& ip_be);

// Parse IPv6 address
bool parse_ipv6(const std::string& ip_str, Ipv6Key& ip);

// Parse CIDR notation
bool parse_cidr_v4(const std::string& cidr_str, uint32_t& ip_be, uint8_t& prefix_len);
bool parse_cidr_v6(const std::string& cidr_str, Ipv6Key& ip, uint8_t& prefix_len);

// Format addresses for display
std::string format_ipv4(uint32_t ip_be);
std::string format_ipv6(const Ipv6Key& ip);
```

### Network Deny Functions

```cpp
// Add/remove IP addresses
Result<void> add_deny_ip(BpfState& state, const std::string& ip);
Result<void> del_deny_ip(BpfState& state, const std::string& ip);

// Add/remove CIDR ranges
Result<void> add_deny_cidr(BpfState& state, const std::string& cidr);
Result<void> del_deny_cidr(BpfState& state, const std::string& cidr);

// Add/remove port rules
Result<void> add_deny_port(BpfState& state, uint16_t port,
                           uint8_t protocol, uint8_t direction);
Result<void> del_deny_port(BpfState& state, uint16_t port,
                           uint8_t protocol, uint8_t direction);

// List current rules
Result<std::vector<uint32_t>> list_deny_ipv4(BpfState& state);
Result<std::vector<Ipv6Key>> list_deny_ipv6(BpfState& state);
Result<std::vector<PortKey>> list_deny_ports(BpfState& state);
```

### Network Statistics

```cpp
Result<NetBlockStats> read_net_block_stats(BpfState& state);

struct NetBlockStats {
    uint64_t connect_blocks;  // Blocked outgoing connections
    uint64_t bind_blocks;     // Blocked bind operations
    uint64_t ringbuf_drops;   // Dropped events
};

Result<std::vector<std::pair<std::string, uint64_t>>>
read_net_ip_stats(BpfState& state);

Result<std::vector<std::pair<uint16_t, uint64_t>>>
read_net_port_stats(BpfState& state);
```

---

## Cryptographic Operations

### Key Types

```cpp
using PublicKey = std::array<uint8_t, 32>;   // Ed25519 public key
using SecretKey = std::array<uint8_t, 64>;   // Ed25519 secret key
using Signature = std::array<uint8_t, 64>;   // Ed25519 signature
```

### Key Generation

```cpp
Result<std::pair<PublicKey, SecretKey>> generate_keypair();
```

### Signing

```cpp
Result<Signature> sign_message(const std::string& message,
                               const SecretKey& secret_key);
Result<Signature> sign_bytes(const uint8_t* data, size_t data_len,
                             const SecretKey& secret_key);
```

### Verification

```cpp
bool verify_signature(const std::string& message,
                      const Signature& signature,
                      const PublicKey& public_key);
bool verify_bytes(const uint8_t* data, size_t data_len,
                  const Signature& signature,
                  const PublicKey& public_key);
```

### Bundle Operations

```cpp
// Parse a signed bundle from file content
Result<SignedPolicyBundle> parse_signed_bundle(const std::string& content);

// Create a signed bundle
Result<std::string> create_signed_bundle(const std::string& policy_content,
                                         const SecretKey& secret_key,
                                         uint64_t policy_version,
                                         uint64_t expires);

// Verify bundle against trusted keys
Result<void> verify_bundle(const SignedPolicyBundle& bundle,
                           const std::vector<PublicKey>& trusted_keys);

// Load trusted keys from /etc/aegisbpf/keys/*.pub
Result<std::vector<PublicKey>> load_trusted_keys();
```

### Anti-Rollback

```cpp
uint64_t read_version_counter();
Result<void> write_version_counter(uint64_t version);
bool check_version_acceptable(const SignedPolicyBundle& bundle);
```

---

## BPF Maps Reference

### File Blocking Maps

| Map Name | Type | Key | Value | Max Entries |
|----------|------|-----|-------|-------------|
| `deny_inode_map` | HASH | `InodeId` | `u8` | 65,536 |
| `deny_path_map` | HASH | `PathKey` | `u8` | 16,384 |
| `allow_cgroup_map` | HASH | `u64` (cgid) | `u8` | 1,024 |
| `survival_allowlist` | HASH | `InodeId` | `u8` | 256 |
| `deny_bloom` | BLOOM_FILTER | - | `u64` | 16,384 |

### Network Maps

| Map Name | Type | Key | Value | Max Entries |
|----------|------|-----|-------|-------------|
| `deny_ipv4` | HASH | `__be32` | `u8` | 65,536 |
| `deny_ipv6` | HASH | `Ipv6Key` | `u8` | 65,536 |
| `deny_port` | HASH | `PortKey` | `u8` | 4,096 |
| `deny_cidr_v4` | LPM_TRIE | `Ipv4LpmKey` | `u8` | 16,384 |
| `deny_cidr_v6` | LPM_TRIE | `Ipv6LpmKey` | `u8` | 16,384 |

### Statistics Maps

| Map Name | Type | Key | Value | Max Entries |
|----------|------|-----|-------|-------------|
| `block_stats` | PERCPU_ARRAY | `u32` (0) | `BlockStats` | 1 |
| `deny_cgroup_stats` | PERCPU_HASH | `u64` (cgid) | `u64` | 4,096 |
| `deny_inode_stats` | PERCPU_HASH | `InodeId` | `u64` | 65,536 |
| `deny_path_stats` | PERCPU_HASH | `PathKey` | `u64` | 16,384 |
| `net_block_stats` | PERCPU_ARRAY | `u32` (0) | `NetBlockStats` | 1 |
| `net_ip_stats` | PERCPU_HASH | `NetIpKey` | `u64` | 16,384 |
| `net_port_stats` | PERCPU_HASH | `u16` | `u64` | 4,096 |

### Configuration Maps

| Map Name | Type | Key | Value | Max Entries |
|----------|------|-----|-------|-------------|
| `agent_config_map` | ARRAY | `u32` (0) | `AgentConfig` | 1 |
| `agent_meta_map` | ARRAY | `u32` (0) | `AgentMeta` | 1 |
| `events` | RINGBUF | - | `Event` | 16 MB |

---

## Event Types

### EventType Enumeration

```cpp
enum EventType : uint32_t {
    EVENT_EXEC = 1,              // Process execution
    EVENT_BLOCK = 2,             // File access blocked
    EVENT_NET_CONNECT_BLOCK = 10, // Network connect blocked
    EVENT_NET_BIND_BLOCK = 11,    // Network bind blocked
};
```

### Event Structures

#### ExecEvent

```cpp
struct ExecEvent {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;  // Process start time (ns)
    uint64_t cgid;        // Cgroup ID
    char comm[16];        // Command name
};
```

#### BlockEvent

```cpp
struct BlockEvent {
    uint32_t ppid;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint32_t pid;
    uint64_t cgid;
    char comm[16];
    uint64_t ino;              // Blocked inode
    uint32_t dev;              // Device number
    char path[256];            // Path (if available)
    char action[8];            // "AUDIT", "BLOCK", "TERM", "KILL"
};
```

#### NetBlockEvent

```cpp
struct NetBlockEvent {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint64_t cgid;
    char comm[16];
    uint8_t family;         // AF_INET=2, AF_INET6=10
    uint8_t protocol;       // IPPROTO_TCP=6, IPPROTO_UDP=17
    uint16_t local_port;    // For bind events
    uint16_t remote_port;   // For connect events
    uint8_t direction;      // 0=egress, 1=bind
    uint8_t _pad;
    uint32_t remote_ipv4;   // Network byte order
    uint8_t remote_ipv6[16];
    char action[8];         // "AUDIT", "BLOCK", "TERM", "KILL"
    char rule_type[16];     // "ip", "port", "cidr"
};
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AEGIS_BPF_OBJ` | Path to BPF object file | Auto-detected |
| `AEGIS_KEYS_DIR` | Directory for trusted keys | `/etc/aegisbpf/keys` |
| `AEGIS_SKIP_BPF_VERIFY` | Skip BPF integrity check | `0` |
| `AEGIS_POLICY_SHA256` | Expected policy hash | - |
| `AEGIS_POLICY_SHA256_FILE` | File containing policy hash | - |
| `AEGIS_VERSION_COUNTER_PATH` | Anti-rollback counter path | `/var/lib/aegisbpf/version_counter` |

### Signal Constants

```cpp
inline constexpr uint8_t kEnforceSignalNone = 0;   // No signal
inline constexpr uint8_t kEnforceSignalInt = 2;    // SIGINT
inline constexpr uint8_t kEnforceSignalKill = 9;   // SIGKILL (escalated)
inline constexpr uint8_t kEnforceSignalTerm = 15;  // SIGTERM (default)
```

### Default Values

```cpp
inline constexpr uint32_t kSigkillEscalationThresholdDefault = 5;
inline constexpr uint32_t kSigkillEscalationWindowSecondsDefault = 30;
inline constexpr size_t kDenyPathMax = 256;
inline constexpr uint32_t kLayoutVersion = 1;
```

---

## File System Paths

### BPF Pins

```
/sys/fs/bpf/aegisbpf/
├── deny_inode           # Inode deny map
├── deny_path            # Path deny map
├── allow_cgroup         # Cgroup allowlist
├── block_stats          # Global statistics
├── deny_cgroup_stats    # Per-cgroup stats
├── deny_inode_stats     # Per-inode stats
├── deny_path_stats      # Per-path stats
├── agent_meta           # Layout version
├── survival_allowlist   # Protected binaries
├── deny_ipv4            # IPv4 deny list
├── deny_ipv6            # IPv6 deny list
├── deny_port            # Port deny list
├── deny_cidr_v4         # IPv4 CIDR trie
├── deny_cidr_v6         # IPv6 CIDR trie
├── net_block_stats      # Network statistics
├── net_ip_stats         # Per-IP statistics
└── net_port_stats       # Per-port statistics
```

### Configuration Paths

```
/etc/aegisbpf/
├── keys/                # Trusted signing keys (*.pub)
├── policy.conf          # Default policy file
├── break_glass          # Break-glass trigger file
├── break_glass.token    # Break-glass token
└── aegis.bpf.sha256     # BPF object hash (override)

/var/lib/aegisbpf/
├── deny.db              # Persistent deny database
├── policy.applied       # Last applied policy
├── policy.applied.prev  # Previous policy (for rollback)
├── policy.applied.sha256# Hash of applied policy
├── version_counter      # Anti-rollback counter
└── break_glass          # Alternative break-glass location
```

### Installation Paths

```
/usr/bin/aegisbpf              # Main binary
/usr/lib/aegisbpf/aegis.bpf.o  # BPF object file
/usr/lib/aegisbpf/aegis.bpf.sha256  # BPF hash
/usr/lib/systemd/system/aegisbpf.service  # Systemd unit
```

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design overview
- [POLICY.md](POLICY.md) - Policy file format details
- [NETWORK_LAYER_DESIGN.md](NETWORK_LAYER_DESIGN.md) - Network blocking design
- [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) - Key rotation procedures
