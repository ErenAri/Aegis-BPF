# AegisBPF Network Layer Design

Status: Reference design for the shipped network layer plus future extensions.

Current implementation ships exact IP, CIDR, port, and IP:port deny rules. Bloom-filter fast paths in this document are not implemented today.

## Executive Summary

This document specifies the architecture for adding network monitoring and enforcement capabilities to AegisBPF. The design extends the existing file access control framework to provide egress/ingress network policy enforcement using LSM socket hooks, maintaining consistency with existing patterns while adding network-specific functionality.

---

## 1. Architecture Overview

### 1.1 High-Level Design

```
+-------------------------------------------------------------------------+
|                        USER SPACE (aegisbpf daemon)                     |
+-------------------------------------------------------------------------+
|  CLI Parser  |  Policy Mgr  |  Event Handler  |  Metrics  |  Network   |
|              |  (extended)  |  (extended)     |  Exporter |  Manager   |
+------------------------------+------------------------------------------+
                               | libbpf
                               |
          +--------------------+--------------------+
          |                                         |
+---------+--------------------+  +----------------+---------------------+
|  BPF Maps (existing+new)     |  |  BPF Programs (existing+new)         |
|  (pinned in bpffs)           |  |  (kernel space)                      |
+------------------------------+  +--------------------------------------+
| [EXISTING]                   |  | [EXISTING]                           |
| deny_inode                   |  | LSM: file_open                       |
| deny_path                    |  | LSM: inode_permission                |
| allow_cgroup                 |  | TP: sys_enter_openat                 |
| events (ringbuf)             |  | TP: sched_*                          |
| block_stats                  |  |                                      |
| ...                          |  | [NEW - NETWORK]                      |
|                              |  | LSM: socket_connect                  |
| [NEW - NETWORK]              |  | LSM: socket_bind                     |
| deny_ipv4                    |  | LSM: socket_listen                   |
| deny_ipv6                    |  | LSM: socket_sendmsg (optional)       |
| deny_port                    |  |                                      |
| deny_cidr_v4                 |  |                                      |
| deny_cidr_v6                 |  |                                      |
| net_block_stats              |  |                                      |
| net_conn_stats               |  |                                      |
+------------------------------+  +--------------------------------------+
```

### 1.2 Design Principles

1. **Consistency**: Mirror existing file access patterns (deny maps, cgroup allowlist, audit/enforce modes)
2. **Minimal Overhead**: Use efficient map structures (LPM trie for CIDR, bloom filter for fast-path rejection)
3. **Fail-Safe**: Network enforcement respects break-glass mode and deadman switch
4. **Incremental**: Network layer is optional - file-only deployments remain supported
5. **Observable**: Full event visibility with Prometheus metrics integration

---

## 2. BPF Program Design

### 2.1 New LSM Hooks

#### 2.1.1 `socket_connect` - Egress Control

```c
SEC("lsm/socket_connect")
int BPF_PROG(aegis_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
```

**Purpose**: Control outbound connections (TCP connect, UDP sendto with destination)

**Decision Flow**:
```
1. Extract address family (AF_INET/AF_INET6)
2. Extract destination IP and port
3. Check cgroup allowlist → ALLOW if matched
4. Check deny_port map → DENY if matched
5. Check deny_ipv4/ipv6 exact match → DENY if matched
6. Check deny_cidr_v4/v6 LPM trie → DENY if matched
7. DEFAULT: ALLOW
```

#### 2.1.2 `socket_bind` - Service Exposure Control

```c
SEC("lsm/socket_bind")
int BPF_PROG(aegis_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
```

**Purpose**: Control which ports/addresses processes can bind to

**Use Cases**:
- Prevent unauthorized services from starting
- Restrict bind addresses (e.g., block 0.0.0.0 binds)

#### 2.1.3 `socket_listen` - Server Control (Optional)

```c
SEC("lsm/socket_listen")
int BPF_PROG(aegis_socket_listen, struct socket *sock, int backlog)
```

**Purpose**: Additional control point for server sockets

### 2.2 Event Types

Extend `enum event_type`:

```c
enum event_type {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2,
    // New network events
    EVENT_NET_CONNECT_BLOCK = 10,
    EVENT_NET_BIND_BLOCK = 11,
    EVENT_NET_LISTEN_BLOCK = 12,
};
```

### 2.3 Network Event Structure

```c
struct net_block_event {
    // Process context (same as file events)
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
    __u64 cgid;
    char comm[16];

    // Network specific
    __u8 family;        // AF_INET or AF_INET6
    __u8 protocol;      // IPPROTO_TCP, IPPROTO_UDP
    __u16 local_port;
    __u16 remote_port;
    __u8 direction;     // 0=egress, 1=ingress/bind
    __u8 _pad;

    union {
        __be32 ipv4;
        __u8 ipv6[16];
    } local_addr;

    union {
        __be32 ipv4;
        __u8 ipv6[16];
    } remote_addr;

    char action[8];     // "AUDIT" or "KILL"
    char rule_type[16]; // "ip", "port", "cidr"
};
```

---

## 3. BPF Map Design

### 3.1 New Maps

#### 3.1.1 IPv4 Deny Map (Exact Match)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);           // IPv4 address
    __type(value, __u8);           // flags (reserved)
} deny_ipv4 SEC(".maps");
```

#### 3.1.2 IPv6 Deny Map (Exact Match)

```c
struct ipv6_key {
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, __u8);
} deny_ipv6 SEC(".maps");
```

#### 3.1.3 IPv4 CIDR Deny Map (LPM Trie)

```c
struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} deny_cidr_v4 SEC(".maps");
```

#### 3.1.4 IPv6 CIDR Deny Map (LPM Trie)

```c
struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
} deny_cidr_v6 SEC(".maps");
```

#### 3.1.5 Port Deny Map

```c
struct port_key {
    __u16 port;
    __u8 protocol;  // IPPROTO_TCP=6, IPPROTO_UDP=17, 0=any
    __u8 direction; // 0=egress, 1=bind, 2=both
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct port_key);
    __type(value, __u8);
} deny_port SEC(".maps");
```

#### 3.1.6 IP:Port Combo Deny Map

```c
struct ip_port_key_v4 {
    __be32 addr;
    __u16 port;
    __u8 protocol;
    __u8 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct ip_port_key_v4);
    __type(value, __u8);
} deny_ip_port_v4 SEC(".maps");
```

#### 3.1.7 Network Statistics Maps

```c
// Per-IP block counts
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, __be32);  // IPv4
    __type(value, __u64);
} net_ip_stats SEC(".maps");

// Per-port block counts
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, __u64);
} net_port_stats SEC(".maps");

// Global network block stats
struct net_stats_entry {
    __u64 connect_blocks;
    __u64 bind_blocks;
    __u64 listen_blocks;
    __u64 ringbuf_drops;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_stats_entry);
} net_block_stats SEC(".maps");
```

### 3.2 Map Pinning Paths

```c
// New pin paths in types.hpp
inline constexpr const char* kDenyIpv4Pin = "/sys/fs/bpf/aegisbpf/deny_ipv4";
inline constexpr const char* kDenyIpv6Pin = "/sys/fs/bpf/aegisbpf/deny_ipv6";
inline constexpr const char* kDenyCidrV4Pin = "/sys/fs/bpf/aegisbpf/deny_cidr_v4";
inline constexpr const char* kDenyCidrV6Pin = "/sys/fs/bpf/aegisbpf/deny_cidr_v6";
inline constexpr const char* kDenyPortPin = "/sys/fs/bpf/aegisbpf/deny_port";
inline constexpr const char* kDenyIpPortV4Pin = "/sys/fs/bpf/aegisbpf/deny_ip_port_v4";
inline constexpr const char* kNetBlockStatsPin = "/sys/fs/bpf/aegisbpf/net_block_stats";
inline constexpr const char* kNetIpStatsPin = "/sys/fs/bpf/aegisbpf/net_ip_stats";
inline constexpr const char* kNetPortStatsPin = "/sys/fs/bpf/aegisbpf/net_port_stats";
```

---

## 4. Policy Schema Extension

### 4.1 Extended Policy Format

```ini
version=2

[deny_path]
/etc/shadow
/etc/passwd

[deny_inode]
8388609:131073

[allow_cgroup]
/sys/fs/cgroup/system.slice/docker.service

# ===== NEW NETWORK SECTIONS =====

[deny_ip]
# Single IPs
192.168.1.100
10.0.0.1
2001:db8::1

[deny_cidr]
# CIDR ranges
10.0.0.0/8
192.168.0.0/16
2001:db8::/32

[deny_port]
# port[:protocol[:direction]]
# protocol: tcp, udp, any (default: any)
# direction: egress, bind, both (default: both)
22
3389:tcp:egress
53:udp:egress

[deny_ip_port]
# ip:port[:protocol]
192.168.1.1:443
10.0.0.1:22:tcp

[allow_egress]
# Explicit egress allowlist (if deny-by-default mode)
# Only consulted if network_default=deny
8.8.8.8:53:udp
1.1.1.1:53:udp
```

### 4.2 Policy Struct Extension

```cpp
// In types.hpp
struct NetworkPolicy {
    std::vector<std::string> deny_ips;          // Exact IPs
    std::vector<std::string> deny_cidrs;        // CIDR ranges
    std::vector<PortRule> deny_ports;           // Port rules
    std::vector<IpPortRule> deny_ip_ports;      // IP:port combos
    std::vector<std::string> allow_egress;      // Allowlist (optional)
    bool network_enabled = false;
    bool default_deny_egress = false;           // Future: deny-by-default mode
};

struct PortRule {
    uint16_t port;
    uint8_t protocol;    // 0=any, 6=tcp, 17=udp
    uint8_t direction;   // 0=egress, 1=bind, 2=both
};

struct IpPortRule {
    std::string ip;
    uint16_t port;
    uint8_t protocol;
};

struct Policy {
    int version = 0;
    // Existing file rules
    std::vector<std::string> deny_paths;
    std::vector<InodeId> deny_inodes;
    std::vector<std::string> allow_cgroup_paths;
    std::vector<uint64_t> allow_cgroup_ids;
    // New network rules
    NetworkPolicy network;
};
```

---

## 5. User Space Components

### 5.1 CLI Extensions

```bash
# Network deny management
aegisbpf network deny add --ip 192.168.1.100
aegisbpf network deny add --cidr 10.0.0.0/8
aegisbpf network deny add --port 22 --protocol tcp --direction egress
aegisbpf network deny add --ip-port 192.168.1.1:443
aegisbpf network deny del --ip 192.168.1.100
aegisbpf network deny list
aegisbpf network deny clear

# Network statistics
aegisbpf network stats
aegisbpf network stats --by-ip
aegisbpf network stats --by-port

# Combined status
aegisbpf stats --all  # File + network stats
```

### 5.2 New Source Files

```
src/
+-- network_ops.hpp      # Network BPF map operations
+-- network_ops.cpp
+-- network_policy.hpp   # Network policy parsing
+-- network_policy.cpp
+-- network_events.hpp   # Network event handling
+-- network_events.cpp
+-- network_types.hpp    # Network-specific types
```

### 5.3 BpfState Extension

```cpp
class BpfState {
public:
    // Existing...

    // New network maps
    bpf_map* deny_ipv4 = nullptr;
    bpf_map* deny_ipv6 = nullptr;
    bpf_map* deny_cidr_v4 = nullptr;
    bpf_map* deny_cidr_v6 = nullptr;
    bpf_map* deny_port = nullptr;
    bpf_map* deny_ip_port_v4 = nullptr;
    bpf_map* net_block_stats = nullptr;
    bpf_map* net_ip_stats = nullptr;
    bpf_map* net_port_stats = nullptr;

    // Reuse flags
    bool deny_ipv4_reused = false;
    bool deny_ipv6_reused = false;
    // ... etc
};
```

### 5.4 Event Handler Extension

```cpp
// In events.cpp
void print_net_block_event(const NetBlockEvent& ev) {
    std::ostringstream oss;
    oss << "{\"type\":\"net_block\""
        << ",\"pid\":" << ev.pid
        << ",\"ppid\":" << ev.ppid
        << ",\"cgid\":" << ev.cgid
        << ",\"family\":\"" << (ev.family == AF_INET ? "ipv4" : "ipv6") << "\""
        << ",\"protocol\":\"" << protocol_name(ev.protocol) << "\""
        << ",\"remote_ip\":\"" << format_ip(ev) << "\""
        << ",\"remote_port\":" << ntohs(ev.remote_port)
        << ",\"direction\":\"" << (ev.direction ? "bind" : "egress") << "\""
        << ",\"action\":\"" << ev.action << "\""
        << ",\"rule_type\":\"" << ev.rule_type << "\""
        << ",\"comm\":\"" << json_escape(ev.comm) << "\"}";
    // ... output to stdout/journald
}
```

---

## 6. Prometheus Metrics Extension

```cpp
// New metrics
aegisbpf_net_blocks_total{type="connect"}
aegisbpf_net_blocks_total{type="bind"}
aegisbpf_net_blocks_by_ip_total{ip="192.168.1.100"}
aegisbpf_net_blocks_by_port_total{port="22"}
aegisbpf_net_ringbuf_drops_total
aegisbpf_net_rules_total{type="ip"}
aegisbpf_net_rules_total{type="cidr"}
aegisbpf_net_rules_total{type="port"}
```

---

## 7. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Add network event types and structures to BPF code
- [ ] Implement `deny_ipv4`, `deny_port` maps
- [ ] Implement `socket_connect` LSM hook (IPv4 only)
- [ ] Add basic userspace event handling
- [ ] Unit tests for map operations

### Phase 2: Full IPv4 Support (Week 2-3)
- [ ] Implement CIDR matching with LPM trie
- [ ] Implement `socket_bind` hook
- [ ] Add policy parser extensions
- [ ] CLI commands for network rules
- [ ] Integration tests

### Phase 3: IPv6 Support (Week 3-4)
- [ ] Add IPv6 maps and hook logic
- [ ] Test dual-stack scenarios
- [ ] Performance benchmarking

### Phase 4: Production Hardening (Week 4-5)
- [ ] Prometheus metrics integration
- [ ] Journald event logging
- [ ] Documentation
- [ ] Helm chart updates
- [ ] Load testing

---

## 8. Performance Considerations

### 8.1 Hot Path Optimization

```c
// Fast-path check order in socket_connect:
// 1. Cgroup allowlist (HASH lookup) - skip if trusted
// 2. Bloom filter for IPs (optional, reduces false lookups)
// 3. Exact IP match (HASH)
// 4. Port match (HASH)
// 5. CIDR match (LPM) - most expensive, do last
```

### 8.2 Expected Performance

| Operation | Latency |
|-----------|---------|
| Cgroup allowlist check | ~50-100ns |
| Exact IP lookup | ~50-150ns |
| Port lookup | ~50-100ns |
| CIDR LPM lookup | ~200-500ns |
| **Total (worst case)** | **~500-900ns** |

### 8.3 Map Sizing Guidelines

| Map | Max Entries | Memory |
|-----|-------------|--------|
| deny_ipv4 | 65,536 | ~512KB |
| deny_ipv6 | 65,536 | ~1.5MB |
| deny_cidr_v4 | 16,384 | ~256KB |
| deny_cidr_v6 | 16,384 | ~512KB |
| deny_port | 4,096 | ~32KB |

---

## 9. Testing Strategy

### 9.1 Unit Tests
- Map operation correctness
- Policy parsing (valid/invalid inputs)
- IP/CIDR parsing utilities

### 9.2 Integration Tests
```bash
# Test egress blocking
aegisbpf network deny add --ip 1.2.3.4
curl -m 1 http://1.2.3.4  # Should fail/timeout

# Test port blocking
aegisbpf network deny add --port 8080 --direction egress
curl -m 1 http://localhost:8080  # Should fail

# Test cgroup bypass
aegisbpf allow add /sys/fs/cgroup/trusted.slice
# Process in trusted.slice should connect despite rules
```

### 9.3 Performance Tests
- Connection rate with rules loaded
- Latency impact measurement
- Memory usage under load

---

## 10. Security Considerations

### 10.1 Bypass Prevention
- DNS bypass: Consider optional DNS query monitoring
- Localhost: Decide on loopback policy (default: allow)
- IPv4-mapped IPv6: Handle `::ffff:` addresses

### 10.2 Fail-Safe Behavior
- Break-glass mode disables network enforcement
- Deadman switch reverts to audit mode
- Survival allowlist doesn't apply to network (no "critical IPs")

---

## 11. Future Extensions

1. **DNS Monitoring**: Track DNS queries for domain-based rules
2. **Connection Tracking**: Stateful connection monitoring
3. **Bandwidth Limits**: Rate limiting per process/cgroup
4. **Network Namespaces**: Container-aware policies
5. **Default-Deny Mode**: Explicit allowlist for egress

---

## Appendix A: Complete BPF Hook Implementation

```c
// bpf/aegis_net.bpf.c (new file or merged into aegis.bpf.c)

SEC("lsm/socket_connect")
int BPF_PROG(aegis_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!address)
        return 0;

    __u16 family = address->sa_family;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (is_cgroup_allowed(cgid))
        return 0;

    __u8 audit = get_effective_audit_mode();
    __be32 ipv4 = 0;
    __u16 port = 0;

    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        ipv4 = BPF_CORE_READ(sin, sin_addr.s_addr);
        port = BPF_CORE_READ(sin, sin_port);

        // Check exact IP
        if (bpf_map_lookup_elem(&deny_ipv4, &ipv4))
            goto deny;

        // Check CIDR
        struct ipv4_lpm_key lpm_key = {
            .prefixlen = 32,
            .addr = ipv4
        };
        if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key))
            goto deny;
    }

    // Check port
    struct port_key pk = {
        .port = bpf_ntohs(port),
        .protocol = 0,  // any
        .direction = 0  // egress
    };
    if (bpf_map_lookup_elem(&deny_port, &pk))
        goto deny;

    return 0;

deny:
    increment_net_connect_stats();
    emit_net_block_event(cgid, family, ipv4, port, audit);

    if (!audit)
        bpf_send_signal(SIGKILL);

    return audit ? 0 : -EPERM;
}
```

---

## Appendix B: Migration Path

For existing deployments:

1. **Policy version bump**: `version=2` indicates network support
2. **Backward compatible**: `version=1` policies work unchanged
3. **Optional activation**: Network hooks only attach if policy has network rules
4. **Gradual rollout**: Start with `--network-audit-only` flag
