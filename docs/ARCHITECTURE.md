# AegisBPF Architecture

This document describes the current internal architecture of AegisBPF, an
eBPF-based runtime security agent.

## Overview

AegisBPF uses eBPF to enforce file deny rules and selected network deny rules at
the kernel boundary. It uses BPF LSM hooks for enforce-capable kernels and
tracepoints for audit-only fallback when enforce-capable hooks are unavailable.

```
+-----------------------------------------------------------------+
|                        User Space                               |
|  +----------------------------------------------------------+   |
|  |                     aegisbpf daemon                      |   |
|  |  +---------+ +---------+ +---------+ +-----------------+ |   |
|  |  | Policy  | |  BPF    | | Event   | |    Metrics      | |   |
|  |  | Manager | |  Ops    | | Handler | |    (Prometheus) | |   |
|  |  +----+----+ +----+----+ +----+----+ +--------+--------+ |   |
|  |       |           |           |               |          |   |
|  |       |      +----+-----------+---------------+          |   |
|  |       |      |                                           |   |
|  |       |      v                                           |   |
|  |       |  +-------------------------------------------+   |   |
|  |       +->|            libbpf                         |   |   |
|  |          +-------------------------------------------+   |   |
|  +----------------------------------------------------------+   |
|                              |                                  |
|                              | bpf() syscall                    |
+------------------------------+----------------------------------+
|                        Kernel Space                             |
|                              |                                  |
|  +---------------------------+-------------------------------+  |
|  |                    BPF Subsystem                          |  |
|  |  +-------------+  +-------------+  +---------------------+|  |
|  |  | LSM Hooks   |  | Tracepoints |  |      BPF Maps       ||  |
|  |  | file_open   |  | sched_exec  |  |  +---------------+  ||  |
|  |  | inode_perm  |  | openat      |  |  | deny_inode    |  ||  |
|  |  | connect     |  | fork / exit |  |  | deny_path     |  ||  |
|  |  | bind/listen |  |             |  |  | net_* maps    |  ||  |
|  |  | accept/send |  |             |  |  | allow_* maps  |  ||  |
|  |  +------+------+  +------+------+  |  | events (ring) |  ||  |
|  |         |                |         |  | block_stats   |  ||  |
|  |         +----------------+---------+--+---------------+--+|  |
|  +-----------------------------------------------------------+  |
|                              |                                  |
|                              v                                  |
|  +-----------------------------------------------------------+  |
|  |                    exec() syscall                         |  |
|  +-----------------------------------------------------------+  |
+-----------------------------------------------------------------+
```

## Components

### Kernel Space (BPF Programs)

#### bpf/aegis.bpf.c

The BPF program runs in kernel context and implements:

1. **File enforcement hooks**
   - `file_open` and/or `inode_permission`
   - Can return `-EPERM` to block file access
   - Check deny and allow maps plus exec-identity state
   - Only active when BPF LSM is enabled

2. **Network enforcement hooks**
   - `socket_connect`, `socket_bind`, `socket_listen`, `socket_accept`,
     `socket_sendmsg`
   - Used for exact IP, CIDR, port, and exact IP:port deny logic
   - `listen()` remains port-deny only in the current release
   - These hooks are optional and may be disabled when the kernel does not
     expose them

3. **Tracepoints**
   - `sched_process_exec`: emits EXEC events for process executions
   - `sys_enter_openat`: emits audit-only BLOCK events for deny_path matches
   - Works without BPF LSM (audit-only paths)

4. **BPF Maps**
   - `deny_inode`: Hash map of blocked (dev, inode) pairs
   - `deny_path`: Hash map of blocked paths
   - `allow_cgroup`: Hash map of allowed cgroup IDs
   - `allow_exec_inode`: VERIFIED_EXEC allowlist map
   - `deny_ipv4` / `deny_ipv6`: Exact IP deny maps
   - `deny_cidr_v4` / `deny_cidr_v6`: CIDR deny maps
   - `deny_port`: Port/protocol/direction deny map
   - `deny_ip_port_v4` / `deny_ip_port_v6`: Exact remote IP:port deny maps
   - `events`: Ring buffer for sending events to userspace
   - `block_stats`: Global counters for blocks and drops
   - `net_block_stats`, `net_ip_stats`, `net_port_stats`: Network counters
   - `deny_cgroup_stats`: Per-cgroup block counters
   - `deny_inode_stats`: Per-inode block counters
   - `deny_path_stats`: Per-path block counters
   - `agent_meta` / `agent_config`: Runtime metadata and posture config

### User Space

#### src/main.cpp

Entry point and CLI interface:
- Parses command-line arguments
- Initializes logging
- Dispatches to appropriate command handler
- Manages signal handling for graceful shutdown

#### BPF lifecycle modules

- `src/bpf_ops.cpp`
  - Owns object loading, map discovery, map sizing, pin reuse, and low-level
    map operations
- `src/bpf_attach.cpp`
  - Owns attach orchestration and attach-contract state
- `src/bpf_maps.cpp`
  - Owns shadow-map helpers and map-pressure reporting
- `src/bpf_integrity.cpp`
  - Owns BPF object path resolution and integrity verification
- `src/bpf_config.cpp`
  - Owns agent config and agent-meta map updates

#### Policy modules

- `src/policy_parse.cpp`
  - Parses INI-style policy files and validates syntax/semantics
- `src/policy_runtime.cpp`
  - Applies policy state to BPF maps, records applied policy, and handles
    rollback
- `src/policy.cpp`
  - Handles export/write-facing policy helpers

#### Daemon modules

- `src/daemon.cpp`
  - Startup orchestration, attach flow, capability report write, and event loop
- `src/daemon_posture.cpp`
  - Applied-policy requirement loading and capability report generation
- `src/daemon_policy_gate.cpp`
  - Enforce gating and audit-fallback decisions for policy requirements
- `src/daemon_runtime.cpp`
  - Runtime-state tracking, signal handling, and deadman heartbeat

#### src/events.cpp

Event handling:
- Receives events from BPF ring buffer
- Formats events for output (JSON/text)
- Sends events to journald or stdout

#### src/utils.cpp

Utility functions:
- Path validation and canonicalization
- Cgroup path resolution
- Inode-to-path mapping
- String manipulation

#### src/sha256.cpp

SHA256 implementation:
- Pure C++ implementation (no external deps)
- Used for policy file verification
- Used for path-based hash lookups

#### src/seccomp.cpp

Seccomp filter:
- Applies syscall allowlist after initialization
- Reduces attack surface if agent is compromised

#### src/logging.hpp

Structured logging:
- Chainable API for field addition
- Text and JSON output formats
- Log level filtering
- Thread-safe singleton

#### src/result.hpp

Error handling:
- `Result<T>` type for success/failure
- `Error` class with code, message, context
- `TRY()` macro for early return

## Data Flow

### File Access Blocking (Enforce Mode)

```
1. Process calls open("/etc/shadow")
           |
           v
2. Kernel invokes file_open LSM hook
           |
           v
3. BPF program handle_file_open runs
           |
           +--- Check allow_cgroup map
           |    +- If cgroup allowed → ALLOW
           |
           +--- Check deny_inode map
                +- If inode blocked → DENY + emit event
           |
           v
4. Return 0 (allow) or -EPERM (deny)
           |
           v
5. If denied, ring buffer event sent to userspace
           |
           v
6. aegisbpf daemon receives event
           |
           v
7. Event logged to journald/stdout
```

### Audit Mode

```
1. Process executes a binary (execve)
           |
           v
2. execve() completes successfully
           |
           v
3. Kernel fires sched_process_exec tracepoint
           |
           v
4. BPF program handle_execve runs
           |
           v
5. EXEC event emitted to ring buffer
           |
           v
6. aegisbpf daemon receives event
           |
           v
7. Event logged to journald/stdout
```

```
1. Process opens a file (open/openat)
           |
           v
2. Kernel fires sys_enter_openat tracepoint
           |
           v
3. BPF program handle_openat runs
           |
           v
4. If path is in deny_path, emit audit-only BLOCK event
           |
           v
5. aegisbpf daemon receives event
           |
           v
6. Event logged to journald/stdout
```

## BPF Map Pinning

Maps are pinned to `/sys/fs/bpf/aegisbpf/` for persistence:

```
/sys/fs/bpf/aegisbpf/
+-- deny_inode          # Blocked inodes
+-- deny_path           # Blocked paths
+-- allow_cgroup        # Allowed cgroups
+-- allow_exec_inode    # VERIFIED_EXEC allowlist
+-- deny_ipv4 / deny_ipv6
+-- deny_cidr_v4 / deny_cidr_v6
+-- deny_port
+-- deny_ip_port_v4 / deny_ip_port_v6
+-- block_stats         # Global counters
+-- net_block_stats     # Network counters
+-- deny_cgroup_stats   # Per-cgroup stats
+-- deny_inode_stats    # Per-inode stats
+-- deny_path_stats     # Per-path stats
+-- agent_meta          # Layout version
+-- agent_config        # Runtime config/posture
```

Pinning allows:
- Persistent deny lists across agent restarts
- Multiple agent instances sharing state
- External tools to inspect/modify maps

## Error Handling Strategy

AegisBPF uses a Result<T> monad pattern:

```cpp
Result<InodeId> path_to_inode(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed");
    }
    return InodeId{static_cast<uint32_t>(st.st_dev), st.st_ino};
}

// Usage with TRY macro
Result<void> block_file(const std::string& path) {
    auto inode = TRY(path_to_inode(path));
    TRY(add_to_deny_map(inode));
    return {};
}
```

Benefits:
- Explicit error handling at every call site
- Error context preservation through the call stack
- No exceptions (suitable for signal handlers)

## Concurrency Model

- **Single-threaded main loop**: ring buffer polling in the daemon
- **Thread-safe caches**: CgroupPathCache and CwdCache use mutex
- **Atomic runtime state**: runtime transitions and attach tunables use atomics
- **Background heartbeat**: a dedicated deadman thread updates the kernel
  deadline while the main loop remains single-threaded

## Security Considerations

1. **Principle of Least Privilege**
   - Minimal capability set (SYS_ADMIN, BPF, PERFMON)
   - Seccomp filter restricts syscalls
   - AppArmor/SELinux confine file access

2. **Input Validation**
   - All CLI paths validated before use
   - Policy files parsed with strict error handling
   - SHA256 verification for policy integrity

3. **Defense in Depth**
   - Multiple security layers (BPF, seccomp, MAC)
   - RAII for resource cleanup
   - Crash-safe persistent state

## Performance Characteristics

- **BPF overhead**: ~100-500ns per file open
- **Map lookups**: O(1) hash table operations
- **Ring buffer**: Lock-free producer-consumer
- **Memory usage**: ~10MB base + map sizes
- **CPU usage**: Minimal when idle, proportional to exec rate

## Kernel Requirements

| Feature | Minimum Version | Notes |
|---------|----------------|-------|
| BPF CO-RE | 5.5 | Compile-once, run-everywhere |
| BPF LSM | 5.7 | Required for enforce mode |
| Ring buffer | 5.8 | More efficient than perf buffer |
| CAP_BPF | 5.8 | Dedicated capability |
| BTF | 5.2 | Type information |
