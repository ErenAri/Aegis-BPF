# AegisBPF Technical Blog Series

Five deep-dive blog posts covering AegisBPF's core technical innovations.
Target audience: Security engineers, SREs, eBPF developers.

---

## Post 1: "Preventing PID Reuse Attacks in eBPF"

**Length:** ~2,000 words
**Target:** Medium, Dev.to, /r/linux, /r/netsec, Hacker News

### Outline

1. **The Problem**: PID reuse in Linux (32K default, fast recycling under load)
   - How PID reuse breaks naive process tracking
   - Example: Process A (PID 100) exits, Process B (PID 100) starts
   - Security impact: Wrong process inherits trust/deny state

2. **How Others Solve It** (or don't):
   - Falco: PID + timestamp correlation (racy under high fork rates)
   - Kernel audit: AUDIT_PID with boot_id (heavy overhead)
   - systemd: Cgroup-based tracking (doesn't work cross-cgroup)

3. **AegisBPF's Approach**:
   - `exec_id = f(PID, start_time_ns)` — cryptographically unique
   - Dead process cache (LRU map) for post-mortem lookups
   - Start_time comparison on every map access
   - No false attributions even at 10K+ forks/sec

4. **Implementation Details**:
   - BPF tracepoint on `sched_process_exec` and `sched_process_exit`
   - Per-CPU process_tree map for lock-free updates
   - Code walkthrough of exec_id generation

5. **Benchmarks**: Fork-bomb PID reuse rate vs tracking accuracy

---

## Post 2: "Low-Overhead Network Policy in eBPF"

**Length:** ~2,500 words
**Target:** Medium, eBPF community Slack, CNCF blog

### Outline

1. **The Challenge**: Enforcing network policy at scale
   - CNI (Cilium, Calico) operates at L3/L4 packet level
   - AegisBPF operates at syscall level (socket_connect, etc.)
   - Tradeoffs: packet-level precision vs syscall-level attribution

2. **Three-Level Lookup Architecture**:
   - Level 1: Exact IP match (BPF_MAP_TYPE_HASH, O(1))
   - Level 2: CIDR match (BPF_MAP_TYPE_LPM_TRIE, O(prefix_len))
   - Level 3: Port + protocol + direction (BPF_MAP_TYPE_HASH, O(1))
   - Combined IP+port rules for precise endpoint blocking

3. **Direction-Aware Rules**:
   - Why "block port 80" isn't enough (egress vs bind vs listen)
   - Hook selection per direction
   - Implementation of direction byte in port_key struct

4. **Performance Analysis**:
   - Socket connect latency with 0, 100, 1K, 10K network rules
   - LPM trie depth impact on CIDR lookup speed
   - Comparison with iptables/nftables overhead

5. **Real-World Example**: Blocking C2 channels and mining pools

---

## Post 3: "Inode-First Enforcement: Why Path Lookups Are Too Slow"

**Length:** ~2,500 words
**Target:** Medium, LWN.net, Hacker News

### Outline

1. **The Path Resolution Problem**:
   - Every file access in Linux resolves a path to an inode
   - Security tools that match on paths must re-resolve or compare strings
   - Cost: dentry cache walk + string comparison per rule per check

2. **AppArmor's Approach** (path-based):
   - Profile matching on pathname
   - dentry traversal on every check
   - Performance impact at scale

3. **AegisBPF's Inode-First Strategy**:
   - Pre-resolve paths to (inode, device) at policy-apply time
   - BPF hash map with 16-byte key (8-byte inode + 4-byte device + 4-byte pad)
   - Single O(1) lookup per file_open hook
   - No string comparison, no path traversal

4. **TOCTOU Analysis**:
   - File rename after inode resolution
   - Why inode+device is stable (immutable once allocated)
   - Edge cases: bind mounts, overlayfs, hardlinks
   - Mitigation strategies for each

5. **Benchmarks**:
   - file_open latency with path-based vs inode-based rules
   - Scaling: overhead vs rule count (inode stays flat)
   - Real-world: nginx request latency under enforcement

---

## Post 4: "Dynamic Survival Binary Discovery Across Distros"

**Length:** ~1,800 words
**Target:** Dev.to, /r/linux, /r/selfhosted

### Outline

1. **The Self-Denial Problem**:
   - What happens when your security tool blocks `init`?
   - What happens when it blocks `bash` during a policy update?
   - Bricking the system is worse than no security tool

2. **Why Static Lists Don't Work**:
   - Binary paths differ: `/usr/bin/bash` vs `/bin/bash`
   - Distro variants: Alpine (busybox) vs Ubuntu vs RHEL
   - Container images: Distroless, scratch, custom base

3. **AegisBPF's Discovery Algorithm**:
   - Enumerate known shell paths across distros
   - Resolve to inodes (cross-filesystem-safe)
   - Include PID 1 (init/systemd)
   - Include the agent binary itself
   - Store in `survival_allowlist` map

4. **Implementation Walk-Through**:
   - Code: scan_survival_binaries() function
   - Inode resolution with stat()
   - Error handling: missing binary is OK (skip, don't fail)

5. **Testing**: Automated distro matrix (Ubuntu, Debian, Fedora, Alpine)

---

## Post 5: "Building Production-Grade eBPF: Lessons from 200+ Tests"

**Length:** ~3,000 words
**Target:** Medium, CNCF blog, conference talk companion

### Outline

1. **The Testing Pyramid for BPF**:
   - Unit tests (userspace logic): policy parsing, key construction, hashing
   - Integration tests (BPF + userspace): map operations, event handling
   - E2E tests (full enforcement): block verification, policy reload
   - Contract tests: metrics, man pages, map schema

2. **Challenge: You Can't Unit Test the Kernel**:
   - BPF programs can't run outside the kernel
   - Verifier behavior varies by kernel version
   - Solutions: SKIP_BPF_BUILD for CI, kernel-matrix workflow

3. **Fuzzing BPF Userspace**:
   - Policy parser fuzzing (libFuzzer)
   - Network address parsing fuzzing
   - Results: bugs found, coverage achieved

4. **Contract Testing Pattern**:
   - Metrics contract: every exported metric must be documented
   - Map schema contract: every BPF map must be in BPF_MAP_SCHEMA.md
   - Man page contract: CLI options must match actual behavior
   - Why contracts prevent documentation drift

5. **CI Architecture**:
   - 29 workflows, 240+ tests
   - Kernel version matrix (5.15, 6.1, 6.6, 6.8)
   - Multi-arch (x86_64, ARM64)
   - Performance baselines with ratcheting
   - Coverage enforcement (never go down)

6. **Lessons Learned**:
   - Always test the policy parser (it's the attack surface)
   - Per-CPU map aggregation is tricky (test with mock CPU counts)
   - Ring buffer drops are expected, not errors
   - Version your map layouts (layout_version field)
   - RAII for BPF lifecycle (BpfState pattern)

---

## Publishing Schedule

| Week | Post | Cross-Post |
|------|------|------------|
| 1 | Post 1: PID Reuse | HN, /r/linux, /r/netsec |
| 3 | Post 2: Network Policy | eBPF Slack, CNCF |
| 5 | Post 3: Inode-First | HN, LWN.net |
| 7 | Post 4: Survival Binaries | /r/linux, /r/selfhosted |
| 9 | Post 5: Testing eBPF | CNCF blog, KubeCon companion |

## Promotion Channels

- Hacker News: `Show HN: AegisBPF — [post title]`
- Reddit: /r/linux, /r/netsec, /r/kubernetes, /r/ebpf
- eBPF Slack: #general channel
- Twitter/X: Thread with key insights + link
- LinkedIn: Article repost
- CNCF Newsletter: Submit for inclusion
