# aegis-next Roadmap

> Status: MOSTLY IMPLEMENTED — derived from deep research on BPF arena
> scalability, Tetragon/Tracee/Falco internals, sched_ext enforcement
> patterns, and enterprise kernel compatibility. May 2026.
> Phase 1-4 items are implemented except where noted below.

## Current State (v0.2 — enforcement-capable prototype)

- 5 LSM hooks (exec, file_open, socket_connect, socket_bind, kernel_module_request)
  with policy-driven enforcement (return -EPERM on deny)
- Flat 64MB arena slot array, 1M nodes, wrap-around with generation tag
- pid_slot LRU hash for parent linkage
- In-kernel GC via BPF timer
- Minimal sched_ext scheduler (time-slice throttle + quarantine bridge)
- In-kernel policy engine: BPF hash map keyed by (hook, match_type, match_val)
  with per-cgroup scoping and comm/path/port matching
- In-kernel rate limiting: per-cgroup event rate tracking with windowed counters,
  automatic quarantine bridge, and LSM deny verdict on all hooks (exec, file, net, etc.)
- user_ringbuf for zero-copy policy hot-reload (bulk batch updates)
- Targeted signal delivery via bpf_send_signal_task (6.13+ fallback)
- File security labeling via bpf_set_dentry_xattr (6.13+)
- In-kernel binary authorization: fsverity digest + PKCS7 signature verification
- Userspace: poll loop, deny-list comm matching, graph dump/lineage CLI
- Operator integration: CRD → ConfigMap with dual-format policy (INI + aegis-next),
  denyComm support across full stack (BPF map + daemon parser + INI translator),
  EnforceCapable node probing via BPF LSM kernel label, aegis-next line format
- LOC: ~3,000+ total

What's missing: real graph (arena hash index), path resolution (bpf_path_d_path),
network 5-tuple correlation, fallback for older kernels, comprehensive tests,
hardening.

---

## Phase 1 — Make the Graph Real

Goal: transform the flat slot array into a queryable provenance graph
that resolves file paths, correlates network flows, and supports O(1)
lookup by PID/inode/cgroup. This is the foundation everything else
builds on.

### P1.1 Arena Hash Index for O(1) Lookup

**Files:** `bpf/arena_htable.h` (new), `bpf/provenance.bpf.c`

Build a simple open-addressing hash table inside the arena. Keys are
composite (kind + ID): `(EXEC, tgid)`, `(FILE, inode)`, `(SOCK, 5-tuple-hash)`.
Values are slot indices into the existing node array.

- Arena hash lives at a fixed offset after the node array
- 256K buckets, linear probing, bounded to 8 steps (verifier-safe)
- Insert from `record_base()`, lookup from `record_task()`/`record_event()`
- Replaces the pid_slot LRU hash for parent lookup
- Userspace reads hash directly via mmap for O(1) queries

Verifier budget: ~40 instructions per lookup (load key, hash, 8-step probe).
Well within the 1M limit even when inlined into every hook.

### P1.2 File Path Resolution

**Files:** `bpf/provenance.bpf.c`, `bpf/path_cache.bpf.c` (new)

Two-tier approach based on research findings:

**Tier 1 — Sleepable LSM hooks (file_open, bprm_check_security):**
Use `bpf_path_d_path()` kfunc (kernel 6.8+) with `BPF_F_SLEEPABLE`.
Write resolved path (up to 256 bytes) into a per-CPU scratch buffer,
then copy into a dedicated arena path slab. Store path-slab-index in
the prov_node's `object_id` field (repurposed from raw inode).

**Tier 2 — Non-sleepable hooks (file_permission, mmap_file):**
Look up cached path from Tier 1 by (device, inode) composite key in
the arena hash. If cache miss, fall back to inode-only recording.

**Path slab:** fixed 256-byte slots in a second arena region (or at
tail of existing arena after nodes + hash). Allocate via a simple
bump pointer with wrap-around. ~16K path slots = 4MB.

Kernel requirement: 6.8+ for `bpf_path_d_path()`. On older kernels,
record inode only (current behavior).

### P1.3 Network Flow Correlation with 5-Tuple

**Files:** `bpf/provenance.bpf.c` (extend socket_connect),
`bpf/net_track.bpf.c` (new, optional)

Current state: socket_connect records `(port << 32 | addr)` as object_id.

Extend to:
- Extract full 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
  from `socket_connect` LSM hook using `bpf_probe_read_kernel` on
  `struct sockaddr_in`/`sockaddr_in6`
- Store 5-tuple in a compact 20-byte struct within the prov_node
  (reuse object_id + extra + 8 bytes from comm reduction or overflow slab)
- Index by flow hash in the arena hash table
- Add `socket_bind` and `socket_listen` LSM hooks for server-side tracking

Optional (Phase 1.5): add `cgroup/connect4` / `cgroup/connect6` hooks
for per-cgroup network policy groundwork.

### P1.4 Container/Cgroup Namespace Awareness

**Files:** `bpf/provenance.bpf.c`, `include/aegis_next_prov.hpp`

Current state: `bpf_get_current_cgroup_id()` stored as `cgid`.

Extend:
- Add `mnt_ns`, `pid_ns`, `net_ns` (from `task->nsproxy`) to prov_node
  (use 8 bytes: pack 3x 32-bit namespace IDs, or store inum as u32)
- Add container-ID heuristic: read cgroup path prefix to extract
  container runtime ID (first 12 chars of cgroup leaf)
- This enables policy rules scoped to container, not just PID

Layout change: prov_node grows from 64 to 80 bytes (or use an overflow
slab for namespace data to preserve 64-byte alignment).

### P1.5 Ring Buffer Hybrid for Real-Time Alerts

**Files:** `bpf/provenance.bpf.c`, `src/main.cpp`

Research consensus: arena for state, ringbuf for alerts.

- Add a `BPF_MAP_TYPE_RINGBUF` (2MB) for high-priority event signaling
- LSM hooks that match a policy rule write a compact alert (slot index +
  kind + action) to the ringbuf
- Userspace replaces the 1-second poll loop with `ring_buffer__poll()`
  for sub-millisecond detection latency
- Arena remains the source of truth; ringbuf is just a notification channel
- This is prerequisite for Phase 2 enforcement (can't enforce with 1s latency)

### P1.6 Upgrade prov_node Layout

**Files:** `bpf/prov_types.h`, `include/aegis_next_prov.hpp`,
`include/prov_arena_types.h`

Consolidated layout change (do once, break the on-wire format once):

```c
struct prov_node {          // target: 80 bytes
    u64 ts_ns;              //  0: timestamp
    u32 pid;                //  8: thread ID
    u32 ppid;               // 12: parent tgid
    u32 tgid;               // 16: thread group ID
    u32 uid;                // 20: user ID
    u64 cgid;               // 24: cgroup ID
    u64 object_id;          // 32: inode / flow-hash / path-slab-index
    u64 prev_index;         // 40: parent/exec node slot
    u8  kind;               // 48: PROV_KIND_*
    u8  flags;              // 49: generation tag
    u16 extra;              // 50: open_flags / addr_family
    u32 ns_ids;             // 52: packed mnt_ns(16) + pid_ns(16)
    char comm[12];          // 56: task comm
    u32 net_ns;             // 68: network namespace
    u32 path_slab_idx;      // 72: index into path slab (0 = none)
    u32 _reserved;          // 76: alignment padding
};                          // 80 bytes total
```

Update static_asserts in both C and C++ headers. Bump arena magic number
to signal format change.

---

## Phase 2 — Make Enforcement Real

Goal: the agent can actually deny malicious operations in-kernel with
sub-millisecond latency, driven by a policy engine.

### P2.1 LSM Deny Path

**Files:** `bpf/provenance.bpf.c`, `bpf/policy.bpf.c` (new)

Change LSM hooks from `return 0` to policy-driven enforcement:

- `bprm_check_security`: return `-EPERM` for denied binaries
- `file_open` / `file_permission`: return `-EACCES` for protected paths
- `socket_connect` / `socket_bind`: return `-EACCES` for blocked destinations

Policy evaluation in BPF:
- Policy rules stored in a `BPF_MAP_TYPE_HASH` (not arena — needs fast
  atomic lookup without ARENA_PTR overhead)
- Key: `(hook_type, match_field_hash)` — e.g., (EXEC, sha256_prefix)
- Value: `(action, flags)` — ALLOW/DENY/LOG/QUARANTINE
- Bounded to 3 map lookups per hook (kind match, path match, cgroup match)
- ~60 instructions per policy evaluation

Additionally use `bpf_send_signal(SIGKILL)` for kill-on-detect scenarios
(defense-in-depth: deny the syscall AND kill the process).

### P2.2 New LSM Hook Points

**Files:** `bpf/provenance.bpf.c`

Add critical hooks identified from Tetragon/Falco analysis:

| Hook | Purpose | Sleepable |
|------|---------|-----------|
| `file_permission` | FIM read/write deny | No |
| `mmap_file` | Fileless malware (W+X prevention) | No |
| `file_mprotect` | RWX escalation detection | No |
| `task_alloc` | Fork bomb / process limit | No |
| `socket_bind` | Bind shell prevention | No |
| `socket_listen` | C2 listener detection | No |
| `bpf` | Self-protection (block BPF unload) | No |
| `kernel_module_request` | Kernel rootkit prevention | No |

Each hook: record event to arena + evaluate policy + return verdict.
Non-sleepable hooks use cached path data from P1.2 Tier 2.

### P2.3 In-Kernel Enforcement Bridge (LSM to sched_ext)

**Files:** `bpf/provenance.bpf.c`, `bpf/quarantine.bpf.c`

Replace the userspace poll-based quarantine with in-kernel bridge:

- When an LSM hook detects a policy violation but the action is
  QUARANTINE (not DENY), write the cgroup ID directly to the
  quarantine map from BPF (no userspace round-trip)
- Latency: <1 microsecond (map update in BPF) vs ~1 second (current)
- The sched_ext scheduler already reads this map — no changes needed

### P2.4 Policy Language and Loader

**Files:** `src/policy.cpp` (new), `src/policy.hpp` (new),
`src/main.cpp`

Minimal YAML policy format:

```yaml
rules:
  - name: block-reverse-shell
    hook: socket_connect
    match:
      comm: [bash, sh, zsh, python3]
      dst_port: [4444, 5555, 8080]
    action: deny

  - name: protect-etc-shadow
    hook: file_open
    match:
      path_prefix: /etc/shadow
    action: deny
    except:
      comm: [passwd, shadow]

  - name: quarantine-crypto-miner
    hook: bprm_check_security
    match:
      comm: [xmrig, minerd]
    action: quarantine
```

Userspace parses YAML, compiles rules into BPF map entries, loads them
via `bpf_map_update_elem`. Hot-reload: update map entries without
reloading BPF programs.

### P2.5 sched_ext Enforcement Upgrade

**Files:** `bpf/quarantine.bpf.c`

Beyond time-slice reduction:

- **CPU pinning**: quarantined cgroups dispatched only to a designated
  "jail" CPU set (e.g., CPU 0 only), preventing cache side-channels
- **Priority inversion**: quarantined tasks get `SCX_DSQ_GLOBAL` with
  minimum vtime weight, yielding to all other work
- **Scheduling denial**: for KILL-level quarantine, refuse to dispatch
  entirely (task starves), combined with SIGKILL from LSM

Read quarantine level from the shared map per-enqueue. Research confirms
hash lookup per enqueue is O(1) and adds negligible overhead if bounded.

### P2.6 Agent Self-Protection

**Files:** `bpf/selfprotect.bpf.c` (new)

Hook `lsm/bpf` and `lsm/bpf_map`:
- Deny `BPF_PROG_DETACH` / `BPF_MAP_DELETE_ELEM` on our own programs/maps
  unless the calling process matches a known hash (the agent binary itself)
- Deny `kernel_module_request` for unsigned modules
- This prevents a privileged attacker from blinding the agent

Verify caller identity via:
- `bpf_get_current_task_btf()` -> read binary inode
- Compare against a "trusted inode" stored in a map at startup

---

## Phase 3 — Make It Production-Ready

Goal: the agent runs reliably on real enterprise hosts across kernel
versions, with proper testing, graceful degradation, and operational
tooling.

### P3.1 Ring Buffer Fallback for Kernels < 6.9

**Files:** `bpf/provenance_legacy.bpf.c` (new), `CMakeLists.txt`,
`src/main.cpp`

Dual-compile approach (research consensus):
- Primary: arena-backed (kernel 6.9+) — current architecture
- Fallback: ringbuf + hash maps (kernel 5.10+) — traditional approach

Userspace probes at startup:
```cpp
int probe_fd = bpf_map_create(BPF_MAP_TYPE_ARENA, ...);
if (probe_fd >= 0) {
    close(probe_fd);
    load arena program
} else {
    load legacy ringbuf program
}
```

The fallback program uses the same prov_node struct but sends events
through a ringbuf. Userspace maintains the graph in a userspace hash
map. Higher overhead but functional on Ubuntu 22.04 HWE (6.8),
RHEL 9.x (5.14+backports), Amazon Linux 2023 (6.1+).

### P3.2 Kernel Version Feature Matrix

Runtime feature probing, not compile-time:

| Feature | Probe Method | Fallback |
|---------|-------------|----------|
| Arena (6.9+) | `bpf_map_create(ARENA)` | Ringbuf + hash maps |
| sched_ext (6.12+) | `bpf_map_create` + struct_ops load | Skip quarantine scheduler |
| `bpf_path_d_path` (6.8+) | BTF kfunc probe | Inode-only recording |
| RCU kfuncs (6.7+) | BTF kfunc probe | Skip catch-up scan |
| Open-coded iterators (6.7+) | BTF kfunc probe | Skip catch-up scan |
| BPF signing (6.18+) | Keyring probe | Unsigned load |

Each feature degrades independently. The agent always provides
baseline LSM observability (exec + file + network) regardless of
kernel version (minimum: 5.10 for sleepable BPF LSM).

### P3.3 BPF Program Testing

**Files:** `tests/test_bpf_arena.cpp` (new),
`tests/test_bpf_policy.cpp` (new), `.github/workflows/aegis-next.yml`

**Unit tests (userspace, GTest):**
- Arena hash table: insert, lookup, collision, wrap
- Policy compilation: YAML -> map entries
- Lineage walk: deep chains, stale detection, wrap-around
- Path slab: allocation, wrap, lookup

**Integration tests (require kernel, BPF_PROG_TEST_RUN):**
- Load BPF program, run catch-up via `bpf_prog_test_run_opts`
- Verify arena header magic and node count
- Trigger exec/file_open/socket_connect, verify nodes in arena
- Policy deny: load deny rule, verify hook returns -EPERM
- GC: fill arena past wrap, verify stale nodes cleaned

**CI matrix (GitHub Actions):**
- Ubuntu 24.04 (kernel 6.8): fallback mode, userspace tests only
- Ubuntu 24.10+ or custom runner (kernel 6.12+): full arena + sched_ext
- Clang 18 + Clang 19: verify both toolchains
- Use QEMU micro-VMs for kernel matrix if custom runners unavailable

### P3.4 Event Persistence and Export

**Files:** `src/export.cpp` (new), `src/export.hpp` (new)

Arena is volatile — power loss loses everything. Add export:

- Ringbuf alerts are written to a rotated JSONL file (like Tetragon)
- Periodic arena snapshot: dump recent N nodes to structured log
- Optional: forward alerts to syslog / CEF (reuse mainline aegisbpf
  CEF formatter from `src/events/cef_formatter.cpp`)
- Optional: Prometheus metrics endpoint (event rate, deny count,
  arena utilization, GC stats)

### P3.5 CLI and Daemon Improvements

**Files:** `src/main.cpp`, `src/daemon.cpp` (new)

- Daemonize with proper signal handling, PID file, systemd unit
- `aegisbpf-next status`: show hook counts, arena utilization,
  policy rule count, quarantine entries, GC stats
- `aegisbpf-next policy load <file.yaml>`: hot-reload policy
- `aegisbpf-next policy list`: show active rules
- `aegisbpf-next export --format=json|cef`: tail events
- Config file (`/etc/aegis-next/config.yaml`) for defaults

### P3.6 Pre-Fault Arena Pages

**Files:** `src/main.cpp`

Research finding: first arena page access triggers a major page fault.
Pre-fault the working set at startup:

```cpp
// After skeleton open+load, before attach:
volatile char *base = (volatile char *)skel->arena;
for (size_t i = 0; i < prefault_bytes; i += 4096)
    (void)base[i];  // touch each page
```

This eliminates latency spikes during the first burst of events.

### P3.7 Documentation and Hardening Review

**Files:** `docs/HARDENING.md` (update), `docs/ARCHITECTURE.md` (new)

Per graduation criteria in README:
- Document arena attack surface (shared mmap = untrusted data from
  userspace perspective; BPF must validate all arena reads before
  enforcement decisions)
- Document TOCTOU mitigations (use LSM hooks not tracepoints,
  bind policy to inode not path string)
- Document self-protection model (lsm/bpf hook)
- Architecture diagram: arena layout, hook flow, policy evaluation,
  enforcement pipeline, sched_ext bridge

---

## Dependency Graph

```
P1.1 Arena Hash ──────────────────────────────┐
P1.2 Path Resolution ─────────────────────────┤
P1.3 Network 5-Tuple ─────────────────────────┤
P1.4 Namespace Awareness ──────────────────────┤
P1.5 Ringbuf Hybrid ──────────────────────────┼──> P2.1 LSM Deny
P1.6 Layout Upgrade (do first in Phase 1) ────┘    P2.2 New Hooks
                                                    P2.3 In-Kernel Bridge
P2.1 LSM Deny ────────────────────────────────┐    P2.4 Policy Language
P2.2 New Hooks ────────────────────────────────┤
P2.3 In-Kernel Bridge ────────────────────────┤
P2.4 Policy Language ─────────────────────────┼──> P3.1 Fallback
P2.5 sched_ext Upgrade ───────────────────────┤    P3.3 Testing
P2.6 Self-Protection ─────────────────────────┘    P3.4 Export
                                                    P3.5 CLI/Daemon

P3.x (all) ──────────────────────────────────┐
P2.1 (policy) ────────────────────────────────┼──> P4.1 Binary Auth
P2.3 (bridge) ────────────────────────────────┤    P4.2 user_ringbuf
                                              │    P4.3 Rate Limiting
                                              │    P4.4 File Labeling
                                              │    P4.5 Targeted Signal
                                              └──> P4.6 Feature Probes
```

## Execution Order

Phase 1 tasks can mostly be parallelized. Recommended sequence:

1. **P1.6** Layout upgrade (breaking change — do first)
2. **P1.1** Arena hash (unblocks everything else)
3. **P1.5** Ringbuf hybrid (unblocks enforcement latency)
4. **P1.2** Path resolution (biggest user-visible improvement)
5. **P1.3** Network 5-tuple
6. **P1.4** Namespace awareness

Phase 2 sequence:

7. **P2.1** LSM deny path (the core enforcement primitive)
8. **P2.4** Policy language (makes deny usable)
9. **P2.2** New hook points (expand coverage)
10. **P2.3** In-kernel bridge (remove userspace latency)
11. **P2.5** sched_ext upgrade
12. **P2.6** Self-protection

Phase 3 sequence:

13. **P3.3** Testing (should start early, expand throughout)
14. **P3.1** Fallback (enables enterprise deployment)
15. **P3.2** Feature matrix
16. **P3.6** Pre-fault
17. **P3.4** Export
18. **P3.5** CLI/daemon
19. **P3.7** Docs and hardening review

## Phase 4 — Beyond the State of the Art

> Status: PARTIALLY IMPLEMENTED — May 2026. These features use cutting-edge BPF
> capabilities (kernel 6.7-6.13+) that no competing security tool
> implements. Research confirmed: Falco, Tetragon, Tracee, and KubeArmor
> lack all of these.

Goal: make aegis-next definitively more advanced than any open-source
BPF security tool by leveraging features no competitor uses.

### P4.1 In-Kernel Binary Authorization

**Files:** `bpf/binary_auth.bpf.c` (new)

The crown jewel. A complete binary integrity verification pipeline
that runs entirely in-kernel with zero userspace round-trips:

```
exec() → bpf_get_file_xattr("security.aegis.verified")
         → cache HIT? → use cached verdict
         → cache MISS:
           → bpf_get_fsverity_digest(file)
           → lookup digest prefix in trusted_digests BPF_MAP_TYPE_HASH
           → (optional) bpf_verify_pkcs7_signature() against system keyring
           → bpf_set_dentry_xattr() to cache result for next open
           → return verdict (allow / deny / log)
```

**Why no competitor has this:**
- Falco/Tetragon detect exec events but never verify binary integrity
- KubeArmor uses process whitelists (comm name, not cryptographic)
- Tracee computes hashes in userspace (100x slower, TOCTOU vulnerable)
- Song Liu (Meta) presented this pattern at LPC 2023 but no tool
  productized it

**Kernel requirements:**
- `bpf_get_fsverity_digest`: 6.7+ (CONFIG_FS_VERITY)
- `bpf_get_file_xattr`: 6.8+
- `bpf_set_dentry_xattr`: 6.13+ (optional, for caching)
- `bpf_verify_pkcs7_signature`: 6.1+ (CONFIG_SYSTEM_DATA_VERIFICATION)

All kfuncs declared `__weak` — program loads even without the config.

**Maps:**
- `aegis_trusted_digests` (HASH, 16K entries): digest prefix → verdict
- `aegis_auth_stats` (PERCPU_ARRAY): allowed/denied/cache_hit/no_verity
- `aegis_auth_mode` (ARRAY): enforce/audit/disabled
- `aegis_auth_ringbuf` (RINGBUF, 1MB): auth events for userspace logging

### P4.2 user_ringbuf for Zero-Copy Policy Hot-Reload

**Files:** `bpf/provenance.bpf.c` (extended)

Replaces per-rule `bpf_map_update_elem()` syscalls with a bulk
user_ringbuf channel. Userspace writes `policy_msg` structs into
the ringbuf; a BPF callback (`policy_ringbuf_cb`) processes add/
delete/flush operations in-kernel without syscall overhead.

```c
struct policy_msg {
    __u8  msg_type;    // POLICY_MSG_ADD / DELETE / FLUSH
    struct policy_key key;
    struct policy_val val;
};
```

Drain triggered via `aegis_next_drain_policy` SEC("syscall") program.

**Why no competitor has this:** All BPF security tools use
`bpf_map_update_elem()` for policy delivery, which takes one syscall
per rule and serializes on the map spinlock. user_ringbuf enables
atomic batch updates with zero copies.

**Kernel:** 6.1+ (BPF_MAP_TYPE_USER_RINGBUF)

### P4.3 In-Kernel Rate Limiting

**Files:** `bpf/provenance.bpf.c` (extended)

Per-cgroup event rate tracking with 1-second sliding window.
Integrated into `record_event()` — every LSM hook event is
automatically rate-checked. When the rate exceeds a configurable
threshold, the offending cgroup is immediately quarantined via
the in-kernel bridge to sched_ext.

```c
struct rate_key { __u64 cgid; __u8 kind; };
struct rate_val { __u64 window_start_ns; __u32 count; __u32 max_rate; };
```

**Detection targets:**
- Fork bombs: PROV_KIND_TASK_ALLOC > 50/sec/cgroup
- Connection floods: PROV_KIND_SOCKET_CONNECT > 100/sec/cgroup
- File scan storms: PROV_KIND_FILE_OPEN > configurable

**Maps:**
- `aegis_rate_limits` (LRU_HASH, 8K entries): rate counters
- `aegis_rate_config` (ARRAY, 16 entries): per-kind thresholds

**Why no competitor has this:** Competitors do rate counting in
userspace (100x latency) or don't have per-cgroup rate limiting at all.

### P4.4 File Security Labeling via xattr

**Files:** `bpf/provenance.bpf.c` (extended)

After recording file events, write "security.aegis.seen" xattr on
the accessed file. This creates a persistent forensic trail:
- Which files were accessed under aegis supervision
- Cache for binary authorization (avoid re-verification)
- Evidence that survives process exit

Uses `bpf_set_dentry_xattr()` (6.13+), degrades gracefully when
unavailable.

### P4.5 Targeted Signal Delivery

**Files:** `bpf/provenance.bpf.c` (extended)

Upgraded from `bpf_send_signal(SIGKILL)` (targets only current task)
to `bpf_send_signal_task(task, SIGKILL, PIDTYPE_TGID, 0)` which can
target a specific task by reference. Falls back to the old API on
kernels < 6.13.

### P4.6 Feature Probe Extensions

**Files:** `include/feature_probe.hpp` (extended)

Runtime detection of Phase 4 capabilities:
- `user_ringbuf`: BPF_MAP_TYPE_USER_RINGBUF availability
- `fsverity`: CONFIG_FS_VERITY via filesystem scan
- `xattr`: bpf_get_file_xattr kfunc (approximated by arena + LSM)
- `binary_auth`: composite (fsverity + LSM + xattr)

### CLI Extensions

```
aegisbpf-next auth start [--audit|--enforce]
aegisbpf-next auth trust <hex-digest>
aegisbpf-next auth list
aegisbpf-next auth stats
aegisbpf-next rate set <kind> <max_per_second>
```

---

### Competitive Position After Phase 4

| Feature | aegis-next | Falco | Tetragon | Tracee | KubeArmor |
|---------|-----------|-------|----------|--------|-----------|
| In-kernel binary auth (fsverity) | **yes** | no | no | no | no |
| In-kernel PKCS7 sig verify | **yes** | no | no | no | no |
| xattr security labeling | **yes** | no | no | no | no |
| user_ringbuf policy channel | **yes** | no | no | no | no |
| In-kernel rate limiting | **yes** | no | partial | no | no |
| Targeted bpf_send_signal_task | **yes** | no | yes | no | no |
| BPF arena (zero-copy graph) | **yes** | no | no | no | no |
| sched_ext quarantine | **yes** | no | no | no | no |
| In-kernel policy enforcement | **yes** | no | **yes** | no | **yes** |
| Self-protection (lsm/bpf) | **yes** | no | partial | no | no |

---

## Non-Goals (explicit)

- Kubernetes integration (Pod labels, CRDs) — defer to post-graduation
- Custom BPF policy language (Rego, CEL) — YAML is enough for now
- GUI / web dashboard — CLI-first
- Windows / macOS support — Linux-only
- BPF exceptions (`bpf_throw`) — CVE-2026-31526 still unresolved
- Per-namespace BPF tokens — ecosystem not ready (Pixie #2040, cilium/ebpf #43587)

---

## Implementation Status (May 2026)

| Item | Status | Notes |
|------|--------|-------|
| **P1.1** Arena Hash Index | ✅ Done | `bpf/arena_htable.h` — 64K buckets, 8-step linear probe |
| **P1.2** Path Resolution | ✅ Done | `bpf_d_path()` + path slab (256B × 4K slots) |
| **P1.3** Network 5-Tuple | ✅ Done | Net slab (48B × 4K), IPv4/IPv6 extraction |
| **P1.4** Namespace Awareness | ✅ Done | `mnt_ns` + `pid_ns` in prov_node |
| **P1.5** Ringbuf Alerts | ✅ Done | 2MB ringbuf, 16-byte alert struct |
| **P1.6** Node Layout | ✅ Done | 80-byte prov_node, magic 0xA591_5BPF_A5E61571 |
| **P2.1** LSM Deny Path | ✅ Done | Policy hash map, -EPERM/-EACCES on all hooks |
| **P2.2** New Hook Points | ✅ Done | 14 LSM hooks (exec, file, net, task, kmod, ptrace, setuid, rename, unlink, sendmsg) |
| **P2.3** In-Kernel Bridge | ✅ Done | LSM → quarantine map → sched_ext, zero userspace |
| **P2.4** Policy Language | ⚠️ Partial | INI-style loader, not YAML; hot-reload works |
| **P2.5** sched_ext Upgrade | ✅ Done | 4 quarantine levels (none/throttle/pin/starve) |
| **P2.6** Self-Protection | ✅ Done | `bpf/selfprotect.bpf.c` — lsm/bpf + lsm/bpf_map |
| **P3.1** Ringbuf Fallback | ✅ Done | `bpf/provenance_legacy.bpf.c` for kernel < 6.9 |
| **P3.2** Feature Matrix | ✅ Done | `include/feature_probe.hpp` — 8 runtime probes |
| **P3.3** BPF Testing | ✅ Done | Unit tests + fuzz harness + CI workflow |
| **P3.4** Event Export | ✅ Done | JSONL exporter with file rotation |
| **P3.5** CLI/Daemon | ✅ Done | 20+ subcommands; missing formal daemonization |
| **P3.6** Pre-Fault Pages | ✅ Done | `src/main.cpp:562-577` |
| **P3.7** Documentation | ✅ Done | `docs/HARDENING.md` + `docs/ARCHITECTURE.md` |
| **P4.1** Binary Auth | ✅ Done | `bpf/binary_auth.bpf.c` — fsverity + PKCS7 + xattr |
| **P4.2** user_ringbuf | ✅ Done | Batch policy updates via callback |
| **P4.3** Rate Limiting | ✅ Done | Per-cgroup sliding window + LSM deny verdict |
| **P4.4** Xattr Labeling | ✅ Done | `security.aegis.seen` on file_open |
| **P4.5** Signal Delivery | ✅ Done | `bpf_send_signal_task` with fallback |
| **P4.6** Feature Probes | ✅ Done | Composite binary_auth check |
