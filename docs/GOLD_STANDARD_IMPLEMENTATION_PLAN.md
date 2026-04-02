# AegisBPF Gold Standard Implementation Plan

**Based on:** Deep Research Production Deployability Audit
**Goal:** Address all critical findings to make AegisBPF the gold-standard eBPF security agent
**Principle:** Each phase is independently shippable and improves production safety

---

## Phase 0: Immediate Safety Fixes (1-2 days)
*Zero-risk cleanups that eliminate known foot-guns*

### 0.1 Normalize Error Handling Across Hooks
**Problem:** Network hooks fail-closed on parse errors (`enforcement_result()` → `-EPERM`), file hooks fail-open (`return 0`). This creates unpredictable behavior under stress — a network parse failure blocks traffic while a file parse failure silently allows access.

**Files:**
- `bpf/aegis_net.bpf.h` lines 45, 60, 68 (socket_connect), 291, 305, 312 (socket_bind), 826, 837, 849 (socket_sendmsg)
- `bpf/aegis_file.bpf.h` lines 18, 23, 30

**Change:** Replace bare `enforcement_result()` on parse failures with `return 0` (fail-open). Parse failures are infrastructure bugs, not security events — they should never deny legitimate traffic. Add a per-CPU counter `parse_error_count` so operators can detect the condition.

**Rationale:** Fail-open on parse errors is the only safe default for a production security tool. Operators detect the anomaly via metrics, not via user-facing outages.

### 0.2 Replace Hardcoded Kernel Constants
**Problem:** `LOCKDOWN_MODULE_SIGNATURE == 1` and `BPF_PROG_LOAD = 5` / `BPF_MAP_CREATE = 0` are baked into BPF code as magic numbers. These are historically stable but violate defense-in-depth.

**Files:**
- `bpf/aegis_kernel.bpf.h` line 109 (`if (what != 1)`)
- `bpf/aegis_kernel.bpf.h` line 186-189 (`if (cmd != 5 && cmd != 0)`)

**Change:** Define named constants at the top of the file with comments referencing the kernel header source. Add a `BPF_CORE_READ` approach where feasible, or CO-RE enum value reads. At minimum, use `#define AEGIS_LOCKDOWN_MODULE_SIGNATURE 1` etc.

### 0.3 Deduplicate Attach Logic
**Problem:** `attach_prog()` is copy-pasted between `bpf_ops.cpp:142-157` and `bpf_attach.cpp:15-30`. Divergence risk.

**Change:** Move `attach_prog()` into a shared header or into `bpf_ops.cpp` as a public function, and have `bpf_attach.cpp` call it.

---

## Phase 1: Container-Compatible Identity (3-5 days)
*Make the agent production-safe on real Kubernetes clusters*

### 1.1 Fix OverlayFS Hard-Reject in Verified Exec
**Problem:** `file_is_verified_exec_identity()` in `bpf/aegis_common.h:841` returns 0 for OverlayFS. This means `verified_exec = false` for virtually all container workloads. If `EXEC_IDENTITY_FLAG_PROTECT_CONNECT` is enabled, it blocks networking for the entire fleet.

**Change:**
1. Add a new config flag `agent_cfg.overlayfs_trust_mode` with values:
   - `0` = reject (current behavior, for bare-metal hardened hosts)
   - `1` = trust-with-checks (verify the underlying inode via OverlayFS redirect, check ownership/perms)
   - `2` = trust-all (treat OverlayFS like any other filesystem — for container-first deployments)
2. Default to `1` (trust-with-checks) so containers work out of the box.
3. Userspace sets this based on a CLI flag `--overlayfs-trust=check|reject|trust`.

**Files:**
- `bpf/aegis_common.h:841` — overlayfs magic check
- `bpf/aegis_common.h:831-862` — `file_is_verified_exec_identity()` function
- `src/bpf_config.cpp` — write the new config field to `.bss`
- `src/types.hpp` — add the config field to `AgentConfig`

### 1.2 Gate PROTECT_* Flags Behind Runtime Capability Probes
**Problem:** Enabling `EXEC_IDENTITY_FLAG_PROTECT_CONNECT` or `PROTECT_FILES` on a cluster with overlay rootfs silently blocks everything.

**Change:**
1. At daemon startup, probe the root filesystem type of a representative container cgroup.
2. If OverlayFS is detected and `overlayfs_trust_mode == 0` (reject), emit a **hard warning** and refuse to enable PROTECT_CONNECT/PROTECT_FILES unless `--force-protect` is set.
3. Log the conflict clearly: `"PROTECT_CONNECT requires overlayfs trust; set --overlayfs-trust=check or disable protect mode"`

**Files:**
- `src/daemon.cpp` — startup validation
- `src/bpf_config.cpp` — flag gating logic

### 1.3 Document Container Deployment Modes
**Change:** Add `docs/CONTAINER_DEPLOYMENT.md` documenting the three identity modes, which flags are safe for containers, and a decision tree for operators.

---

## Phase 2: Hardened Inode Identity (3-5 days)
*Eliminate inode-reuse and path-drift vulnerabilities*

### 2.1 Extend `inode_id` Key with Generation Field
**Problem:** `struct inode_id { ino, dev, pad }` at `bpf/aegis_common.h:280` can collide after inode reuse (file delete + create reuses same inode number). High-churn environments (CI, container builds) hit this in practice.

**Change:**
```c
struct inode_id {
    __u64 ino;       /* inode number */
    __u32 dev;       /* device number */
    __u32 gen;       /* inode generation (i_generation) or ctime_nsec */
};
```
- When `i_generation` is available (most local filesystems), use it. It increments on inode reuse.
- Fallback: use `ctime_nsec` as a tie-breaker (changes on every metadata update, good enough for collision avoidance).
- Userspace policy resolver must populate `gen` when building deny entries.

**Files:**
- `bpf/aegis_common.h:280-284` — struct definition
- `bpf/aegis_file.bpf.h:33-35` — key construction in file_open
- `bpf/aegis_exec.bpf.h:264-266` — key construction in exec
- All userspace code that builds `inode_id` keys: `src/policy_runtime.cpp`, `src/bpf_maps.cpp`

### 2.2 Add Path→Inode Reconciliation Loop
**Problem:** If userspace builds deny rules from paths but enforcement is inode-based, any rename/replace invalidates the rule.

**Change:** In the daemon event loop, periodically (every 60s) re-stat deny_path entries and reconcile `deny_inode_map` with fresh `(dev, ino, gen)` tuples. Log when a path→inode mapping changes (indicates file replacement).

**Files:**
- `src/daemon.cpp` — add reconciliation timer
- `src/policy_runtime.cpp` — add `reconcile_inode_map()` function

---

## Phase 3: Atomic Policy Commits (2-3 days)
*Eliminate partial-update windows*

### 3.1 Add Policy Generation Counter
**Problem:** `sync_from_shadow()` in `src/bpf_maps.cpp:212` updates maps sequentially. Between the first and last sync, BPF programs see inconsistent state (e.g., network deny updated but file deny not yet).

**Change:**
1. Add a new single-entry BPF array map `policy_generation` (`__u64`).
2. Before sync: write `generation + 1` to a "pending" slot.
3. After all maps are synced: atomically write `generation + 1` to the active slot.
4. BPF hooks read `policy_generation` at the start of each invocation. If it's mid-update (pending != active), use the previous generation's rules (effectively stale-read, which is safe).

**Simpler alternative (recommended):** Since BPF map updates are per-entry atomic, the real risk is "network rules updated, file rules stale." Add a `policy_ready` flag in `agent_cfg` (.bss):
1. Userspace sets `agent_cfg.policy_updating = 1` before sync.
2. BPF hooks check this flag. While set, continue enforcing the old rules (skip new entries).
3. After all syncs complete, set `agent_cfg.policy_updating = 0`.

This is simpler, avoids new maps, and the window is milliseconds.

**Files:**
- `bpf/aegis_common.h` — add `policy_updating` to agent config struct
- `src/bpf_config.cpp` — set/clear the flag
- `src/policy_runtime.cpp:399-422` — wrap sync phase with flag toggle
- All BPF hooks — add early check for `policy_updating` (return current-behavior, not new deny)

---

## Phase 4: Per-Cgroup Policy Scoping (5-7 days)
*Enable multi-tenant Kubernetes deployments*

### 4.1 Add Cgroup-Scoped Deny Maps
**Problem:** All deny maps are global. The only per-workload control is `allow_cgroup_map` (bypass all enforcement). Multi-tenant clusters need targeted denies per namespace/workload.

**Change:** Add parallel "scoped" maps:
```c
struct cgroup_inode_key {
    __u64 cgid;
    struct inode_id inode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_INODE_ENTRIES);
    __type(key, struct cgroup_inode_key);
    __type(value, __u8);
} deny_inode_cgroup_map SEC(".maps");
```

Similarly for network rules:
```c
struct cgroup_net_key {
    __u64 cgid;
    __u32 addr;   /* or full net rule key */
};
```

### 4.2 Two-Tier Lookup in BPF Hooks
**Change:** Each hook does:
1. Get `cgid = bpf_get_current_cgroup_id()`
2. Check `allow_cgroup_map` — if found, skip enforcement (existing behavior)
3. Check `deny_inode_cgroup_map` with `(cgid, inode_id)` — if found, deny
4. Fallback to global `deny_inode_map` — if found, deny
5. Allow

This is backward-compatible: existing global-only deployments work unchanged. Cgroup-scoped rules are additive.

### 4.3 Operator CRD Integration
**Change:** The Kubernetes operator translates namespace-scoped `AegisPolicy` CRDs into cgroup-scoped map entries by resolving namespace → cgroup ID mapping via the identity cache.

**Files:**
- `bpf/aegis_common.h` — new map definitions, new key structs
- `bpf/aegis_file.bpf.h` — two-tier lookup
- `bpf/aegis_net.bpf.h` — two-tier lookup
- `bpf/aegis_exec.bpf.h` — two-tier lookup
- `src/bpf_ops.cpp` — discover new maps
- `src/policy_runtime.cpp` — populate cgroup-scoped maps
- `operator/controllers/` — cgroup ID resolution

---

## Phase 5: Resilient Enforcement Modes (2-3 days)
*Make enforcement survive agent downtime*

### 5.1 Add Fail-Static Mode
**Problem:** Deadman switch at `bpf/aegis_common.h:881-884` forces audit-only on expiry. This means enforcement silently stops if the daemon crashes or hangs. Tetragon's model ("enforcement continues during downtime") is the industry expectation.

**Change:** Add `agent_cfg.deadman_mode`:
- `DEADMAN_FAILSAFE_AUDIT` (0) — current behavior: expire → audit (fail-open)
- `DEADMAN_FAILSAFE_STATIC` (1) — expire → keep last-known enforcement (no changes)
- `DEADMAN_FAILSAFE_LOCKDOWN` (2) — expire → deny all (fail-closed, for high-assurance)

In fail-static mode, BPF programs ignore the deadline and continue enforcing whatever rules are in maps. The daemon not refreshing the heartbeat only stops *new* policy updates and telemetry collection.

**Files:**
- `bpf/aegis_common.h:864-888` — `get_effective_audit_mode()` — add mode check
- `src/types.hpp` — add `deadman_mode` to config
- `src/daemon.cpp` — CLI flag `--deadman-mode=audit|static|lockdown`
- `src/bpf_config.cpp` — write to .bss

### 5.2 Clear State Signaling
**Change:** Add a `runtime_state` map (single-entry) that BPF hooks write to on each enforcement decision:
- `ENFORCING` — normal operation
- `ENFORCING_STALE` — deadman expired but fail-static active (last-known rules)
- `AUDIT_ONLY` — deadman forced audit
- `LOCKDOWN` — deadman forced deny-all

Userspace reads this for Prometheus metrics (`aegisbpf_enforcement_state`). Operators get clear visibility into whether enforcement is live, stale, or degraded.

---

## Phase 6: Performance Hardening (2-3 days)
*Address audit's performance concerns*

### 6.1 Add `net_policy_empty` / `file_policy_empty` Fast-Path Audit
**Status:** These already exist in the code. Verify they are correctly maintained across all policy update paths (shadow sync, direct apply, rollback).

### 6.2 Benchmark `bpf_d_path()` on Exec Path
**Problem:** `bpf_d_path()` in the verified-exec computation can be slow in complex mount namespace layouts.

**Change:** Add a configurable toggle `agent_cfg.exec_identity_use_dpath` (default: true). When disabled, skip the trusted-root-path check and rely only on ownership/fsverity/allowlist. Measure the performance delta.

### 6.3 Ringbuf Backpressure Documentation
**Status:** Already implemented (dual-path backpressure with PERCPU_ARRAY counters). Document the expected behavior: enforcement is never conditioned on ringbuf capacity; only telemetry is dropped.

---

## Phase Summary

| Phase | Effort | Risk Reduction | Ships Independently |
|-------|--------|---------------|-------------------|
| **0: Safety Fixes** | 1-2d | High (eliminates outage-causing bugs) | Yes |
| **1: Container Identity** | 3-5d | Critical (unblocks all K8s deployments) | Yes |
| **2: Inode Hardening** | 3-5d | High (eliminates TOCTOU class) | Yes |
| **3: Atomic Commits** | 2-3d | Medium (prevents policy split-brain) | Yes |
| **4: Cgroup Scoping** | 5-7d | High (enables multi-tenancy) | Yes |
| **5: Resilient Modes** | 2-3d | High (matches Tetragon posture) | Yes |
| **6: Performance** | 2-3d | Medium (validates audit claims) | Yes |

**Total estimated effort: 19-28 days**
**Recommended order: 0 → 1 → 5 → 3 → 2 → 4 → 6**
(Safety first, then unblock containers, then resilience, then correctness, then multi-tenancy)

---

## Success Criteria

After all phases:
- [ ] OverlayFS containers get valid exec identity (PROTECT_CONNECT works on K8s)
- [ ] Inode reuse cannot cause policy cross-contamination
- [ ] Policy updates are atomic from the kernel's perspective
- [ ] Per-namespace deny rules work on multi-tenant clusters
- [ ] Agent crash does not silently disable enforcement
- [ ] All parse errors fail-open with metric visibility
- [ ] No hardcoded kernel constants in enforcement paths
- [ ] Zero duplicated code in attach paths
- [ ] Competitive benchmark shows <5% overhead on file_open
