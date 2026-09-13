# Atomic Policy Swap — Design

**Date:** 2026-09-13
**Status:** Approved, pending implementation
**Scope:** `bpf/aegis_common.h`, `src/policy_runtime.cpp`, `src/bpf_config.cpp`, `src/bpf_ops.cpp`, tests

## Problem

Every policy reload degrades enforcement to audit-only.

`get_effective_audit_mode()` in `bpf/aegis_common.h:1063` returns audit when the
committed policy generation does not match the expected one:

```c
/* Policy generation mismatch: maps are mid-update -- force audit to
 * avoid enforcing a partially-synced ruleset. */
if (!is_policy_consistent())
    return 1;
```

Userspace deliberately opens that window. `policy_runtime.cpp:518` bumps the
generation immediately before copying shadow maps into live maps, and commits
the matching value afterwards (`policy_runtime.cpp:943`, `:1013`). The comment at
`policy_runtime.cpp:285-290` documents the intent.

The window exists because the final step is a copy. `sync_from_shadow()`
(`policy_runtime.cpp:533-556`) moves entries element by element into the live
maps, and an element-by-element copy cannot be atomic. Audit-only is the
fallback chosen to avoid enforcing a half-written ruleset.

This is a security defect, not only an architectural wart. For the duration of
every reload, a mandatory access control engine stops denying. An attacker who
can trigger or merely predict a reload gets a window in which the agent is a
logger. For a MAC system, fail-safe must mean *keep enforcing the previous
policy*, never *stop enforcing*.

### What is already correct

The shadow machinery is sound and is retained. `create_shadow_map_set()`
(`policy_runtime.cpp:295`) builds fully populated shadow maps off to the side,
and the existing entry-count verification (`policy_runtime.cpp:495-515`) checks
them before anything live is touched. Only the commit step is wrong.

## Goals

1. No policy reload may reduce enforcement, at any point, for any duration.
2. A reload is observed either entirely or not at all, across **all** policy
   domains — file, network, and cgroup rules never mix generations.
3. A failed reload leaves the previous policy enforcing, untouched.
4. No regression in hot-path latency or verifier budget.

### Non-goals

- Changing policy semantics, the policy language, or the rule set.
- Changing how single-element dynamic denies (TTL registry) are applied.
- Reworking stats, event, or process-state maps.

## Design

### Map layout

Each policy map becomes an outer `BPF_MAP_TYPE_ARRAY_OF_MAPS` with
`max_entries = 2`, holding right-sized inner maps. One additional map,
`active_slot` (`BPF_MAP_TYPE_ARRAY`, one `u32`), names the live slot. It follows
the existing `policy_generation` precedent: a dedicated single-entry array map
is a clean single-word commit point.

Two slots are required by goal 2. Userspace populates the **inactive** slot —
16 separate, individually non-atomic writes that no hook observes — and then
flips `active_slot` once. That single `u32` write is the only observable
transition, so all domains change together.

**Policy maps to convert (16):**

| Domain | Maps |
| --- | --- |
| File/exec | `deny_inode_map`, `deny_path_map`, `deny_comm_map`, `allow_cgroup_map`, `allow_exec_inode_map`, `trusted_exec_hash` |
| Network | `deny_ipv4`, `deny_ipv6`, `deny_port`, `deny_ip_port_v4`, `deny_ip_port_v6`, `deny_cidr_v4`, `deny_cidr_v6` |
| Cgroup | `deny_cgroup_inode`, `deny_cgroup_ipv4`, `deny_cgroup_port` |

Fifteen of these are the maps `sync_from_shadow()` currently writes.
`trusted_exec_hash` is the sixteenth: it is policy-derived (it appears in
`reset_policy_maps()`) but today **bypasses the shadow path entirely** and is
written directly to the live map. That is a latent inconsistency — exec-trust
rules can currently straddle a reload independently of every other domain.
Bringing it into the slot mechanism fixes it, and is required by goal 2.

**Explicitly not converted.** Stats, event, and runtime-state maps stay live and
unslotted: `process_tree`, `dead_processes`, `events`, `priority_events`,
`diagnostics`, `backpressure`, `hook_latency`, `enforce_signal_state`,
`agent_meta_map`, `exec_identity_mode_map`, `event_approver_*`, and all
`*_stats` maps. These carry observed state, not policy; swapping them would
discard live data.

`survival_allowlist` is also **not** converted. It holds "critical binaries that
can NEVER be blocked" (`bpf/aegis_common.h:446`), is managed by its own CLI
(`aegis survival list` / `verify`), and is not populated from the policy file.
Swapping it on every reload would risk momentarily presenting an empty
never-block list — the opposite of the safety property it exists to provide.

`deny_cidr_v4` and `deny_cidr_v6` are `BPF_MAP_TYPE_LPM_TRIE`; all other policy
maps are `BPF_MAP_TYPE_HASH`.

### Memory

Policy hash maps are preallocated, so today they consume `max_entries` worth of
locked memory regardless of rule count — 65536 slots for `deny_inode_map` even
with ten rules, roughly 20–25 MB across the policy surface.

Inner maps are created sized to the actual rule count plus headroom. After the
flip, the now-inactive slots are deleted, dropping the old inner maps' refcount
so the kernel RCU-frees them. Steady state is therefore **~1× actual rule
count**, below today's 1× preallocated maximum, with a transient 2× during a
reload.

Headroom exists so that runtime single-element inserts (dynamic/TTL denies) do
not hit `max_entries` between reloads. Sizing: `max(64, rules * 2)`.

### Hot path

```c
__u32 z = 0;
__u32 *sp = bpf_map_lookup_elem(&active_slot, &z);
__u32 slot = sp ? *sp : 0;                      /* read ONCE per hook */
void *inner = bpf_map_lookup_elem(&deny_inode_outer, &slot);
if (inner)
    bpf_map_lookup_elem(inner, &key);
```

Cost is close to neutral for the index read: `is_policy_consistent()`'s lookup
of `policy_generation` is removed and the `active_slot` lookup replaces it. The
new cost is one outer-map indirection per policy map actually consulted.

**Invariant — single slot read.** `slot` MUST be read once at hook entry and
threaded through every helper in that invocation. Re-reading it mid-hook can
straddle a flip and evaluate old file rules against new network rules, which
defeats goal 2. This is enforced by passing `slot` as an explicit parameter
rather than re-reading a global, and is covered by a dedicated test.

**Empty-slot semantics.** A `NULL` inner map means the slot is unpopulated,
which must be treated as *the map is empty* — identical to today's behavior for
an empty map. For denylists that means no match (allow); for allowlists
(`allow_exec_inode_map`, `allow_cgroup_map`,
`trusted_exec_hash`) an empty map has different meaning and is already mediated
by `refresh_policy_empty_hints()` and `exec_identity_mode_map`. Those hints keep
their current semantics and must be recomputed from the **new** inner maps
before the flip, not after — otherwise a window exists where hints describe the
old generation. This is the highest-risk detail in the change: inverting it
turns an allowlist into an allow-all.

### Commit protocol

```
1. snapshot rule set
2. for each policy map: create right-sized inner map
3. populate all inner maps
4. verify entry counts                     (reuses existing verification)
5. compute policy-empty hints from new inner maps
6. insert each inner -> outer[inactive]    (16 writes, unobserved)
7. FLIP: update(active_slot, 0, inactive)  <-- single atomic commit
8. delete outer[now-inactive]              -> kernel RCU-frees old inner maps
9. bump policy_generation                  (observability only)
```

Failure at any of steps 1–6 returns an error without flipping. The old policy
remains live and enforcing. This is the fail-safe behavior required by goal 3.

### Removals

- `is_policy_consistent()` and its call site in `get_effective_audit_mode()`
  (`bpf/aegis_common.h:1023-1037`, `:1063-1066`).
- `bump_policy_generation()`'s enforcement role (`src/bpf_config.cpp:301`); the
  function remains but only advances an observability counter.
- The bulk direct-apply fallback branch (`src/policy_runtime.cpp:558+`).

The `policy_generation` map is **kept**. It no longer gates enforcement but
still reports which generation is live, which `aegis explain` and the posture
output consume. Its pin path (`kPolicyGenerationPin`) is unchanged.

### Direct-apply fallback removal

Today, if `create_shadow_map_set()` fails, the code falls back to mutating live
maps in place (`policy_runtime.cpp:293-306`), which reopens the audit window.
That fallback is removed. If inner-map creation fails, the reload fails and the
previous policy keeps enforcing.

This is a deliberate behavior change: a reload that previously succeeded in
degraded mode now fails cleanly. Failing safe is correct for a MAC engine, and
it collapses two apply paths into one.

Single-element dynamic denies (TTL registry, `src/ttl_registry.hpp`) are
unaffected. They write one element at a time into the live inner map; per-element
map updates are already atomic and need no slot machinery.

### Pinning and restart

`src/bpf_ops.cpp` pins maps and reuses them across agent restarts
(`try_reuse_optional`, `bpf_ops.cpp:543-549`). Outer maps and `active_slot` are
pinned; inner maps need no pins of their own because the outer slot holds a
reference that keeps them alive.

Consequence to verify, not assume: policy should now survive an agent restart
intact, because the pinned outer maps still reference populated inner maps.

## Compatibility

| Requirement | Version | Note |
| --- | --- | --- |
| `BPF_MAP_TYPE_ARRAY_OF_MAPS` | 4.12+ | Below the project floor; no concern. |
| `LPM_TRIE` as inner map | verified 7.0 | Must be confirmed at 5.14/5.15 on the matrix. |
| Inner `max_entries` ≠ template | **5.11+** | `bpf_map_meta_equal()` stopped comparing `max_entries` in 5.11. |

The project floor is kernel 5.8+ with BTF (`README.md:551`), while the CI matrix
runs 5.14, 5.15, 6.1, 6.5, 6.6, 6.8. Right-sizing therefore requires 5.11+.

**Fallback for 5.8–5.10:** detect the capability at startup; if unavailable,
create inner maps at the template's `max_entries` instead of right-sized. The
swap remains fully atomic — only the memory saving is lost. This keeps the
declared floor intact.

Verified locally on kernel 7.0.0-28-generic: `LPM_TRIE` inner maps insert into an
`ARRAY_OF_MAPS`, a populated live slot can be replaced in place, and an inner map
whose `max_entries` differs from the template is accepted.

## Testing

**The decisive test.** Hammer a denied operation from N threads while reloading
policy in a loop; assert zero operations are allowed. This fails against the
current code — the audit window is precisely when a deny leaks — and passes
after the change. It is the regression proof for the whole effort.

Additional coverage:

- **Cross-domain atomicity.** A policy whose file and network rules must agree;
  flip repeatedly under load and assert the two are never observed from
  different generations. Covers the single-slot-read invariant.
- **Fail-safe reload.** Force inner-map creation to fail; assert no flip occurs,
  the old policy still denies, and the error surfaces.
- **Allowlist empty-slot semantics.** Assert an unpopulated allowlist slot does
  not become allow-all.
- **Restart reuse.** Restart the agent against pinned outer maps; assert policy
  is still enforced without re-application.
- **Memory.** Assert steady-state locked memory for a small policy is below the
  current preallocated baseline.
- **Verifier budget.** Re-run veristat across the matrix; inner-map lookups add
  instructions to every hook.
- **Kernel matrix.** Confirm `LPM_TRIE`-as-inner and the 5.11 `max_entries`
  behavior at 5.14/5.15.

## Risks

| Risk | Mitigation |
| --- | --- |
| Allowlist empty-slot inversion turns deny into allow-all | Hints computed pre-flip from new inner maps; dedicated test |
| Slot re-read mid-hook mixes generations | `slot` passed explicitly as a parameter; cross-domain test |
| Verifier budget exceeded on some hook | veristat across matrix before merge |
| `LPM_TRIE` inner unsupported at floor | Confirm on matrix; CIDR maps keep a non-slotted path if not |
| Right-sizing unsupported below 5.11 | Runtime capability probe, template-sized fallback |

## Out of scope

Capability enforcement, source-aware (`fromSource`) rules, and the differential
policy oracle are separate milestone items and are not part of this change.
