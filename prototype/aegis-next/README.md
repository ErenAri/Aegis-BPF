# aegis-next (prototype)

> **Status: PROTOTYPE — all 4 phases fully implemented. Breaking changes still expected. Not for production.**
>
> This directory is an isolated playground for the post-2024 BPF
> stack (BPF arena maps, sched_ext, open-coded iterators). It is
> **not** linked into the shipped `aegisbpf` daemon, does **not**
> ship in release packages, and is gated behind a separate CMake
> flag so a casual build is unaffected.
>
> All Phase 1–4 roadmap items are implemented and tested. See
> [`ROADMAP.md`](ROADMAP.md) for the full status table.

## Why this exists

AegisBPF's mainline daemon is designed around the 2019-2023 BPF
toolbox (BPF-LSM, ringbufs, CO-RE, kprobes). Every comparable
security agent we surveyed (Cilium Tetragon, Falco, Tracee,
KubeArmor, Pixie) sits on the same toolbox. None of them are
load-bearing on the features that landed in kernels 6.6 – 6.14:

| Feature                          | Kernel | Used by surveyed agents? |
|----------------------------------|--------|--------------------------|
| BPF arena maps (`BPF_MAP_TYPE_ARENA`) | 6.9  | No (one Cilium experiment for LPM tries) |
| sched_ext (BPF-defined scheduler class) | 6.12 | No |
| Open-coded iterators              | 6.4   | Opportunistic only (Tetragon, Cilium toFQDN) |
| BPF tokens (delegated privilege)  | 6.9   | Pixie attempted, hit verifier-limit fallback (#2040); cilium/ebpf library gap (#43587) |
| BPF exceptions (`bpf_throw`)      | 6.7   | No — CVE-2026-31526 (April 2026) makes them unsafe today |

The `aegis-next` track is a research split that asks: **what does
an LSM agent look like when the post-2024 features are foundation,
not garnish?**

## What this prototype demonstrates

A complete in-kernel security agent built on post-2024 BPF primitives
that no shipping agent uses as foundation today.

An 82 MiB BPF arena map (`aegis_next_arena`) is allocated at load
time. Nine LSM hooks write 80-byte `prov_node` records directly into
the arena — no perfbuf, no per-event syscall round-trip. A 2MB
ringbuf carries compact alerts for sub-ms notification. Policy
evaluation, rate limiting, quarantine bridging, binary authorization,
and file security labeling all run entirely in-kernel.

Userspace `mmap(2)`s the arena read-only and walks the slot array
on demand. The header at offset 0 carries a monotonic
`next_index` cursor, so userspace can tail it like a log without
ever issuing a `bpf_map_lookup_elem`.

```text
  ┌───────────────────────────────────────────────────────────┐
  │ aegis_next_arena (BPF_MAP_TYPE_ARENA, 82 MiB, mmapable)   │
  │                                                           │
  │  ┌────────────┐  ┌────────────────────────────────────┐   │
  │  │ prov_header│  │ prov_node[0..1<<20]                │   │
  │  │  next_idx  │  │  {pid,ppid,tgid,uid,cgid,ino,      │   │
  │  └────────────┘  │   prev_index ─┐, ...}              │   │
  │                  └───────────────│────────────────────┘   │
  └──────────────────────────────────│────────────────────────┘
       ▲  ▲                          │     ▲
       │  │                          │     │ userspace mmap
       │  │ BPF lsm/bprm_check_security    │
       │  │                          │     │
       │  ├──────────────────────────┘     │
       │  │
       │  ▼
       │  ┌──────────────────────────────────┐
       │  │ aegis_next_pid_slot (LRU_HASH)   │
       │  │  tgid -> last slot in prov_node  │
       │  │  used to populate prev_index     │
       │  └──────────────────────────────────┘
       │
   bpf_arena_alloc_pages() once, lazily, from inside BPF
```

### Important constraint: no kernel pointers in the arena

KASLR forbids arena content from holding raw kernel pointers. The
provenance graph therefore uses **synthetic IDs only**:

- `pid`, `ppid`, `tgid` from `task_struct`
- `cgid` from `bpf_get_current_cgroup_id`
- `exec_inode` from `bprm->file->f_inode->i_ino`

Adjacency between nodes is encoded as a `prev_index` integer into
the same slot array, not as a pointer. This makes the structure
mmapable into userspace without violating arena rules.

## Building

The prototype is **off by default**. To opt in:

```bash
cmake -DBUILD_AEGIS_NEXT=ON -S . -B build
cmake --build build --target aegisbpf-next
```

Configure aborts the prototype subdirectory with a clear `WARNING`
message (not an error) on kernels older than 6.9, so the rest of
the tree still builds for contributors on LTS hosts.

The binary lands at `build/prototype/aegisbpf-next`.

## Running

```bash
# Attach LSM hooks + start event recording
sudo ./build/prototype/aegisbpf-next attach

# In another terminal:
sudo ./build/prototype/aegisbpf-next status          # system overview
sudo ./build/prototype/aegisbpf-next graph dump       # recent events
sudo ./build/prototype/aegisbpf-next graph lineage 1  # walk pid 1
sudo ./build/prototype/aegisbpf-next policy load examples/policy.rules
sudo ./build/prototype/aegisbpf-next export tail 20   # last 20 JSONL events

# Optional: sched_ext quarantine + self-protection
sudo ./build/prototype/aegisbpf-next sched start      # in another terminal
sudo ./build/prototype/aegisbpf-next protect           # in another terminal

# Phase 4: binary authorization (kernel 6.7+, CONFIG_FS_VERITY)
sudo ./build/prototype/aegisbpf-next auth start --audit
sudo ./build/prototype/aegisbpf-next auth trust 0123456789abcdef...
sudo ./build/prototype/aegisbpf-next auth list
sudo ./build/prototype/aegisbpf-next auth stats

# Phase 4: rate limiting
sudo ./build/prototype/aegisbpf-next rate set fork 30   # 30 forks/sec max
sudo ./build/prototype/aegisbpf-next rate set conn 50   # 50 connects/sec max
```

Requires:
- **Arena mode** (full): Linux >= 6.9 with `CONFIG_BPF_LSM=y` and
  `lsm=` boot param including `bpf`.
- **Ringbuf-only mode** (fallback): Linux >= 5.11 with
  `CONFIG_BPF_LSM=y`. Automatically selected when arena maps are
  unavailable. Graph/lineage commands are not available; events are
  exported to JSONL only.
- Linux >= 6.12 with `CONFIG_SCHED_CLASS_EXT=y` for `sched`
  subcommands.
- `CAP_BPF` + `CAP_SYS_ADMIN` (typical: run as root).

## What's wired up so far

### Phase 1 — Arena Infrastructure

- ✅ **P1.1 Arena hash table.** O(1) lookup by composite key
  `(kind<<56|id)`, 64K buckets, 8-step linear probe. Replaces
  the old linear scan for lineage walks.
- ✅ **P1.2 Path slab.** 4K × 256B arena-resident slots for
  resolved file paths via `bpf_d_path`. Atomic bump allocator
  with wrap-around.
- ✅ **P1.3 Network 5-tuple slab.** 4K × 48B slots for full
  flow records (family, proto, src/dst IP+port). `socket_bind`
  and `socket_listen` hooks added.
- ✅ **P1.4 Namespace awareness.** `mnt_ns` and `pid_ns` fields
  in each 80-byte provenance node for container identification.
- ✅ **P1.5 Ringbuf hybrid.** 2MB `BPF_MAP_TYPE_RINGBUF` for
  sub-millisecond event notification. Arena remains source of truth;
  ringbuf carries compact alerts (slot + pid + kind).

### Phase 2 — Enforcement & Self-Protection

- ✅ **P2.1 LSM deny path.** `BPF_MAP_TYPE_HASH` policy map with
  FNV-1a comm hash matching. `evaluate_policy()` checks comm, port,
  and cgroup rules, returning `-EPERM` on deny.
- ✅ **P2.2 Expanded LSM hooks.** 9 hooks total: `bprm_check_security`,
  `file_open`, `socket_connect/bind/listen`, `file_permission` (FIM),
  `mmap_file` (W+X prevention), `task_alloc` (fork bomb),
  `kernel_module_request` (rootkit prevention).
- ✅ **P2.3 In-kernel enforcement bridge.** QUARANTINE policy action
  writes cgroup→level directly to the sched_ext quarantine map from
  BPF. Latency: <1μs (vs ~1s userspace round-trip).
- ✅ **P2.4 Policy file loader.** Line-based policy format with
  hot-reload. Supports deny/allow/log/quarantine actions + kill flag.
- ✅ **P2.5 Tiered sched_ext enforcement.** Three quarantine levels:
  throttle (1ms slice), pin (CPU 0 isolation), starve (100μs).
  Per-CPU stats counters for observability.
- ✅ **P2.6 Self-protection.** `lsm/bpf` + `lsm/bpf_map` hooks deny
  program detach and map tampering from non-trusted callers. Caller
  identity verified via binary inode comparison.

### Phase 3 — Production Readiness

- ✅ **P3.2 Runtime feature probing.** Probes BPF LSM, arena maps,
  ringbuf, sched_ext at startup. Fails early with clear messages.
- ✅ **P3.3 Test suite.** 39 GTest cases across 10 test suites:
  layout assertions, lineage walk, pid lookup, generation, FNV-1a
  hash, hash table, path/net slab helpers.
- ✅ **P3.4 JSONL event export.** Arena events written as JSONL
  with ISO 8601 timestamps, full node context, path + flow data.
  File rotation at 50MB. `export tail [N]` subcommand.
- ✅ **P3.5 Status command.** `status` shows feature probes, arena
  utilization, policy rule count, quarantine entries, export file.
- ✅ **P3.6 Arena pre-fault.** Touches every 4K page at startup to
  eliminate major page fault latency spikes.
- ✅ **P3.1 Ringbuf-only fallback.** Separate BPF program
  (`provenance_legacy.bpf.c`) for kernels < 6.9 that lack arena
  maps. Same 9 LSM hooks, same policy/quarantine enforcement, but
  full events (~372B) flow through the ringbuf. Feature probe at
  startup auto-selects arena or legacy mode. JSONL export works in
  both modes; graph/lineage commands require arena mode.

### Phase 4 — Beyond the State of the Art (no competitor has these)

- ✅ **P4.1 In-kernel binary authorization.** Complete fsverity digest →
  trusted-list lookup → xattr cache pipeline running entirely in-kernel.
  `bpf_get_fsverity_digest()` + `bpf_get_file_xattr()` +
  `bpf_set_dentry_xattr()` + `bpf_verify_pkcs7_signature()`.
  Enforce/audit/disable modes. Separate `binary_auth.bpf.c` program.
- ✅ **P4.2 user_ringbuf policy channel.** Zero-copy policy hot-reload
  via `BPF_MAP_TYPE_USER_RINGBUF`. Userspace writes policy batches;
  BPF callback processes add/delete/flush without syscall overhead.
- ✅ **P4.3 In-kernel rate limiting.** Per-cgroup sliding window rate
  tracker. Automatically quarantines cgroups exceeding fork/conn/file
  thresholds. Configurable via `rate set` CLI.
- ✅ **P4.4 File security labeling.** `bpf_set_dentry_xattr()` writes
  "security.aegis.seen" on accessed files — persistent forensic trail
  surviving process exit. Degrades gracefully on kernel < 6.13.
- ✅ **P4.5 Targeted signal delivery.** `bpf_send_signal_task()` sends
  SIGKILL to specific tasks by reference (6.13+). Falls back to
  `bpf_send_signal()` on older kernels.
- ✅ **P4.6 Extended feature probes.** Runtime detection of user_ringbuf,
  fsverity, xattr kfuncs, and composite binary_auth availability.

### Infrastructure

- ✅ **CI workflow.** `.github/workflows/aegis-next.yml` triggers on
  prototype changes. Kernel ≥ 6.9 gets full BPF compile; older
  runners build and run the userspace test suite only.
- ✅ **Generational eviction.** Arena header carries a `generation`
  counter. Stale nodes are detected during lineage walks.
- ✅ **In-kernel GC.** `bpf_timer` fires every 30s, sweeps
  `pid_slot` LRU hash for overwritten entries.
- ✅ **Exec catch-up.** Open-coded task iterator seeds the arena
  with existing processes at attach time.

## What's deliberately deferred indefinitely

- **BPF exceptions** (`bpf_throw`). CVE-2026-31526 (April 2026)
  showed the unwind path leaks unrefcounted resources, creating a
  privilege-escalation primitive. Will revisit only if the
  upstream fix lands with a clear "safe to use" signal.
- **Per-namespace BPF tokens**. Pixie's #2040 (4096-instruction
  verifier fallback) and cilium/ebpf's #43587 (no library bindings)
  mean the ecosystem isn't ready. Mainline AegisBPF keeps the
  capability-based model until both are resolved.

## What sets this apart from every other eBPF security agent

No open-source runtime security agent (Falco, Tetragon, Tracee,
KubeArmor) uses any of these BPF primitives as load-bearing
infrastructure. aegis-next combines all of them in a single program:

- **BPF arena maps** (6.9+) for zero-syscall provenance graph traversal
- **sched_ext** (6.12+) for CPU-level quarantine enforcement
- **user_ringbuf** for zero-copy policy hot-reload
- **bpf_set_dentry_xattr** (6.13+) for persistent file security labeling
- **bpf_send_signal_task** (6.13+) for targeted process termination
- **bpf_get_fsverity_digest** (6.7+) for in-kernel binary authorization
- **Open-coded task iterator** for catch-up process seeding at attach time
- **BPF timer** for in-kernel garbage collection (no userspace polling)

## Graduation path

Components in `aegis-next` graduate back into mainline `src/` only
when they satisfy ALL of:

1. Behavior is stable across at least two consecutive kernel
   minor versions.
2. A fallback exists for kernels below the feature's introduction.
3. Test coverage matches mainline standards
   (`tests/test_*.cpp` Google Test, fuzz harness if input-driven).
4. Hardening review of the new attack surface lands in
   `docs/HARDENING.md`.

Until then, breaking changes to the prototype's on-arena layout,
program section names, and CLI are explicitly allowed without
deprecation cycles.
