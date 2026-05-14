# aegis-next (prototype)

> **Status: PROTOTYPE — breaking changes expected. Not for production.**
>
> This directory is an isolated playground for the post-2024 BPF
> stack (BPF arena maps, sched_ext, open-coded iterators). It is
> **not** linked into the shipped `aegisbpf` daemon, does **not**
> ship in release packages, and is gated behind a separate CMake
> flag so a casual build is unaffected.

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

A 64 MiB BPF arena map (`aegis_next_arena`) is allocated at load
time. On every successful exec (`lsm/bprm_check_security`) the BPF
program writes one `prov_node` record directly into the arena —
no perfbuf, no ringbuf, no per-event syscall round-trip.

Userspace `mmap(2)`s the arena read-only and walks the slot array
on demand. The header at offset 0 carries a monotonic
`next_index` cursor, so userspace can tail it like a log without
ever issuing a `bpf_map_lookup_elem`.

```text
  ┌───────────────────────────────────────────────────────────┐
  │ aegis_next_arena (BPF_MAP_TYPE_ARENA, 64 MiB, mmapable)   │
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
sudo ./build/prototype/aegisbpf-next
# exec stuff in another terminal...
# Ctrl-C to dump the recorded provenance nodes.
```

Requires:
- Linux >= 6.9 with `CONFIG_BPF_LSM=y` and `lsm=` boot param
  including `bpf`.
- Linux >= 6.12 with `CONFIG_SCHED_CLASS_EXT=y` for `sched`
  subcommands.
- `CAP_BPF` + `CAP_SYS_ADMIN` (typical: run as root).

## What's wired up so far

- ✅ **Arena map + LSM hook + userspace mmap** (scaffold PR).
- ✅ **Hash-indexed parent lookup.** `aegis_next_pid_slot`
  (`BPF_MAP_TYPE_LRU_HASH`, 64K entries) maps `tgid -> last slot
  index`. Each exec records its parent's slot in `prev_index`,
  and userspace can walk the chain backwards to reconstruct
  lineage.
- ✅ **Graph CLI subcommands.** `aegisbpf-next attach`,
  `graph dump`, `graph lineage <pid>`, `graph stats`. Arena map
  is pinned in bpffs so graph commands work from a separate
  process while the daemon is live.
- ✅ **Exec catch-up via open-coded task iterator.** A
  `SEC("syscall")` BPF program runs once after attach, iterating
  all thread-group leaders via `bpf_for_each(task, ...)` (kfuncs
  from Linux 6.4). Seeds the arena with existing processes so
  lineage chains are reachable from attach-time onward — not just
  from the first exec we observe. This is the first load-bearing
  use of open-coded iterators in the prototype.
- ✅ **Multi-hook nodes.** Three LSM hooks now write to the arena:
  `bprm_check_security` (exec, kind=0), `file_open` (kind=1),
  `socket_connect` (kind=2). Non-exec events link to the owning
  exec node (current process's most recent exec) via
  `prev_index`, turning the slot array into a proper provenance
  graph with typed edges. Struct stays at 64 bytes (comm shrunk
  to 12, added kind/flags/extra fields).
- ✅ **sched_ext quarantine scheduler (F2.1).** A minimal
  `struct_ops`-based sched_ext scheduler (`quarantine.bpf.c`)
  proves the load/attach/dispatch wiring. The `.enqueue()`
  callback reads a `BPF_MAP_TYPE_HASH` quarantine map (cgroup
  id → level) and throttles quarantined tasks to a 1 ms time
  slice (vs 5 ms default). Userspace CLI: `sched start` loads
  and attaches the scheduler; `sched quarantine <cgid> <level>`
  writes the map. Requires Linux ≥ 6.12 with
  `CONFIG_SCHED_CLASS_EXT=y`.

## What's deliberately NOT here (yet)

The following are explicitly out of scope and tracked for
follow-up PRs:

- **GC / eviction** beyond modular wrap on overflow and LRU on
  the pid hash.
- **Quarantine map pinning + CLI** (F2.2). Pin the quarantine
  map in bpffs so `sched quarantine` works from a separate process.
- **LSM verdict → quarantine bridge** (F2.3). LSM hooks write
  quarantine entries based on policy violations.
- **Full sched_ext + LSM pipeline** (F2.4). End-to-end:
  policy violation → quarantine map → scheduler throttle.

## What's deliberately deferred indefinitely

- **BPF exceptions** (`bpf_throw`). CVE-2026-31526 (April 2026)
  showed the unwind path leaks unrefcounted resources, creating a
  privilege-escalation primitive. Will revisit only if the
  upstream fix lands with a clear "safe to use" signal.
- **Per-namespace BPF tokens**. Pixie's #2040 (4096-instruction
  verifier fallback) and cilium/ebpf's #43587 (no library bindings)
  mean the ecosystem isn't ready. Mainline AegisBPF keeps the
  capability-based model until both are resolved.

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
