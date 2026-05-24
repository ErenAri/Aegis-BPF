# aegis-next Architecture

## 1. Overview

aegis-next is a BPF-based runtime security agent that builds an in-kernel
provenance graph inside a BPF arena (shared mmap region). Fourteen LSM hooks
record process, file, and network events into a fixed-size arena; a policy
engine evaluates rules in-kernel and returns `-EPERM` to deny violations.
A sched_ext scheduler provides tiered CPU quarantine for offending cgroups,
and an optional binary authorization module verifies executables via fsverity
digests entirely in-kernel.

## 2. System Architecture

```
 Userspace                                        Kernel (BPF)
 =========                                        ============

 +-------------------+                            +-------------------------+
 | aegisbpf-next     |                            | provenance.bpf.c        |
 | (main.cpp)        |                            |   14 LSM hooks          |
 |                   |                            |   record_base()         |
 | mmap(arena fd) ---|------- shared mmap ------->|   arena_nodes[]         |
 | read hdr, nodes   |                            |   arena_ht[]            |
 |                   |                            |   path_slab[]           |
 | poll(ringbuf fd) -|<------ ringbuf alerts -----|   emit_alert()          |
 | 16B aegis_alert   |                            |   (slot, pid, kind)     |
 |                   |                            |                         |
 | bpf_map_update() -|------- policy map -------->|   aegis_next_policy     |
 | user_ringbuf     -|------- policy hot-reload ->|   aegis_policy_ringbuf  |
 |                   |                            |   policy_ringbuf_cb()   |
 +-------------------+                            +-------+---------+------+
                                                          |         |
                                              quarantine  |         | -EPERM
                                              map write   |         | verdict
                                                          v         |
                                                  +-------+------+  |
                                                  | quarantine   |  |
                                                  | .bpf.c       |  |
                                                  | sched_ext    |  |
                                                  | enqueue()    |  |
                                                  | throttle/pin |  |
                                                  +--------------+  |
                                                                    |
                                                  +--------------+  |
                                                  | binary_auth  |  |
                                                  | .bpf.c       |--+
                                                  | fsverity +   |
                                                  | xattr cache  |
                                                  +--------------+

                                                  +--------------+
                                                  | selfprotect  |
                                                  | .bpf.c       |
                                                  | lsm/bpf      |
                                                  | lsm/bpf_map  |
                                                  +--------------+
```

### Data flow summary

1. **LSM hook fires** -> `record_base()` writes an 80B `prov_node` into arena
2. **Arena hash table** updated with `(kind<<56 | id)` -> slot index
3. **16B alert** pushed to ringbuf (slot, pid, kind)
4. **Policy evaluated** in-kernel: comm -> port -> cgroup -> verdict
5. **Quarantine bridge**: `POLICY_ACTION_QUARANTINE` writes cgroup ID directly
   to the shared quarantine map (no userspace round-trip)
6. **Userspace** mmaps the arena fd, polls the ringbuf for wakeups

## 3. Arena Layout

Total arena size: `AEGIS_NEXT_ARENA_PAGES = 21041` pages (86,179,856 bytes).

```
Offset (bytes)       Size              Content
---------------------------------------------------------------------------
0x0000_0000 (0)      32 B              arena_hdr (prov_header)
0x0000_0020 (32)     83,886,080 B      arena_nodes[1M] (80 B x 1,048,576)
0x0500_0020          4 B               arena_ready (int)
0x0500_0024          4 B               (padding)
0x0500_0028          1,048,576 B       arena_ht[64K] (16 B x 65,536)
0x0510_0028          8 B               path_slab_next (u64 bump ptr)
0x0510_0030          1,048,576 B       path_slab[4K] (256 B x 4,096)
0x0520_0030          8 B               net_slab_next (u64 bump ptr)
0x0520_0038          196,608 B         net_slab[4K] (48 B x 4,096)
0x0522_FFB8          ---               end (~86.2 MB)
```

All globals are declared `__arena SEC(".addr_space.1")` and live in a single
`BPF_MAP_TYPE_ARENA` map. Userspace accesses the same memory via `mmap()` on
the arena map fd.

## 4. prov_node Layout

80-byte struct, stored in `arena_nodes[]`:

```
Offset  Size  Type    Field           Description
------  ----  ------  ----------      ----------------------------------
 0      8     u64     ts_ns           ktime_get_ns() timestamp
 8      4     u32     pid             task pid (thread ID)
12      4     u32     ppid            parent tgid
16      4     u32     tgid            thread group ID (userspace PID)
20      4     u32     uid             uid from task->cred
24      8     u64     cgid            cgroup v2 ID
32      8     u64     object_id       inode (exec/file) or port<<32|addr (socket)
40      8     u64     prev_index      parent exec slot (lineage backlink)
48      1     u8      kind            PROV_KIND_* event type
49      1     u8      flags           generation tag (low byte)
50      2     u16     extra           open_flags / addr_family per kind
52      4     u32     path_slab_idx   1-based index into path_slab[] (0=none)
56      12    char[]  comm            task comm (truncated to 12 bytes)
68      4     u32     net_slab_idx    1-based index into net_slab[] (0=none)
72      4     u32     mnt_ns          mount namespace inum
76      4     u32     pid_ns          PID namespace inum
------
80 bytes total
```

Defined in `bpf/provenance.bpf.c` (BPF side) and `include/prov_arena_types.h`
(C++ side). Both must match byte-for-byte.

## 5. LSM Hook Coverage

14 hooks in `provenance.bpf.c`, plus 1 in `binary_auth.bpf.c` and 2 in
`selfprotect.bpf.c`:

| # | LSM Hook                | BPF Program Name                  | Kind Recorded           | Sleepable | Enforces            |
|---|-------------------------|-----------------------------------|-------------------------|-----------|---------------------|
| 1 | bprm_check_security     | aegis_next_on_exec                | PROV_KIND_EXEC          | No        | Policy deny + kill  |
| 2 | file_open               | aegis_next_on_file_open           | PROV_KIND_FILE_OPEN     | No        | Policy deny         |
| 3 | socket_connect          | aegis_next_on_socket_connect      | PROV_KIND_SOCKET_CONNECT| No        | Policy deny + rate  |
| 4 | socket_bind             | aegis_next_on_socket_bind         | PROV_KIND_SOCKET_BIND   | No        | Policy deny         |
| 5 | socket_listen           | aegis_next_on_socket_listen       | PROV_KIND_SOCKET_LISTEN | No        | Policy deny         |
| 6 | file_permission         | aegis_next_on_file_perm           | PROV_KIND_FILE_PERM     | No        | Policy deny (FIM)   |
| 7 | mmap_file               | aegis_next_on_mmap_file           | PROV_KIND_MMAP_FILE     | No        | W+X prevention      |
| 8 | task_alloc              | aegis_next_on_task_alloc          | PROV_KIND_TASK_ALLOC    | No        | Fork bomb + rate    |
| 9 | kernel_module_request   | aegis_next_on_kmod_req            | PROV_KIND_KMOD_REQ      | No        | Policy deny         |
|10 | ptrace_access_check     | aegis_next_on_ptrace              | PROV_KIND_PTRACE        | No        | Policy deny         |
|11 | task_fix_setuid         | aegis_next_on_setuid              | PROV_KIND_SETUID        | No        | Policy deny         |
|12 | path_rename             | aegis_next_on_rename              | PROV_KIND_RENAME        | No        | Policy deny         |
|13 | path_unlink             | aegis_next_on_unlink              | PROV_KIND_UNLINK        | No        | Policy deny         |
|14 | socket_sendmsg          | aegis_next_on_sendmsg             | PROV_KIND_SENDMSG       | No        | Policy deny         |
|   | **binary_auth.bpf.c**   |                                   |                         |           |                     |
|15 | bprm_check_security     | aegis_binary_auth                 | fsverity verdict        | Yes (.s)  | Digest deny/allow   |
|   | **selfprotect.bpf.c**   |                                   |                         |           |                     |
|16 | bpf                     | aegis_selfprotect_bpf             | (none)                  | No        | Block prog detach   |
|17 | bpf_map                 | aegis_selfprotect_bpf_map         | (none)                  | No        | Block map write     |

## 6. Policy Engine

### Key structure

```
policy_key (8 bytes)              policy_val (8 bytes)
+--------+------------+-----+    +--------+-------+-----+----------+
| hook   | match_type | pad |    | action | flags | pad | reserved |
| u8     | u8         | u16 |    | u8     | u8    | u16 | u32      |
+--------+------------+-----+    +--------+-------+-----+----------+
| match_val (u32)           |
+---------------------------+
```

- `hook`: `PROV_KIND_*` (which LSM hook this rule applies to)
- `match_type`: `POLICY_MATCH_COMM` (0), `POLICY_MATCH_PATH` (1),
  `POLICY_MATCH_PORT` (2), `POLICY_MATCH_CGROUP` (3), `POLICY_MATCH_DIGEST` (4)
- `match_val`: FNV-1a hash of comm/path, raw port number, or cgroup ID low 32 bits
- `action`: `ALLOW` (0), `DENY` (1), `LOG` (2), `QUARANTINE` (3)
- `flags`: `POLICY_FLAG_KILL` (bit 0) -- send SIGKILL after deny

### Evaluation flow

```
evaluate_policy(hook, comm, port, cgid):
  1. key = {hook, MATCH_COMM, fnv1a(comm)}  -> lookup aegis_next_policy
  2. key = {hook, MATCH_PORT, port}          -> lookup (if port != 0)
  3. key = {hook, MATCH_CGROUP, (u32)cgid}   -> lookup (if cgid != 0)
  4. evaluate_policy_path(hook, path_hash)   -> lookup (if path resolved)

  Any hit with action=DENY   -> set deny=1, optionally SIGKILL
  Any hit with action=QUARANTINE -> write cgid to quarantine map
  Return: 0 (allow) or -1 (deny)
```

### Hot-reload via user_ringbuf

Userspace writes `policy_msg` structs (msg_type + key + val) into
`aegis_policy_ringbuf` (`BPF_MAP_TYPE_USER_RINGBUF`, 256KB). The BPF
callback `policy_ringbuf_cb()` processes ADD/DELETE/FLUSH messages in bulk,
avoiding per-rule syscall overhead. Drained via `aegis_next_drain_policy()`
(SEC("syscall")).

## 7. Enforcement Pipeline

```
LSM hook fires
    |
    v
record_base(task, kind, object_id, extra)
    |  -> write prov_node to arena_nodes[slot]
    |  -> insert into arena_ht[]
    |  -> emit_alert(slot, pid, kind) via ringbuf
    |
    v
evaluate_policy(hook, comm, port, cgid)
    |  -> up to 4 hash map lookups (comm, port, cgroup, path)
    |
    +-- action=ALLOW       -> return 0
    +-- action=LOG         -> return 0 (node recorded, alert sent)
    +-- action=DENY        -> return -EPERM
    |     +-- POLICY_FLAG_KILL set?
    |           -> bpf_send_signal_task(SIGKILL) or bpf_send_signal(9)
    +-- action=QUARANTINE  -> bpf_map_update_elem(quarantine, cgid, level)
                               -> return 0 (task continues, scheduler throttles)

check_rate_limit(cgid, kind)
    |  -> per-cgroup sliding window counter in aegis_rate_limits (LRU hash)
    |  -> if count > threshold: auto-quarantine cgroup
    |
    v
final verdict returned to kernel LSM framework
```

### Quarantine bridge

When `evaluate_policy()` returns `POLICY_ACTION_QUARANTINE`, it writes the
cgroup ID directly into the `aegis_next_quarantine` hash map. The sched_ext
scheduler (`quarantine.bpf.c`) reads this map on every `enqueue()` call:

| Level | Name     | Time Slice | CPU Pinning | Effect                   |
|-------|----------|------------|-------------|--------------------------|
| 0     | NONE     | 5 ms       | global DSQ  | Normal scheduling        |
| 1     | THROTTLE | 1 ms       | global DSQ  | Reduced CPU time         |
| 2     | PIN      | 1 ms       | CPU 0 only  | Cache isolation          |
| 3     | STARVE   | 100 us     | CPU 0 only  | Effective starvation     |

## 8. Kernel Compatibility

| Feature              | Min Kernel | Config Required              | Used By                  |
|----------------------|------------|------------------------------|--------------------------|
| BPF arena map        | 6.9+       | (mainline)                   | provenance.bpf.c         |
| sched_ext            | 6.12+      | CONFIG_SCHED_CLASS_EXT       | quarantine.bpf.c         |
| bpf_get_fsverity_digest | 6.7+    | CONFIG_FS_VERITY             | binary_auth.bpf.c        |
| bpf_get_file_xattr   | 6.8+      | (mainline)                   | binary_auth.bpf.c        |
| bpf_set_dentry_xattr | 6.13+     | (mainline)                   | binary_auth.bpf.c        |
| bpf_send_signal_task | 6.13+     | (mainline)                   | provenance.bpf.c         |
| user_ringbuf         | 6.1+       | (mainline)                   | provenance.bpf.c (policy)|
| BPF LSM              | 5.7+       | CONFIG_BPF_LSM               | all LSM programs         |
| open-coded task iter | 6.7+       | (mainline)                   | provenance.bpf.c catchup |

### Fallback: provenance_legacy.bpf.c

On kernels < 6.9 (no `BPF_MAP_TYPE_ARENA`), the agent loads
`provenance_legacy.bpf.c` instead. This provides the same 14 LSM hooks and
policy enforcement but sends full ~372-byte events through a ringbuf instead
of writing to the arena. No arena hash table, no path/net slabs, no catch-up
scan. Minimum kernel: ~5.11 (BPF LSM + ringbuf + `bpf_get_current_task_btf`).

Feature availability is determined at startup by `feature_probe.hpp`.

## 9. BPF Programs

| File                       | Purpose                                   | Program Type      | LOC  |
|----------------------------|-------------------------------------------|-------------------|------|
| provenance.bpf.c           | Arena-backed provenance graph, 14 LSM hooks, policy engine, rate limiter | LSM + syscall | ~1475 |
| provenance_legacy.bpf.c   | Ringbuf-only fallback for kernels < 6.9   | LSM               | ~744 |
| quarantine.bpf.c           | sched_ext tiered CPU quarantine            | struct_ops        | ~143 |
| selfprotect.bpf.c          | Agent self-protection (anti-tamper)        | LSM               | ~129 |
| binary_auth.bpf.c          | In-kernel binary authorization via fsverity | LSM (sleepable)  | ~309 |

| File                       | Purpose                                   | Type              | LOC  |
|----------------------------|-------------------------------------------|-------------------|------|
| arena_htable.h             | Open-addressing hash table for arena       | BPF header        | ~113 |
| prov_types.h               | Shared constants (BPF + userspace)         | C header          | ~107 |

## 10. File Index

### BPF (kernel side)

| File | Description |
|------|-------------|
| `bpf/provenance.bpf.c` | Main BPF program: arena layout, 14 LSM hooks, policy engine, rate limiter, GC timer |
| `bpf/provenance_legacy.bpf.c` | Ringbuf-only fallback provenance for kernels without arena support |
| `bpf/quarantine.bpf.c` | sched_ext scheduler with 4-level CPU quarantine |
| `bpf/selfprotect.bpf.c` | Anti-tamper: blocks unauthorized BPF prog detach and map writes |
| `bpf/binary_auth.bpf.c` | In-kernel binary authorization via fsverity digest + xattr cache |
| `bpf/arena_htable.h` | Open-addressing hash table (64K buckets, 8-step linear probe) |
| `bpf/prov_types.h` | Shared constants: event kinds, policy match types, rate limits |

### Userspace (C++)

| File | Description |
|------|-------------|
| `src/main.cpp` | CLI driver: attach, graph dump/lineage/stats, sched start/quarantine |
| `src/prov_walk.hpp` | Provenance graph walk API (lineage, ancestry queries) |
| `src/prov_walk.cpp` | Provenance walk implementation |
| `src/event_export.hpp` | JSONL and OCSF event serialization for ringbuf events |
| `include/prov_arena_types.h` | C-compatible struct definitions matching BPF arena globals |
| `include/aegis_next_prov.hpp` | Arena mmap helpers, layout constants, type aliases |
| `include/feature_probe.hpp` | Runtime kernel feature detection (arena, sched_ext, fsverity) |

### Build / Deploy / Test

| File | Description |
|------|-------------|
| `CMakeLists.txt` | CMake build: BPF skeleton generation, C++ compilation |
| `Dockerfile` | Container build image |
| `.dockerignore` | Docker build exclusions |
| `deploy/aegisbpf-next.service` | systemd unit file |
| `deploy/aegisbpf-next.conf` | Agent configuration file |
| `packaging/postinst` | Debian package post-install script |
| `packaging/postrm` | Debian package post-remove script |
| `tests/test_prov_walk.cpp` | Unit tests for provenance walk |
| `tests/fuzz_prov.cpp` | Fuzz testing for provenance parsing |
| `tests/e2e_policy_delivery.sh` | End-to-end test for policy hot-reload |
| `bench/workload.sh` | Benchmark workload generator |
| `bench/compare.sh` | Benchmark comparison script |
| `examples/policy.rules` | Example policy rule set |
| `examples/rules-cryptomining.rules` | Detection rules: cryptomining |
| `examples/rules-reverse-shell.rules` | Detection rules: reverse shells |
| `examples/rules-container-escape.rules` | Detection rules: container escapes |
| `examples/rules-lateral-movement.rules` | Detection rules: lateral movement |
| `examples/rules-k8s-runtime.rules` | Detection rules: Kubernetes runtime |
| `examples/rules-compliance-cis.rules` | Compliance rules: CIS benchmarks |
