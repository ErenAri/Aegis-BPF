# aegis-next Security Hardening Model

This document describes the security hardening properties of the aegis-next
BPF agent. All enforcement logic runs in BPF (kernel side). Userspace is
treated as an observer.

## Arena Attack Surface

The provenance graph lives in a `BPF_MAP_TYPE_ARENA` (`bpf/provenance.bpf.c`)
that is `mmap`'d into the agent's address space. BPF writes nodes and metadata;
userspace reads via the shared mapping. From the kernel's perspective, the
mmap'd region is **untrusted userspace memory** -- a compromised agent process
could corrupt its own view of the arena at any time.

Consequences:

- Arena data must never be used for enforcement decisions in userspace.
  All policy evaluation (`evaluate_policy()`) and rate-limit checks
  (`check_rate_limit()`) execute entirely in BPF kernel context.
- The arena header (`prov_header`) contains a monotonic `next_index` cursor
  and `generation` counter. These are authoritative only from the BPF side;
  userspace treats them as hints for display and graph traversal.
- `prov_node` fields such as `pid`, `cgid`, and `object_id` are synthetic
  IDs -- never raw kernel pointers -- which side-steps KASLR leakage.

## TOCTOU Mitigations

- **LSM hooks, not tracepoints.** All enforcement hooks (`lsm/bprm_check_security`,
  `lsm/file_open`, `lsm/socket_connect`, etc.) are mandatory access control
  points. The kernel holds the relevant lock/refcount at hook invocation,
  preventing the object from changing between check and use.
- **Inode-based policy binding.** Policy rules match on inode number
  (`object_id` in `prov_node`), cgroup ID, or comm hash -- never on a
  path string that could be swapped via rename between check and open.
  See `evaluate_policy()` in `bpf/provenance.bpf.c:385`.
- **Atomic policy delivery via user_ringbuf.** Policy updates are batched into
  `aegis_policy_ringbuf` (`BPF_MAP_TYPE_USER_RINGBUF`) and drained atomically
  by the `aegis_next_drain_policy` syscall program (`bpf/provenance.bpf.c:630`).
  A half-written batch leaves existing rules intact; the flush/add sequence
  ensures the policy map is never in a partially-applied state visible to
  enforcement hooks.

## Self-Protection Model

Implemented in `bpf/selfprotect.bpf.c`. Two LSM hooks prevent an attacker
with `CAP_BPF` from disabling the agent:

- **`lsm/bpf`** -- gates `BPF_PROG_DETACH` and `BPF_LINK_DETACH` commands.
  Non-trusted callers receive `-EPERM`.
- **`lsm/bpf_map`** -- gates write access (`FMODE_WRITE`) to BPF maps.
  Prevents adversary processes from deleting map entries or corrupting policy.

Caller identity is established by comparing `task->mm->exe_file->f_inode->i_ino`
against the trusted inode stored in `aegis_selfprotect_trusted` at load time.
An `aegis_selfprotect_enabled` flag allows the agent to disable protection for
graceful shutdown.

**Limitations (current prototype):**

- Mount namespace is not checked. An attacker could hard-link a different
  binary to the same inode in another mount namespace. (TODO)
- File hash (e.g., `ima_inode_hash`) is not verified. The inode check
  confirms identity but not integrity. (TODO)

## Binary Authorization

Implemented in `bpf/binary_auth.bpf.c`. The `lsm.s/bprm_check_security` hook
runs a multi-stage pipeline on every `execve`:

1. **xattr cache check** -- `bpf_get_file_xattr("security.aegis.verified")`
   returns a cached verdict, skipping cryptographic work on repeat execs.
2. **fsverity digest** -- `bpf_get_fsverity_digest()` extracts the Merkle
   tree root hash. Files without fsverity are denied (enforce) or logged (audit).
3. **Trusted digest lookup** -- the first 8 bytes of the digest key into
   `aegis_trusted_digests` (BPF hash map, up to 16K entries).
4. **PKCS7 signature verification** -- `bpf_verify_pkcs7_signature()` against
   the system keyring (optional, gated on kernel config).
5. **xattr caching** -- `bpf_set_dentry_xattr()` persists the verdict for
   subsequent opens.

The entire pipeline executes in-kernel with zero userspace round-trips.
All kfuncs are declared `__weak`, so the program loads on kernels that lack
`CONFIG_FS_VERITY` or `CONFIG_SYSTEM_DATA_VERIFICATION` -- userspace probes
availability at startup and degrades gracefully.

## Rate Limiting as Defense

Implemented in `bpf/provenance.bpf.c:544` (`check_rate_limit()`). Per-cgroup
windowed counters track event rates using an LRU hash map (`aegis_rate_limits`).

- Each `(cgroup_id, event_kind)` pair maintains a `window_start_ns` and
  `count`. When `count` exceeds the threshold within a 1-second window
  (`RATE_LIMIT_WINDOW_NS`), the cgroup is automatically quarantined.
- Thresholds are configurable per event kind via `aegis_rate_config` map.
  Hardcoded defaults: 50 forks/sec (`RATE_LIMIT_FORK_MAX`), 100 connects/sec
  (`RATE_LIMIT_CONN_MAX`), 200/sec for other event types.
- On threshold breach, the rate limiter writes `QUARANTINE_THROTTLE` to the
  shared `aegis_next_quarantine` map and emits a `PROV_KIND_RATE_LIMIT` alert.
- For exec events, the LSM hook returns `-EPERM` directly, killing the
  exec attempt in-kernel (fork bomb suppression).

Detection coverage: fork bombs (`PROV_KIND_TASK_ALLOC`), connection floods
(`PROV_KIND_SOCKET_CONNECT`), file scan storms (`PROV_KIND_FILE_OPEN`).

## Quarantine Escalation

Implemented in `bpf/quarantine.bpf.c`. A `sched_ext` scheduler reads the
`aegis_next_quarantine` map (shared with the LSM provenance program) on
every enqueue decision. Four escalation levels:

| Level | Name       | Time Slice | CPU Placement    | Effect                          |
|-------|------------|------------|------------------|---------------------------------|
| 0     | `NONE`     | 5 ms       | global DSQ       | Normal scheduling               |
| 1     | `THROTTLE` | 1 ms       | global DSQ       | Reduced priority                |
| 2     | `PIN`      | 1 ms       | CPU 0 only       | Cache isolation + throttle      |
| 3     | `STARVE`   | 100 us     | CPU 0 only       | Effective starvation            |

- **CPU isolation:** `PIN` and `STARVE` dispatch to `SCX_DSQ_LOCAL_ON | CPU 0`,
  confining the quarantined workload to a single core and preventing it from
  interfering with the rest of the system.
- **Priority inversion:** quarantined tasks receive drastically shorter time
  slices. At `STARVE` level (100 us), the task can barely make progress --
  just enough to avoid triggering the sched_ext watchdog timer.
- **Bridge to SIGKILL:** when policy has `POLICY_FLAG_KILL`, the LSM side
  sends `SIGKILL`. `STARVE`-level quarantine ensures the task cannot execute
  meaningful work in the window before signal delivery.

## Limitations and Future Work

The following areas are **not hardened** in the current prototype:

- **Mount namespace check in self-protection.** `selfprotect.bpf.c` compares
  inode numbers but does not verify the mount namespace. A same-inode binary
  in a different namespace would pass the check.
- **IMA/file hash in self-protection.** The trusted inode check confirms
  identity (same file) but not integrity (same contents). Integrating
  `ima_inode_hash` would close this gap.
- **CAP_BPF holder bypass.** A process with `CAP_BPF` that matches the
  trusted inode (e.g., the agent itself, or a hard link) can modify maps
  and detach programs. The self-protection model trusts the agent binary
  unconditionally.
- **Arena data validation in userspace.** Userspace reads arena contents
  via mmap without structural validation. A kernel bug that corrupts
  arena layout could cause the userspace reader to crash or misinterpret
  data. Arena data should be validated (magic, bounds, generation) before use.
- **Policy generation gating.** There is no explicit `policy_generation`
  counter that forces audit-only mode during a partial policy reload.
  The user_ringbuf drain is atomic per batch, but a crash mid-batch could
  leave stale rules in the map.
- **Quarantine demotion.** Quarantine levels escalate automatically but
  there is no automatic demotion path. A quarantined cgroup stays at its
  level until userspace explicitly clears the entry.
