# Daemon hardening

`aegisbpfd` ships several layered self-defences. Each is opt-in so
operators can adopt them at the pace their kernel/userland allows.

| Layer | Flag | Default | Kernel | Effect |
|-------|------|---------|--------|--------|
| seccomp-bpf syscall allowlist | `--seccomp` | off | ≥ 3.5 | Restricts the daemon to ~60 needed syscalls; default deny → `SECCOMP_RET_KILL_PROCESS`. |
| Landlock filesystem sandbox | `--landlock` | off | ≥ 5.13 | Restricts the daemon to a fixed allowlist of paths (BPF maps, config, state, `/proc`). |
| Capability drop (`CAP_BPF`/`CAP_PERFMON`) | `--drop-caps` | off | ≥ 5.8 | Reduces daemon capabilities to the minimum runtime set after init; eliminates `CAP_SYS_ADMIN` from the daemon's surface. |
| Signed BPF objects | `AEGIS_REQUIRE_BPF_SIG=1` | off | n/a | Hard-requires Ed25519 signature on `aegis.bpf.o` (`docs/SIGNED_BPF_OBJECTS.md`). |
| Anti-rollback policy versioning | always on | n/a | n/a | Monotonic counter in `/var/lib/aegisbpf/version_counter`. |
| Break-glass disable | file marker | n/a | n/a | `/etc/aegisbpf/break_glass[.token]` short-circuits enforcement (audit-only). |

This document focuses on the **Landlock** layer and the
**capability-drop** layer. The seccomp layer is described inline in
`src/seccomp.cpp`; signing is in
[`docs/SIGNED_BPF_OBJECTS.md`](SIGNED_BPF_OBJECTS.md).

## Capability drop

The kernel 5.8 capability split introduced `CAP_BPF` and `CAP_PERFMON`
as fine-grained alternatives to `CAP_SYS_ADMIN` for BPF-related
operations. Until then, every eBPF agent had to hold the all-powerful
`CAP_SYS_ADMIN` for its full lifetime — even after BPF programs were
loaded and attached and the only remaining runtime work was reading
ringbuf events and updating maps. AegisBPF closes that window.

### How to enable

Pass `--drop-caps` to `aegisbpfd run`. It is independent of `--seccomp`
and `--landlock` and stacks with both:

```
aegisbpfd run --enforce --seccomp --landlock --drop-caps
```

### What gets retained

The default minimum runtime set is built by `default_capability_config()`
in [`src/capabilities.cpp`](../src/capabilities.cpp):

| Capability | Why retained |
|---|---|
| `CAP_BPF` | `bpf(2)` syscall for runtime map updates (policy reload, OverlayFS copy-up propagation, deny-rate counter writes). |
| `CAP_PERFMON` | BPF helpers (e.g. tracepoint reads) and certain map-iteration ops. |
| `CAP_DAC_READ_SEARCH` | Read `/proc/<pid>/*` across users (process-tree reconciliation, K8s identity cache reload). |
| `CAP_SYS_RESOURCE` | Pre-5.11 `setrlimit(RLIMIT_MEMLOCK)` bumps for older kernels; redundant on 5.11+ where bpf() handles memlock automatically. Kept conservatively. |

Everything else — including `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
`CAP_DAC_OVERRIDE`, `CAP_SETPCAP`, the ambient set, and the
inheritable set — is removed from the effective, permitted, and
bounding sets. The bounding set is dropped first (it requires
`CAP_SETPCAP`, which is itself dropped from the effective set
moments later); see the comment at the top of `drop_to_minimum()` in
`src/capabilities.cpp`.

### When the drop happens

After every initialization step that needs `CAP_SYS_ADMIN` is
complete (BPF program load, map setup, BPF-LSM hook attach, ringbuf
creation, `/proc` reconciliation), and after Landlock + seccomp are
applied, but **before** the heartbeat thread is spawned. Since Linux
capabilities are per-thread and `pthread_create()` inherits the
calling thread's set via `clone()`, dropping on the main thread
before any worker thread spawn means the workers also start without
`CAP_SYS_ADMIN`.

### Failure modes

| Condition | Behavior |
|---|---|
| Kernel < 5.8 (no `CAP_BPF` / `CAP_PERFMON`) | Log INFO ("Skipping capability drop: kernel < 5.8 lacks CAP_BPF / CAP_PERFMON"), continue without dropping. The daemon retains full caps; other defences (Landlock, seccomp) are unaffected. |
| `capset(2)` returns `-EPERM` | Daemon refuses to start (`EXIT_FAILURE`). This indicates a kernel-side restriction the operator must investigate. |
| `prctl(PR_CAPBSET_DROP)` returns an error other than `EINVAL` | Daemon refuses to start. (`EINVAL` on caps the kernel doesn't know about is tolerated.) |

The daemon never fails open. If the drop fails it returns non-zero and
the operator decides whether to retry without `--drop-caps` or to
investigate the kernel side.

### What capability drop does not protect

- **Kernel exploits.** A bug in the BPF verifier or in any LSM hook
  that lets the daemon escape the kernel's capability check is not
  defended by this layer.
- **Code already running before the drop.** The drop is post-init;
  anything in `daemon_run()` before the drop point still runs with
  full caps. (Landlock + seccomp narrow that surface separately.)
- **Pre-existing FDs.** Any file descriptor the daemon already opened
  before the drop remains usable. The drop affects future syscalls
  that require a cap, not existing handles.

### Verifying the drop

After startup, the daemon logs:

```
Capability drop applied {retain_mask=0xc001000004, effective=0xc001000004,
permitted=0xc001000004, inheritable=0, bounding=0xc001000004}
```

(`0xc001000004` decodes to `CAP_DAC_READ_SEARCH | CAP_SYS_RESOURCE |
CAP_PERFMON | CAP_BPF`.) Operators can independently verify by
reading `/proc/<pid>/status` and checking `CapEff` against the
expected mask.

## Landlock self-sandbox

Landlock is a stackable LSM (mainline since Linux 5.13) that lets an
unprivileged process restrict its own filesystem access to a fixed
allowlist. Unlike seccomp, it speaks at the inode/path level, so it
defends against post-exploit lateral file reads even when the
attacker has the syscalls they need.

### Enabling it

Pass `--landlock` to `aegisbpfd run`. The flag is independent of
`--seccomp` — they layer cleanly:

```bash
aegisbpfd run --enforce --seccomp --landlock
```

Order at startup:

1. Load BPF object, attach hooks, open all required files / pinned maps.
2. Probe the kernel ABI (`landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)`).
3. Build the path allowlist (see below) and call `landlock_add_rule`
   for each `O_PATH` open that succeeds. Missing paths are skipped
   with an INFO log line, not an error.
4. `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` (idempotent with seccomp).
5. `landlock_restrict_self()` activates the ruleset.
6. Apply the seccomp filter (last, since the syscall surface narrows
   harshly there).

If the kernel does not support Landlock, the daemon logs a warning and
continues without it; `--landlock` never causes startup to fail on an
older kernel.

### Allowlist (default)

Built by `default_landlock_config()` in
[`src/landlock.cpp`](../src/landlock.cpp):

| Path | Mode | Why |
|------|------|-----|
| `/etc/aegisbpf` | RO | configuration, trusted keys, BPF object hash, break-glass marker |
| `/usr/lib/aegisbpf` | RO | installed BPF object + sidecar |
| `/proc` | RO | process introspection (`/proc/<pid>/{stat,comm,exe,cgroup}`) |
| `/sys/kernel/btf` | RO | BTF for CO‑RE relocations |
| `/var/lib/aegisbpf` | RW | applied policy, version counter, capabilities report, control state, lock file |
| `/sys/fs/bpf` | RW | pinned BPF maps under `/sys/fs/bpf/aegisbpf/...` |
| `$AEGIS_KEYS_DIR` | RO | optional override of trusted-keys dir |
| `dirname($AEGIS_BPF_OBJ)` | RO | optional override of BPF object directory |

After `landlock_restrict_self()` returns, any open(2) outside this set
fails with `EACCES`. The daemon does not need any further filesystem
access at runtime — events flow over the BPF ringbuf, not the FS.

### ABI support matrix

| Kernel | ABI | Adds |
|--------|-----|------|
| 5.13   | 1   | RO/RW/EXECUTE on inodes, MAKE_*, REMOVE_* |
| 5.19   | 2   | `LANDLOCK_ACCESS_FS_REFER` (cross-directory rename) |
| 6.2    | 3   | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| ≥ 6.7  | 4+  | (network rules, IOCTL — not yet used here) |

The daemon picks up extra restrictions automatically on newer ABIs;
older kernels just see the original bit set.

### Failure modes

| Condition | Behaviour |
|-----------|-----------|
| `landlock_create_ruleset` returns -1 (kernel/LSM disabled) | Log `WARN`, continue without sandbox. |
| Allowlist path doesn't exist | Skip with INFO log, do not fail. |
| `landlock_add_rule` fails | Daemon refuses to start (`EXIT_FAILURE`) — this would silently widen the sandbox otherwise. |
| `prctl(NO_NEW_PRIVS)` fails | Daemon refuses to start. |
| `landlock_restrict_self` fails | Daemon refuses to start. |

### Inspecting at runtime

The daemon's startup log includes:

```
Agent started seccomp=true landlock=true landlock_abi=3
```

To verify confinement empirically:

```bash
$ sudo strace -f -e openat -p $(pidof aegisbpfd) 2>&1 | \
    awk '/= -1 EACCES/ { print }' | head
```

You should see `EACCES` on any post-startup attempts to read paths
outside the allowlist.

### What Landlock does not protect

- Network egress (use `--seccomp` and the existing
  `deny_ipv4`/`deny_port` policy maps).
- Kernel exploits — Landlock is just an LSM, it does not stop ROP into
  the kernel.
- ptrace/proc-attach by root (use Yama LSM:
  `kernel.yama.ptrace_scope=2`).
- Already-open file descriptors. The sandbox only filters new opens;
  fds inherited at startup are unaffected (this is intentional).

## See also

- [`docs/SIGNED_BPF_OBJECTS.md`](SIGNED_BPF_OBJECTS.md) — Ed25519 signing of `aegis.bpf.o`.
- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — attacker capabilities and trust boundaries.
- [`src/landlock.cpp`](../src/landlock.cpp), [`tests/test_landlock_sandbox.cpp`](../tests/test_landlock_sandbox.cpp).
