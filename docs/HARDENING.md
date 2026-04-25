# Daemon hardening

`aegisbpfd` ships several layered self-defences. Each is opt-in so
operators can adopt them at the pace their kernel/userland allows.

| Layer | Flag | Default | Kernel | Effect |
|-------|------|---------|--------|--------|
| seccomp-bpf syscall allowlist | `--seccomp` | off | ≥ 3.5 | Restricts the daemon to ~60 needed syscalls; default deny → `SECCOMP_RET_KILL_PROCESS`. |
| Landlock filesystem sandbox | `--landlock` | off | ≥ 5.13 | Restricts the daemon to a fixed allowlist of paths (BPF maps, config, state, `/proc`). |
| Signed BPF objects | `AEGIS_REQUIRE_BPF_SIG=1` | off | n/a | Hard-requires Ed25519 signature on `aegis.bpf.o` (`docs/SIGNED_BPF_OBJECTS.md`). |
| Anti-rollback policy versioning | always on | n/a | n/a | Monotonic counter in `/var/lib/aegisbpf/version_counter`. |
| Break-glass disable | file marker | n/a | n/a | `/etc/aegisbpf/break_glass[.token]` short-circuits enforcement (audit-only). |

This document focuses on the **Landlock** layer. The seccomp layer is
described inline in `src/seccomp.cpp`; signing is in
[`docs/SIGNED_BPF_OBJECTS.md`](SIGNED_BPF_OBJECTS.md).

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
