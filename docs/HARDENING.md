# Daemon hardening

`aegisbpfd` ships several layered self-defences. Each is opt-in so
operators can adopt them at the pace their kernel/userland allows.

| Layer | Flag | Default | Kernel | Effect |
|-------|------|---------|--------|--------|
| seccomp-bpf syscall allowlist | `--seccomp` | off | ≥ 3.5 | Restricts the daemon to ~60 needed syscalls; default deny → `SECCOMP_RET_KILL_PROCESS`. |
| Landlock filesystem sandbox | `--landlock` | off | ≥ 5.13 | Restricts the daemon to a fixed allowlist of paths (BPF maps, config, state, `/proc`). |
| Post-attach capability drop | `--drop-caps` | off | ≥ 5.8 | Drops `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`, etc. once BPF programs are attached; only `CAP_NET_ADMIN` and `CAP_DAC_READ_SEARCH` are kept. |
| Signed BPF objects | `AEGIS_REQUIRE_BPF_SIG=1` | off | n/a | Hard-requires Ed25519 signature on `aegis.bpf.o` (`docs/SIGNED_BPF_OBJECTS.md`). |
| Anti-rollback policy versioning | always on | n/a | n/a | Monotonic counter in `/var/lib/aegisbpf/version_counter`. |
| Break-glass disable | file marker | n/a | n/a | `/etc/aegisbpf/break_glass[.token]` short-circuits enforcement (audit-only). |
| Pinned-link crash fail-safe | `AEGIS_ENFORCE_PIN_LINKS=1` | off | ≥ 5.7 (BPF LSM) | Pins LSM links into bpffs so enforcement survives daemon crash / `SIGKILL` / OOM. |

## Pinned-link daemon-crash fail-safe

When `AEGIS_ENFORCE_PIN_LINKS=1` is set in the daemon's environment,
every successful BPF program attach is immediately followed by
`bpf_link__pin(link, "<pin_root>/<program_name>")` where `<pin_root>`
defaults to `/sys/fs/bpf/aegisbpf` (overridable via `AEGIS_PIN_ROOT`).
The pin holds an independent kernel reference to the LSM link object,
so closing the userspace fd — whether from a normal shutdown, a
segfault, an OOM-kill, `systemctl stop aegisbpfd`, or a hostile
`kill -9` against the daemon — **does not detach the LSM hook**.
Enforcement continues until a sysadmin explicitly unpins (`rm
/sys/fs/bpf/aegisbpf/<program>` or `bpftool link detach`).

### Why it matters

Without pinning, the kill chain to disable AegisBPF is a single
syscall: an attacker who has gained `CAP_KILL` against root only
needs to SIGKILL `aegisbpfd` and every LSM hook detaches with it.
With pinning, the same attacker must additionally `umount` or `rm`
inside `/sys/fs/bpf/aegisbpf/` — operations that themselves trigger
audit logs and require `CAP_SYS_ADMIN`.

### Prerequisites

- bpffs mounted at the parent of `<pin_root>` (default
  `/sys/fs/bpf`). The daemon refuses to start with a remediation
  message if `statfs(2).f_type != BPF_FS_MAGIC`:
  ```
  mount -t bpf bpf /sys/fs/bpf
  ```
- `CAP_BPF` or `CAP_SYS_ADMIN` (already required by the daemon).

### Watchdog

The heartbeat thread additionally `stat()`s every pinned link each
tick and emits a structured ERROR if any are missing — this catches
operator `rm`, `bpftool link detach`, or kernel-module reload events
that would otherwise silently degrade enforcement. Auto-reattach is
deferred to a follow-up release; today the watchdog is read-only.

### Operator runbook

```bash
# Enable
sudo AEGIS_ENFORCE_PIN_LINKS=1 systemctl restart aegisbpfd

# Inspect
sudo ls -la /sys/fs/bpf/aegisbpf/
sudo bpftool link show

# Disable enforcement after daemon stop (operator-initiated)
sudo rm -rf /sys/fs/bpf/aegisbpf/
```

### Limitations

- The pin survives daemon **crash**; it does not survive **reboot**
  (bpffs is tmpfs-backed).
- On daemon **restart with the flag set**, the existing pins from
  the prior daemon are not auto-recovered or auto-unpinned. Operator
  must `rm -rf /sys/fs/bpf/aegisbpf/` before starting the new daemon
  if the policy or BPF object has changed between versions. A future
  release will add stale-pin handling.
- `AEGIS_UNPIN_ON_EXIT=1` for clean shutdowns is on the roadmap.

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

## Capability splitting (post-attach drop)

Linux 5.8 split `CAP_SYS_ADMIN`'s BPF subset into two narrower
capabilities:

- **`CAP_BPF`** — generic BPF map/program ops (load, create, update).
- **`CAP_PERFMON`** — `perf_event_open`, kprobe/tracepoint attach.

`BPF_PROG_TYPE_LSM` still requires `CAP_SYS_ADMIN` *at load time*, but
`bpf()` operations against an already-open map fd do **not** re-check
capabilities. That gives `aegisbpfd` a window: load + attach with full
caps, then drop everything that isn't strictly needed for steady-state
operation.

### Enabling it

Pass `--drop-caps` to `aegisbpfd run`. Like `--seccomp` and
`--landlock`, the flag is opt-in and stacks cleanly with them:

```bash
aegisbpfd run --enforce --seccomp --landlock --drop-caps
```

Order at startup (combined with the other layers):

1. Load BPF object, attach all hooks (LSM, tracepoints, cgroup,
   sched, etc.).
2. Open all required files / pinned maps; build path allowlist.
3. **Drop capabilities** (this layer) — clears effective/permitted/
   inheritable, lowers ambient, drops bounding for everything outside
   the keep set.
4. Apply Landlock ruleset.
5. `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)`.
6. Apply seccomp filter.

If the running kernel does not support split caps (probed via
`PR_CAPBSET_READ` on `CAP_BPF`), the daemon logs a warning and skips
the drop — `--drop-caps` never causes startup to fail on an older
kernel.

### Keep set

After the drop, the daemon retains only:

| Capability | Why |
|------------|-----|
| `CAP_NET_ADMIN` | cgroup-attached BPF program updates and network policy map edits. |
| `CAP_DAC_READ_SEARCH` | reading `/proc/<pid>/{exe,cgroup,ns/*}` across user namespaces during attribution. |

Everything else — `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`,
`CAP_SYS_PTRACE`, `CAP_SYS_RESOURCE`, etc. — is removed from the
effective, permitted, inheritable, and bounding sets, and lowered out
of ambient. A subsequent `bpf(BPF_PROG_LOAD)` from the daemon would
fail with `EPERM`.

### How the drop works

`drop_capabilities()` in [`src/capabilities.cpp`](../src/capabilities.cpp)
runs four steps per cap, using the direct `capget(2)` / `capset(2)`
syscalls (the glibc wrappers are deprecated):

1. **`capget`** — snapshot current effective/permitted/inheritable.
2. **`PR_CAP_AMBIENT_LOWER`** — drop from ambient set (`EINVAL`/`ENOENT`
   ignored; the cap may not have been there).
3. **`capset`** — write back the snapshot with the target bits cleared
   in all three sets. This makes the cap non-usable even if step 4 is
   blocked by `NoNewPrivileges`.
4. **`PR_CAPBSET_DROP`** — drop from bounding set (`EPERM`/`EINVAL`
   ignored — `setpcap` may not be available, e.g. inside a container
   with reduced bounding caps).

The order matters: clearing effective/permitted *before* the bounding
drop guarantees the cap is gone from runtime use even when the
bounding drop fails. `apply_post_attach_cap_drop()` enumerates the
caps actually present in the live snapshot (rather than hard-coding a
list), so future kernels that introduce new caps remain covered.

### Failure modes

| Condition | Behaviour |
|-----------|-----------|
| Kernel < 5.8 (no `CAP_BPF`) | Log `WARN`, continue without drop. |
| `capget` fails | Log `WARN` with errno, continue (existing caps unchanged). |
| `capset` fails | Log `WARN` with errno, continue. The Landlock + seccomp layers still constrain damage. |
| `PR_CAPBSET_DROP` returns `EPERM` | Silently ignored (other steps already removed the cap from effective use). |

The daemon never refuses to start because of cap-drop failures — this
is **defence in depth**, not the primary control. The systemd unit's
`CapabilityBoundingSet=` and `AmbientCapabilities=` already restrict
the cap surface; this layer is the last shrink-wrap.

### Inspecting at runtime

The startup log includes a `cap_drop` field and the count of caps that
were removed:

```
Agent started seccomp=true landlock=true cap_drop=true caps_dropped=37
```

To verify empirically:

```bash
$ grep ^Cap /proc/$(pidof aegisbpfd)/status
CapInh:	0000000000001000
CapPrm:	0000001000001000
CapEff:	0000001000001000
CapBnd:	0000001000001000
CapAmb:	0000000000000000
```

The bits set should correspond to the keep set
(`CAP_DAC_READ_SEARCH = 2 → 1<<2 = 0x4`,
`CAP_NET_ADMIN = 12 → 1<<12 = 0x1000`); everything else cleared.

### What capability splitting does not protect

- Pre-attach exploits — until step 3, the daemon still has full
  caps. Combine with seccomp + signing to narrow that window.
- Kernel exploits via the BPF maps that `aegisbpfd` keeps open — held
  fds bypass the cap check on `bpf()` ops. The keep set is deliberately
  small for this reason.
- Out-of-band privilege from setuid binaries — `NoNewPrivileges` (set
  by the seccomp layer) blocks that path.

## See also

- [`docs/SIGNED_BPF_OBJECTS.md`](SIGNED_BPF_OBJECTS.md) — Ed25519 signing of `aegis.bpf.o`.
- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — attacker capabilities and trust boundaries.
- [`src/landlock.cpp`](../src/landlock.cpp), [`tests/test_landlock_sandbox.cpp`](../tests/test_landlock_sandbox.cpp).
- [`src/capabilities.cpp`](../src/capabilities.cpp), [`tests/test_capabilities.cpp`](../tests/test_capabilities.cpp).
