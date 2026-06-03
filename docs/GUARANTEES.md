# AegisBPF Enforcement Guarantees

Version: 1.0 (2026-02-09)

This document defines what AegisBPF enforces, what it does not enforce, and the
reasoning behind each boundary.  For the full threat model and attacker surface,
see `docs/THREAT_MODEL.md`.

## Enforced (when BPF LSM is available and the host is not root-compromised)

### Inode-based file deny

- Inode deny is **race-free**: the kernel resolves the inode before the LSM
  hook fires.  There is no TOCTOU window between name resolution and
  enforcement.
- Deny decisions use the `(dev, ino)` tuple, making them immune to rename,
  hardlink, bind-mount, and symlink indirection as long as the same inode is
  referenced.
- Inode deny entries are populated from userspace `stat()` at policy-apply
  time.  The kernel-side lookup in `deny_inode_map` is O(1) hash lookup per
  checked inode.

### Path-based deny (audit fallback)

- Path deny entries use **canonicalized absolute paths** resolved at
  policy-apply time (via `realpath()`).
- Path-based deny is the primary enforcement mechanism when the tracepoint
  audit fallback is active (BPF LSM unavailable).
- Path entries support the `deny_path_map` BPF hash map and are compared
  byte-for-byte in the BPF program.

### Network deny

- **Exact IP deny:** IPv4 and IPv6 addresses are matched in dedicated hash
  maps (`deny_ipv4_map`, `deny_ipv6_map`).
- **CIDR range deny:** IPv4 and IPv6 CIDR ranges use BPF LPM (Longest Prefix
  Match) trie maps for O(prefix-length) lookup.
- **Port deny:** Port + protocol + direction tuples are matched in a hash map
  (`deny_port_map`). Port-oriented rules also apply to `listen()` when the
  kernel exposes the `socket_listen` LSM hook and to `accept()` when the
  kernel exposes the `socket_accept` LSM hook.
- **Inbound accepted-peer deny:** When the kernel exposes `socket_accept`,
  accepted inbound connections also evaluate remote exact IP, CIDR, and
  IP:port deny rules against the accepted peer tuple.
- Network deny is enforced synchronously in `socket_connect` and
  `socket_bind` LSM hooks, with additional `socket_listen` coverage for
  port-deny rules when that hook is available, `socket_accept` coverage for
  established inbound accepts when that hook is available, plus outbound
  `socket_sendmsg` coverage when that hook is available.  The syscall returns
  `-EPERM` before the operation completes.

### Policy integrity

- **Signed bundles:** Policy bundles can be cryptographically signed with
  Ed25519 keys.  `--require-signature` mode rejects unsigned or incorrectly
  signed policy.
- **Anti-rollback:** A monotonic `policy_version` counter prevents replay of
  older policy bundles.  The counter is persisted via atomic file write.
- **BPF object integrity:** The BPF object hash is verified against the
  build-time SHA-256 at load time.

### Self-protection

- **Seccomp filter:** The agent applies a strict seccomp-BPF allowlist after
  initialization, limiting its own syscall surface.
- **Survival allowlist:** Critical system binaries (`/sbin/init`, `systemd`,
  etc.) are added to a BPF map and are never blocked, even if a misconfigured
  policy would otherwise deny them.
- **Cgroup allowlist:** The agent's own cgroup is exempted from deny rules to
  prevent self-denial.
- **Deadman switch:** If the agent fails to update its heartbeat within the
  configured deadline, the BPF programs revert to audit-only mode.

## Not enforced

### File rename and hardlink after policy apply

- If a denied file is renamed or hardlinked after policy is applied, the
  **inode deny still holds** (same `dev:ino`).
- However, the **path-based deny entry becomes stale**: the old path no longer
  matches, and the new path was never added.
- Mitigation: re-apply policy or use inode-based deny for highest assurance.

### File delete and recreate (inode reuse)

- If a denied file is deleted and a new file is created at the same path, the
  new file gets a **new inode**.  The old inode deny entry no longer applies.
- The path deny entry will still match the path, but only in audit/tracepoint
  mode.
- Mitigation: re-apply policy after file lifecycle events.

### Path-based deny TOCTOU

- There is an inherent TOCTOU window between userspace `realpath()` resolution
  at policy-apply time and kernel-side enforcement.
- If the filesystem layout changes between `realpath()` and the next `open()`
  syscall, the resolved path may no longer be accurate.
- **This does not affect inode-based deny**, which is resolved atomically by
  the kernel.

### Audit-only mode

- When `audit_only=1` is set (or when BPF LSM is unavailable and the agent
  falls back to tracepoint-only mode), deny decisions are logged but **not
  enforced**.  Syscalls succeed.
- The deadman switch reverts to audit-only, not to full enforcement.

### Partial network coverage

- `listen()` remains port-deny only when the kernel exposes `socket_listen`.
- `accept()` is covered for remote exact IP, CIDR, IP:port, and local-port
  deny rules when the kernel exposes `socket_accept`.
- `sendmsg()` is covered for outbound exact IP, CIDR, IP:port, and egress-port
  rules when the kernel exposes `socket_sendmsg`.
- Exact IP and CIDR rules do not apply to `listen()` decisions in this release.

### Non-ext4/xfs filesystems

- ext4 and xfs are the primary validated filesystems.
- OverlayFS is supported with caveats (upper/lower layer inode differences).
- Network and distributed filesystems (NFS, FUSE variants) are not guaranteed
  surfaces.

### OverlayFS copy-up propagation is asynchronous

- `lsm/inode_copy_up` fires synchronously when a denied lower-layer inode is
  copied up, but the hook only emits an event and allows the copy-up to proceed.
- Userspace re-resolves the new upper-layer inode and adds it to the deny map.
  Between the copy-up completing and that re-propagation there is a brief window
  in which the new upper-layer inode is not yet denied. This is detection plus
  best-effort propagation, not synchronous enforcement.

### Signal-fallback enforcement is opt-in and signal-based

- On kernels without BPF-LSM, `connect()` and `open()` cannot be denied with
  `-EPERM`. The opt-in `--enforce-fallback=signal` flag arms two symmetric
  syscall tracepoints — `sys_enter_connect` (network) and `sys_enter_openat`
  (file) — that, in enforce mode, terminate a process reaching a denied endpoint
  or opening a denied path via `bpf_send_signal()` (default `SIGKILL`).
- This is signal-based termination, not synchronous denial: the syscall may
  partially proceed before the signal is delivered on syscall return. It is also
  evaluated on the *syscall-entry* view — protocol is not resolvable for
  `connect()` (protocol-agnostic rules only), and the file path is matched
  by-path rather than by-inode, so the file arm does **not** carry the
  inode-alias guarantee that the `lsm/file_open` deny does (proved in
  `proofs/inode_alias_resistance.py`). Signal-fallback is a strictly weaker tier.
- The network arm is verified to fire (`SIGKILL`, `net_connect_block`
  action=`KILL`) on a connect to a denied IP; the file arm mirrors it on an open
  of a denied path.
- **Gate status:** when BPF-LSM is genuinely absent **and** the operator opts in
  with `--enforce-fallback=signal` **and** the kernel can deliver the signal
  (tracepoints + bpf syscall), the enforce-gate now *promotes* signal-fallback to
  the primary posture: the daemon runs in the distinct `ENFORCE_SIGNAL`
  runtime-state instead of degrading to audit-only. No-Pretend is preserved — it
  is a separate, strictly-weaker state (asynchronous kill, not synchronous
  `-EPERM`), `enforce_capable` stays `false` (the `BPF_LSM_DISABLED` blocker is
  still reported), and the daemon never claims `ENFORCE`. Without the opt-in (or
  without signal capability) the gate behaves as before (fail-closed / audit
  fallback). The promotion *decision* is unit-tested (No-Pretend truth table);
  the in-kernel kill on a real no-LSM host remains validated by design + the
  matrix load gate, with a live no-LSM-kernel behavioral test as the one open
  follow-up.

## Known bypass classes

| Bypass | Affected surface | Mitigation |
|--------|-----------------|------------|
| Rename denied file to new path | Path deny (audit) | Use inode deny; re-apply policy |
| Delete + recreate at same path | Inode deny | Re-apply policy; monitor file lifecycle |
| OverlayFS upper/lower inode split | Inode deny on overlay | Mitigated for `deny_always` rules via race-free `lsm/inode_copy_up` hook; `protect_verified_exec` rules use event-driven userspace propagation |
| Mount namespace path divergence | Path deny (audit) | Inode deny is namespace-independent |
| Privileged container (`CAP_SYS_ADMIN`) | All surfaces | Treat as trust boundary breach |
| Kernel module / root compromise | All surfaces | Out of scope (see THREAT_MODEL.md) |

## TOCTOU stance

**Inode-based enforcement is atomic.**  The kernel resolves `dentry → inode`
before the LSM hook fires.  There is no userspace-visible window.

**Path-based enforcement has inherent TOCTOU.**  Paths are resolved in
userspace at policy-apply time.  Between resolution and the next kernel check,
the filesystem can change.  For this reason, inode deny is the recommended
enforcement primitive.  Path deny exists primarily for audit/observability and
as a fallback when inode resolution is impractical.

## Related documents

- `docs/THREAT_MODEL.md` — Threat model and attacker scope
- `docs/BYPASS_CATALOG.md` — Dispositioned bypass surface catalog
- `docs/POLICY_SEMANTICS.md` — Policy rule types and resolution
- `docs/COMPATIBILITY.md` — Kernel and filesystem compatibility
