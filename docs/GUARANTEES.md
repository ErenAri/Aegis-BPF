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
  (`deny_port_map`).
- Network deny is enforced synchronously in `socket_connect` and `socket_bind`
  LSM hooks.  The syscall returns `-EPERM` before the connection is
  established.

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

### Inbound network connections

- `accept()`, `listen()`, and `sendmsg()` are not covered by deny rules in
  this release.
- Only `connect()` (outbound) and `bind()` are enforced.

### Non-ext4/xfs filesystems

- ext4 and xfs are the primary validated filesystems.
- OverlayFS is supported with caveats (upper/lower layer inode differences).
- Network and distributed filesystems (NFS, FUSE variants) are not guaranteed
  surfaces.

## Known bypass classes

| Bypass | Affected surface | Mitigation |
|--------|-----------------|------------|
| Rename denied file to new path | Path deny (audit) | Use inode deny; re-apply policy |
| Delete + recreate at same path | Inode deny | Re-apply policy; monitor file lifecycle |
| OverlayFS upper/lower inode split | Inode deny on overlay | Test with `kernel-matrix.yml` overlay scenarios |
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
