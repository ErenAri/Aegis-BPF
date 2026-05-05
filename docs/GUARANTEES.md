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

### Path-based deny

Two distinct enforcement modes apply depending on which kernel surface is
available:

**LSM mode (race-free, prevention-grade).** When BPF LSM is available, path
deny is enforced inside the `lsm/file_open` hook using the in-kernel
`bpf_d_path()` helper.  The helper walks the same `struct path` the kernel
is about to authorize, under the same kernel locks, and returns a canonical
absolute path that the BPF program looks up in `deny_path_map` synchronously.
There is **no userspace TOCTOU window**: resolution and enforcement happen in
the same hook invocation, the open is rejected with `-EPERM` before the file
descriptor is returned.  This brings path deny to parity with inode deny for
the prevention guarantee.

**Tracepoint fallback (audit-only, TOCTOU-prone).** When BPF LSM is not
available, the agent falls back to `tracepoint/sys_enter_openat`.  The
tracepoint sees the **userspace-supplied filename string before kernel path
resolution** and does a byte-compare against `deny_path_map`.  This mode is
audit-only — tracepoints cannot block the syscall — and is inherently
TOCTOU-prone because the canonical path the kernel ultimately resolves may
differ from what the userspace string suggests (symlink swaps, bind mount
changes, relative-path racing).

Path deny entries are populated from userspace `realpath()` at policy-apply
time and stored in `deny_path_map` as fixed-length byte strings.

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

### Path-based deny TOCTOU (tracepoint fallback only)

- The LSM `file_open` path-deny mode is race-free (see "Path-based deny"
  above): canonical resolution happens inside the same hook that authorizes
  the open, so there is no observable TOCTOU window.
- The **tracepoint `sys_enter_openat` fallback remains TOCTOU-prone**: it
  inspects the userspace-supplied filename string before kernel resolution.
  Symlink swaps, bind-mount changes, or relative-path race conditions can
  cause the canonical path the kernel resolves to diverge from what the
  string would suggest.
- The tracepoint fallback is **audit-only** and cannot block the syscall;
  any logged hit should be treated as a possibly-false-positive observation,
  not a guaranteed enforcement decision.
- Inode-based deny remains the strongest primitive on either surface.

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

## Known bypass classes

| Bypass | Affected surface | Mitigation |
|--------|-----------------|------------|
| Rename denied file to new path | Path deny (any mode) | Use inode deny; re-apply policy |
| Symlink-swap / bind-mount race | Path deny (tracepoint fallback) | Run on a kernel with BPF LSM (race-free `bpf_d_path` mode); use inode deny |
| Delete + recreate at same path | Inode deny | Re-apply policy; monitor file lifecycle |
| OverlayFS upper/lower inode split | Inode deny on overlay | Test with `kernel-matrix.yml` overlay scenarios |
| Mount namespace path divergence | Path deny (audit) | Inode deny is namespace-independent |
| Privileged container (`CAP_SYS_ADMIN`) | All surfaces | Treat as trust boundary breach |
| Kernel module / root compromise | All surfaces | Out of scope (see THREAT_MODEL.md) |

## TOCTOU stance

**Inode-based enforcement is atomic.**  The kernel resolves `dentry → inode`
before the LSM hook fires.  There is no userspace-visible window.

**Path-based enforcement is race-free under LSM.**  The `lsm/file_open`
hook calls `bpf_d_path()` on the same `struct path` the kernel is
authorizing, so canonical resolution and `deny_path_map` lookup happen
atomically inside the same hook invocation.  Paths are resolved in
userspace at policy-apply time only to populate the deny map; enforcement
itself uses the kernel's resolution.

**Path-based enforcement is TOCTOU-prone in tracepoint fallback mode.**
Without LSM, the agent falls back to `tracepoint/sys_enter_openat`, which
only sees the userspace-supplied filename string before kernel resolution.
This mode is audit-only.  Inode deny remains the strongest primitive on
either surface and is recommended for any rule whose target file already
exists at policy-apply time.

## Related documents

- `docs/THREAT_MODEL.md` — Threat model and attacker scope
- `docs/BYPASS_CATALOG.md` — Dispositioned bypass surface catalog
- `docs/POLICY_SEMANTICS.md` — Policy rule types and resolution
- `docs/COMPATIBILITY.md` — Kernel and filesystem compatibility
