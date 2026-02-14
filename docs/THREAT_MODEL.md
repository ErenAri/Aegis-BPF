# AegisBPF Threat Model

Version: 2.0 (2026-02-14) -- Phase 6 Production Roadmap
Status: Canonical threat model for AegisBPF runtime security agent.

This document defines the assets AegisBPF protects, the threat actors it
defends against, trust boundaries, the attack surface with mitigations, explicit
non-goals, and residual risks.  For a dispositioned list of known bypass
surfaces, see `docs/BYPASS_CATALOG.md`.  For enforcement guarantees and TOCTOU
analysis, see `docs/GUARANTEES.md`.

## Attacker model

### In scope
- Unprivileged and limited-privileged users attempting file and network access
  that should be denied.
- Compromised workloads attempting lateral movement, data exfiltration, or
  policy bypass from user space.
- Supply-chain tampering of policy bundles and shipped BPF artifacts before
  runtime load.

### Out of scope
- Kernel compromise, malicious kernel modules, or verifier-level bypasses after
  host kernel integrity is lost.
- Physical attacks against host hardware or firmware.
- Post-root compromise scenarios where an attacker controls all capabilities
  needed to rewrite maps, binaries, and policies.

## Known blind spots
- TOCTOU windows around pathname resolution still depend on inode/path map
  freshness and canonicalization timing.
- Enforcement does not currently cover every network operation family (for
  example `accept` and `sendmsg` paths remain outside current enforcement).
- Strong guarantees depend on operators enabling signed-policy enforcement in
  production (`--require-signature`).

---

## 1. Assets

AegisBPF protects three categories of assets on the host.

### 1.1 Files Protected by Deny Lists

| Asset | Storage | Protection Mechanism |
|-------|---------|---------------------|
| Deny inode map (`deny_inode_map`) | BPF hash map pinned at `/sys/fs/bpf/aegisbpf/deny_inode` | Kernel-enforced `-EPERM` via LSM `file_open` / `inode_permission` hooks |
| Deny path map (`deny_path_map`) | BPF hash map pinned at `/sys/fs/bpf/aegisbpf/deny_path` | Byte-for-byte path comparison in BPF program; audit fallback via tracepoints |
| Policy files on disk | `/etc/aegisbpf/policy.conf`, `/var/lib/aegisbpf/policy.applied` | SHA-256 integrity verification, Ed25519 signature enforcement, file permission checks |
| Applied policy state | `/var/lib/aegisbpf/deny.db`, version counter, applied hash | Atomic writes (`write-rename` pattern), root ownership requirement |

Deny list entries are keyed by `(dev, ino)` tuples (inode-based) or
canonicalized absolute paths (path-based).  Inode-based deny is the primary
enforcement primitive and is immune to rename, hardlink, and symlink
indirection.

### 1.2 Network Endpoints

| Asset | Storage | Protection Mechanism |
|-------|---------|---------------------|
| IPv4 deny map | BPF hash map pinned at `/sys/fs/bpf/aegisbpf/deny_ipv4` | Exact-match lookup in `socket_connect` / `socket_bind` LSM hooks |
| IPv6 deny map | BPF hash map pinned at `/sys/fs/bpf/aegisbpf/deny_ipv6` | Exact-match lookup in `socket_connect` / `socket_bind` LSM hooks |
| CIDR v4 deny map | BPF LPM trie pinned at `/sys/fs/bpf/aegisbpf/deny_cidr_v4` | Longest-prefix-match lookup, O(prefix-length) |
| CIDR v6 deny map | BPF LPM trie pinned at `/sys/fs/bpf/aegisbpf/deny_cidr_v6` | Longest-prefix-match lookup, O(prefix-length) |
| Port deny map | BPF hash map pinned at `/sys/fs/bpf/aegisbpf/deny_port` | Port + protocol + direction tuple matching |

Network deny rules are enforced synchronously in kernel LSM hooks.  The
offending syscall receives `-EPERM` before the connection or bind completes.
Outbound (`connect`) and `bind` operations are in scope; `accept`, `listen`,
and `sendmsg` are not enforced in this release.

### 1.3 Process Integrity

| Asset | Description |
|-------|-------------|
| Agent self-protection | Agent cgroup is added to `allow_cgroup` map to prevent self-denial |
| Survival allowlist | Critical system binaries (`/sbin/init`, `systemd`, etc.) are never blocked, even under policy misconfiguration |
| Process identity | Events include `(pid, start_time)` composite key for stable correlation across PID reuse |
| Audit trail | Structured JSON events emitted via BPF ring buffer with `exec_id`, `trace_id`, and `parent_exec_id` fields |
| BPF object integrity | SHA-256 hash of `aegis.bpf.o` is verified before kernel load |

---

## 2. Threat Actors

### 2.1 Malicious Insider

| Attribute | Description |
|-----------|-------------|
| Capability | Unprivileged or limited-privileged user account on the host |
| Motivation | Exfiltrate sensitive files, disable monitoring, tamper with policy |
| Attack vectors | Direct file access to denied paths, policy file modification, cgroup escape attempts |
| AegisBPF response | Kernel-level deny via LSM hooks; policy files require root ownership and signature verification; config directory permission validation (must be root-owned, not world-writable) |

### 2.2 Compromised Service

| Attribute | Description |
|-----------|-------------|
| Capability | Code execution within a containerized or cgroup-scoped workload |
| Motivation | Lateral movement, data exfiltration, persistence establishment |
| Attack vectors | Opening denied files, connecting to denied network endpoints, attempting to modify BPF maps |
| AegisBPF response | Cgroup-scoped enforcement; workload traffic filtered by IP/CIDR/port deny rules; BPF map modification requires `CAP_BPF` (root only) |

### 2.3 Supply Chain Attack

| Attribute | Description |
|-----------|-------------|
| Capability | Ability to modify artifacts before or during deployment |
| Motivation | Inject malicious policy, replace BPF object, downgrade agent behavior |
| Attack vectors | Tampered policy files, replaced `aegis.bpf.o` binary, policy version rollback |
| AegisBPF response | Ed25519 signed policy bundles with `--require-signature` enforcement; BPF object SHA-256 integrity check at load time; monotonic `policy_version` counter prevents replay of older bundles; Sigstore/Cosign integration for container image signing |

### 2.4 Kernel Exploit

| Attribute | Description |
|-----------|-------------|
| Capability | Ability to exploit kernel vulnerabilities to gain arbitrary kernel code execution |
| Motivation | Bypass all userspace and BPF-based security controls |
| Attack vectors | Kernel memory corruption, malicious kernel modules, BPF verifier bugs |
| AegisBPF response | **Explicitly out of scope.** AegisBPF depends on kernel integrity as a foundational assumption. See Section 5 (Non-Goals). |

---

## 3. Trust Boundaries

### 3.1 Trust Boundary Diagram

```
+=========================================================================+
|                         TRUSTED DOMAIN                                  |
|                                                                         |
|  +---------------------------+   +-----------------------------+        |
|  | Kernel BPF Verifier       |   | Root-owned Daemon           |        |
|  | - Validates all BPF       |   | - Runs as root/CAP_BPF      |        |
|  |   programs before load    |   | - Manages BPF maps          |        |
|  | - Enforces memory safety  |   | - Applies signed policies   |        |
|  | - Guarantees termination  |   | - Seccomp-filtered after    |        |
|  +---------------------------+   |   initialization            |        |
|                                  +-----------------------------+        |
|  +---------------------------+   +-----------------------------+        |
|  | Signed Policy Files       |   | Pinned BPF Maps             |        |
|  | - Ed25519 signatures      |   | - /sys/fs/bpf/aegisbpf/*    |        |
|  | - Anti-rollback versioning |   | - Requires CAP_BPF to write |        |
|  | - SHA-256 content hash    |   | - Survive daemon restart     |        |
|  +---------------------------+   +-----------------------------+        |
|                                                                         |
+============================== BOUNDARY =================================+
|                                                                         |
|                        UNTRUSTED DOMAIN                                 |
|                                                                         |
|  +---------------------------+   +-----------------------------+        |
|  | User Processes            |   | Network Inputs              |        |
|  | - Subject to deny rules   |   | - Inbound/outbound traffic  |        |
|  | - Cannot modify BPF maps  |   | - Filtered by IP/CIDR/port  |        |
|  | - Cgroup-scoped            |   |   deny maps                |        |
|  +---------------------------+   +-----------------------------+        |
|  +---------------------------+                                          |
|  | Unsigned Policies         |                                          |
|  | - Rejected when           |                                          |
|  |   --require-signature set |                                          |
|  | - No provenance guarantee |                                          |
|  +---------------------------+                                          |
|                                                                         |
+=========================================================================+
```

### 3.2 Trusted Components

| Component | Trust Basis |
|-----------|-------------|
| **Kernel BPF verifier** | Validates all BPF programs for memory safety, bounded loops, and valid map access before loading. AegisBPF assumes the verifier is correct. |
| **Root-owned daemon** | The `aegisbpf` daemon runs with `CAP_SYS_ADMIN`, `CAP_BPF`, and `CAP_PERFMON`. It is the sole entity that loads BPF programs, manages maps, and applies policy. After initialization, a seccomp allowlist restricts its syscall surface. |
| **Signed policy files** | Policy bundles signed with Ed25519 keys from the trusted key directory (`/etc/aegisbpf/keys/`). The key directory must be root-owned, not world-writable, and symlinks to key files are rejected. |
| **Pinned BPF maps** | Maps pinned under `/sys/fs/bpf/aegisbpf/` persist across daemon restarts and are only writable by processes with `CAP_BPF`. |
| **BPF object file** | The compiled `aegis.bpf.o` is verified against its build-time SHA-256 hash before kernel load, preventing silent replacement. |

### 3.3 Untrusted Components

| Component | Risk |
|-----------|------|
| **User processes** | Subject to all deny rules. Cannot modify BPF maps without `CAP_BPF`. May attempt to access denied files or network endpoints. |
| **Network inputs** | All inbound and outbound network connections from untrusted workloads are subject to IP, CIDR, and port deny rules. |
| **Unsigned policies** | Policies without Ed25519 signatures provide no provenance or integrity guarantee. When `--require-signature` is set, unsigned policies are rejected outright. |
| **Log/metric consumers** | Consumers of audit events and Prometheus metrics are not trusted to make enforcement decisions. They receive telemetry only. |

---

## 4. Attack Surface

### 4.1 Attack Surface Matrix

| # | Attack Vector | Severity | Mitigation | Status |
|---|--------------|----------|------------|--------|
| AS-1 | Policy file tampering | High | Ed25519 signing + file permission checks | **Implemented** |
| AS-2 | Binary replacement (`aegis.bpf.o`) | High | Binary hash identity (SHA-256 verification at load) | **Implemented** (full binary identity tracking planned Phase 2) |
| AS-3 | PID reuse for event correlation confusion | Medium | `start_time` in process key (`exec_id = pid:start_time`) | **Implemented** |
| AS-4 | BPF map exhaustion (denial of service) | Medium | Pressure monitoring and alerting | **Planned (Phase 5)** |
| AS-5 | Daemon crash / hang | High | Pinned maps + deadman switch | **Implemented** |
| AS-6 | Config map tampering | High | Requires `CAP_BPF` (root only) | **Implemented** |
| AS-7 | Policy version rollback | Medium | Monotonic version counter with anti-rollback check | **Implemented** |
| AS-8 | Break-glass abuse | Medium | Cryptographic token validation (Ed25519 + 24h expiry) | **Implemented** |
| AS-9 | Ring buffer event suppression | Low | Drop counter metric + alerting | **Implemented** |
| AS-10 | Unsigned policy injection | High | `--require-signature` mode rejects unsigned bundles | **Implemented** |

### 4.2 Detailed Mitigation Analysis

#### AS-1: Policy File Tampering

**Threat:** An attacker with write access to `/etc/aegisbpf/` modifies or
replaces policy files to weaken deny rules or add broad allow exceptions.

**Mitigations:**
- **Ed25519 signed bundles:** Production deployments use `policy apply --require-signature`, which rejects any policy that is not signed by a key in the trusted key directory.
- **SHA-256 hash verification:** `policy apply --sha256 <hash>` verifies file content integrity before applying rules to BPF maps.
- **File permission checks:** `validate_file_permissions()` rejects files that are world-writable or (when `require_root_owner` is set) not owned by root.
- **Config directory validation:** `validate_config_directory_permissions()` confirms `/etc/aegisbpf` is root-owned and not world-writable at daemon startup.
- **Key directory security:** The trusted keys directory is validated for root ownership, and symlinks to key files are rejected to prevent symlink-based key injection.
- **Atomic writes:** All persistent state updates use the write-rename pattern via `atomic_write_file()` to prevent partial-write corruption.

#### AS-2: Binary Replacement

**Threat:** An attacker replaces `aegis.bpf.o` on disk with a modified BPF
program that permits all operations or exfiltrates data.

**Mitigations:**
- **SHA-256 verification at load time:** The BPF object hash is checked against the expected hash stored at `/etc/aegisbpf/aegis.bpf.sha256` before the object is loaded into the kernel.
- **Root-only write access:** The BPF object is installed at `/usr/lib/aegisbpf/aegis.bpf.o` with root-only write permissions.
- **Phase 2 enhancement (planned):** Full binary hash identity tracking will extend this to runtime re-verification and integration with container image signatures.

#### AS-3: PID Reuse

**Threat:** After a process exits, the kernel may reassign its PID to a new
process.  An attacker could attempt to correlate events from different processes
to confuse forensic analysis.

**Mitigations:**
- **Composite process key:** All events include `(pid, start_time)` as the process identity, forming the `exec_id` field (e.g., `"12345:123456789"`).
- **Parent correlation:** Events also include `parent_start_time` and `parent_exec_id` for reliable process tree reconstruction.
- **CWD cache validation:** The `CwdCache` validates `start_time` before returning cached working directory entries, preventing stale PID associations.

#### AS-4: BPF Map Exhaustion

**Threat:** An attacker triggers conditions that fill BPF hash maps to capacity,
causing legitimate deny rules to be silently dropped or new rules to fail
insertion.

**Mitigations (planned Phase 5):**
- **Map pressure monitoring:** Prometheus metrics will track map utilization ratios and alert when maps approach capacity.
- **Entry count verification:** Post-apply verification (`verify_map_entry_count()`) already confirms that map contents match expected counts after every policy application.
- **Configurable map sizes:** `set_max_deny_inodes()`, `set_max_deny_paths()`, and `set_max_network_entries()` allow capacity tuning at build time.
- **Shadow map validation:** The shadow-then-sync policy application path validates entry counts in shadow maps before touching live maps.

#### AS-5: Daemon Crash or Hang

**Threat:** If the daemon crashes or becomes unresponsive, enforcement could
lapse, leaving the host unprotected.

**Mitigations:**
- **Pinned BPF maps:** All maps are pinned to `/sys/fs/bpf/aegisbpf/` and survive daemon restarts.  BPF programs continue enforcing rules in the kernel regardless of daemon state.
- **Deadman switch:** A configurable heartbeat mechanism updates a deadline timestamp in the BPF config map.  If the daemon fails to renew the heartbeat within the TTL, the BPF programs automatically revert to audit-only mode rather than silently failing open or closed.
- **Heartbeat thread:** A dedicated thread refreshes the deadman deadline at `TTL/2` intervals.
- **Auto-revert on deny-rate spikes:** If the deny rate exceeds a configurable threshold for a sustained period, the agent automatically reverts to audit-only mode to prevent cascading failures from policy misconfiguration.
- **Crash-safe policy application:** The shadow-then-sync approach populates shadow maps first, verifies integrity, and only then syncs to live maps.  If the daemon crashes during apply, the previous live maps remain intact.
- **Rollback support:** `policy rollback` restores the previously applied policy from `/var/lib/aegisbpf/policy.applied.prev`.

#### AS-6: Config Map Tampering

**Threat:** An attacker modifies the `agent_config_map` to disable enforcement
(set `audit_only = 1`) or alter the deadman deadline.

**Mitigations:**
- **Capability requirement:** Modifying BPF maps via `bpf_map_update_elem()` requires `CAP_BPF`, which is only available to root or processes with explicit capability grants.
- **No unprivileged BPF writes:** The kernel enforces that only appropriately privileged processes can write to BPF maps.
- **Seccomp restriction:** After initialization, the daemon's own seccomp filter restricts its syscall surface, reducing the risk of exploitation that could be used to modify maps.

#### AS-7: Policy Version Rollback

**Threat:** An attacker replays a previously valid (but now revoked or outdated)
signed policy bundle to weaken protection.

**Mitigations:**
- **Monotonic version counter:** Each signed bundle includes a `policy_version` field.  The agent persists the highest accepted version in `/var/lib/aegisbpf/version_counter` via atomic write.
- **Anti-rollback check:** `check_version_acceptable()` rejects any bundle whose version is not strictly greater than the current counter.
- **Version counter atomicity:** The counter file is updated via `atomic_write_file()` to prevent partial writes.

#### AS-8: Break-Glass Abuse

**Threat:** An attacker creates or modifies the break-glass token to force the
agent into audit-only mode, disabling enforcement.

**Mitigations:**
- **Cryptographic validation:** Break-glass tokens use the format `<timestamp>:<ed25519_signature>` and are verified against trusted keys.
- **24-hour expiry:** Tokens older than 24 hours are automatically rejected.
- **File permission validation:** The break-glass token path is validated for proper ownership and permissions before the token is accepted.
- **Operational controls:** Break-glass events are logged prominently and require incident ticket + postmortem + mandatory rollback per the incident response procedure.

---

## 5. Non-Goals

AegisBPF explicitly does **not** attempt to defend against the following threats.
These are outside the security boundary and require complementary controls.

| Non-Goal | Rationale |
|----------|-----------|
| **Kernel exploits** | AegisBPF runs as a BPF program inside the kernel.  If the kernel itself is compromised (via memory corruption, malicious modules, or other kernel-level attacks), all BPF-based enforcement is unreliable.  Kernel integrity is a prerequisite, not something AegisBPF can provide. |
| **BPF verifier bugs** | The BPF verifier is assumed correct.  A verifier bypass that allows loading malicious BPF programs would undermine the entire enforcement model.  This is a kernel subsystem defect, not an application-layer concern. |
| **Physical access** | An attacker with physical access to the host can modify boot parameters, attach debugging hardware, or replace storage media.  These attacks require hardware-level mitigations (Secure Boot, TPM, disk encryption) that are outside AegisBPF's scope. |
| **Side-channel attacks** | Timing attacks, speculative execution attacks (Spectre/Meltdown variants), and cache-based side channels are CPU and kernel concerns.  AegisBPF does use constant-time hash comparisons to avoid leaking policy content via timing, but it does not claim defense against microarchitectural side channels. |
| **Host root compromise** | If an attacker gains full root access on the host, they can unload BPF programs, modify pinned maps, replace the daemon binary, or disable security controls entirely.  AegisBPF assumes the host root is part of the trusted computing base. |
| **Inbound network enforcement** | `accept()`, `listen()`, and `sendmsg()` are not covered by deny rules in this release.  Only `connect()` (outbound) and `bind()` operations are enforced. |

---

## 6. Residual Risks

The following risks are acknowledged, analyzed, and accepted with documented
mitigations or monitoring strategies.

### 6.1 TOCTOU Between `stat()` and BPF Check

**Description:** At policy-apply time, the daemon calls `stat()` (via
`realpath()`) to resolve file paths to `(dev, ino)` tuples.  There is a
time-of-check/time-of-use window between this userspace resolution and the
subsequent kernel-side enforcement via the BPF LSM hook.

**Impact:** If the filesystem layout changes between `stat()` and the next
`open()` syscall (e.g., a file is moved, deleted, or replaced), the resolved
inode may no longer correspond to the intended file.

**Analysis:**
- **Inode-based enforcement is atomic within the kernel:** Once an inode deny
  entry is in the BPF map, the kernel resolves `dentry -> inode` before the LSM
  hook fires.  There is no userspace-visible TOCTOU window at enforcement time.
- **The TOCTOU window exists only at policy-apply time**, between the daemon's
  `stat()` call and the BPF map update.  This is a narrow window (typically
  microseconds) and requires an attacker to race the policy application.
- **Path-based deny has a wider TOCTOU surface:** Path entries are resolved
  once at apply time via `realpath()`.  If the filesystem changes after
  resolution, the path entry may be stale.

**Accepted mitigations:**
- Use inode-based deny as the primary enforcement primitive.
- Re-apply policy after known filesystem lifecycle events.
- Path-based deny is recommended only for audit/observability, not as a
  sole enforcement mechanism.
- Future enhancement: inotify-based policy refresh on filesystem changes.

### 6.2 OverlayFS Inode Indirection

**Description:** OverlayFS presents a merged view of upper and lower layers.
When a file is copied up from the lower layer to the upper layer (copy-on-write
semantics), the upper layer file receives a **new inode** that differs from
both the lower layer inode and any inode previously observed.

**Impact:** An inode deny rule applied against a lower-layer file will not match
after copy-up, because the upper-layer inode is different.  The file becomes
accessible despite the deny rule.

**Analysis:**
- This is inherent to overlayfs copy-on-write semantics and cannot be fully
  resolved without filesystem-specific hooks.
- The CI kernel-matrix workflow includes overlay-specific test scenarios to
  validate behavior and detect regressions.
- Container workloads using overlayfs are the primary affected environment.

**Accepted mitigations:**
- Document overlay behavior in `docs/COMPATIBILITY.md`.
- Test overlayfs scenarios in CI (`kernel-matrix.yml` overlay test).
- For high-assurance use cases, apply deny rules from within the container's
  mount namespace where inodes are resolved against the merged view.
- Re-apply policy after container image pulls or layer changes.

### 6.3 tmpfs Volatility

**Description:** Files on tmpfs exist only in memory and are lost on reboot or
unmount.  Inode numbers on tmpfs are assigned dynamically and are not stable
across mounts.

**Impact:**
- Deny rules targeting tmpfs inodes become invalid after the tmpfs is
  unmounted and remounted (all inode numbers are reassigned).
- An attacker could create files on tmpfs to stage operations that are not
  covered by deny rules targeting persistent filesystem inodes.
- `/tmp` is commonly a tmpfs mount, making it a frequent staging ground.

**Accepted mitigations:**
- Path-based deny provides coverage for well-known tmpfs paths
  (e.g., `/tmp/known_malware`).
- Policy should be re-applied after tmpfs remounts.
- Inode-based deny is not recommended as the sole protection mechanism for
  tmpfs-resident files due to inode instability.
- For security-critical paths on tmpfs, use path-based deny in conjunction
  with inode deny and re-apply after any remount event.

### 6.4 Residual Risk Summary

| Risk | Likelihood | Impact | Mitigation Status |
|------|-----------|--------|-------------------|
| TOCTOU at policy-apply (`stat()` vs BPF check) | Low (narrow window, requires racing policy apply) | Medium (missed deny for one file lifecycle) | Accepted; inode enforcement is atomic at check time |
| OverlayFS inode indirection on copy-up | Medium (common in container workloads) | Medium (deny bypass for copied-up files) | Accepted; CI-tested, documented, re-apply guidance |
| tmpfs inode volatility | Low (requires tmpfs remount) | Low (inode rules become stale) | Accepted; path-based deny recommended for tmpfs |
| Ring buffer drops under extreme load | Low (sized for expected workload) | Low (audit events lost, enforcement unaffected) | Monitored; `aegisbpf_ringbuf_drops_total` metric + alerting |
| Audit-only degradation (no BPF LSM) | Medium (kernel config dependent) | High (no enforcement) | Detected at startup; logged prominently; capability check in `daemon_run()` |
| Cgroup allowlist over-scoping | Low (operational control) | Medium (broad bypass) | Change-controlled, audited, short-lived exceptions |

---

## 7. Security Controls Summary

### 7.1 Defense-in-Depth Layers

```
+----------------------------------------------------------+
| Layer 5: Cryptographic                                   |
| Constant-time comparisons, BPF integrity, policy sigs    |
+----------------------------------------------------------+
| Layer 4: Code Signing                                    |
| Sigstore/Cosign + SBOM                                   |
+----------------------------------------------------------+
| Layer 3: MAC Policies                                    |
| AppArmor / SELinux                                       |
+----------------------------------------------------------+
| Layer 2: Seccomp                                         |
| Syscall allowlist (--seccomp)                            |
+----------------------------------------------------------+
| Layer 1: Capabilities                                    |
| CAP_SYS_ADMIN, CAP_BPF, CAP_PERFMON                     |
+----------------------------------------------------------+
```

### 7.2 Security Hardening Checklist

| Control | Implementation |
|---------|---------------|
| Compiler hardening | `FORTIFY_SOURCE=2`, `stack-protector-strong`, PIE, full RELRO |
| BPF operation timeouts | Prevents indefinite hangs during BPF syscalls |
| Secure temp files | `mkstemp()` for symlink-attack resistant temporary files |
| Atomic file writes | Write-rename pattern for all persistent state |
| Key directory validation | Root ownership, no world-writable, symlink rejection |
| Break-glass token crypto | Ed25519 signature + 24-hour expiry window |
| Auto-revert | Audit-only fallback on deny-rate spikes (configurable threshold) |
| Map verification | Post-apply entry count check with crash-safe rollback |
| Thread-safe formatting | `localtime_r` / `gmtime_r` (no global state) |
| Seccomp hardening | Removed `SYS_execve`, replaced `popen` with zlib |
| O(1) cgroup resolution | `open_by_handle_at` for efficient cgroup path lookup |
| Struct layout assertions | Compile-time size and offset checks between userspace and BPF |

---

## 8. Compliance and Coverage Boundaries

### 8.1 Syscall Path Coverage

| Syscall Path | Enforcement | Notes |
|-------------|-------------|-------|
| `open` / `openat` / `openat2` | In scope | LSM `file_open` and `inode_permission` hooks |
| `execve` | Partial | Inode deny applies; exec telemetry is audit signal |
| `mmap` (executable mapping) | Partial | Depends on kernel hook behavior and file-open path |
| `socket_connect` | In scope | IPv4/IPv6 exact, CIDR, and port deny |
| `socket_bind` | In scope | Port-oriented deny logic |
| `accept` / `listen` / `sendmsg` | Out of scope | No enforcement in this release |

### 8.2 Filesystem Coverage

| Filesystem | Status | Notes |
|-----------|--------|-------|
| ext4 | Primary validated | Full inode + path enforcement |
| xfs | Primary validated | Full inode + path enforcement |
| OverlayFS | Supported with caveats | Upper/lower inode split; see Section 6.2 |
| tmpfs | Supported with caveats | Volatile inodes; see Section 6.3 |
| NFS / FUSE | Not guaranteed | Not a primary enforcement surface |

---

## Related Documents

| Document | Relationship |
|----------|-------------|
| `docs/GUARANTEES.md` | Enforcement guarantees and TOCTOU analysis |
| `docs/BYPASS_CATALOG.md` | Dispositioned bypass surface catalog |
| `docs/POLICY_SEMANTICS.md` | Policy rule types and resolution semantics |
| `docs/COMPATIBILITY.md` | Kernel and filesystem compatibility matrix |
| `docs/KEY_MANAGEMENT.md` | Policy signing key rotation and revocation |
| `docs/INCIDENT_RESPONSE.md` | Incident handling procedures |
| `docs/PRODUCTION_READINESS.md` | Production readiness checklist |
| `docs/PERFORMANCE.md` | Performance profile and capacity planning |
| `SECURITY.md` | Vulnerability reporting and hardening details |
