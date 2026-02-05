# AegisBPF Threat Model

Version: 1.0 (2026-02-05)
Status: Canonical threat model for the v1 contract.

This document defines what AegisBPF is designed to defend, what is explicitly
out of scope, and where bypass risk remains.

For a dispositioned list of known bypass surfaces, see
`docs/BYPASS_CATALOG.md`.

## Security objective

Prevent unauthorized file and network operations from untrusted workloads on a
Linux host, while producing usable audit evidence for incident response.

## Assets and trust boundaries

### Protected assets
- File access policy state (`deny_*`, `allow_*` maps and applied policy files)
- BPF object integrity (`aegis.bpf.o` + expected SHA256)
- Policy trust chain (trusted public keys + signed bundles)
- Audit/event stream (ring buffer output + metrics)

### Trust boundaries
- Kernel-space BPF programs enforce decisions; user-space consumes telemetry.
- The agent runs with elevated privilege and is part of the trusted computing
  base.
- Consumers of logs/metrics are not trusted to make enforcement decisions.

## Attacker model

### In scope
- Unprivileged host processes attempting blocked file opens.
- Container workloads attempting disallowed file/network operations.
- Policy tampering attempts without access to trusted signing keys.
- Supply-chain tampering of the BPF object on disk.

### Out of scope
- Host root compromise.
- Kernel compromise, malicious kernel modules, or verifier bugs.
- Physical/firmware attacks.
- Privileged container escape where attacker gains host-level capabilities
  equivalent to root.

## Coverage boundaries

| Surface | Covered | Notes |
|---|---|---|
| File enforce path | Yes (LSM `file_open` + `inode_permission`) | Returns `-EPERM` in enforce mode |
| File audit fallback | Partial (`openat` tracepoint) | Audit only; cannot block |
| Network egress/connect | Yes (`socket_connect`) | IPv4 + IPv6 exact/CIDR/port |
| Network bind | Yes (`socket_bind`) | Port-oriented deny logic |
| Inbound accept/listen/sendmsg | No | Currently out of scope |
| Non-LSM kernel paths | Partial | Depends on available hooks |

### Syscall path coverage boundaries

This release treats file enforcement coverage as limited to LSM-backed open
permission paths:

| Path | Contract status | Notes |
|---|---|---|
| `open` / `openat` / `openat2` | In scope | Covered via LSM permission hooks, not by tracepoints alone |
| `execve` | Partial | File access policy still enforced via inode checks; process-exec telemetry is audit signal |
| `mmap` executable mapping | Partial | Depends on kernel hook behavior and file-open path leading to mapping |
| `socket_connect` / `socket_bind` | In scope for network deny policy | Rule types documented in `docs/POLICY_SEMANTICS.md` |
| `accept` / `listen` / `sendmsg` | Out of scope | No block guarantees in this release |

### Filesystem caveats

- ext4/xfs are the primary validated filesystems for enforcement semantics.
- OverlayFS is supported with caveats: upper/lower inode behavior can differ
  from single-layer filesystems.
- Bind mounts may present the same inode under multiple paths; inode deny still
  applies, path telemetry can differ.
- Network/distributed filesystems (for example NFS/FUSE variants) are not a
  primary guarantee surface in this release.

### Container and orchestration caveats

- Mount namespaces can cause path-view differences between the agent and target
  workloads; inode enforcement remains the primary invariant.
- User namespaces are treated as a bypass-risk amplifier when combined with
  privileged runtime configuration.
- Privileged Kubernetes pods (`privileged: true`, broad host namespace/device
  access, or equivalent host-level capability) are outside the default trust
  boundary and must be treated as high-risk exceptions.

## Known blind spots and bypass surface

### Namespaces and mounts
- Path rules are canonicalized in the agent's mount namespace at policy-apply
  time; namespace-specific path views can differ.
- Bind mounts can expose the same inode under multiple paths. Inode deny rules
  still hold, but path-only observability can appear inconsistent.
- OverlayFS can produce different upper/lower inode behavior than plain ext4/xfs.

### Filesystem/object lifecycle
- Inode-based enforcement is robust to rename/hardlink but can be affected by
  inode reuse after delete/recreate cycles.
- Path entries in `deny_path_map` mainly support tracepoint audit fallback;
  enforce decisions are inode-driven.

### Privilege and policy bypass vectors
- `allow_cgroup` and break-glass are intentional bypass controls and must be
  tightly governed.
- Privileged workloads (`CAP_SYS_ADMIN`/equivalent) can undermine host
  controls; treat as trust boundary breach.
- If BPF LSM is unavailable, enforcement degrades to audit-only.

### Accepted vs non-accepted bypasses

| Case | Status | Required handling |
|---|---|---|
| `allow_cgroup` exemption | Accepted (explicit) | Change-controlled, audited, short-lived where possible |
| Break-glass mode | Accepted (explicit emergency control) | Incident ticket + postmortem + mandatory rollback |
| Host root or kernel compromise | Not accepted (out of scope) | Treat as full trust-boundary failure |
| Privileged orchestrator workloads bypassing host controls | Not accepted for core guarantee | Scope as exception, not as protected workload |

## Security guarantees (when prerequisites hold)

If BPF LSM is enabled and the host is not root-compromised:
- Denied inodes are blocked with `-EPERM`.
- Audit events include stable process correlation fields (`exec_id`, `trace_id`).
- Signed bundle anti-rollback is enforced via monotonic `policy_version`.
- BPF object hash verification prevents silent binary swap at load time.

## Residual risk management

- Run with signature enforcement: `policy apply --require-signature`.
- Keep trusted keys in root-owned path, rotate at defined cadence.
- Treat audit-only mode as reduced-security operation and alert on it.
- Use runbooks for ring-buffer drops, false positives, and break-glass events.

Related docs:
- `docs/POLICY_SEMANTICS.md`
- `docs/COMPATIBILITY.md`
- `docs/KEY_MANAGEMENT.md`
- `docs/runbooks/`
