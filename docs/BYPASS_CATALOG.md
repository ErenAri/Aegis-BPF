# AegisBPF Bypass Catalog

Version: 1.0 (2026-02-05)
Status: Canonical bypass catalog for the v1 contract.

This catalog records known bypass surfaces and their disposition. Each entry is
classified as accepted, mitigated, or roadmap to keep claims defensible.

## Accepted (out of scope for v1)

- **Root compromise / kernel compromise**
  - Out of scope by threat model. Kernel modules or root can bypass policy.
- **Non-LSM enforcement paths when BPF LSM is unavailable**
  - Tracepoint fallback is audit-only; syscall deny is not possible.
- **Inbound network surfaces (`accept`, `listen`, `sendmsg`)**
  - Not enforced in current release; no block guarantees.
- **Privileged container escape with host-level capabilities**
  - Treated as root-equivalent in scope definition.

## Mitigated (explicitly handled)

- **Symlink swaps**
  - Canonical path resolution + inode-based enforcement.
- **Rename / hardlink path drift**
  - Inode-based deny persists across renames and hardlinks.
- **Bind-mount aliases**
  - Enforcement is inode-driven; path telemetry can differ by namespace.

## Roadmap (planned mitigation or coverage expansion)

- **Inbound network enforcement**
  - Add hooks and semantics for `accept`/`listen` surfaces.
- **Broader filesystem matrix**
  - Extend validation beyond ext4/xfs to additional FS types.
- **Namespace-specific path views**
  - Improve operator tooling to reconcile path differences across namespaces.
