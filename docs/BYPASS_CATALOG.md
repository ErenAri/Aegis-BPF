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
- **Privileged container escape with host-level capabilities**
  - Treated as root-equivalent in scope definition.

## Mitigated (explicitly handled)

- **Symlink swaps**
  - Canonical path resolution + inode-based enforcement.
  - Evidence: `docs/EDGE_CASE_COMPLIANCE_SUITE.md` (symlink swap scenarios).
- **Rename / hardlink path drift**
  - Inode-based deny persists across renames and hardlinks.
  - Evidence: `docs/EDGE_CASE_COMPLIANCE_SUITE.md` (rename + hardlink scenarios).
- **Bind-mount aliases**
  - Enforcement is inode-driven; path telemetry can differ by namespace.
  - Evidence: `docs/EDGE_CASE_COMPLIANCE_SUITE.md` (bind‑mount alias scenarios).
- **Outbound message sends (`sendmsg`)**
  - Covered by the same remote endpoint deny semantics as `connect()` when the
    kernel exposes `socket_sendmsg`.
  - Evidence: `docs/NETWORK_LAYER_DESIGN.md`, `docs/POLICY_SEMANTICS.md`.

## Roadmap (planned mitigation or coverage expansion)

- **Pre-accept inbound policy coverage**
  - Add earlier inbound filtering or richer hook coverage before `accept()`
    returns the socket to user space.
- **Broader filesystem matrix**
  - Extend validation beyond ext4/xfs to additional FS types.
- **Namespace-specific path views**
  - Improve operator tooling to reconcile path differences across namespaces.
