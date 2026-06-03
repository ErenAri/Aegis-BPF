# AegisBPF Bypass Catalog

Version: 2.0 (2026-06-01)
Status: Canonical bypass catalog for the v1 contract.

This catalog records known bypass surfaces and their disposition, classified as
**accepted**, **mitigated**, or **roadmap** to keep claims defensible.

Per the enforcement-semantics whitepaper (§5): *no bypass is considered
mitigated unless it is backed by a reproducible regression test.* That rule is
machine-enforced — `scripts/validate_enforcement_proof_contract.py` (the
`enforcement-proof-contract` CI job) fails the build if any **mitigated** entry
below lacks a `Regression:` anchor that resolves to a real test. Recognized
anchor forms:

- `enforcement_proof.sh:<name>` — a behavioral probe in
  `tests/enforcement/enforcement_proof.sh` (`assert_bypass <name>` /
  `assert_blocked <name>`), run against a live enforcing daemon on the kernel
  matrix.
- `test_bypasses.cpp::<TestName>` — a gtest in `tests/e2e/test_bypasses.cpp`.
- `kernel-matrix.yml:<step name>` — a step in `.github/workflows/kernel-matrix.yml`.

Entries may *additionally* cite a `Proof:` anchor of the form
`<script.py>::<TheoremId>` (e.g. `inode_alias_resistance.py::T2`), pointing at a
**machine-checked theorem** in `proofs/`. The behavioral `Regression:` anchor
binds the *deployed behavior* on the kernel matrix; the `Proof:` anchor binds the
*decision logic* — the LSM verdict is a pure function of inode identity and
cgroup, never of the path, so the whole path-aliasing family is impossible by
construction. Proof anchors are likewise machine-validated by
`scripts/validate_enforcement_proof_contract.py`. See [`proofs/README.md`](../proofs/README.md).

---

## Accepted (out of scope for v1)

### BYP-A1 Root / kernel compromise
- **Status:** accepted
- Out of scope by threat model. Kernel modules or root can bypass policy.

### BYP-A2 Non-LSM enforcement paths when BPF-LSM is unavailable
- **Status:** accepted
- Tracepoint fallback is audit-only; synchronous syscall deny is not possible.
  The daemon refuses to claim enforce in this state (No-Pretend invariant).

### BYP-A3 Privileged container escape with host-level capabilities
- **Status:** accepted
- Treated as root-equivalent in the scope definition.

---

## Mitigated (behavioral regression test required)

Enforcement is **inode-based** (`[deny_path]` resolves to the target inode at
apply time and populates the inode map), so inode-aliasing bypasses must still
be denied. Each entry below is proven by a behavioral probe that, against a live
enforcing daemon, performs the bypass from a non-exempt cgroup and asserts the
access is still denied.

### BYP-M1 Symlink swap
- **Status:** mitigated
- **Class:** file
- **PoC:** create a symlink to a denied file and `open()` it via the link.
- **Mitigation:** inode-based deny — the symlink resolves to the same inode.
- **Regression:** `enforcement_proof.sh:symlink`, `test_bypasses.cpp::SymlinkBypass`
- **Proof:** `inode_alias_resistance.py::T1`, `inode_alias_resistance.py::T2` —
  the verdict is invariant under path-aliasing; a denied inode is denied via
  every alias.

### BYP-M2 Hardlink alias
- **Status:** mitigated
- **Class:** file
- **PoC:** hardlink a denied file to a new path and `open()` the new path.
- **Mitigation:** inode-based deny — the hardlink shares the inode.
- **Regression:** `enforcement_proof.sh:hardlink`, `test_bypasses.cpp::HardlinkBypass`
- **Proof:** `inode_alias_resistance.py::T1`, `inode_alias_resistance.py::T2`

### BYP-M3 Rename / path drift
- **Status:** mitigated
- **Class:** file
- **PoC:** rename a denied file and `open()` it at the new path.
- **Mitigation:** inode-based deny persists across rename (inode unchanged).
- **Regression:** `enforcement_proof.sh:rename`, `test_bypasses.cpp::RenameBypass`
- **Proof:** `inode_alias_resistance.py::T1`, `inode_alias_resistance.py::T2`

### BYP-M4 Bind-mount alias
- **Status:** mitigated
- **Class:** file
- **PoC:** `mount --bind` a denied file onto a new path and `open()` it there.
- **Mitigation:** inode-based deny — the bind alias shares the inode.
- **Regression:** `enforcement_proof.sh:bindmount`
- **Proof:** `inode_alias_resistance.py::T1`, `inode_alias_resistance.py::T2`

### BYP-M5 Outbound datagram (`sendmsg`) endpoint evasion
- **Status:** mitigated
- **Class:** network
- **PoC:** reach a denied remote endpoint via UDP `sendto()` instead of `connect()`.
- **Mitigation:** `lsm/socket_sendmsg` applies the same remote-endpoint deny as
  `connect()`; the `sendto()` returns `-EPERM`.
- **Regression:** `enforcement_proof.sh:sendmsg`

### BYP-M6 OverlayFS copy-up of a denied lower inode
- **Status:** mitigated
- **Class:** file
- **PoC:** reach a denied lower-layer file through an overlayfs merged path and
  write to it (which would trigger copy-up).
- **Mitigation:** the merged dentry maps to the denied lower inode, so access is
  refused (`lsm/file_open`) and the copy-up does not succeed; the upper layer
  never receives a copy. `lsm/inode_copy_up` (`handle_inode_copy_up`) closes the
  copy-up path synchronously for `RULE_FLAG_DENY_ALWAYS` rules.
- **Regression:** `enforcement_proof.sh:overlay_copyup`
- **Proof:** `inode_alias_resistance.py::T2` — the merged dentry's lower inode is
  the denied inode, so `file_open` denies it like any other alias.

---

## Roadmap (mechanism present or planned; behavioral regression pending)

These have either a designed mechanism without a behavioral regression yet, or
planned coverage expansion. They are deliberately **not** labeled mitigated
until a reproducible test exists.

### BYP-R1 Pre-accept inbound policy coverage
- **Status:** roadmap
- Add earlier inbound filtering / richer hook coverage before `accept()` returns.

### BYP-R2 Broader filesystem matrix
- **Status:** roadmap
- Extend validation beyond ext4/xfs to additional filesystem types.

### BYP-R3 Namespace-specific path views
- **Status:** roadmap
- Improve operator tooling to reconcile path differences across namespaces.
