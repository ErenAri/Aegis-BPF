# Enforcement Semantics Whitepaper (v1.0)

Status: **published**  
Applies to: `main` (docs refreshed 2026-03-20)  
Primary references: `docs/THREAT_MODEL.md`, `docs/POLICY_SEMANTICS.md`,
`docs/BYPASS_CATALOG.md`, `docs/REFERENCE_ENFORCEMENT_SLICE.md`

This document is the canonical, defensible statement of what AegisBPF **does**
and **does not** enforce. Any enforcement change must update this whitepaper
and add/refresh evidence in the compliance suite.

## 1) Scope and guarantees (contract)

### In-scope (ENFORCED)

Each ENFORCED class below is bound to a behavioral proof: every class returns a
synchronous `-EPERM` from its BPF-LSM hook, asserted from a non-exempt cgroup by
`tests/enforcement/enforcement_proof.sh` (the proof harness) on the kernel
matrix. The class↔hook↔proof binding is the manifest
`tests/enforcement/enforcement_classes.tsv`, and
`scripts/validate_enforcement_proof_contract.py` fails CI if any ENFORCED claim
here lacks a manifest entry and a harness probe (and vice versa). "When the LSM
hook is available" applies throughout: where an optional hook is absent the
posture contract degrades per `docs/CAPABILITY_POSTURE_CONTRACT.md` (it does not
silently claim enforce — see §1 "No Pretend Enforce").

- **File deny** via BPF LSM (`file_open` / `inode_permission`) for configured
  rules (path/inode), as documented in `docs/POLICY_SEMANTICS.md`.
- **Network deny** for configured outbound exact IP, CIDR, port, and exact
  IP:port rules on `connect()` and `sendmsg()`, plus port-deny `bind()` /
  `listen()` coverage and accepted-peer `accept()` coverage when the
  corresponding LSM hooks are available (see
  `docs/NETWORK_LAYER_DESIGN.md`).
- **Module-load deny** via BPF LSM (`kernel_read_file` for `finit_module(2)` and
  `kernel_load_data` for `init_module(2)`) when `deny_module_load` is set.
- **Exec deny (comm)** via BPF LSM (`bprm_check_security`) for configured
  `deny_comm` process names.
- **ptrace deny** via BPF LSM (`ptrace_access_check`) when `deny_ptrace` is set.
- **BPF program-load deny** via BPF LSM (`bpf`) when `deny_bpf` is set.

### Audited (AUDITED)
- Tracepoint-based audit fallback for environments without enforce-capable LSM.

### Non-goals (explicit)
- Coverage beyond documented hooks (e.g., broader runtime security surfaces).
- Guaranteed enforcement when kernel prerequisites are missing or misconfigured.
- Perfect mediation across all namespace/overlay/mount variants without explicit
  tests and evidence.

## 2) Trust boundaries

The trusted boundary is the **Linux kernel + BPF LSM attach points**.
User space components (agent/CLI/policy store) are part of the trusted path
only when integrity and permissions are correct. The precise threat model is
defined in `docs/THREAT_MODEL.md`.

## 3) Policy decision model (summary)

This section is a high‑level summary. The full, normative semantics are in
`docs/POLICY_SEMANTICS.md`.

- **Precedence:** deny rules override allow rules (unless explicitly documented
  otherwise).
- **Path vs inode:** inode-based rules are authoritative where applicable;
  path rules depend on canonicalization and resolved file identity at policy
  load.
- **Normalization:** path normalization rules (including symlinks and relative
  traversal) follow `docs/POLICY_SEMANTICS.md`.
- **Namespaces & mounts:** enforcement is per‑kernel object and may differ
  across mount namespaces. Bind/overlay semantics are explicitly documented in
  policy semantics and validated in the compliance suite.

## 4) TOCTOU stance

AegisBPF enforces decisions at LSM hook points. It **does not** claim to be
immune to all time‑of‑check/time‑of‑use races outside those hooks. The TOCTOU
stance and expectations are documented in `docs/POLICY_SEMANTICS.md` and
validated in the Edge‑Case Compliance Suite.

## 5) Known bypasses and accepted limitations

All known bypasses are recorded in `docs/BYPASS_CATALOG.md` and labeled as:
- **accepted** (out of scope today),
- **mitigated** (covered by policy or tests), or
- **roadmap** (planned).

No bypass should be considered resolved unless it is backed by a reproducible
test case and evidence artifacts.

## 6) Evidence and verification

Evidence for this contract is produced by:
- **Enforcement proof harness:** `tests/enforcement/enforcement_proof.sh` — boots
  the real artifact and asserts `-EPERM` per ENFORCED class + the bypass
  regressions, on the kernel matrix.
- **Determinism benchmark:** `docs/DETERMINISM_BENCHMARK.md` +
  `tests/enforcement/determinism_demo.sh` — synchronous in-kernel deny vs
  post-hoc signal.
- **Proof contract gate:** `scripts/validate_enforcement_proof_contract.py`
  (CI job `enforcement-proof-contract`) — fails the build if any ENFORCED claim
  or mitigated bypass lacks a backing test.
- **Edge‑Case Compliance Suite:** `docs/EDGE_CASE_COMPLIANCE_SUITE.md`
- **Kernel Matrix:** `.github/workflows/kernel-matrix.yml`
- **Reference Enforcement Slice:** `docs/REFERENCE_ENFORCEMENT_SLICE.md`

## 7) Change control

Any change to enforcement logic must:
1) Update this whitepaper.
2) Update `docs/POLICY_SEMANTICS.md` or `docs/BYPASS_CATALOG.md` as needed.
3) Add/refresh compliance suite evidence.
4) Pass kernel‑matrix and e2e evidence gates.
