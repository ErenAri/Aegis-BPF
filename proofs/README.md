# Machine-checked enforcement proofs

This directory contains lightweight **formal proofs** of AegisBPF enforcement
invariants, discharged by the [Z3](https://github.com/Z3Prover/z3) SMT solver.
They turn claims in [`docs/BYPASS_CATALOG.md`](../docs/BYPASS_CATALOG.md) and the
[enforcement-semantics whitepaper](../docs/ENFORCEMENT_SEMANTICS_WHITEPAPER.md)
from *"we tested this behavior"* into *"this property holds for every input the
model admits."* This is the **"machine-checked guarantees"** half of the
enforcement wedge ([`docs/ENFORCEMENT_WEDGE_STRATEGY.md`](../docs/ENFORCEMENT_WEDGE_STRATEGY.md)).

## Run

```bash
proofs/run.sh
```

First run creates `proofs/.venv` and installs the pinned `z3-solver`. Exit code
`0` means every obligation was discharged.

## What is proved

`inode_alias_resistance.py` models the file-enforcement decision exactly as
implemented in `bpf/aegis_file.bpf.h` (`handle_file_open` and
`handle_inode_permission_impl`) and discharges:

| # | Theorem | Why it matters |
|---|---------|----------------|
| **T1** | **Alias-invariance** — two paths resolving to the same inode get the same verdict. | The structural core: enforcement consults the *inode*, never the path string. |
| **T2** | **Alias-bypass impossible** — a `DENY_ALWAYS` inode, accessed from a non-exempt cgroup, is denied via *every* aliasing path. | Directly proves the BYP-M1..M4, BYP-M6 family (symlink / hardlink / rename / bind-mount / overlay) cannot evade the rule. |
| **T3** | **No path-only escape** — fixing cgroup + config + maps and varying only the path leaves the verdict constant. | The threat model: an attacker who can mint paths but not change cgroup/inode/config cannot flip DENY→ALLOW. |
| **T4** | **No false-deny** — an un-denied inode is allowed via every alias. | Inode-keying must not *over*-block; safety for legitimate access. |
| **T5** | **Cgroup-scoped deny beats the global allowlist** — a per-workload deny survives even when the cgroup is in `allow_cgroup_map`. | Locks the `!cg_rule` ordering guard in the hook; a refactor that drops it breaks this proof. |
| **T6** | **Determinism** — identical inputs always yield identical verdicts. | The determinism contract, asserted rather than assumed. |
| W1/W2 | DENY and ALLOW are both reachable. | Anti-vacuity: guards against a degenerate model where everything trivially holds. |

## The fidelity anchor (and how it is guarded)

The proofs reason about a **model** of the hook logic, transcribed by hand into
`decision()`. A proof is only as good as that correspondence, so we are explicit
about the single modeling assumption and we guard it:

- **Assumption.** When `lsm/file_open` / `lsm/inode_permission` fires for an
  access reached via path `p`, the inode handed to the hook is `resolve(p)`.
  Every alias-bypass is "multiple paths naming one inode," and the VFS resolves
  the path to that one inode *before* the LSM hook runs — the hook never sees
  the path string. This is what makes inode-keying alias-invariant.

- **Guard.** `check_model_fidelity.py` extracts the brace-balanced bodies of the
  modeled functions, normalizes away comments/whitespace, hashes them, and
  compares against `MODEL_FIDELITY.lock`. If the hook logic changes, the build
  fails and asks you to re-verify `decision()` then refresh the lock:

  ```bash
  python3 proofs/check_model_fidelity.py --update
  ```

  This makes silent model drift impossible: you cannot change the enforcement
  logic without the proof loudly demanding re-verification.

## Scope / honest limits

This is a **lightweight formal method**, not end-to-end verification:

- It proves properties of a *model* of the C hook logic, not of the compiled
  eBPF bytecode. The model↔code link is maintained by hand and guarded by the
  digest above.
- It does **not** model the kernel VFS, the verifier, or map-update atomicity;
  those are covered by the behavioral kernel-matrix probes
  (`tests/enforcement/enforcement_proof.sh`) and the cross-kernel load gate.
- The two methods are complementary: the proof shows the *logic* admits no
  path-based escape; the behavioral probes show the *deployed system* denies on
  real kernels. The catalog cites both.
