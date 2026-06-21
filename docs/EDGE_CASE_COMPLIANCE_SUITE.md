# Edge‑Case Compliance Suite (v1.1)

Status: **published**  
Primary harness: `scripts/e2e_file_enforcement_matrix.sh`  
Summary validator: `scripts/validate_e2e_matrix_summary.py`

This suite defines the **edge‑case behaviors** AegisBPF claims to enforce for
file deny semantics. The goal is to turn ambiguous claims into **reproducible,
verifiable tests**.

## What this suite covers

The harness currently exercises:
- **Direct reads:** common readers against the denied inode
- **Symlink behavior:** direct symlinks and swap‑after‑policy
- **Hardlinks:** same‑dir and cross‑dir
- **Rename flows:** rename before/after access; path traversal
- **Bind‑mount aliases:** canonical path vs mount alias
- **OverlayFS aliases:** when the runner can mount overlayfs and inode identity is stable
- **Mount namespaces:** when `unshare -m` is permitted
- **Execution path:** deny for exec from file targets
- **Audit evidence:** expected action and inode appear in the agent log

> For full coverage detail, see the test definitions in
> `scripts/e2e_file_enforcement_matrix.sh`.

## Expected outcomes (contract)

- **Blocked**: any access to a denied target by canonical path or inode
  (per `docs/POLICY_SEMANTICS.md`).
- **Allowed**: benign targets or controls not covered by deny rules.
- **Skipped**: when kernel or environment constraints make a scenario invalid
  (recorded in the summary artifacts as `skipped_checks`).
- **Covered**: every summary must include per-scenario counters under
  `coverage`. The validator requires the categories `direct_read`, `symlink`,
  `hardlink`, `exec`, `benign_control`, `symlink_swap`, `traversal`, `rename`,
  `bind_mount`, `overlayfs`, `mount_namespace`, and `audit_log`. Optional
  kernel-dependent categories may be skipped, but they must be represented.

## How to run (local / CI)

```bash
sudo BIN=./build/aegisbpf \
  SUMMARY_OUT=artifacts/e2e-matrix-summary.json \
  scripts/e2e_file_enforcement_matrix.sh

python3 scripts/validate_e2e_matrix_summary.py \
  --summary artifacts/e2e-matrix-summary.json \
  --min-total-checks 100 \
  --max-failed-checks 0
```

## Evidence artifacts

The suite is executed in **E2E (BPF LSM)** (`.github/workflows/e2e.yml`).

Artifacts produced:
- `e2e-evidence/matrix_summary.json`
- `e2e-evidence/*` supplementary logs from the e2e workflow

`kernel-matrix.yml` produces portability and CTest evidence, but it does not run
this file-enforcement matrix directly.

## Results

Public, human‑readable results live in:
`docs/EDGE_CASE_COMPLIANCE_RESULTS.md`

## Latest evidence run

- Kernel Matrix (dispatch): 2026-02-06  
  Run: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/21735329269

## Change control

Any enforcement change that can affect file deny semantics must:
1. Update this suite if a new edge case is introduced.
2. Add or update the summary `coverage` category for the scenario.
3. Update expected outcomes in `docs/POLICY_SEMANTICS.md`.
4. Produce fresh evidence artifacts linked from `docs/EVIDENCE.md`.
