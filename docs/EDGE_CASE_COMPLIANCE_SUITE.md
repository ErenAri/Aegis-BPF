# Edge‑Case Compliance Suite (v1.0)

Status: **published**  
Primary harness: `scripts/e2e_file_enforcement_matrix.sh`  
Summary validator: `scripts/validate_e2e_matrix_summary.py`

This suite defines the **edge‑case behaviors** AegisBPF claims to enforce for
file deny semantics. The goal is to turn ambiguous claims into **reproducible,
verifiable tests**.

## What this suite covers

The harness currently exercises:
- **Symlink behavior:** direct, chained, and swap‑after‑policy
- **Hardlinks:** same‑dir and cross‑dir
- **Rename flows:** rename before/after access; path traversal
- **Bind‑mount aliases:** canonical path vs mount alias
- **Execution path:** deny for exec from file targets
- **Common readers:** cat/head/tail/dd/grep/awk/sed/od/wc/python

> For full coverage detail, see the test definitions in
> `scripts/e2e_file_enforcement_matrix.sh`.

## Expected outcomes (contract)

- **Blocked**: any access to a denied target by canonical path or inode
  (per `docs/POLICY_SEMANTICS.md`).
- **Allowed**: benign targets or controls not covered by deny rules.
- **Skipped**: when kernel or environment constraints make a scenario invalid
  (recorded in the summary artifacts as `skipped_checks`).

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

The suite is executed in:
- **Kernel Matrix** (`.github/workflows/kernel-matrix.yml`)
- **E2E (BPF LSM)** (`.github/workflows/e2e.yml`)

Artifacts produced:
- `kernel-matrix-<runner>/ctest.log`
- `kernel-matrix-<runner>/summary.json`
- `e2e-evidence/*` (when run from the e2e workflow)

## Latest evidence run

- Kernel Matrix (dispatch): 2026-02-06  
  Run: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/21735329269

## Change control

Any enforcement change that can affect file deny semantics must:
1) Update this suite if a new edge case is introduced.
2) Update expected outcomes in `docs/POLICY_SEMANTICS.md`.
3) Produce fresh evidence artifacts linked from `docs/EVIDENCE.md`.

