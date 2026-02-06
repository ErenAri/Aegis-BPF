# Edge‑Case Compliance Results

Status: **pending**  
Last updated: 2026-02-06

This file records **human‑readable results** for the Edge‑Case Compliance Suite.
Evidence artifacts are always attached to CI runs; this document is the public
summary.

## Latest run status

- **Run:** Kernel Matrix (dispatch) 2026-02-06  
  https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/21735329269
- **Artifacts:** `kernel-matrix-kernel-5.14`, `kernel-matrix-kernel-6.1`,
  `kernel-matrix-kernel-6.5`, `kernel-matrix-kernel-6.8`

**Note:** The kernel‑matrix workflow currently runs unit/integration tests and
does **not** execute the edge‑case suite. Results below are therefore marked
`PENDING` until an E2E run is captured and linked here.

## Expected results table (placeholder)

| Scenario group | Expected behavior | Result | Evidence |
|---------------|-------------------|--------|----------|
| Symlink swaps | Blocked | PENDING | Run + artifact (TBD) |
| Hardlinks | Blocked | PENDING | Run + artifact (TBD) |
| Rename races | Blocked | PENDING | Run + artifact (TBD) |
| Bind‑mount aliases | Blocked | PENDING | Run + artifact (TBD) |
| Exec deny | Blocked | PENDING | Run + artifact (TBD) |
| Benign controls | Allowed | PENDING | Run + artifact (TBD) |

## How to produce evidence

Run the suite in an E2E environment:

```bash
sudo BIN=./build/aegisbpf \
  SUMMARY_OUT=artifacts/e2e-matrix-summary.json \
  scripts/e2e_file_enforcement_matrix.sh

python3 scripts/validate_e2e_matrix_summary.py \
  --summary artifacts/e2e-matrix-summary.json \
  --min-total-checks 100 \
  --max-failed-checks 0
```

Then publish:
- the run URL
- artifact names
- an updated PASS/FAIL table above

