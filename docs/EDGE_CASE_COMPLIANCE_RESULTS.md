# Edge‑Case Compliance Results

Status: **current**  
Last updated: 2026-02-15

This file records **human‑readable results** for the Edge‑Case Compliance Suite.
Evidence artifacts are always attached to CI runs; this document is the public
summary.

## Latest run status

- **Run:** E2E (BPF LSM) push (main), 2026-02-15  
  https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/22043845463
- **Artifact:** `e2e-evidence`
- **Canonical summary (`matrix_summary.json`):**
  - `total_checks`: `114`
  - `passed_checks`: `114`
  - `failed_checks`: `0`
  - `skipped_checks`: `0`
  - `kernel_release`: `6.14.0-37-generic`
  - `os_id`: `ubuntu`
  - `os_version`: `24.04`
  - `workspace_fs`: `ext2/ext3`

## Results table

| Scenario group | Expected behavior | Result | Evidence |
|---------------|-------------------|--------|----------|
| Symlink swaps | Blocked | PASS | `e2e-evidence/matrix_summary.json` (`failed_checks=0`) |
| Hardlinks | Blocked | PASS | `e2e-evidence/matrix_summary.json` (`failed_checks=0`) |
| Rename races | Blocked | PASS | `e2e-evidence/matrix_summary.json` (`failed_checks=0`) |
| Bind‑mount aliases | Blocked | PASS | `e2e-evidence/matrix_summary.json` (`failed_checks=0`) |
| Exec deny | Blocked | PASS | `e2e-evidence/matrix_summary.json` (`failed_checks=0`) |
| Benign controls | Allowed | PASS | `e2e-evidence/matrix_summary.json` (`failed_checks=0`) |

Notes:
- The strict edge-case gate is `scripts/e2e_file_enforcement_matrix.sh` +
  `scripts/validate_e2e_matrix_summary.py`.
- Additional exploratory probes (`fs_matrix.log`, `namespace_matrix.log`,
  `enforcement_proofs.log`) are retained as supplementary diagnostics and are
  not the canonical contract gate for this table.

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
