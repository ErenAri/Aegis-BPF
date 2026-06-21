# Edge‑Case Compliance Results

Status: **current contract; latest privileged evidence is historical**
Last updated: 2026-06-21

This file records **human‑readable results** for the Edge‑Case Compliance Suite.
Evidence artifacts are always attached to CI runs; this document is the public
summary.

## Latest published run status

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

This run predates the v1.1 category-coverage summary. New privileged evidence
must include the `coverage` object validated by
`scripts/validate_e2e_matrix_summary.py`.

## Current contract table

| Scenario group | Expected behavior | Result | Evidence |
|---------------|-------------------|--------|----------|
| Direct reads | Blocked | Required | `coverage.direct_read.passed > 0` |
| Symlink targets | Blocked | Required | `coverage.symlink.passed > 0` |
| Symlink swaps | Blocked | Required | `coverage.symlink_swap.passed > 0` |
| Hardlinks | Blocked | Required | `coverage.hardlink.passed > 0` |
| Rename and traversal | Blocked | Required | `coverage.rename.passed > 0`, `coverage.traversal.passed > 0` |
| Bind‑mount aliases | Blocked or skipped with reason | Required category | `coverage.bind_mount.total > 0` |
| OverlayFS aliases | Blocked or skipped with reason | Required category | `coverage.overlayfs.total > 0` |
| Mount namespace views | Blocked or skipped with reason | Required category | `coverage.mount_namespace.total > 0` |
| Exec deny | Blocked | Required | `coverage.exec.passed > 0` |
| Benign controls | Allowed | Required | `coverage.benign_control.passed > 0` |
| Audit evidence | Expected action and inode logged | Required | `coverage.audit_log.passed > 0` |

Notes:
- The strict edge-case gate is `scripts/e2e_file_enforcement_matrix.sh` +
  `scripts/validate_e2e_matrix_summary.py`.
- The validator rejects summaries whose category counters do not add up to the
  top-level pass/fail/skip totals.
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
