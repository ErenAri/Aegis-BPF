# Edge-Case Compliance Suite

Version: 1.0 (2026-02-05)
Status: Canonical compliance suite for v1 enforcement semantics.

This suite validates edge-case enforcement behavior that is easy to get wrong
in production (symlinks, hardlinks, rename drift, bind mounts, and mount
namespace views). The suite is the authority for deterministic pass/fail
outcomes for these scenarios.

## What it covers

Baseline basis set (must always be covered):
- direct path deny
- symlink targets and symlink swaps
- hardlink paths (same inode)
- rename before/after open
- bind mount alias behavior

## How to run

The canonical suite is:

```
scripts/e2e_file_enforcement_matrix.sh
```

Requirements:
- root privileges
- BPF LSM enabled
- cgroup v2 + bpffs mounted
- `aegisbpf` binary built (`./build/aegisbpf`)

Example:

```
sudo env PRESERVE_TMP_ON_FAIL=1 SUMMARY_OUT=/tmp/e2e-matrix-summary.json \
  ./scripts/e2e_file_enforcement_matrix.sh
python3 scripts/validate_e2e_matrix_summary.py \
  /tmp/e2e-matrix-summary.json \
  --min-total-checks 100 \
  --max-failed-checks 0
```

## Evidence contract

- Summary JSON is required for CI evidence and is validated by
  `scripts/validate_e2e_matrix_summary.py`.
- Scenario count must meet or exceed the current gate (>= 60 in Phase A,
  >= 100 in Phase B, >= 120 in Phase C).

## Updating the suite

When new edge cases are added:
- Update this document with the new scenario class.
- Ensure the summary validator minimum is adjusted only when the roadmap gate
  increases.
- Keep deterministic PASS/FAIL behavior (no flaky timing assumptions).
