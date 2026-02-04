#!/usr/bin/env python3
"""Validate Phase-2 evidence and workflow contracts remain enforced."""

from __future__ import annotations

from pathlib import Path
import sys


def require_text(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    return [f"{path}: missing '{item}'" for item in missing]


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: check_phase2_evidence_contract.py "
            "<phase2-evidence.md> <e2e.yml> <kernel-matrix.yml> <e2e-matrix.sh>",
            file=sys.stderr,
        )
        return 2

    evidence_doc = Path(sys.argv[1])
    e2e_workflow = Path(sys.argv[2])
    kernel_workflow = Path(sys.argv[3])
    e2e_script = Path(sys.argv[4])

    errors: list[str] = []
    errors += require_text(
        evidence_doc,
        [
            "Phase 2 Correctness Evidence",
            "Coverage basis set",
            "symlink",
            "hardlink",
            "rename",
            "bind mounts",
            "OverlayFS",
            "mount namespaces",
            "user namespaces",
            "scripts/e2e_file_enforcement_matrix.sh",
            "kernel-matrix-pr",
            "scripts/run_parser_fuzz_changed.sh",
            "smoke-fuzz",
            "failure_modes_contract",
            "tests/check_failure_modes_contract.py",
            "docs/MATURITY_PROGRAM.md",
        ],
    )
    errors += require_text(
        e2e_workflow,
        [
            "SUMMARY_OUT=/tmp/e2e-matrix-summary.json",
            "Upload e2e matrix artifacts",
            "e2e-matrix-summary.json",
        ],
    )
    errors += require_text(
        kernel_workflow,
        [
            "SUMMARY_OUT=/tmp/e2e-matrix-summary.json",
            "Upload kernel-matrix artifacts",
            "kernel-matrix-artifacts-",
        ],
    )
    errors += require_text(
        e2e_script,
        [
            "SUMMARY_OUT",
            "inode stable across rename",
            "cat renamed",
        ],
    )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
