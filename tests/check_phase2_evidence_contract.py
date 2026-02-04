#!/usr/bin/env python3
"""Validate Phase-2 evidence page keeps required correctness markers."""

from __future__ import annotations

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_phase2_evidence_contract.py <phase2-evidence.md>", file=sys.stderr)
        return 2

    text = Path(sys.argv[1]).read_text(encoding="utf-8")
    required_snippets = [
        "Phase 2 Correctness Evidence",
        "scripts/e2e_file_enforcement_matrix.sh",
        "kernel-matrix-pr",
        "scripts/run_parser_fuzz_changed.sh",
        "smoke-fuzz",
        "failure_modes_contract",
        "tests/check_failure_modes_contract.py",
        "docs/MATURITY_PROGRAM.md",
    ]

    missing = [item for item in required_snippets if item not in text]
    if missing:
        print("phase-2 evidence page missing required content:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
