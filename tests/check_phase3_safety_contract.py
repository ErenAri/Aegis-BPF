#!/usr/bin/env python3
"""Validate Phase-3 operational safety evidence and guardrail tests."""

from __future__ import annotations

from pathlib import Path
import re
import sys


TEST_PATTERN = re.compile(r"TEST(?:_F)?\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)")


def load_tests(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {f"{suite}.{name}" for suite, name in TEST_PATTERN.findall(text)}


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: check_phase3_safety_contract.py <phase3-evidence.md> <test-file> [<test-file> ...]",
            file=sys.stderr,
        )
        return 2

    doc_path = Path(sys.argv[1])
    doc_text = doc_path.read_text(encoding="utf-8")
    required_doc_snippets = [
        "Phase 3 Operational Safety Evidence",
        "--allow-sigkill",
        "ENABLE_SIGKILL_ENFORCEMENT",
        ".github/workflows/canary.yml",
        "docs/runbooks/RECOVERY_break_glass.md",
        "RollbackControlPathCompletesWithinFiveSecondsUnderLoad",
        ".github/workflows/incident-drill.yml",
    ]
    missing_doc = [item for item in required_doc_snippets if item not in doc_text]
    if missing_doc:
        print("phase-3 evidence page missing required content:", file=sys.stderr)
        for item in missing_doc:
            print(f"  - {item}", file=sys.stderr)
        return 1

    discovered: set[str] = set()
    for arg in sys.argv[2:]:
        discovered |= load_tests(Path(arg))

    required_tests = {
        "TracingTest.DaemonRunGuardsSigkillBehindBuildAndRuntimeFlags",
        "PolicyRollbackTest.RollbackControlPathCompletesWithinFiveSecondsUnderLoad",
    }
    missing_tests = sorted(required_tests - discovered)
    if missing_tests:
        print("phase-3 safety contract missing required tests:", file=sys.stderr)
        for item in missing_tests:
            print(f"  - {item}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
