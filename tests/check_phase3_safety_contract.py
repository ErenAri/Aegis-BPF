#!/usr/bin/env python3
"""Validate Phase-3 operational safety evidence and guardrail contracts."""

from __future__ import annotations

from pathlib import Path
import re
import sys


TEST_PATTERN = re.compile(r"TEST(?:_F)?\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)")


def load_tests(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {f"{suite}.{name}" for suite, name in TEST_PATTERN.findall(text)}


def main() -> int:
    if len(sys.argv) < 6:
        print(
            "usage: check_phase3_safety_contract.py "
            "<phase3-evidence.md> <canary.yml> <go-live-gate.yml> <canary_gate.sh> "
            "<test-file> [<test-file> ...]",
            file=sys.stderr,
        )
        return 2

    doc_path = Path(sys.argv[1])
    canary_workflow_path = Path(sys.argv[2])
    go_live_workflow_path = Path(sys.argv[3])
    canary_gate_path = Path(sys.argv[4])
    doc_text = doc_path.read_text(encoding="utf-8")
    required_doc_snippets = [
        "Phase 3 Operational Safety Evidence",
        "--allow-sigkill",
        "ENABLE_SIGKILL_ENFORCEMENT",
        ".github/workflows/canary.yml",
        ".github/workflows/go-live-gate.yml",
        "docs/runbooks/RECOVERY_break_glass.md",
        "ALLOW_SIGKILL_CANARY",
        "DaemonRunForcesAuditOnlyWhenBreakGlassActive",
        "Attach contract validation failed",
        "RollbackControlPathCompletesWithinFiveSecondsUnderLoad",
        "1,000 rollback attempts",
        "MAX_EVENT_DROP_RATIO_PCT",
        "MIN_TOTAL_DECISIONS",
        ".github/workflows/incident-drill.yml",
    ]
    missing_doc = [item for item in required_doc_snippets if item not in doc_text]
    if missing_doc:
        print("phase-3 evidence page missing required content:", file=sys.stderr)
        for item in missing_doc:
            print(f"  - {item}", file=sys.stderr)
        return 1

    canary_workflow_text = canary_workflow_path.read_text(encoding="utf-8")
    go_live_workflow_text = go_live_workflow_path.read_text(encoding="utf-8")
    canary_gate_text = canary_gate_path.read_text(encoding="utf-8")

    workflow_missing: list[str] = []
    if "ENFORCE_SIGNAL=term" not in canary_workflow_text:
        workflow_missing.append(f"{canary_workflow_path}: missing 'ENFORCE_SIGNAL=term'")
    if "ENFORCE_SIGNAL=term" not in go_live_workflow_text:
        workflow_missing.append(f"{go_live_workflow_path}: missing 'ENFORCE_SIGNAL=term'")
    if "MAX_EVENT_DROP_RATIO_PCT=0.1" not in canary_workflow_text:
        workflow_missing.append(
            f"{canary_workflow_path}: missing 'MAX_EVENT_DROP_RATIO_PCT=0.1'"
        )
    if "MAX_EVENT_DROP_RATIO_PCT=0.1" not in go_live_workflow_text:
        workflow_missing.append(
            f"{go_live_workflow_path}: missing 'MAX_EVENT_DROP_RATIO_PCT=0.1'"
        )
    if "ALLOW_SIGKILL_CANARY" not in canary_gate_text:
        workflow_missing.append(f"{canary_gate_path}: missing 'ALLOW_SIGKILL_CANARY'")
    if "Refusing ENFORCE_SIGNAL=kill" not in canary_gate_text:
        workflow_missing.append(f"{canary_gate_path}: missing kill-signal guard message")
    if "MAX_EVENT_DROP_RATIO_PCT" not in canary_gate_text:
        workflow_missing.append(f"{canary_gate_path}: missing 'MAX_EVENT_DROP_RATIO_PCT'")
    if "MIN_TOTAL_DECISIONS" not in canary_gate_text:
        workflow_missing.append(f"{canary_gate_path}: missing 'MIN_TOTAL_DECISIONS'")

    if workflow_missing:
        for item in workflow_missing:
            print(item, file=sys.stderr)
        return 1

    discovered: set[str] = set()
    test_sources: list[str] = []
    for arg in sys.argv[5:]:
        path = Path(arg)
        discovered |= load_tests(path)
        test_sources.append(path.read_text(encoding="utf-8"))

    required_tests = {
        "TracingTest.DaemonRunGuardsSigkillBehindBuildAndRuntimeFlags",
        "TracingTest.DaemonRunForcesAuditOnlyWhenBreakGlassActive",
        "TracingTest.DaemonRunRejectsSilentPartialAttachContract",
        "PolicyRollbackTest.RollbackControlPathCompletesWithinFiveSecondsUnderLoad",
    }
    missing_tests = sorted(required_tests - discovered)
    if missing_tests:
        print("phase-3 safety contract missing required tests:", file=sys.stderr)
        for item in missing_tests:
            print(f"  - {item}", file=sys.stderr)
        return 1

    combined_tests = "\n".join(test_sources)
    attempts_match = re.search(
        r"RollbackControlPathCompletesWithinFiveSecondsUnderLoad\).*?constexpr int kAttempts = (\d+);",
        combined_tests,
        flags=re.S,
    )
    if attempts_match is None:
        print("phase-3 safety contract missing rollback stress iteration constant", file=sys.stderr)
        return 1
    attempts = int(attempts_match.group(1))
    if attempts < 1000:
        print(
            f"phase-3 safety contract requires >=1000 rollback iterations, found {attempts}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
