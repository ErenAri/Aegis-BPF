#!/usr/bin/env python3
"""Validate that failure-mode regression tests remain present."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def load_tests(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"TEST(?:_F)?\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)")
    return {f"{suite}.{name}" for suite, name in pattern.findall(text)}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check_failure_modes_contract.py <test-file> [<test-file> ...]", file=sys.stderr)
        return 2

    discovered: set[str] = set()
    for arg in sys.argv[1:]:
        discovered |= load_tests(Path(arg))

    required = {
        # Parser/format failure path.
        "PolicyTest.MissingVersion",
        # Signed-policy parsing/signature failure paths.
        "CmdPolicyApplySignedTest.RequireSignatureRejectsUnsignedPolicy",
        "CmdPolicyApplySignedTest.RejectsCorruptedBundleSignature",
        # Map update and rollback failure paths.
        "PolicyRollbackTest.MapFullFailureTriggersRollbackAttemptWhenEnabled",
        "PolicyRollbackTest.RollbackFailureStillReturnsOriginalApplyError",
        # Observability degradation path (ring buffer drops surfaced).
        "MetricsTest.IncludesRingbufDropsInBlockMetrics",
        "MetricsTest.IncludesRingbufDropsInNetMetrics",
        # BPF load/verifier failure paths.
        "TracingTest.DaemonRunMarksLoadSpanErrorWhenLoadBpfFails",
        "TracingTest.DaemonRunSurfacesVerifierRejectError",
        # Strict degrade fail-closed path.
        "TracingTest.DaemonRunStrictDegradeFailsWhenEnforceFallsBack",
    }

    missing = sorted(required - discovered)
    if missing:
        print("failure-mode regression contract is missing required tests:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
