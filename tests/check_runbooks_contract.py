#!/usr/bin/env python3
"""Ensure production runbook pack exists and follows a minimal structure."""

from __future__ import annotations

from pathlib import Path
import sys


REQUIRED_FILES = [
    "ALERT_high_block_rate.md",
    "ALERT_ringbuf_drops.md",
    "ALERT_policy_apply_failed.md",
    "INCIDENT_agent_crash.md",
    "INCIDENT_false_positive_block.md",
    "MAINTENANCE_key_rotation.md",
    "MAINTENANCE_policy_update.md",
    "RECOVERY_break_glass.md",
]

REQUIRED_SECTIONS = [
    "## Alert Description and Severity",
    "## Diagnostic Steps",
    "## Resolution Procedures",
    "## Escalation Path",
    "## Post-Incident Checklist",
]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_runbooks_contract.py <runbooks_dir>", file=sys.stderr)
        return 2

    runbooks_dir = Path(sys.argv[1])
    if not runbooks_dir.is_dir():
        print(f"runbooks directory missing: {runbooks_dir}", file=sys.stderr)
        return 1

    failed = False

    for name in REQUIRED_FILES:
        path = runbooks_dir / name
        if not path.is_file():
            print(f"missing runbook: {path}", file=sys.stderr)
            failed = True
            continue

        text = path.read_text(encoding="utf-8")
        for heading in REQUIRED_SECTIONS:
            if heading not in text:
                print(f"{path}: missing section '{heading}'", file=sys.stderr)
                failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
