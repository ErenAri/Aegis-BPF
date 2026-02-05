#!/usr/bin/env python3
"""Validate presence of core production-security documentation contracts."""

from __future__ import annotations

import sys
from pathlib import Path


def require_text(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [n for n in needles if n not in text]
    return [f"{path}: missing '{n}'" for n in missing]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []

    errors += require_text(
        root / "docs" / "THREAT_MODEL.md",
        ["## Attacker model", "### In scope", "### Out of scope", "Known blind spots"],
    )
    errors += require_text(
        root / "docs" / "POLICY_SEMANTICS.md",
        ["## Path rule normalization", "## Edge-case matrix", "## Signed bundle semantics"],
    )
    errors += require_text(
        root / "docs" / "METRICS_OPERATIONS.md",
        ["## Metric interpretation and action", "## Operator response flow"],
    )
    errors += require_text(
        root / "docs" / "EVIDENCE.md",
        ["## Evidence map", "## How to access evidence"],
    )
    errors += require_text(
        root / "docs" / "EXTERNAL_VALIDATION.md",
        ["## Status", "## Published reviews"],
    )
    errors += require_text(
        root / "docs" / "CI_EXECUTION_STRATEGY.md",
        ["## Strategy", "## Kernel matrix minimum", "## Enforcement-path PR rule"],
    )
    errors += require_text(
        root / "README.md",
        [
            "docs/THREAT_MODEL.md",
            "docs/POLICY_SEMANTICS.md",
            "docs/METRICS_OPERATIONS.md",
            "docs/EVIDENCE.md",
            "docs/EXTERNAL_VALIDATION.md",
            "docs/CI_EXECUTION_STRATEGY.md",
            "Claim Taxonomy",
            "`ENFORCED`",
            "`AUDITED`",
            "`PLANNED`",
        ],
    )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1

    print("Security documentation contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
