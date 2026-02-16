#!/usr/bin/env python3
"""Validate enforcement guarantees document and cross-links."""

from __future__ import annotations

from pathlib import Path
import sys


REQUIRED_SECTIONS = [
    "## Default Behavioral Contract",
    "## Guaranteed",
    "## Best-Effort",
    "## Not Guaranteed",
    "## Fail-Closed vs Fail-Open Matrix",
]


def require(path: Path, needles: list[str], errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"missing file: {path}")
        return
    text = path.read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            errors.append(f"{path}: missing '{needle}'")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    guarantees = root / "docs" / "ENFORCEMENT_GUARANTEES.md"
    readme = root / "README.md"
    readiness = root / "docs" / "PRODUCTION_READINESS.md"

    errors: list[str] = []
    require(guarantees, REQUIRED_SECTIONS + ["fail-closed", "audit-fallback"], errors)
    require(readme, ["docs/ENFORCEMENT_GUARANTEES.md"], errors)
    require(readiness, ["docs/ENFORCEMENT_GUARANTEES.md"], errors)

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("Enforcement guarantees contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
