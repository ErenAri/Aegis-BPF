#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path


def fail(msg: str) -> int:
    sys.stderr.write(msg.rstrip() + "\n")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate docs/PERF_BASELINE.md contract fields"
    )
    parser.add_argument("path", help="Path to PERF_BASELINE.md")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if baseline is not published (status=pending) or required fields are missing.",
    )
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        return fail(f"missing perf baseline doc: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")

    status_match = re.search(r"^Status:\s*\*\*(.+?)\*\*\s*$", text, re.M)
    if not status_match:
        return fail("missing Status: **...** line")

    status = status_match.group(1).strip().lower()
    if args.strict and status in ("pending", "tbd", "todo"):
        return fail(f"baseline status is not published (Status: {status_match.group(1)!r})")

    if not re.search(r"^Last updated:\s*\d{4}-\d{2}-\d{2}\s*$", text, re.M):
        return fail("missing or invalid 'Last updated: YYYY-MM-DD' line")

    if args.strict:
        if not re.search(r"^\s*Run:\s*https://github\.com/.+/actions/runs/\d+\s*$", text, re.M):
            return fail("strict: missing GitHub Actions run link (Run: https://github.com/.../actions/runs/<id>)")

        required_markers = [
            r"\*\*Hardware:\*\*",
            r"\*\*Kernel \+ distro:\*\*",
            r"open_p95_ratio",
            r"connect_p95_ratio",
        ]
        for marker in required_markers:
            if not re.search(marker, text):
                return fail(f"strict: missing required baseline field marker: {marker}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
