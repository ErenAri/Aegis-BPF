#!/usr/bin/env python3
"""Validate kernel e2e matrix summary contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate e2e matrix summary JSON")
    parser.add_argument("summary", type=Path, help="Path to e2e-matrix summary JSON")
    parser.add_argument(
        "--min-total-checks",
        type=int,
        default=60,
        help="Minimum required total checks (default: 60)",
    )
    parser.add_argument(
        "--max-failed-checks",
        type=int,
        default=0,
        help="Maximum allowed failed checks (default: 0)",
    )
    return parser.parse_args()


def read_summary(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"missing file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def require_int(summary: dict[str, object], key: str) -> int:
    value = summary.get(key)
    if not isinstance(value, int):
        raise ValueError(f"summary key '{key}' must be an integer")
    return value


def main() -> int:
    args = parse_args()

    try:
        summary = read_summary(args.summary)
        total_checks = require_int(summary, "total_checks")
        failed_checks = require_int(summary, "failed_checks")
        passed_checks = require_int(summary, "passed_checks")
        skipped_checks = require_int(summary, "skipped_checks")
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(exc, file=sys.stderr)
        return 1

    if total_checks < args.min_total_checks:
        print(
            f"total_checks={total_checks} below minimum {args.min_total_checks}",
            file=sys.stderr,
        )
        return 1

    if failed_checks > args.max_failed_checks:
        print(
            f"failed_checks={failed_checks} exceeds max {args.max_failed_checks}",
            file=sys.stderr,
        )
        return 1

    if passed_checks + failed_checks + skipped_checks != total_checks:
        print(
            "summary consistency error: passed+failed+skipped != total",
            file=sys.stderr,
        )
        return 1

    print(
        "E2E matrix summary validated: "
        f"total={total_checks} passed={passed_checks} failed={failed_checks} skipped={skipped_checks}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
