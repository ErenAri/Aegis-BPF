#!/usr/bin/env python3
"""Validate kernel e2e matrix summary contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


DEFAULT_REQUIRED_CATEGORIES = (
    "direct_read",
    "symlink",
    "hardlink",
    "exec",
    "benign_control",
    "symlink_swap",
    "traversal",
    "rename",
    "bind_mount",
    "overlayfs",
    "mount_namespace",
    "audit_log",
)

DEFAULT_REQUIRED_PASSED_CATEGORIES = (
    "direct_read",
    "symlink",
    "hardlink",
    "exec",
    "benign_control",
    "symlink_swap",
    "traversal",
    "rename",
    "audit_log",
)

COUNTER_KEYS = ("total", "passed", "failed", "skipped")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate e2e matrix summary JSON")
    parser.add_argument(
        "summary",
        nargs="?",
        type=Path,
        help="Path to e2e-matrix summary JSON",
    )
    parser.add_argument(
        "--summary",
        dest="summary_flag",
        type=Path,
        help="Path to e2e-matrix summary JSON",
    )
    parser.add_argument(
        "--min-total-checks",
        type=int,
        default=100,
        help="Minimum required total checks (default: 100)",
    )
    parser.add_argument(
        "--max-failed-checks",
        type=int,
        default=0,
        help="Maximum allowed failed checks (default: 0)",
    )
    parser.add_argument(
        "--require-category",
        action="append",
        default=[],
        help="Additional coverage category that must be present",
    )
    parser.add_argument(
        "--require-passed-category",
        action="append",
        default=[],
        help="Additional coverage category that must have at least one passed check",
    )
    return parser.parse_args()


def resolve_summary_path(args: argparse.Namespace) -> Path:
    if args.summary is None and args.summary_flag is None:
        raise ValueError("summary path is required")
    if args.summary is not None and args.summary_flag is not None:
        if args.summary != args.summary_flag:
            raise ValueError("summary path provided twice with different values")
    return args.summary_flag or args.summary


def read_summary(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"missing file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def require_int(summary: dict[str, object], key: str) -> int:
    value = summary.get(key)
    if not isinstance(value, int):
        raise ValueError(f"summary key '{key}' must be an integer")
    return value


def require_counter(payload: dict[str, object], key: str, path: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"{path}.{key} must be an integer")
    if value < 0:
        raise ValueError(f"{path}.{key} must not be negative")
    return value


def combined_required(defaults: tuple[str, ...], additions: list[str]) -> tuple[str, ...]:
    required = list(defaults)
    for category in additions:
        if category not in required:
            required.append(category)
    return tuple(required)


def validate_coverage(
    summary: dict[str, object],
    top_level: dict[str, int],
    required_categories: tuple[str, ...],
    required_passed_categories: tuple[str, ...],
) -> dict[str, dict[str, int]]:
    coverage = summary.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("summary key 'coverage' must be an object")

    category_stats: dict[str, dict[str, int]] = {}
    for category, raw_stats in coverage.items():
        if not isinstance(category, str) or not category:
            raise ValueError("coverage category names must be non-empty strings")
        if not isinstance(raw_stats, dict):
            raise ValueError(f"coverage.{category} must be an object")

        stats = {
            key: require_counter(raw_stats, key, f"coverage.{category}")
            for key in COUNTER_KEYS
        }
        if stats["passed"] + stats["failed"] + stats["skipped"] != stats["total"]:
            raise ValueError(
                f"coverage.{category} consistency error: "
                "passed+failed+skipped != total"
            )
        category_stats[category] = stats

    for category in required_categories:
        if category not in category_stats:
            raise ValueError(f"missing required coverage category: {category}")
        if category_stats[category]["total"] <= 0:
            raise ValueError(f"required coverage category has no checks: {category}")

    for category in required_passed_categories:
        if category not in category_stats:
            raise ValueError(f"missing required passed coverage category: {category}")
        if category_stats[category]["passed"] <= 0:
            raise ValueError(
                f"required coverage category has no passed checks: {category}"
            )

    for key in COUNTER_KEYS:
        category_sum = sum(stats[key] for stats in category_stats.values())
        summary_key = f"{key}_checks" if key != "total" else "total_checks"
        if category_sum != top_level[summary_key]:
            raise ValueError(
                f"coverage consistency error: coverage {key} sum "
                f"{category_sum} != {summary_key} {top_level[summary_key]}"
            )

    return category_stats


def main() -> int:
    args = parse_args()

    try:
        summary_path = resolve_summary_path(args)
        summary = read_summary(summary_path)
        total_checks = require_int(summary, "total_checks")
        failed_checks = require_int(summary, "failed_checks")
        passed_checks = require_int(summary, "passed_checks")
        skipped_checks = require_int(summary, "skipped_checks")
        top_level = {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "skipped_checks": skipped_checks,
        }
        category_stats = validate_coverage(
            summary,
            top_level,
            combined_required(DEFAULT_REQUIRED_CATEGORIES, args.require_category),
            combined_required(
                DEFAULT_REQUIRED_PASSED_CATEGORIES,
                args.require_passed_category,
            ),
        )
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
        f"total={total_checks} passed={passed_checks} failed={failed_checks} "
        f"skipped={skipped_checks} categories={len(category_stats)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
