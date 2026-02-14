#!/usr/bin/env python3
"""Filter Google Benchmark JSON to stable rows for CI comparison."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level object")
    return payload


def benchmark_time_ns(entry: dict[str, Any]) -> float:
    value = entry.get("real_time")
    if isinstance(value, (int, float)):
        return float(value)
    value = entry.get("cpu_time")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def should_keep(entry: dict[str, Any], min_mean_time_ns: float) -> bool:
    aggregate = entry.get("aggregate_name")
    if aggregate is None:
        # If aggregate output is disabled, keep single-run rows only.
        return True
    if aggregate != "mean":
        return False
    if benchmark_time_ns(entry) < min_mean_time_ns:
        return False
    return True


def filter_benchmarks(payload: dict[str, Any], min_mean_time_ns: float) -> tuple[dict[str, Any], int, int]:
    raw_rows = payload.get("benchmarks")
    if not isinstance(raw_rows, list):
        raise ValueError("input payload is missing 'benchmarks' list")

    kept_rows: list[dict[str, Any]] = []
    for row in raw_rows:
        if not isinstance(row, dict):
            continue
        if should_keep(row, min_mean_time_ns=min_mean_time_ns):
            kept_rows.append(row)

    if not kept_rows:
        raise ValueError("filter removed all benchmark rows; lower --min-mean-time-ns")

    out = dict(payload)
    out["benchmarks"] = kept_rows
    return out, len(raw_rows), len(kept_rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Path to raw Google Benchmark JSON")
    parser.add_argument("--output", type=Path, required=True, help="Path to filtered JSON")
    parser.add_argument(
        "--min-mean-time-ns",
        type=float,
        default=10.0,
        help="Drop mean rows below this time floor (default: 10ns)",
    )
    args = parser.parse_args()

    try:
        payload = load_json(args.input)
        filtered, total_rows, kept_rows = filter_benchmarks(payload, min_mean_time_ns=args.min_mean_time_ns)
    except ValueError as exc:
        print(str(exc))
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(filtered, indent=2) + "\n", encoding="utf-8")
    print(
        f"Filtered benchmark rows: kept {kept_rows}/{total_rows} "
        f"(min_mean_time_ns={args.min_mean_time_ns:g}) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
