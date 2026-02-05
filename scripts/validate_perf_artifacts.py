#!/usr/bin/env python3
"""Validate perf JSON artifacts and emit a human-readable evidence report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected top-level object")
    return value


def require_keys(path: Path, payload: dict[str, Any], keys: list[str]) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise ValueError(f"{path}: missing keys: {', '.join(missing)}")


def require_number(path: Path, payload: dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, (int, float)):
        raise ValueError(f"{path}: '{key}' must be numeric")
    return float(value)


def validate_percentile_order(path: Path, payload: dict[str, Any]) -> None:
    p50 = require_number(path, payload, "p50_us")
    p95 = require_number(path, payload, "p95_us")
    p99 = require_number(path, payload, "p99_us")
    if not (p50 <= p95 <= p99):
        raise ValueError(f"{path}: expected p50_us <= p95_us <= p99_us")


def validate_open_profile(path: Path, payload: dict[str, Any], with_agent: bool) -> None:
    require_keys(
        path,
        payload,
        ["iterations", "seconds", "us_per_op", "p50_us", "p95_us", "p99_us", "file", "with_agent"],
    )
    validate_percentile_order(path, payload)
    if not isinstance(payload.get("file"), str) or not payload["file"]:
        raise ValueError(f"{path}: 'file' must be non-empty string")
    if payload.get("with_agent") is not with_agent:
        raise ValueError(f"{path}: expected with_agent={with_agent}")


def validate_connect_profile(path: Path, payload: dict[str, Any], with_agent: bool) -> None:
    require_keys(
        path,
        payload,
        ["iterations", "seconds", "us_per_op", "p50_us", "p95_us", "p99_us", "host", "port", "with_agent"],
    )
    validate_percentile_order(path, payload)
    if not isinstance(payload.get("host"), str) or not payload["host"]:
        raise ValueError(f"{path}: 'host' must be non-empty string")
    if not isinstance(payload.get("port"), int) or payload["port"] <= 0:
        raise ValueError(f"{path}: 'port' must be positive integer")
    if payload.get("with_agent") is not with_agent:
        raise ValueError(f"{path}: expected with_agent={with_agent}")


def validate_workload_suite(path: Path, payload: dict[str, Any]) -> None:
    require_keys(path, payload, ["benchmarks"])
    benches = payload["benchmarks"]
    if not isinstance(benches, list) or not benches:
        raise ValueError(f"{path}: 'benchmarks' must be a non-empty list")
    required_names = {"open_close", "connect_loopback", "full_read", "stat_walk"}
    seen_names: set[str] = set()
    for idx, item in enumerate(benches):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: benchmark[{idx}] must be object")
        require_keys(
            path,
            item,
            [
                "name",
                "baseline_us_per_op",
                "with_agent_us_per_op",
                "delta_us_per_op",
                "delta_pct",
                "max_allowed_pct",
                "pass",
            ],
        )
        if not isinstance(item["name"], str):
            raise ValueError(f"{path}: benchmark[{idx}].name must be string")
        seen_names.add(item["name"])
        if not isinstance(item["pass"], bool):
            raise ValueError(f"{path}: benchmark[{idx}].pass must be bool")
    missing_names = sorted(required_names - seen_names)
    if missing_names:
        raise ValueError(f"{path}: missing benchmark rows: {', '.join(missing_names)}")


def ratio(a: float, b: float, label: str) -> float:
    if b <= 0:
        raise ValueError(f"{label}: baseline must be > 0")
    return a / b


def render_report(
    open_baseline: dict[str, Any],
    open_with_agent: dict[str, Any],
    connect_baseline: dict[str, Any],
    connect_with_agent: dict[str, Any],
    workload: dict[str, Any],
    max_open_p95_ratio: float,
    max_connect_p95_ratio: float,
    open_p95_ratio: float,
    connect_p95_ratio: float,
    workload_failed_rows: list[str],
    gate_errors: list[str],
) -> str:
    open_ratio = ratio(float(open_with_agent["us_per_op"]), float(open_baseline["us_per_op"]), "open us_per_op")
    connect_ratio = ratio(
        float(connect_with_agent["us_per_op"]),
        float(connect_baseline["us_per_op"]),
        "connect us_per_op",
    )

    lines = [
        "# Perf Evidence Report",
        "",
        "## Open profile",
        f"- baseline_us_per_op: `{open_baseline['us_per_op']}`",
        f"- with_agent_us_per_op: `{open_with_agent['us_per_op']}`",
        f"- ratio: `{open_ratio:.3f}`",
        f"- p50/p95/p99 (with agent): `{open_with_agent['p50_us']}` / `{open_with_agent['p95_us']}` / `{open_with_agent['p99_us']}`",
        "",
        "## Connect profile",
        f"- baseline_us_per_op: `{connect_baseline['us_per_op']}`",
        f"- with_agent_us_per_op: `{connect_with_agent['us_per_op']}`",
        f"- ratio: `{connect_ratio:.3f}`",
        f"- p50/p95/p99 (with agent): `{connect_with_agent['p50_us']}` / `{connect_with_agent['p95_us']}` / `{connect_with_agent['p99_us']}`",
        "",
        "## Workload suite rows",
    ]
    for item in workload["benchmarks"]:
        lines.append(
            f"- `{item['name']}`: delta_pct=`{item['delta_pct']}` max_allowed_pct=`{item['max_allowed_pct']}` pass=`{item['pass']}`"
        )
    lines += [
        "",
        "## KPI gates",
        f"- open_p95_ratio: `{open_p95_ratio:.6f}` (target <= `{max_open_p95_ratio:.6f}`)",
        f"- connect_p95_ratio: `{connect_p95_ratio:.6f}` (target <= `{max_connect_p95_ratio:.6f}`)",
        f"- workload_failed_rows: `{', '.join(workload_failed_rows) if workload_failed_rows else 'none'}`",
        f"- gate_status: `{'pass' if not gate_errors else 'fail'}`",
    ]
    if gate_errors:
        lines += ["", "## Gate failures"] + [f"- {error}" for error in gate_errors]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open-baseline", type=Path, required=True)
    parser.add_argument("--open-with-agent", type=Path, required=True)
    parser.add_argument("--connect-baseline", type=Path, required=True)
    parser.add_argument("--connect-with-agent", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-open-p95-ratio", type=float, default=1.05)
    parser.add_argument("--max-connect-p95-ratio", type=float, default=1.05)
    args = parser.parse_args()

    try:
        open_baseline = load_json(args.open_baseline)
        open_with_agent = load_json(args.open_with_agent)
        connect_baseline = load_json(args.connect_baseline)
        connect_with_agent = load_json(args.connect_with_agent)
        workload = load_json(args.workload)

        validate_open_profile(args.open_baseline, open_baseline, with_agent=False)
        validate_open_profile(args.open_with_agent, open_with_agent, with_agent=True)
        validate_connect_profile(args.connect_baseline, connect_baseline, with_agent=False)
        validate_connect_profile(args.connect_with_agent, connect_with_agent, with_agent=True)
        validate_workload_suite(args.workload, workload)
    except ValueError as exc:
        print(str(exc))
        return 1

    gate_errors: list[str] = []
    try:
        open_p95_ratio = ratio(
            float(open_with_agent["p95_us"]),
            float(open_baseline["p95_us"]),
            "open p95_us",
        )
        connect_p95_ratio = ratio(
            float(connect_with_agent["p95_us"]),
            float(connect_baseline["p95_us"]),
            "connect p95_us",
        )
    except ValueError as exc:
        print(str(exc))
        return 1

    workload_failed_rows = [str(item["name"]) for item in workload["benchmarks"] if not bool(item["pass"])]
    if workload_failed_rows:
        gate_errors.append(f"workload rows failed thresholds: {', '.join(workload_failed_rows)}")

    if open_p95_ratio > args.max_open_p95_ratio:
        gate_errors.append(
            f"open p95 ratio {open_p95_ratio:.6f} exceeds target {args.max_open_p95_ratio:.6f}"
        )
    if connect_p95_ratio > args.max_connect_p95_ratio:
        gate_errors.append(
            f"connect p95 ratio {connect_p95_ratio:.6f} exceeds target {args.max_connect_p95_ratio:.6f}"
        )

    report = render_report(
        open_baseline=open_baseline,
        open_with_agent=open_with_agent,
        connect_baseline=connect_baseline,
        connect_with_agent=connect_with_agent,
        workload=workload,
        max_open_p95_ratio=args.max_open_p95_ratio,
        max_connect_p95_ratio=args.max_connect_p95_ratio,
        open_p95_ratio=open_p95_ratio,
        connect_p95_ratio=connect_p95_ratio,
        workload_failed_rows=workload_failed_rows,
        gate_errors=gate_errors,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8")
    print(report, end="")
    if gate_errors:
        for error in gate_errors:
            print(error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
