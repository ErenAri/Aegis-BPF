#!/usr/bin/env python3
"""Generate canonical perf baseline evidence JSON + markdown table."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any


_SCHEMA_SEMVER = "1.0.0"


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


def require_number(path: Path, payload: dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, (int, float)):
        raise ValueError(f"{path}: '{key}' must be numeric")
    return float(value)


def parse_semver(value: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError(f"invalid semver: {value!r}")
    return value


def overhead_pct(with_agent: float, baseline: float) -> float:
    if baseline <= 0:
        return 0.0
    return ((with_agent - baseline) / baseline) * 100.0


def to_bool(value: Any) -> bool:
    return bool(value)


def row(
    scenario: str,
    metric: str,
    result: float,
    budget: float,
    unit: str,
    evidence: str,
) -> dict[str, Any]:
    status = "PASS" if result <= budget else "FAIL"
    return {
        "scenario": scenario,
        "metric": metric,
        "result": round(result, 6),
        "budget": round(budget, 6),
        "unit": unit,
        "status": status,
        "evidence": evidence,
    }


def markdown_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Canonical Perf Baseline",
        "",
        "| Scenario | Metric | Result | Budget | Status | Evidence |",
        "|---|---|---:|---:|---|---|",
    ]
    for item in rows:
        lines.append(
            "| "
            f"`{item['scenario']}` | "
            f"`{item['metric']}` | "
            f"`{item['result']}{item['unit']}` | "
            f"`{item['budget']}{item['unit']}` | "
            f"`{item['status']}` | "
            f"`{item['evidence']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open-compare", type=Path, required=True)
    parser.add_argument("--open-baseline", type=Path, required=True)
    parser.add_argument("--open-with-agent", type=Path, required=True)
    parser.add_argument("--connect-baseline", type=Path, required=True)
    parser.add_argument("--connect-with-agent", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--slo-summary", type=Path)
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    parser.add_argument("--max-open-delta-pct", type=float, default=10.0)
    parser.add_argument("--max-open-p95-overhead-pct", type=float, default=10.0)
    parser.add_argument("--max-connect-p95-overhead-pct", type=float, default=10.0)
    parser.add_argument("--max-workload-failed-rows", type=int, default=0)
    parser.add_argument("--repository", default="")
    parser.add_argument("--workflow", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--ref", default="")
    parser.add_argument("--sha", default="")
    parser.add_argument("--schema-semver", default=_SCHEMA_SEMVER)
    args = parser.parse_args()

    schema_semver = parse_semver(args.schema_semver)

    open_compare = load_json(args.open_compare)
    open_base = load_json(args.open_baseline)
    open_with = load_json(args.open_with_agent)
    connect_base = load_json(args.connect_baseline)
    connect_with = load_json(args.connect_with_agent)
    workload = load_json(args.workload)
    environment = load_json(args.environment)
    slo_summary = load_json(args.slo_summary) if args.slo_summary else {}

    open_delta_pct = require_number(args.open_compare, open_compare, "delta_pct")
    open_p95_overhead_pct = overhead_pct(
        require_number(args.open_with_agent, open_with, "p95_us"),
        require_number(args.open_baseline, open_base, "p95_us"),
    )
    connect_p95_overhead_pct = overhead_pct(
        require_number(args.connect_with_agent, connect_with, "p95_us"),
        require_number(args.connect_baseline, connect_base, "p95_us"),
    )

    benches = workload.get("benchmarks")
    if not isinstance(benches, list) or not benches:
        raise ValueError(f"{args.workload}: 'benchmarks' must be non-empty list")

    failed_rows: list[str] = []
    table_rows: list[dict[str, Any]] = [
        row(
            scenario="audit_mode_open",
            metric="delta_pct",
            result=open_delta_pct,
            budget=args.max_open_delta_pct,
            unit="%",
            evidence=str(args.open_compare),
        ),
        row(
            scenario="audit_mode_open",
            metric="p95_overhead_pct",
            result=open_p95_overhead_pct,
            budget=args.max_open_p95_overhead_pct,
            unit="%",
            evidence=f"{args.open_baseline},{args.open_with_agent}",
        ),
        row(
            scenario="audit_mode_connect",
            metric="p95_overhead_pct",
            result=connect_p95_overhead_pct,
            budget=args.max_connect_p95_overhead_pct,
            unit="%",
            evidence=f"{args.connect_baseline},{args.connect_with_agent}",
        ),
    ]

    workload_rows: list[dict[str, Any]] = []
    for idx, item in enumerate(benches):
        if not isinstance(item, dict):
            raise ValueError(f"{args.workload}: benchmark[{idx}] must be object")
        name = str(item.get("name", f"row_{idx}"))
        delta_pct = item.get("delta_pct")
        if not isinstance(delta_pct, (int, float)):
            raise ValueError(f"{args.workload}: benchmark[{idx}].delta_pct must be numeric")
        max_allowed = item.get("max_allowed_pct")
        if not isinstance(max_allowed, (int, float)):
            raise ValueError(f"{args.workload}: benchmark[{idx}].max_allowed_pct must be numeric")
        passed = to_bool(item.get("pass"))
        if not passed:
            failed_rows.append(name)
        workload_rows.append(
            row(
                scenario=f"workload_{name}",
                metric="delta_pct",
                result=float(delta_pct),
                budget=float(max_allowed),
                unit="%",
                evidence=str(args.workload),
            )
        )

    table_rows.extend(workload_rows)
    table_rows.append(
        row(
            scenario="workload_suite",
            metric="failed_rows",
            result=float(len(failed_rows)),
            budget=float(args.max_workload_failed_rows),
            unit="",
            evidence=str(args.workload),
        )
    )

    gate_pass = all(item["status"] == "PASS" for item in table_rows)

    run_url = args.run_url
    if not run_url and args.repository and args.run_id:
        run_url = f"https://github.com/{args.repository}/actions/runs/{args.run_id}"

    canonical = {
        "schema_version": 1,
        "schema_semver": schema_semver,
        "generated_at_unix": int(time.time()),
        "ci": {
            "repository": args.repository,
            "workflow": args.workflow,
            "run_id": args.run_id,
            "run_url": run_url,
            "ref": args.ref,
            "sha": args.sha,
        },
        "environment": environment,
        "budgets": {
            "max_open_delta_pct": args.max_open_delta_pct,
            "max_open_p95_overhead_pct": args.max_open_p95_overhead_pct,
            "max_connect_p95_overhead_pct": args.max_connect_p95_overhead_pct,
            "max_workload_failed_rows": args.max_workload_failed_rows,
        },
        "microbench": {
            "open_compare": open_compare,
            "open_percentiles": {
                "baseline": open_base,
                "with_agent": open_with,
                "p95_overhead_pct": round(open_p95_overhead_pct, 6),
            },
            "connect_percentiles": {
                "baseline": connect_base,
                "with_agent": connect_with,
                "p95_overhead_pct": round(connect_p95_overhead_pct, 6),
            },
        },
        "workload_suite": workload,
        "taxonomy": [
            {
                "category": "syscall_microbench",
                "scenario": "open_close",
                "metric": "delta_pct",
                "source": str(args.open_compare),
            },
            {
                "category": "syscall_latency_percentiles",
                "scenario": "open",
                "metric": "p95_overhead_pct",
                "source": f"{args.open_baseline},{args.open_with_agent}",
            },
            {
                "category": "network_workload",
                "scenario": "connect_loopback",
                "metric": "p95_overhead_pct",
                "source": f"{args.connect_baseline},{args.connect_with_agent}",
            },
            {
                "category": "file_workload",
                "scenario": "full_read",
                "metric": "delta_pct",
                "source": str(args.workload),
            },
            {
                "category": "file_workload",
                "scenario": "stat_walk",
                "metric": "delta_pct",
                "source": str(args.workload),
            },
        ],
        "canonical_table": table_rows,
        "gate": {
            "pass": gate_pass,
            "failed_rows": failed_rows,
            "slo_summary_gate_pass": bool(slo_summary.get("gate_pass", gate_pass)),
        },
    }

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    table_md = markdown_table(table_rows)
    args.out_md.write_text(table_md, encoding="utf-8")
    print(table_md, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
