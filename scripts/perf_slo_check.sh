#!/usr/bin/env bash
# perf_slo_check.sh — Deterministic performance SLO gate and canonical evidence table.
#
# Required inputs:
#   OPEN_JSON (default: artifacts/perf/open_compare.json)
#   WORKLOAD_JSON (default: artifacts/perf/workload_suite.json)
#   OPEN_BASELINE_JSON (default: artifacts/perf/open_baseline.json)
#   OPEN_WITH_AGENT_JSON (default: artifacts/perf/open_with_agent.json)
#   CONNECT_BASELINE_JSON (default: artifacts/perf/connect_baseline.json)
#   CONNECT_WITH_AGENT_JSON (default: artifacts/perf/connect_with_agent.json)
#
# Optional inputs:
#   SOAK_JSON (default: artifacts/soak/soak_summary.json)
#   REPORT_OUT (default: artifacts/perf/perf-slo-report.md)
#   SUMMARY_OUT (default: artifacts/perf/perf-slo-summary.json)
#
# Thresholds:
#   MAX_OPEN_DELTA_PCT (fallback to MAX_OPEN_P95_OVERHEAD, default: 10)
#   MAX_CONNECT_P95_OVERHEAD (default: 10)
#   MAX_WORKLOAD_FAILED_ROWS (default: 0)
#   MAX_RSS_GROWTH_MB (default: 128)
#   MAX_RINGBUF_DROP_RATE (default: 0.1)
#   REQUIRE_PERCENTILE_PROFILES (default: 1)
#   REQUIRE_SOAK (default: 0)

set -euo pipefail

OPEN_JSON="${OPEN_JSON:-artifacts/perf/open_compare.json}"
WORKLOAD_JSON="${WORKLOAD_JSON:-artifacts/perf/workload_suite.json}"
OPEN_BASELINE_JSON="${OPEN_BASELINE_JSON:-artifacts/perf/open_baseline.json}"
OPEN_WITH_AGENT_JSON="${OPEN_WITH_AGENT_JSON:-artifacts/perf/open_with_agent.json}"
CONNECT_BASELINE_JSON="${CONNECT_BASELINE_JSON:-artifacts/perf/connect_baseline.json}"
CONNECT_WITH_AGENT_JSON="${CONNECT_WITH_AGENT_JSON:-artifacts/perf/connect_with_agent.json}"
SOAK_JSON="${SOAK_JSON:-artifacts/soak/soak_summary.json}"

MAX_OPEN_DELTA_PCT="${MAX_OPEN_DELTA_PCT:-${MAX_OPEN_P95_OVERHEAD:-10}}"
MAX_CONNECT_P95_OVERHEAD="${MAX_CONNECT_P95_OVERHEAD:-10}"
MAX_WORKLOAD_FAILED_ROWS="${MAX_WORKLOAD_FAILED_ROWS:-0}"
MAX_RSS_GROWTH_MB="${MAX_RSS_GROWTH_MB:-128}"
MAX_RINGBUF_DROP_RATE="${MAX_RINGBUF_DROP_RATE:-0.1}"
REQUIRE_PERCENTILE_PROFILES="${REQUIRE_PERCENTILE_PROFILES:-1}"
REQUIRE_SOAK="${REQUIRE_SOAK:-0}"

REPORT_OUT="${REPORT_OUT:-artifacts/perf/perf-slo-report.md}"
SUMMARY_OUT="${SUMMARY_OUT:-artifacts/perf/perf-slo-summary.json}"

mkdir -p "$(dirname "${REPORT_OUT}")" "$(dirname "${SUMMARY_OUT}")"

export OPEN_JSON WORKLOAD_JSON OPEN_BASELINE_JSON OPEN_WITH_AGENT_JSON CONNECT_BASELINE_JSON CONNECT_WITH_AGENT_JSON
export SOAK_JSON MAX_OPEN_DELTA_PCT MAX_CONNECT_P95_OVERHEAD MAX_WORKLOAD_FAILED_ROWS MAX_RSS_GROWTH_MB
export MAX_RINGBUF_DROP_RATE REQUIRE_PERCENTILE_PROFILES REQUIRE_SOAK REPORT_OUT SUMMARY_OUT

python3 - <<'PY'
import json
import math
import os
import sys
from pathlib import Path


def read_json(path: str, required: bool = True):
    p = Path(path)
    if not p.is_file():
        if required:
            raise FileNotFoundError(path)
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def fnum(value: float | int | None, digits: int = 2) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.{digits}f}"


def as_float(value, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return float(default)


def add_row(rows, violations, scenario, metric, result, budget, unit, evidence):
    failed = float(result) > float(budget)
    rows.append(
        {
            "scenario": scenario,
            "metric": metric,
            "result": float(result),
            "budget": float(budget),
            "unit": unit,
            "status": "FAIL" if failed else "PASS",
            "evidence": evidence,
        }
    )
    if failed:
        violations.append(
            f"{scenario}.{metric}={fnum(result, 4)}{unit} exceeded budget {fnum(budget, 4)}{unit}"
        )


def require_object(path: str, required: bool = True):
    payload = read_json(path, required=required)
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level object")
    return payload


open_json = os.environ["OPEN_JSON"]
workload_json = os.environ["WORKLOAD_JSON"]
open_baseline_json = os.environ["OPEN_BASELINE_JSON"]
open_with_agent_json = os.environ["OPEN_WITH_AGENT_JSON"]
connect_baseline_json = os.environ["CONNECT_BASELINE_JSON"]
connect_with_agent_json = os.environ["CONNECT_WITH_AGENT_JSON"]
soak_json = os.environ["SOAK_JSON"]

open_limit = float(os.environ["MAX_OPEN_DELTA_PCT"])
connect_p95_limit = float(os.environ["MAX_CONNECT_P95_OVERHEAD"])
max_workload_failed_rows = int(float(os.environ["MAX_WORKLOAD_FAILED_ROWS"]))
max_rss_growth_mb = float(os.environ["MAX_RSS_GROWTH_MB"])
max_ringbuf_drop_rate = float(os.environ["MAX_RINGBUF_DROP_RATE"])
require_profiles = os.environ["REQUIRE_PERCENTILE_PROFILES"] not in ("0", "false", "False")
require_soak = os.environ["REQUIRE_SOAK"] not in ("0", "false", "False")

report_out = Path(os.environ["REPORT_OUT"])
summary_out = Path(os.environ["SUMMARY_OUT"])

rows = []
violations = []
hard_errors = []

try:
    open_payload = require_object(open_json, required=True)
except Exception as exc:
    hard_errors.append(str(exc))
    open_payload = None

if open_payload is not None:
    baseline = as_float(open_payload.get("baseline_us_per_op"))
    with_agent = as_float(open_payload.get("with_agent_us_per_op"))
    delta_pct = open_payload.get("delta_pct")
    if not isinstance(delta_pct, (int, float)):
        delta_pct = ((with_agent - baseline) / baseline * 100.0) if baseline > 0 else 0.0
    add_row(
        rows,
        violations,
        scenario="audit_mode_open",
        metric="delta_pct",
        result=float(delta_pct),
        budget=open_limit,
        unit="%",
        evidence=open_json,
    )

try:
    workload_payload = require_object(workload_json, required=True)
except Exception as exc:
    hard_errors.append(str(exc))
    workload_payload = None

if workload_payload is not None:
    bench_rows = workload_payload.get("benchmarks")
    if not isinstance(bench_rows, list):
        hard_errors.append(f"{workload_json}: missing 'benchmarks' list")
    else:
        failed_rows = []
        for idx, item in enumerate(bench_rows):
            if not isinstance(item, dict):
                hard_errors.append(f"{workload_json}: benchmark[{idx}] must be object")
                continue
            name = str(item.get("name", f"row_{idx}"))
            delta_pct = as_float(item.get("delta_pct"))
            limit = as_float(item.get("max_allowed_pct"), open_limit)
            passed = bool(item.get("pass", False))
            add_row(
                rows,
                violations,
                scenario=f"workload_{name}",
                metric="delta_pct",
                result=delta_pct,
                budget=limit,
                unit="%",
                evidence=workload_json,
            )
            if not passed:
                failed_rows.append(name)
        add_row(
            rows,
            violations,
            scenario="workload_suite",
            metric="failed_rows",
            result=float(len(failed_rows)),
            budget=float(max_workload_failed_rows),
            unit="",
            evidence=workload_json,
        )

if require_profiles:
    try:
        open_base = require_object(open_baseline_json, required=True)
        open_with = require_object(open_with_agent_json, required=True)
        connect_base = require_object(connect_baseline_json, required=True)
        connect_with = require_object(connect_with_agent_json, required=True)
    except Exception as exc:
        hard_errors.append(str(exc))
        open_base = open_with = connect_base = connect_with = None

    if (
        open_base is not None
        and open_with is not None
        and connect_base is not None
        and connect_with is not None
    ):
        open_p95_base = as_float(open_base.get("p95_us"))
        open_p95_with = as_float(open_with.get("p95_us"))
        connect_p95_base = as_float(connect_base.get("p95_us"))
        connect_p95_with = as_float(connect_with.get("p95_us"))

        open_p95_overhead = (
            ((open_p95_with - open_p95_base) / open_p95_base) * 100.0 if open_p95_base > 0 else 0.0
        )
        connect_p95_overhead = (
            ((connect_p95_with - connect_p95_base) / connect_p95_base) * 100.0
            if connect_p95_base > 0
            else 0.0
        )

        add_row(
            rows,
            violations,
            scenario="audit_mode_open",
            metric="p95_overhead_pct",
            result=open_p95_overhead,
            budget=open_limit,
            unit="%",
            evidence=f"{open_baseline_json},{open_with_agent_json}",
        )
        add_row(
            rows,
            violations,
            scenario="audit_mode_connect",
            metric="p95_overhead_pct",
            result=connect_p95_overhead,
            budget=connect_p95_limit,
            unit="%",
            evidence=f"{connect_baseline_json},{connect_with_agent_json}",
        )

soak_payload = None
try:
    soak_payload = require_object(soak_json, required=require_soak)
except Exception as exc:
    if require_soak:
        hard_errors.append(str(exc))

if soak_payload is not None:
    rss_growth_kb = as_float(soak_payload.get("rss_growth_kb"))
    rss_growth_mb = rss_growth_kb / 1024.0

    if isinstance(soak_payload.get("event_drop_ratio_pct"), (int, float)):
        drop_rate_pct = as_float(soak_payload.get("event_drop_ratio_pct"))
    else:
        ringbuf_drops = as_float(soak_payload.get("ringbuf_drops"))
        total_events = as_float(soak_payload.get("total_events"), 0.0)
        if total_events <= 0 and isinstance(soak_payload.get("decision_events"), (int, float)):
            total_events = as_float(soak_payload.get("decision_events"))
        drop_rate_pct = (ringbuf_drops / total_events) * 100.0 if total_events > 0 else 0.0

    add_row(
        rows,
        violations,
        scenario="soak_runtime",
        metric="rss_growth_mb",
        result=rss_growth_mb,
        budget=max_rss_growth_mb,
        unit="MB",
        evidence=soak_json,
    )
    add_row(
        rows,
        violations,
        scenario="soak_runtime",
        metric="ringbuf_drop_rate_pct",
        result=drop_rate_pct,
        budget=max_ringbuf_drop_rate,
        unit="%",
        evidence=soak_json,
    )

markdown_lines = [
    "# Perf SLO Gate Report",
    "",
    "## Canonical SLO Table",
    "| Scenario | Metric | Result | Budget | Status | Evidence |",
    "|---|---|---:|---:|---|---|",
]

for row in rows:
    markdown_lines.append(
        f"| `{row['scenario']}` | `{row['metric']}` | "
        f"`{fnum(row['result'], 4)}{row['unit']}` | "
        f"`{fnum(row['budget'], 4)}{row['unit']}` | "
        f"`{row['status']}` | `{row['evidence']}` |"
    )

if hard_errors:
    markdown_lines += ["", "## Input Errors"] + [f"- {item}" for item in hard_errors]
if violations:
    markdown_lines += ["", "## Budget Violations"] + [f"- {item}" for item in violations]

gate_pass = not hard_errors and not violations
markdown_lines += ["", f"## Gate Result", f"`{'PASS' if gate_pass else 'FAIL'}`", ""]
markdown = "\n".join(markdown_lines)
report_out.write_text(markdown, encoding="utf-8")
print(markdown)

summary = {
    "gate_pass": gate_pass,
    "rows": rows,
    "violations": violations,
    "input_errors": hard_errors,
}
summary_out.write_text(json.dumps(summary, separators=(",", ":")), encoding="utf-8")

if gate_pass:
    raise SystemExit(0)
raise SystemExit(1)
PY
