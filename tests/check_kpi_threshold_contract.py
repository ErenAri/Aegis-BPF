#!/usr/bin/env python3
"""Keep product KPI thresholds aligned across docs, scripts, and release gates."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def require(text: str, needle: str, label: str, errors: list[str]) -> None:
    if needle not in text:
        errors.append(f"{label}: missing {needle!r}")


def require_regex(text: str, pattern: str, label: str, errors: list[str]) -> None:
    if re.search(pattern, text, flags=re.M) is None:
        errors.append(f"{label}: missing pattern {pattern!r}")


def main() -> int:
    if len(sys.argv) != 8:
        print(
            "usage: check_kpi_threshold_contract.py "
            "<product-doc> <quality-gates-doc> <perf-doc> "
            "<perf-slo-script> <perf-baseline-generator> <release-workflow> <pr-template>",
            file=sys.stderr,
        )
        return 2

    product_doc = Path(sys.argv[1]).read_text(encoding="utf-8")
    quality_gates = Path(sys.argv[2]).read_text(encoding="utf-8")
    perf_doc = Path(sys.argv[3]).read_text(encoding="utf-8")
    perf_slo = Path(sys.argv[4]).read_text(encoding="utf-8")
    baseline_generator = Path(sys.argv[5]).read_text(encoding="utf-8")
    release_workflow = Path(sys.argv[6]).read_text(encoding="utf-8")
    pr_template = Path(sys.argv[7]).read_text(encoding="utf-8")

    errors: list[str] = []

    require(product_doc, "Rollback success `100%` over `1,000` stress iterations", "product doc", errors)
    require(product_doc, "Rollback completion `p99 <= 5s`", "product doc", errors)
    require(product_doc, "Unexplained event drops `<0.1%`", "product doc", errors)
    require(product_doc, "Syscall overhead `p95 <= 5%`", "product doc", errors)
    require(product_doc, "`0` false-green health states", "product doc", errors)

    require(quality_gates, "Rollback reliability | `100%` over `1,000`", "quality gates", errors)
    require(quality_gates, "Rollback speed | `p99 <= 5s`", "quality gates", errors)
    require(quality_gates, "Unexplained event drops | `<0.1%`", "quality gates", errors)
    require(quality_gates, "Syscall overhead (p95) | `<=5%`", "quality gates", errors)
    require(quality_gates, "p95 ratio gates (`<=1.05`)", "quality gates", errors)

    require(perf_doc, "p95_with_agent / p95_baseline <= 1.05", "perf doc", errors)
    require(perf_doc, "5% p95 KPI budget", "perf doc", errors)
    require(perf_doc, "10% open-delta compatibility row", "perf doc", errors)

    require(perf_slo, 'MAX_OPEN_DELTA_PCT="${MAX_OPEN_DELTA_PCT:-10}"', "perf SLO script", errors)
    require(perf_slo, 'MAX_OPEN_P95_OVERHEAD="${MAX_OPEN_P95_OVERHEAD:-5}"', "perf SLO script", errors)
    require(perf_slo, 'MAX_CONNECT_P95_OVERHEAD="${MAX_CONNECT_P95_OVERHEAD:-5}"', "perf SLO script", errors)
    require(perf_slo, 'MAX_RINGBUF_DROP_RATE="${MAX_RINGBUF_DROP_RATE:-0.1}"', "perf SLO script", errors)

    require_regex(
        baseline_generator,
        r'--max-open-p95-overhead-pct",\s+type=float,\s+default=5\.0\)',
        "perf baseline generator",
        errors,
    )
    require_regex(
        baseline_generator,
        r'--max-connect-p95-overhead-pct",\s+type=float,\s+default=5\.0\)',
        "perf baseline generator",
        errors,
    )

    require(release_workflow, "MAX_OPEN_DELTA_PCT=10", "release workflow", errors)
    require(release_workflow, "MAX_OPEN_P95_OVERHEAD=5", "release workflow", errors)
    require(release_workflow, "MAX_CONNECT_P95_OVERHEAD=5", "release workflow", errors)
    require(release_workflow, "--max-open-delta-pct 10", "release workflow", errors)
    require(release_workflow, "--max-open-p95-overhead-pct 5", "release workflow", errors)
    require(release_workflow, "--max-connect-p95-overhead-pct 5", "release workflow", errors)
    require(release_workflow, "--max-open-p95-ratio 1.05", "release workflow", errors)
    require(release_workflow, "--max-connect-p95-ratio 1.05", "release workflow", errors)
    require(release_workflow, "MAX_EVENT_DROP_RATIO_PCT=0.1", "release workflow", errors)

    require(pr_template, "p95_with_agent / p95_baseline > 1.05", "PR template", errors)

    if errors:
        print("KPI threshold contract drift:", file=sys.stderr)
        for item in errors:
            print(f"  - {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
