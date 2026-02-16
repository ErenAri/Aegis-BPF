#!/usr/bin/env python3
"""Validate minimal Grafana dashboard contract for AegisBPF ops."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_METRICS = [
    "aegisbpf_runtime_state",
    "aegisbpf_ringbuf_drops_total",
    "aegisbpf_net_ringbuf_drops_total",
    "aegisbpf_emergency_toggle_storm_active",
    "aegisbpf_perf_slo_gate_pass",
    "aegisbpf_perf_slo_failed_rows",
]

REQUIRED_TITLES = {
    "Runtime State",
    "Ringbuf Drop Rate",
    "Emergency Toggle Storm Active",
    "Perf SLO Gate Pass",
    "Perf SLO Failed Rows",
}


def collect_target_expressions(node: Any) -> list[str]:
    expressions: list[str] = []
    if isinstance(node, dict):
        targets = node.get("targets")
        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, dict):
                    expr = target.get("expr")
                    if isinstance(expr, str):
                        expressions.append(expr)
        for value in node.values():
            expressions.extend(collect_target_expressions(value))
    elif isinstance(node, list):
        for item in node:
            expressions.extend(collect_target_expressions(item))
    return expressions


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_grafana_dashboard.py <dashboard.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"dashboard file missing: {path}", file=sys.stderr)
        return 1

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print(f"{path}: top-level JSON value must be object", file=sys.stderr)
        return 1

    if payload.get("title") != "AegisBPF Ops Minimal":
        print(f"{path}: unexpected dashboard title", file=sys.stderr)
        return 1

    panels = payload.get("panels")
    if not isinstance(panels, list):
        print(f"{path}: panels must be an array", file=sys.stderr)
        return 1

    panel_titles = {
        panel.get("title")
        for panel in panels
        if isinstance(panel, dict) and isinstance(panel.get("title"), str)
    }
    missing_titles = sorted(REQUIRED_TITLES - panel_titles)
    if missing_titles:
        print(f"{path}: missing required panel titles:", file=sys.stderr)
        for title in missing_titles:
            print(f"  - {title}", file=sys.stderr)
        return 1

    expressions = collect_target_expressions(payload)
    missing_metrics = [metric for metric in REQUIRED_METRICS if not any(metric in expr for expr in expressions)]
    if missing_metrics:
        print(f"{path}: missing required metric expressions:", file=sys.stderr)
        for metric in missing_metrics:
            print(f"  - {metric}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
