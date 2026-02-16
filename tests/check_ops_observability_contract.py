#!/usr/bin/env python3
"""Validate operator-facing observability artifacts (alerts + minimal dashboard)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


REQUIRED_ALERTS = {
    "AegisBPFRuntimeStateDegraded",
    "AegisBPFEmergencyToggleStorm",
    "AegisBPFPerfSLOGateFailed",
}

REQUIRED_ALERT_METRICS = {
    "aegisbpf_runtime_state",
    "aegisbpf_emergency_toggle_storm_active",
    "aegisbpf_perf_slo_failed_rows",
    "aegisbpf_ringbuf_drops_total",
}

REQUIRED_RUNBOOKS = {
    "docs/runbooks/ALERT_runtime_posture.md",
    "docs/runbooks/ALERT_emergency_toggle_storm.md",
    "docs/runbooks/ALERT_perf_slo_breach.md",
}

REQUIRED_DASHBOARD_METRICS = {
    "aegisbpf_runtime_state",
    "aegisbpf_ringbuf_drops_total",
    "aegisbpf_net_ringbuf_drops_total",
    "aegisbpf_emergency_toggle_storm_active",
    "aegisbpf_perf_slo_gate_pass",
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    alerts_path = root / "config" / "prometheus" / "alerts.yml"
    dashboard_path = root / "config" / "grafana" / "aegisbpf-ops-minimal.json"

    errors: list[str] = []
    if not alerts_path.is_file():
        errors.append(f"missing alerts file: {alerts_path}")
    if not dashboard_path.is_file():
        errors.append(f"missing dashboard file: {dashboard_path}")
    for runbook in REQUIRED_RUNBOOKS:
        if not (root / runbook).is_file():
            errors.append(f"missing runbook: {root / runbook}")
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    alerts_text = alerts_path.read_text(encoding="utf-8")
    alert_names = set(re.findall(r"^\s*-\s*alert:\s*([A-Za-z0-9_]+)\s*$", alerts_text, flags=re.M))
    missing_alerts = sorted(REQUIRED_ALERTS - alert_names)
    if missing_alerts:
        errors.append("missing required observability alerts:")
        errors.extend([f"  - {name}" for name in missing_alerts])

    for metric in sorted(REQUIRED_ALERT_METRICS):
        if metric not in alerts_text:
            errors.append(f"{alerts_path}: missing metric reference '{metric}'")
    for runbook in sorted(REQUIRED_RUNBOOKS):
        if runbook not in alerts_text:
            errors.append(f"{alerts_path}: missing runbook reference '{runbook}'")

    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    dashboard_str = json.dumps(dashboard, sort_keys=True)
    for metric in sorted(REQUIRED_DASHBOARD_METRICS):
        if metric not in dashboard_str:
            errors.append(f"{dashboard_path}: missing metric reference '{metric}'")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("Ops observability contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
