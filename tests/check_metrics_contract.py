#!/usr/bin/env python3
"""Ensure exported metrics and observability configs stay in sync."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def extract_exported_metrics(commands_src: str) -> set[str]:
    pattern = re.compile(r'append_metric_header\s*\(\s*oss\s*,\s*"([^"]+)"')
    return set(pattern.findall(commands_src))


def extract_metric_references(text: str) -> set[str]:
    return set(re.findall(r"\baegisbpf_[a-z0-9_]+\b", text))


def extract_documented_metrics(manpage: str) -> set[str]:
    lines = manpage.splitlines()
    start = None
    end = None
    for idx, line in enumerate(lines):
        if line.strip() == "### metrics":
            start = idx
            continue
        if start is not None and idx > start and line.startswith("### "):
            end = idx
            break

    if start is None:
        return set()

    section = "\n".join(lines[start:end])
    return extract_metric_references(section)


def main() -> int:
    if len(sys.argv) < 5:
        print(
            "usage: check_metrics_contract.py <commands_src> <alerts.yml> <dashboard.json> <manpage> [dashboard.json ...]",
            file=sys.stderr,
        )
        return 2

    commands_cpp = Path(sys.argv[1]).read_text(encoding="utf-8")
    alerts = Path(sys.argv[2]).read_text(encoding="utf-8")
    dashboards = [Path(sys.argv[3]).read_text(encoding="utf-8")]
    if len(sys.argv) > 5:
        dashboards.extend(Path(p).read_text(encoding="utf-8") for p in sys.argv[5:])
    manpage = Path(sys.argv[4]).read_text(encoding="utf-8")

    exported = extract_exported_metrics(commands_cpp)
    if not exported:
        print("no exported metrics found in command source", file=sys.stderr)
        return 1

    referenced = extract_metric_references(alerts)
    for dashboard in dashboards:
        referenced |= extract_metric_references(dashboard)
    unknown = sorted(referenced - exported)
    if unknown:
        print("metrics referenced in alerts/dashboard but not exported:", file=sys.stderr)
        for name in unknown:
            print(f"  - {name}", file=sys.stderr)
        return 1

    documented = extract_documented_metrics(manpage)
    missing_docs = sorted(exported - documented)
    if missing_docs:
        print("exported metrics missing from man page metrics section:", file=sys.stderr)
        for name in missing_docs:
            print(f"  - {name}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
