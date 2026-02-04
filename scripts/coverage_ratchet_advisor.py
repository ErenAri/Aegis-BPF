#!/usr/bin/env python3
import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def to_percent(rate: str) -> float:
    return float(rate) * 100.0


def floor_int(value: float) -> int:
    return int(value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute coverage ratchet recommendation")
    parser.add_argument("--coverage-xml", required=True, help="Path to gcovr XML report")
    parser.add_argument("--thresholds", required=True, help="Path to thresholds JSON")
    parser.add_argument("--output", required=True, help="Path to output JSON report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    xml_path = Path(args.coverage_xml)
    thresholds_path = Path(args.thresholds)
    output_path = Path(args.output)

    root = ET.parse(xml_path).getroot()
    line_percent = to_percent(root.attrib["line-rate"])
    branch_percent = to_percent(root.attrib["branch-rate"])

    cfg = json.loads(thresholds_path.read_text(encoding="utf-8"))
    line_min = int(cfg["line_min"])
    branch_min = int(cfg["branch_min"])
    margin = int(cfg.get("ratchet_margin", 3))
    step_line = int(cfg.get("ratchet_step_line", 2))
    step_branch = int(cfg.get("ratchet_step_branch", 1))
    streak_required = int(cfg.get("streak_required", 3))

    meets_margin = (
        line_percent >= (line_min + margin)
        and branch_percent >= (branch_min + margin)
    )

    # Keep one-point safety gap from current measured coverage.
    max_safe_line = max(line_min, floor_int(line_percent) - 1)
    max_safe_branch = max(branch_min, floor_int(branch_percent) - 1)
    proposed_line = min(line_min + step_line, max_safe_line)
    proposed_branch = min(branch_min + step_branch, max_safe_branch)

    report = {
        "current": {
            "line_percent": round(line_percent, 2),
            "branch_percent": round(branch_percent, 2),
        },
        "thresholds": {
            "line_min": line_min,
            "branch_min": branch_min,
        },
        "ratchet": {
            "margin": margin,
            "step_line": step_line,
            "step_branch": step_branch,
            "streak_required": streak_required,
            "meets_margin": meets_margin,
            "proposed_line_min": proposed_line,
            "proposed_branch_min": proposed_branch,
            "has_increase": proposed_line > line_min or proposed_branch > branch_min,
        },
    }

    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
