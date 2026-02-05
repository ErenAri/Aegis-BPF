#!/usr/bin/env python3
"""Validate Super-Phase C trust/adoption evidence gates."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def require_text(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    return [f"{path}: missing '{item}'" for item in missing]


def extract_percent(path: Path, text: str, label: str) -> float:
    match = re.search(
        rf"{re.escape(label)}[^\n]*?:\s*([0-9]+(?:\.[0-9]+)?)%",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"{path}: missing numeric percent for '{label}'")
    return float(match.group(1))


def extract_int(path: Path, text: str, label: str) -> int:
    match = re.search(
        rf"{re.escape(label)}[^\n]*?:\s*([0-9]+)",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"{path}: missing integer value for '{label}'")
    return int(match.group(1))


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: check_superphase_c_adoption_contract.py "
            "<external_review_status.md> <pilot_dir> <market_scorecard.md> "
            "<go_live_checklist.md> <market_leadership_plan.md>",
            file=sys.stderr,
        )
        return 2

    review_status = Path(sys.argv[1])
    pilot_dir = Path(sys.argv[2])
    scorecard = Path(sys.argv[3])
    go_live = Path(sys.argv[4])
    market_plan = Path(sys.argv[5])

    errors: list[str] = []
    errors += require_text(
        review_status,
        [
            "# External Review Status",
            "Unresolved critical findings: `0`",
            "Findings tracker",
            "Exit criteria status",
        ],
    )
    errors += require_text(
        scorecard,
        [
            "Pilot environments",
            "`>=2` active pilots",
            "docs/pilots/",
            "docs/EXTERNAL_REVIEW_STATUS.md",
        ],
    )
    errors += require_text(
        go_live,
        [
            "docs/EXTERNAL_REVIEW_STATUS.md",
            "docs/pilots/",
        ],
    )
    errors += require_text(
        market_plan,
        [
            "`>=2` pilot environments",
            "docs/EXTERNAL_REVIEW_STATUS.md",
            "docs/pilots/",
        ],
    )

    if not pilot_dir.is_dir():
        errors.append(f"missing directory: {pilot_dir}")
    else:
        reports = sorted(p for p in pilot_dir.glob("pilot-*.md") if p.is_file())
        if len(reports) < 2:
            errors.append(f"{pilot_dir}: expected >=2 pilot reports, found {len(reports)}")
        for report in reports:
            text = report.read_text(encoding="utf-8")
            report_markers = [
                "Pilot ID:",
                "Date range:",
                "Rollback success rate",
                "Unexplained event drop ratio",
                "Silent partial attach incidents",
                "Delta % (target: <=5%)",
                "CI/workflow runs:",
            ]
            for marker in report_markers:
                if marker not in text:
                    errors.append(f"{report}: missing '{marker}'")
            try:
                rollback_success = extract_percent(report, text, "Rollback success rate")
                drop_ratio = extract_percent(report, text, "Unexplained event drop ratio")
                syscall_delta = extract_percent(report, text, "Delta %")
                silent_attach_incidents = extract_int(report, text, "Silent partial attach incidents")
            except ValueError as exc:
                errors.append(str(exc))
                continue

            if rollback_success < 100.0:
                errors.append(
                    f"{report}: rollback success {rollback_success:.2f}% must be >=100%"
                )
            if drop_ratio >= 0.1:
                errors.append(
                    f"{report}: unexplained drop ratio {drop_ratio:.3f}% must be <0.1%"
                )
            if syscall_delta > 5.0:
                errors.append(
                    f"{report}: syscall p95 delta {syscall_delta:.2f}% must be <=5%"
                )
            if silent_attach_incidents != 0:
                errors.append(
                    f"{report}: silent partial attach incidents {silent_attach_incidents} must be 0"
                )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
