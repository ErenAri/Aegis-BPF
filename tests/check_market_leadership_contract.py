#!/usr/bin/env python3
"""Validate market-leadership plan and scorecard contracts."""

from __future__ import annotations

from pathlib import Path
import sys


def require_text(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    return [f"{path}: missing '{item}'" for item in missing]


def main() -> int:
    if len(sys.argv) != 11:
        print(
            "usage: check_market_leadership_contract.py "
            "<market_leadership_plan.md> <market_scorecard.md> "
            "<maturity_program.md> <go_live_checklist.md> <pr_template.md> <readme.md> "
            "<external_review_prep.md> <pilot_evidence_template.md> "
            "<external_review_status.md> <pilots_readme.md>",
            file=sys.stderr,
        )
        return 2

    plan_doc = Path(sys.argv[1])
    scorecard_doc = Path(sys.argv[2])
    maturity_doc = Path(sys.argv[3])
    go_live_doc = Path(sys.argv[4])
    pr_template = Path(sys.argv[5])
    readme = Path(sys.argv[6])
    external_review_prep = Path(sys.argv[7])
    pilot_evidence_template = Path(sys.argv[8])
    external_review_status = Path(sys.argv[9])
    pilots_readme = Path(sys.argv[10])

    errors: list[str] = []
    errors += require_text(
        plan_doc,
        [
            "## Execution model (3 super-phases)",
            "Super-Phase A - Defensibility Core",
            "Super-Phase B - Production Survivability",
            "Super-Phase C - Trust and Adoption",
            "`>=100` kernel e2e enforcement cases",
            "`>=4` kernel targets across `>=2` distro families",
            "Rollback success `100%` over `1,000` stress iterations",
            "Rollback completion `p99 <= 5s`",
            "Unexplained event drops `<0.1%`",
            "Syscall overhead `p95 <= 5%`",
            "`0` silent partial attaches",
            "`>=2` pilot environments",
            "docs/EXTERNAL_REVIEW_PREP.md",
            "docs/PILOT_EVIDENCE_TEMPLATE.md",
            "docs/EXTERNAL_REVIEW_STATUS.md",
            "docs/pilots/",
        ],
    )
    errors += require_text(
        scorecard_doc,
        [
            "# Market Leadership Scorecard",
            "Kernel e2e coverage",
            "`>=100` enforced cases",
            "Rollback reliability",
            "`100%` over `1,000` stress iterations",
            "Syscall overhead (p95)",
            "`<=5%` (stretch `<=3%`)",
            "Pilot environments",
            "docs/pilots/",
            "docs/EXTERNAL_REVIEW_STATUS.md",
        ],
    )
    errors += require_text(
        maturity_doc,
        [
            "## Super-phase execution overlay",
            "Super-Phase A (Defensibility Core)",
            "docs/MARKET_LEADERSHIP_PLAN.md",
            "docs/MARKET_SCORECARD.md",
        ],
    )
    errors += require_text(
        go_live_doc,
        [
            "Market leadership scorecard completed",
            "docs/MARKET_SCORECARD.md",
            "docs/EXTERNAL_REVIEW_STATUS.md",
            "docs/pilots/",
        ],
    )
    errors += require_text(
        pr_template,
        [
            "Market-leadership claim mapping",
            "Claim label (ENFORCED/AUDITED/PLANNED):",
            "Spec section:",
            "Test suite/contract:",
            "CI artifact URL:",
            "Runbook/operator guidance:",
        ],
    )
    errors += require_text(
        readme,
        [
            "docs/MARKET_LEADERSHIP_PLAN.md",
            "docs/MARKET_SCORECARD.md",
            "Claim Taxonomy",
            "docs/EXTERNAL_REVIEW_STATUS.md",
            "docs/pilots/",
            "docs/DESIGN_ARTIFACT_STATUS.md",
        ],
    )
    errors += require_text(
        external_review_prep,
        [
            "# External Security Review Prep",
            "Required evidence pack",
            "Exit criteria",
            "`0` unresolved critical findings",
        ],
    )
    errors += require_text(
        pilot_evidence_template,
        [
            "# Pilot Evidence Template",
            "Rollback success rate",
            "Unexplained event drop ratio",
            "Silent partial attach incidents",
            "Explainability quality",
        ],
    )
    errors += require_text(
        external_review_status,
        [
            "# External Review Status",
            "Unresolved critical findings: `0`",
            "Findings tracker",
            "Exit criteria status",
        ],
    )
    errors += require_text(
        pilots_readme,
        [
            "# Pilot Evidence Packs",
            "two active pilot reports",
            "rollback success rate",
            "unexplained event drop ratio",
        ],
    )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
