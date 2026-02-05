#!/usr/bin/env python3
"""Validate Phase-7 reviewability evidence contracts."""

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
    if len(sys.argv) != 6:
        print(
            "usage: check_phase7_reviewability_contract.py "
            "<phase7-evidence.md> <pr-template.md> <go-live-checklist.md> <maturity_program.md> <readme.md>",
            file=sys.stderr,
        )
        return 2

    phase7_doc = Path(sys.argv[1])
    pr_template = Path(sys.argv[2])
    go_live = Path(sys.argv[3])
    maturity = Path(sys.argv[4])
    readme = Path(sys.argv[5])

    errors: list[str] = []
    errors += require_text(
        phase7_doc,
        [
            "Phase 7 Reviewability Evidence Pack",
            "actions/workflows/ci.yml",
            "actions/workflows/release.yml",
            "docs/THREAT_MODEL.md",
            "docs/PHASE6_META_SECURITY_EVIDENCE.md",
            "docs/MARKET_SCORECARD.md",
            "docs/EXTERNAL_REVIEW_STATUS.md",
            "docs/pilots/",
            "docs/DESIGN_ARTIFACT_STATUS.md",
            "docs/runbooks/",
            "Any unverified claim must be downgraded to `PLANNED` or removed",
        ],
    )
    errors += require_text(
        pr_template,
        [
            "Evidence links (required for release-impacting changes)",
            "CI run URL:",
        ],
    )
    errors += require_text(
        go_live,
        [
            "Evidence entries must include direct URLs",
            "Evidence:",
        ],
    )
    errors += require_text(
        maturity,
        [
            "## Phase 7: Evidence pack and reviewability",
            "Single readiness page links to CI runs, benchmark artifacts",
            "Super-phase execution overlay",
        ],
    )
    errors += require_text(
        readme,
        [
            "Claim Taxonomy",
            "`ENFORCED`",
            "`AUDITED`",
            "`PLANNED`",
        ],
    )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
