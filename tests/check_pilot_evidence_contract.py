#!/usr/bin/env python3
"""Validate the public pilot evidence contract."""

from __future__ import annotations

from pathlib import Path
import re
import sys


REQUIRED_SECTIONS = (
    "## Pilot metadata",
    "## Reliability and safety KPIs",
    "## Detection/enforcement KPIs",
    "## Performance KPIs",
    "## Operator feedback",
    "## Differentiation KPIs",
    "## Evidence links",
    "## Actions",
)

REQUIRED_KPIS = (
    "Rollback success rate (target: 100%)",
    "Rollback p99 duration (target: <=5s)",
    "Unexplained event drop ratio (target: <0.1%)",
    "Silent partial attach incidents (target: 0)",
    "Delta % (target: <=5%)",
    "Explainability quality (`why denied`) score",
    "Time-to-correct-policy (median minutes)",
    "Time-to-diagnose-deny (median minutes)",
)


def require(text: str, needle: str, label: str, errors: list[str]) -> None:
    if needle not in text:
        errors.append(f"{label}: missing {needle!r}")


def require_regex(text: str, pattern: str, label: str, errors: list[str]) -> None:
    if re.search(pattern, text, flags=re.M) is None:
        errors.append(f"{label}: missing pattern {pattern!r}")


def check_common_report_shape(text: str, label: str, errors: list[str]) -> None:
    for section in REQUIRED_SECTIONS:
        require(text, section, label, errors)
    for kpi in REQUIRED_KPIS:
        require(text, kpi, label, errors)


def check_template_shape(text: str, label: str, errors: list[str]) -> None:
    check_common_report_shape(text, label, errors)
    require(text, "- Pilot ID:", label, errors)
    require(text, "- Date range:", label, errors)
    require(text, "- Deployment model (systemd/k8s):", label, errors)
    require(text, "Claim changes needed (`ENFORCED`/`AUDITED`/`PLANNED`):", label, errors)


def check_completed_report_shape(text: str, label: str, errors: list[str]) -> None:
    check_common_report_shape(text, label, errors)
    require_regex(text, r"^- Pilot ID: .+", label, errors)
    require_regex(text, r"^- Date range: \d{4}-\d{2}-\d{2} to \d{4}-\d{2}-\d{2}$", label, errors)
    require_regex(text, r"^- Deployment model \(systemd/k8s\): (systemd|kubernetes)$", label, errors)
    require(text, "Claim changes needed (`ENFORCED`/`AUDITED`/`PLANNED`):", label, errors)


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: check_pilot_evidence_contract.py "
            "<template> <pilot-dir> <external-validation-doc> <evidence-doc> <readme>",
            file=sys.stderr,
        )
        return 2

    template_path = Path(sys.argv[1])
    pilot_dir = Path(sys.argv[2])
    external_validation_path = Path(sys.argv[3])
    evidence_path = Path(sys.argv[4])
    readme_index_path = Path(sys.argv[5])

    errors: list[str] = []

    template = template_path.read_text(encoding="utf-8")
    check_template_shape(template, str(template_path), errors)
    require(template, "Internal staging pilots may use the same format", str(template_path), errors)
    require(template, "design-partner validation", str(template_path), errors)

    readme_path = pilot_dir / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    require(readme, "Keep at least two active pilot reports under version control.", str(readme_path), errors)
    require(readme, "Internal staging pilots are product-readiness evidence only.", str(readme_path), errors)
    require(readme, "Use `docs/PILOT_EVIDENCE_TEMPLATE.md`", str(readme_path), errors)

    reports = sorted(path for path in pilot_dir.glob("pilot-*.md") if path.name != "README.md")
    if len(reports) < 2:
        errors.append(f"{pilot_dir}: expected at least two pilot reports, found {len(reports)}")

    for report_path in reports:
        text = report_path.read_text(encoding="utf-8")
        check_completed_report_shape(text, str(report_path), errors)
        require(text, "- Pilot class: internal staging pilot", str(report_path), errors)
        require_regex(text, r"Rollback success rate \(target: 100%\): 100%", str(report_path), errors)
        require_regex(text, r"Silent partial attach incidents \(target: 0\): 0", str(report_path), errors)
        require_regex(
            text,
            r"Delta % \(target: <=5%\): (?:[0-4](?:\.\d+)?|5(?:\.0+)?)%",
            str(report_path),
            errors,
        )
        require_regex(
            text,
            r"Unexplained event drop ratio \(target: <0\.1%\): 0(?:\.0\d*)?%",
            str(report_path),
            errors,
        )

    external_validation = external_validation_path.read_text(encoding="utf-8")
    require(
        external_validation,
        "external design-partner pilot case study has been published",
        str(external_validation_path),
        errors,
    )
    require(
        external_validation,
        "pilot evidence is tracked in `docs/pilots/`",
        str(external_validation_path),
        errors,
    )

    evidence = evidence_path.read_text(encoding="utf-8")
    require(evidence, "Internal staging pilots", str(evidence_path), errors)
    require(evidence, "`docs/pilots/`", str(evidence_path), errors)
    require(evidence, "`docs/PILOT_EVIDENCE_TEMPLATE.md`", str(evidence_path), errors)

    readme_index = readme_index_path.read_text(encoding="utf-8")
    require(readme_index, "[PILOT_EVIDENCE_TEMPLATE.md](docs/PILOT_EVIDENCE_TEMPLATE.md)", str(readme_index_path), errors)
    require(readme_index, "[pilots/](docs/pilots/)", str(readme_index_path), errors)

    if errors:
        print("Pilot evidence contract drift:", file=sys.stderr)
        for item in errors:
            print(f"  - {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
