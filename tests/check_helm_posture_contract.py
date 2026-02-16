#!/usr/bin/env python3
"""Validate Helm posture defaults and template wiring for enforce gating."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def must_contain(path: Path, text: str, needle: str, errors: list[str]) -> None:
    if needle not in text:
        errors.append(f"{path}: missing '{needle}'")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    values_path = root / "helm" / "aegisbpf" / "values.yaml"
    template_path = root / "helm" / "aegisbpf" / "templates" / "daemonset.yaml"
    contract_doc_path = root / "docs" / "HELM_ENFORCE_GATING_CONTRACT.md"

    errors: list[str] = []
    for path in (values_path, template_path, contract_doc_path):
        if not path.is_file():
            errors.append(f"missing file: {path}")
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    values = values_path.read_text(encoding="utf-8")
    template = template_path.read_text(encoding="utf-8")
    contract = contract_doc_path.read_text(encoding="utf-8")

    must_contain(values_path, values, "enforceGateMode: fail-closed", errors)
    must_contain(values_path, values, "requireEnforceReadiness: true", errors)
    must_contain(values_path, values, "mode: auto", errors)
    must_contain(values_path, values, "aegisbpf.io/enforce-capable: \"true\"", errors)

    must_contain(template_path, template, "--enforce-gate-mode={{ .ctx.Values.agent.enforceGateMode }}", errors)
    must_contain(
        template_path,
        template,
        "set $readiness.exec \"command\" (list \"/usr/bin/aegisbpf\" \"health\" \"--require-enforce\")",
        errors,
    )

    # Ensure both-mode split is present (audit + enforce daemonsets).
    both_mode_re = re.compile(r"if eq \$mode \"both\".*?-audit.*?-enforce", re.S)
    if not both_mode_re.search(template):
        errors.append(f"{template_path}: missing deployment.mode=both audit/enforce split")

    for needle in (
        "agent.enforceGateMode=fail-closed",
        "agent.requireEnforceReadiness=true",
        "deployment.mode=auto",
        "enforceNodeSelector",
    ):
        if needle not in contract:
            errors.append(f"{contract_doc_path}: missing '{needle}'")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("Helm posture contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
