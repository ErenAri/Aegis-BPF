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
    helpers_path = root / "helm" / "aegisbpf" / "templates" / "_helpers.tpl"
    operator_deployment_path = root / "helm" / "aegisbpf" / "templates" / "operator-deployment.yaml"
    operator_rbac_path = root / "helm" / "aegisbpf" / "templates" / "operator-rbac.yaml"
    webhook_path = root / "helm" / "aegisbpf" / "templates" / "webhook.yaml"
    contract_doc_path = root / "docs" / "HELM_ENFORCE_GATING_CONTRACT.md"

    errors: list[str] = []
    for path in (
        values_path,
        template_path,
        helpers_path,
        operator_deployment_path,
        operator_rbac_path,
        webhook_path,
        contract_doc_path,
    ):
        if not path.is_file():
            errors.append(f"missing file: {path}")
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    values = values_path.read_text(encoding="utf-8")
    template = template_path.read_text(encoding="utf-8")
    helpers = helpers_path.read_text(encoding="utf-8")
    operator_deployment = operator_deployment_path.read_text(encoding="utf-8")
    operator_rbac = operator_rbac_path.read_text(encoding="utf-8")
    webhook = webhook_path.read_text(encoding="utf-8")
    contract = contract_doc_path.read_text(encoding="utf-8")

    must_contain(values_path, values, "enforceGateMode: fail-closed", errors)
    must_contain(values_path, values, "requireEnforceReadiness: true", errors)
    must_contain(values_path, values, "mode: auto", errors)
    must_contain(values_path, values, "aegisbpf.io/enforce-capable: \"true\"", errors)
    must_contain(values_path, values, 'agentNamespace: ""', errors)
    must_contain(values_path, values, "tag: \"3.12.11-alpine3.22\"", errors)
    must_contain(
        values_path,
        values,
        "sha256:efcdfa6a6b2fd2afb9c7dfa9a5b288a6f68338b5cfdebe6b637d986067d85757",
        errors,
    )
    if re.search(r"operator:\s+.*?tag:\s*latest\b", values, re.S):
        errors.append(f"{values_path}: operator image must not default to latest")

    must_contain(template_path, template, "--enforce-gate-mode={{ .ctx.Values.agent.enforceGateMode }}", errors)
    must_contain(template_path, template, '{{ include "aegisbpf.postureAutomationImage" .ctx }}', errors)
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

    must_contain(helpers_path, helpers, 'define "aegisbpf.operatorImage"', errors)
    must_contain(helpers_path, helpers, 'define "aegisbpf.webhookSecretName"', errors)
    must_contain(operator_deployment_path, operator_deployment, '{{ include "aegisbpf.operatorImage" . }}', errors)
    must_contain(
        operator_deployment_path,
        operator_deployment,
        "--agent-namespace={{ default .Release.Namespace .Values.operator.agentNamespace }}",
        errors,
    )
    must_contain(
        operator_rbac_path,
        operator_rbac,
        "namespace: {{ default .Release.Namespace .Values.operator.agentNamespace }}",
        errors,
    )
    must_contain(operator_rbac_path, operator_rbac, "kind: Role", errors)
    must_contain(operator_rbac_path, operator_rbac, 'resources: ["pods/exec"]', errors)
    cluster_role = operator_rbac.split("kind: ClusterRoleBinding", 1)[0]
    if 'resources: ["pods/exec"]' in cluster_role:
        errors.append(f"{operator_rbac_path}: pods/exec must be scoped by Role, not ClusterRole")
    must_contain(webhook_path, webhook, "operator.webhook.tls.caBundle is required", errors)

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
