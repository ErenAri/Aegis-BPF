#!/usr/bin/env python3
"""Evaluate daemon capabilities.json into machine-readable posture and scheduling labels."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


_SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_OUTPUT_SCHEMA_SEMVER = "1.1.0"


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("top-level JSON value must be an object")
    return payload


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _runtime_label_value(runtime_state: str) -> str:
    if not runtime_state:
        return "unknown"
    return runtime_state.lower().replace("_", "-")


def _check(
    checks: list[dict[str, Any]], check_id: str, passed: bool, detail: str
) -> bool:
    checks.append({"id": check_id, "pass": passed, "detail": detail})
    return passed


def evaluate(report: dict[str, Any], source_path: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    schema_version = report.get("schema_version")
    schema_semver = str(report.get("schema_semver", ""))
    runtime_state = str(report.get("runtime_state", ""))
    enforce_capable = _as_bool(report.get("enforce_capable"))

    policy = _as_dict(report.get("policy"))
    hooks = _as_dict(report.get("hooks"))
    requirements = _as_dict(report.get("requirements"))
    requirements_met = _as_dict(report.get("requirements_met"))
    features = _as_dict(report.get("features"))

    report_schema_ok = _check(
        checks,
        "report_schema",
        schema_version == 1 and bool(_SEMVER_RE.match(schema_semver)),
        f"schema_version={schema_version}, schema_semver={schema_semver!r}",
    )

    policy_parse_ok = _as_bool(policy.get("parse_ok"))
    _check(checks, "policy_parse", policy_parse_ok, f"policy.parse_ok={policy_parse_ok}")

    runtime_ok = runtime_state in {"ENFORCE", "AUDIT_FALLBACK"}
    _check(
        checks,
        "runtime_state",
        runtime_ok,
        f"runtime_state={runtime_state or 'unknown'}",
    )

    _check(
        checks,
        "enforce_capable",
        enforce_capable,
        f"enforce_capable={enforce_capable}",
    )

    network_met = _as_bool(requirements_met.get("network"))
    exec_identity_met = _as_bool(requirements_met.get("exec_identity"))
    exec_runtime_deps_met = _as_bool(requirements_met.get("exec_runtime_deps"))
    ima_appraisal_met = _as_bool(requirements_met.get("ima_appraisal"))
    _check(
        checks,
        "requirements_met",
        network_met and exec_identity_met and exec_runtime_deps_met and ima_appraisal_met,
        (
            f"network={network_met}, exec_identity={exec_identity_met}, "
            f"exec_runtime_deps={exec_runtime_deps_met}, "
            f"ima_appraisal={ima_appraisal_met}"
        ),
    )

    hook_expectations: list[tuple[bool, bool, str, str]] = [
        (
            _as_bool(requirements.get("network_connect_required")),
            _as_bool(hooks.get("lsm_socket_connect")),
            "lsm_socket_connect",
            "network_connect_required",
        ),
        (
            _as_bool(requirements.get("network_bind_required")),
            _as_bool(hooks.get("lsm_socket_bind")),
            "lsm_socket_bind",
            "network_bind_required",
        ),
        (
            _as_bool(requirements.get("verified_exec_required")),
            _as_bool(hooks.get("lsm_bprm_check_security")),
            "lsm_bprm_check_security",
            "verified_exec_required",
        ),
        (
            _as_bool(requirements.get("verified_exec_runtime_deps_required")),
            _as_bool(hooks.get("lsm_file_mmap")),
            "lsm_file_mmap",
            "verified_exec_runtime_deps_required",
        ),
    ]
    hooks_ok = True
    hook_msgs: list[str] = []
    for required, attached, hook_name, req_name in hook_expectations:
        if required and not attached:
            hooks_ok = False
        hook_msgs.append(f"{req_name}={required}->{hook_name}={attached}")
    _check(checks, "required_hooks", hooks_ok, "; ".join(hook_msgs))

    overall_pass = all(_as_bool(check.get("pass")) for check in checks)
    overall = "pass" if overall_pass else "fail"

    labels = {
        "aegisbpf.io/enforce-capable": "true" if enforce_capable else "false",
        "aegisbpf.io/runtime-state": _runtime_label_value(runtime_state),
        "aegisbpf.io/bpf-lsm": "true" if _as_bool(features.get("bpf_lsm")) else "false",
        "aegisbpf.io/network-hooks": (
            "true"
            if _as_bool(hooks.get("lsm_socket_connect"))
            and _as_bool(hooks.get("lsm_socket_bind"))
            else "false"
        ),
        "aegisbpf.io/verified-exec-hook": (
            "true" if _as_bool(hooks.get("lsm_bprm_check_security")) else "false"
        ),
        "aegisbpf.io/runtime-deps-hook": (
            "true" if _as_bool(hooks.get("lsm_file_mmap")) else "false"
        ),
        "aegisbpf.io/exec-runtime-deps-ready": (
            "true" if exec_runtime_deps_met else "false"
        ),
        "aegisbpf.io/ima-appraisal": (
            "true" if _as_bool(features.get("ima_appraisal")) else "false"
        ),
    }

    return {
        "schema_version": 1,
        "schema_semver": _OUTPUT_SCHEMA_SEMVER,
        "input": {
            "path": source_path,
            "report_schema_version": schema_version,
            "report_schema_semver": schema_semver,
        },
        "summary": {
            "overall": overall,
            "enforce_capable": enforce_capable,
            "runtime_state": runtime_state,
            "policy_parse_ok": policy_parse_ok,
            "network_requirements_met": network_met,
            "exec_identity_requirements_met": exec_identity_met,
            "exec_runtime_deps_requirements_met": exec_runtime_deps_met,
            "ima_appraisal_requirements_met": ima_appraisal_met,
            "required_hooks_ok": hooks_ok,
            "report_schema_ok": report_schema_ok,
        },
        "checks": checks,
        "kubernetes": {
            "recommended_node_labels": labels,
            "enforce_node_selector": {"aegisbpf.io/enforce-capable": "true"},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert capabilities.json into a machine-readable posture report and "
            "recommended Kubernetes node labels."
        )
    )
    parser.add_argument(
        "--input",
        default="/var/lib/aegisbpf/capabilities.json",
        help="Path to daemon capabilities report JSON",
    )
    parser.add_argument(
        "--out-json",
        default="",
        help="Optional output path for posture JSON report",
    )
    parser.add_argument(
        "--out-labels-json",
        default="",
        help="Optional output path for Kubernetes label map JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when posture overall status is fail.",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.is_file():
        sys.stderr.write(f"capability report not found: {in_path}\n")
        return 1

    try:
        report = _read_json(in_path)
        posture = evaluate(report, str(in_path))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"failed to evaluate capability posture: {exc}\n")
        return 1

    posture_json = json.dumps(posture, indent=2, sort_keys=True)
    print(posture_json)

    if args.out_json:
        out_path = Path(args.out_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(posture_json + "\n", encoding="utf-8")

    if args.out_labels_json:
        labels_path = Path(args.out_labels_json)
        labels_path.parent.mkdir(parents=True, exist_ok=True)
        labels_payload = posture["kubernetes"]["recommended_node_labels"]
        labels_path.write_text(
            json.dumps(labels_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.strict and posture["summary"]["overall"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
