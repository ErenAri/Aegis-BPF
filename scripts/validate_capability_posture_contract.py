#!/usr/bin/env python3
"""Cross-check capability/posture contract across docs, schema, daemon, and evaluator."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_BLOCKERS = {
    "CAPABILITY_AUDIT_ONLY",
    "BPF_LSM_DISABLED",
    "CORE_UNSUPPORTED",
    "BPFFS_UNMOUNTED",
    "NETWORK_HOOK_UNAVAILABLE",
    "EXEC_IDENTITY_UNAVAILABLE",
    "EXEC_RUNTIME_DEPS_HOOK_UNAVAILABLE",
    "IMA_APPRAISAL_UNAVAILABLE",
}

REQUIRED_DOC_STRINGS = [
    "schema_version",
    "schema_semver",
    "enforce_blockers",
    "No Pretend Enforce Invariant",
    "Helm Defaults Contract",
    "fail-closed",
]

REQUIREMENTS_MET_KEYS = ["network", "exec_identity", "exec_runtime_deps", "ima_appraisal"]


def _required_keys(obj: dict[str, Any], *path: str) -> set[str]:
    cur: Any = obj
    for segment in path:
        if not isinstance(cur, dict):
            return set()
        cur = cur.get(segment)
    if not isinstance(cur, list):
        return set()
    return {item for item in cur if isinstance(item, str)}


def _daemon_emits_key(daemon_src: str, key: str) -> bool:
    # Keys can appear as plain JSON snippets or C++-escaped JSON string literals.
    return (f"\"{key}\"" in daemon_src) or (f"\\\"{key}\\\"" in daemon_src)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    schema_path = root / "config" / "schemas" / "capabilities_v1.json"
    daemon_path = root / "src" / "daemon.cpp"
    evaluator_path = root / "scripts" / "evaluate_capability_posture.py"
    contract_doc_path = root / "docs" / "CAPABILITY_POSTURE_CONTRACT.md"

    errors: list[str] = []

    for path in (schema_path, daemon_path, evaluator_path, contract_doc_path):
        if not path.is_file():
            errors.append(f"missing required contract file: {path}")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    daemon_src = daemon_path.read_text(encoding="utf-8")
    evaluator_src = evaluator_path.read_text(encoding="utf-8")
    contract_doc = contract_doc_path.read_text(encoding="utf-8")

    for needle in REQUIRED_DOC_STRINGS:
        if needle not in contract_doc:
            errors.append(f"{contract_doc_path}: missing '{needle}'")

    top_required = _required_keys(schema, "required")
    for key in sorted(top_required):
        if not _daemon_emits_key(daemon_src, key):
            errors.append(f"{daemon_path}: capability key not emitted in daemon output: {key}")

    nested_required_paths = [
        ("properties", "features", "required"),
        ("properties", "hooks", "required"),
        ("properties", "policy", "required"),
        ("properties", "requirements", "required"),
        ("properties", "requirements_met", "required"),
        ("properties", "exec_identity", "required"),
        ("properties", "state_transitions", "required"),
    ]
    for path in nested_required_paths:
        keys = _required_keys(schema, *path)
        for key in sorted(keys):
            if not _daemon_emits_key(daemon_src, key):
                errors.append(f"{daemon_path}: missing nested capability key emission: {key}")

    for key in REQUIREMENTS_MET_KEYS:
        token = f'requirements_met.get("{key}")'
        if token not in evaluator_src:
            errors.append(f"{evaluator_path}: missing requirements_met evaluator key: {key}")

    for blocker in sorted(REQUIRED_BLOCKERS):
        daemon_token = f'"{blocker}"'
        if daemon_token not in daemon_src:
            errors.append(f"{daemon_path}: missing enforce blocker token: {blocker}")
        if blocker not in contract_doc:
            errors.append(f"{contract_doc_path}: missing blocker documentation: {blocker}")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("Capability/posture contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
