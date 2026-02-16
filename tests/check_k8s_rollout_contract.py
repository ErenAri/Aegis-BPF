#!/usr/bin/env python3
"""Ensure mixed-mode Kubernetes rollout guide keeps required procedures."""

from __future__ import annotations

from pathlib import Path
import sys


REQUIRED_SNIPPETS = [
    "deployment.mode=both",
    "agent.enforceGateMode=fail-closed",
    "agent.requireEnforceReadiness=true",
    "python3 scripts/evaluate_capability_posture.py",
    "kubectl label node <node-name> aegisbpf.io/enforce-capable=true --overwrite",
    "aegisbpf health --require-enforce",
    "aegisbpf capabilities --json",
    "OPA Gatekeeper",
    "Kyverno",
    "TICKET=<id>",
]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "docs" / "K8S_ROLLOUT_AUDIT_ENFORCE.md"
    if not path.is_file():
        print(f"missing rollout guide: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")
    missing = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in text]
    if missing:
        print("K8s rollout contract missing required content:", file=sys.stderr)
        for snippet in missing:
            print(f"  - {snippet}", file=sys.stderr)
        return 1

    print("K8s rollout contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
