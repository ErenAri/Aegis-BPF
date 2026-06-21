#!/usr/bin/env python3
"""Validate CI workflow policy that is not covered by GitHub itself."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


WORKFLOW_DIR = Path(".github/workflows")
SELF_HOSTED_PR_GATE_VAR = "AEGIS_ENABLE_SELF_HOSTED_PR_GATES"


def load_workflow(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    return data


def on_value(workflow: dict[str, Any]) -> Any:
    value = workflow.get("on")
    # PyYAML parses bare "on:" as boolean True in YAML 1.1 mode.
    if value is None and True in workflow:
        value = workflow.get(True)
    return value


def workflow_events(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, dict):
        return {str(item) for item in value.keys()}
    return set()


def runs_on_self_hosted(runs_on: Any) -> bool:
    if isinstance(runs_on, str):
        return "self-hosted" in runs_on
    if isinstance(runs_on, list):
        return any(str(item) == "self-hosted" for item in runs_on)
    return False


def has_self_hosted_pr_gate(job_if: Any) -> bool:
    if not isinstance(job_if, str):
        return False
    normalized = " ".join(job_if.split())
    return (
        "github.event_name != 'pull_request'" in normalized
        and SELF_HOSTED_PR_GATE_VAR in normalized
    )


def main() -> int:
    failures: list[str] = []

    for path in sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml")):
        workflow = load_workflow(path)
        events = workflow_events(on_value(workflow))
        jobs = workflow.get("jobs")
        if "pull_request" not in events or not isinstance(jobs, dict):
            continue

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if not runs_on_self_hosted(job.get("runs-on")):
                continue
            if has_self_hosted_pr_gate(job.get("if")):
                continue
            failures.append(
                f"{path}:{job_id} is a self-hosted pull_request job without "
                f"the {SELF_HOSTED_PR_GATE_VAR} capacity gate"
            )

    if failures:
        print("Self-hosted pull_request workflow policy violations:")
        for failure in failures:
            print(f"  - {failure}")
        print()
        print(
            "Self-hosted PR jobs must avoid queueing indefinitely when the runner "
            "fleet is unavailable. Add a job-level guard such as: "
            "github.event_name != 'pull_request' || "
            f"vars.{SELF_HOSTED_PR_GATE_VAR} == 'true'"
        )
        return 1

    print("CI workflow policy validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
