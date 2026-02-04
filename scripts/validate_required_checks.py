#!/usr/bin/env python3
import argparse
import itertools
import re
from pathlib import Path
from typing import Any

import yaml

WORKFLOW_FILES = [
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/security.yml"),
    Path(".github/workflows/benchmark.yml"),
    Path(".github/workflows/release-readiness.yml"),
    Path(".github/workflows/release-branch-guard.yml"),
]

MATRIX_REF_RE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def load_required(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def normalize_list_value(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def matrix_rows(job: dict[str, Any]) -> list[dict[str, Any]]:
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return [{}]

    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        return [{}]

    include = normalize_list_value(matrix.get("include", []))
    exclude = normalize_list_value(matrix.get("exclude", []))

    base_axes = {
        key: normalize_list_value(value)
        for key, value in matrix.items()
        if key not in {"include", "exclude"}
    }

    rows: list[dict[str, Any]]
    if base_axes:
        keys = sorted(base_axes.keys())
        rows = [
            {k: v for k, v in zip(keys, combo)}
            for combo in itertools.product(*(base_axes[k] for k in keys))
        ]
    else:
        rows = [{}]

    for extra in include:
        if isinstance(extra, dict):
            rows.append(dict(extra))

    def is_excluded(row: dict[str, Any]) -> bool:
        for item in exclude:
            if not isinstance(item, dict):
                continue
            if all(row.get(k) == v for k, v in item.items()):
                return True
        return False

    return [row for row in rows if not is_excluded(row)]


def expand_job_name(name_template: str, row: dict[str, Any]) -> str:
    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in row:
            return str(row[key])
        return match.group(0)

    return MATRIX_REF_RE.sub(repl, name_template)


def discover_contexts() -> set[str]:
    contexts: set[str] = set()

    for workflow_path in WORKFLOW_FILES:
        data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        workflow_name = data.get("name")
        jobs = data.get("jobs")
        if not isinstance(workflow_name, str) or not isinstance(jobs, dict):
            continue

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            name_template = str(job.get("name", job_id))
            rows = matrix_rows(job)
            for row in rows:
                job_name = expand_job_name(name_template, row)
                contexts.add(f"{workflow_name} / {job_name}")

    return contexts


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate required check names against workflow job contexts")
    parser.add_argument("--required", action="append", required=True, help="Path to required-checks file")
    args = parser.parse_args()

    required_files = [Path(p) for p in args.required]
    contexts = discover_contexts()
    status = 0

    for req_file in required_files:
        required = load_required(req_file)
        missing = sorted(item for item in required if item not in contexts)
        if missing:
            status = 1
            print(f"Missing workflow contexts referenced by {req_file}:")
            for item in missing:
                print(f"  - {item}")
        else:
            print(f"{req_file}: all entries map to existing workflow contexts.")

    return status


if __name__ == "__main__":
    raise SystemExit(main())
