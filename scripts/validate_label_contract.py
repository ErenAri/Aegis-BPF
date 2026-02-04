#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path
from typing import List, Set

import yaml


def load_defined_labels(path: Path) -> Set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    names = set()
    for entry in data:
        if isinstance(entry, dict) and "name" in entry:
            names.add(str(entry["name"]))
    return names


def extract_label_mentions(path: Path) -> Set[str]:
    mentions: Set[str] = set()
    text = path.read_text(encoding="utf-8")

    if path.suffix in {".yml", ".yaml"}:
        try:
            data = yaml.safe_load(text)
        except Exception:
            data = None
        if isinstance(data, dict):
            stack: List[object] = [data]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    for key, value in node.items():
                        if key == "labels":
                            if isinstance(value, list):
                                for item in value:
                                    if isinstance(item, str):
                                        mentions.add(item)
                            elif isinstance(value, str):
                                for token in value.split(","):
                                    tok = token.strip()
                                    if tok:
                                        mentions.add(tok)
                        stack.append(value)
                elif isinstance(node, list):
                    stack.extend(node)

    # Capture explicit single-quoted or double-quoted labels in scripts.
    for quoted in re.findall(r"['\"]([A-Za-z0-9._/-]+)['\"]", text):
        if quoted in {
            "bug",
            "enhancement",
            "triage",
            "security",
            "dependencies",
            "critical",
            "release-approved",
            "feature",
            "performance",
            "documentation",
        }:
            mentions.add(quoted)

    return mentions


def main() -> int:
    labels_file = Path("config/repo_labels.json")
    if not labels_file.exists():
        print("Missing config/repo_labels.json", file=sys.stderr)
        return 2

    defined = load_defined_labels(labels_file)
    required = {
        "bug",
        "enhancement",
        "triage",
        "security",
        "dependencies",
        "critical",
        "release-approved",
        "feature",
        "performance",
        "documentation",
    }

    missing_required = sorted(required - defined)
    if missing_required:
        print("Missing mandatory labels in config/repo_labels.json:")
        for label in missing_required:
            print(f"  - {label}")
        return 1

    files = [
        Path(".github/workflows/release-branch-guard.yml"),
        Path(".github/workflows/check-vendored.yml"),
        Path(".github/ISSUE_TEMPLATE/bug_report.yml"),
        Path(".github/ISSUE_TEMPLATE/feature_request.yml"),
        Path(".github/ISSUE_TEMPLATE/security_report.yml"),
    ]
    referenced: Set[str] = set()
    for file in files:
        if file.exists():
            referenced |= extract_label_mentions(file)

    unknown = sorted(label for label in referenced if label not in defined)
    if unknown:
        print("Referenced labels not defined in config/repo_labels.json:")
        for label in unknown:
            print(f"  - {label}")
        return 1

    print("Label contract valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
