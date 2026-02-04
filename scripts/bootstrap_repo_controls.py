#!/usr/bin/env python3
"""
Bootstrap and enforce repository control-plane settings:
- sync labels from config/repo_labels.json
- apply branch protection required checks for main/release branches

Safety:
- dry-run by default
- use --apply to perform mutations
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote


def run_cmd(cmd: List[str], stdin_text: Optional[str] = None) -> str:
    proc = subprocess.run(
        cmd,
        input=stdin_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or f"command failed: {' '.join(cmd)}"
        raise RuntimeError(msg)
    return proc.stdout


def gh_api(repo: str, endpoint: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> str:
    cmd: List[str] = [
        "gh",
        "api",
        "-H",
        "Accept: application/vnd.github+json",
    ]
    if method != "GET":
        cmd += ["-X", method]
    if body is not None:
        cmd += ["--input", "-"]
        return run_cmd(cmd + [f"/repos/{repo}{endpoint}"], stdin_text=json.dumps(body))
    return run_cmd(cmd + [f"/repos/{repo}{endpoint}"])


def gh_api_paginated_lines(repo: str, endpoint: str, jq_expr: str) -> List[str]:
    cmd: List[str] = [
        "gh",
        "api",
        "--paginate",
        "-H",
        "Accept: application/vnd.github+json",
        f"/repos/{repo}{endpoint}",
        "--jq",
        jq_expr,
    ]
    out = run_cmd(cmd)
    return [line.strip() for line in out.splitlines() if line.strip()]


def load_required_checks(path: Path) -> List[str]:
    checks: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        checks.append(line)
    return checks


def sync_labels(repo: str, labels_path: Path, apply: bool) -> None:
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    if not isinstance(labels, list):
        raise RuntimeError(f"Invalid labels file format: {labels_path}")

    existing_names = gh_api_paginated_lines(repo, "/labels?per_page=100", ".[].name")
    existing_map = {name.lower(): name for name in existing_names}

    print(f"[labels] desired={len(labels)} existing={len(existing_names)}")
    for label in labels:
        if not isinstance(label, dict) or "name" not in label:
            raise RuntimeError(f"Invalid label entry: {label}")
        name = str(label["name"])
        key = name.lower()
        color = str(label.get("color", "ededed"))
        description = str(label.get("description", ""))

        payload = {
            "name": name,
            "new_name": name,
            "color": color,
            "description": description,
        }

        if key in existing_map:
            current = existing_map[key]
            print(f"[labels] update: {current} -> {name}")
            if apply:
                gh_api(
                    repo,
                    f"/labels/{quote(current, safe='')}",
                    method="PATCH",
                    body=payload,
                )
        else:
            print(f"[labels] create: {name}")
            if apply:
                gh_api(
                    repo,
                    "/labels",
                    method="POST",
                    body={"name": name, "color": color, "description": description},
                )


def apply_branch_protection(
    repo: str,
    branch: str,
    checks: List[str],
    min_approvals: int,
    apply: bool,
) -> None:
    payload = {
        "required_status_checks": {
            "strict": True,
            "contexts": checks,
        },
        "enforce_admins": True,
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "required_approving_review_count": min_approvals,
        },
        "restrictions": None,
        "required_conversation_resolution": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": False,
    }

    print(f"[branch] protect: {branch} checks={len(checks)} approvals>={min_approvals}")
    if apply:
        gh_api(
            repo,
            f"/branches/{quote(branch, safe='')}/protection",
            method="PUT",
            body=payload,
        )


def discover_release_branches(repo: str, prefix: str, main_branch: str) -> List[str]:
    names = gh_api_paginated_lines(repo, "/branches?per_page=100", ".[].name")
    out = [
        name
        for name in names
        if name.startswith(prefix) and name != main_branch
    ]
    return sorted(set(out))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap repository controls")
    parser.add_argument("--repo", default=os.getenv("REPO") or os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--main-branch", default=os.getenv("MAIN_BRANCH", "main"))
    parser.add_argument("--release-prefix", default=os.getenv("RELEASE_PREFIX", "release/"))
    parser.add_argument("--labels-file", default="config/repo_labels.json")
    parser.add_argument("--required-main", default="config/required_checks.txt")
    parser.add_argument("--required-release", default="config/required_checks_release.txt")
    parser.add_argument("--min-approvals", type=int, default=1)
    parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.repo:
        print("error: set --repo or REPO/GITHUB_REPOSITORY", file=sys.stderr)
        return 2

    if args.min_approvals < 1:
        print("error: --min-approvals must be >= 1", file=sys.stderr)
        return 2

    if not shutil_which("gh"):
        print("error: GitHub CLI (gh) is required", file=sys.stderr)
        return 2

    labels_path = Path(args.labels_file)
    required_main_path = Path(args.required_main)
    required_release_path = Path(args.required_release)

    if not labels_path.exists():
        print(f"error: labels file not found: {labels_path}", file=sys.stderr)
        return 2
    if not required_main_path.exists():
        print(f"error: required checks file not found: {required_main_path}", file=sys.stderr)
        return 2
    if not required_release_path.exists():
        print(f"error: required checks file not found: {required_release_path}", file=sys.stderr)
        return 2

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[mode] {mode}")
    print(f"[repo] {args.repo}")

    try:
        sync_labels(args.repo, labels_path, args.apply)

        main_checks = load_required_checks(required_main_path)
        release_checks = load_required_checks(required_release_path)

        apply_branch_protection(
            args.repo,
            args.main_branch,
            main_checks,
            args.min_approvals,
            args.apply,
        )

        release_branches = discover_release_branches(
            args.repo, args.release_prefix, args.main_branch
        )
        if not release_branches:
            print(f"[branch] no release branches found for prefix '{args.release_prefix}'")
        for branch in release_branches:
            apply_branch_protection(
                args.repo,
                branch,
                release_checks,
                args.min_approvals,
                args.apply,
            )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.apply:
        print("Dry-run complete. Re-run with --apply to persist changes.")
    else:
        print("Repository control-plane bootstrap complete.")
    return 0


def shutil_which(name: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(p) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
