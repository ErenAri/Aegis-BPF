#!/usr/bin/env bash
set -euo pipefail

BRANCH="${BRANCH:-main}"
REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
REQUIRED_FILE="${REQUIRED_FILE:-config/required_checks.txt}"

if [[ -z "${REPO}" ]]; then
    echo "Set REPO=<owner/name> (or GITHUB_REPOSITORY) to audit branch protection." >&2
    exit 2
fi

if [[ ! -f "${REQUIRED_FILE}" ]]; then
    echo "Required-check file not found: ${REQUIRED_FILE}" >&2
    exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "GitHub CLI (gh) is required." >&2
    exit 2
fi

tmp_json="$(mktemp)"
tmp_actual="$(mktemp)"
trap 'rm -f "${tmp_json}" "${tmp_actual}"' EXIT

if ! gh api -H "Accept: application/vnd.github+json" \
    "/repos/${REPO}/branches/${BRANCH}/protection" >"${tmp_json}"; then
    echo "Failed to read branch protection for ${REPO}:${BRANCH}." >&2
    echo "Ensure your token has repository admin read permissions." >&2
    exit 2
fi

python3 - "${tmp_json}" >"${tmp_actual}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

contexts = data.get("required_status_checks", {}).get("contexts", [])
for item in sorted(contexts):
    print(item)
PY

python3 - "${REQUIRED_FILE}" "${tmp_actual}" <<'PY'
import sys
from pathlib import Path

required_path, actual_path = sys.argv[1], sys.argv[2]

def load_lines(path: str) -> list[str]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out

required = set(load_lines(required_path))
actual = set(load_lines(actual_path))

missing = sorted(required - actual)
extra = sorted(actual - required)

if missing:
    print("Missing required checks:")
    for m in missing:
        print(f"  - {m}")
if extra:
    print(f"Additional configured checks (not in {Path(required_path).name}):")
    for e in extra:
        print(f"  - {e}")

if missing:
    raise SystemExit(1)

print("Branch protection required checks are aligned.")
PY
