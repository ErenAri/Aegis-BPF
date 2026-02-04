#!/usr/bin/env bash
set -euo pipefail

# Determine a diff range for PRs/pushes and print changed C/C++ files.
# Optional env:
#   BASE_REF   - e.g. "main" (typically from GITHUB_BASE_REF on PRs)
#   DIFF_RANGE - explicit git diff range, overrides BASE_REF inference

resolve_diff_range() {
    if [[ -n "${DIFF_RANGE:-}" ]]; then
        echo "${DIFF_RANGE}"
        return
    fi

    if [[ -n "${BASE_REF:-}" ]]; then
        local base_ref="${BASE_REF#refs/heads/}"
        if ! git rev-parse --verify --quiet "origin/${base_ref}" >/dev/null; then
            git fetch --no-tags --depth=200 origin "${base_ref}:${base_ref}" >/dev/null 2>&1 || true
        fi
        if git rev-parse --verify --quiet "origin/${base_ref}" >/dev/null; then
            local merge_base
            merge_base="$(git merge-base HEAD "origin/${base_ref}")"
            echo "${merge_base}...HEAD"
            return
        fi
        if git rev-parse --verify --quiet "${base_ref}" >/dev/null; then
            local merge_base
            merge_base="$(git merge-base HEAD "${base_ref}")"
            echo "${merge_base}...HEAD"
            return
        fi
    fi

    if git rev-parse --verify --quiet HEAD~1 >/dev/null; then
        echo "HEAD~1...HEAD"
    else
        echo "HEAD"
    fi
}

DIFF="$(resolve_diff_range)"

filter_paths() {
    local pattern='^(src|tests|bpf)/.*\.(c|cc|cpp|h|hpp)$'
    if command -v rg >/dev/null 2>&1; then
        rg -N "${pattern}" || true
    else
        grep -E "${pattern}" || true
    fi
}

git diff --name-only --diff-filter=ACMR "${DIFF}" \
    | filter_paths \
    | sort -u
