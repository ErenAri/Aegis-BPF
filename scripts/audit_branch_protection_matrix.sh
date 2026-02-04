#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
MAIN_BRANCH="${MAIN_BRANCH:-main}"
REQUIRED_MAIN_FILE="${REQUIRED_MAIN_FILE:-config/required_checks.txt}"
REQUIRED_RELEASE_FILE="${REQUIRED_RELEASE_FILE:-config/required_checks_release.txt}"
RELEASE_PREFIX="${RELEASE_PREFIX:-release/}"

if [[ -z "${REPO}" ]]; then
    echo "Set REPO=<owner/name> (or GITHUB_REPOSITORY)." >&2
    exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "GitHub CLI (gh) is required." >&2
    exit 2
fi

if [[ ! -f "${REQUIRED_MAIN_FILE}" ]]; then
    echo "Missing required checks file: ${REQUIRED_MAIN_FILE}" >&2
    exit 2
fi

if [[ ! -f "${REQUIRED_RELEASE_FILE}" ]]; then
    echo "Missing required checks file: ${REQUIRED_RELEASE_FILE}" >&2
    exit 2
fi

status=0

echo "Auditing branch protection for ${REPO}:${MAIN_BRANCH}"
if ! REPO="${REPO}" BRANCH="${MAIN_BRANCH}" REQUIRED_FILE="${REQUIRED_MAIN_FILE}" scripts/check_branch_protection.sh; then
    status=1
fi

mapfile -t release_branches < <(
    gh api --paginate -H "Accept: application/vnd.github+json" \
        "/repos/${REPO}/branches?protected=true&per_page=100" \
        --jq ".[] | select(.name | startswith(\"${RELEASE_PREFIX}\")) | .name"
)

if [[ "${#release_branches[@]}" -eq 0 ]]; then
    echo "No protected release branches found with prefix '${RELEASE_PREFIX}'."
    exit "${status}"
fi

echo "Auditing ${#release_branches[@]} protected release branch(es)"
for branch in "${release_branches[@]}"; do
    echo "Auditing branch protection for ${REPO}:${branch}"
    if ! REPO="${REPO}" BRANCH="${branch}" REQUIRED_FILE="${REQUIRED_RELEASE_FILE}" scripts/check_branch_protection.sh; then
        status=1
    fi
done

exit "${status}"
