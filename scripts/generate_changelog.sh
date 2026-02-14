#!/usr/bin/env bash
# generate_changelog.sh — Generate CHANGELOG.md from git commit history
#
# Usage: scripts/generate_changelog.sh [--since TAG] [--output FILE]
#
# Environment variables:
#   SINCE_TAG   - Generate changes since this tag (default: latest tag)
#   OUTPUT      - Output file path (default: stdout)
#
# Commit format convention (conventional commits):
#   feat(scope): description    -> Features
#   fix(scope): description     -> Bug Fixes
#   perf(scope): description    -> Performance
#   docs(scope): description    -> Documentation
#   ci(scope): description      -> CI/CD
#   refactor(scope): description -> Refactoring
#   test(scope): description    -> Tests
#   chore(scope): description   -> Chores

set -euo pipefail

SINCE_TAG=""
OUTPUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --since)
            SINCE_TAG="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--since TAG] [--output FILE]" >&2
            exit 1
            ;;
    esac
done

SINCE_TAG="${SINCE_TAG:-${SINCE_TAG:-}}"
OUTPUT="${OUTPUT:-${OUTPUT:-}}"

# Find latest tag if not specified
if [ -z "$SINCE_TAG" ]; then
    SINCE_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
fi

if [ -n "$SINCE_TAG" ]; then
    RANGE="${SINCE_TAG}..HEAD"
    HEADER="## Changes since ${SINCE_TAG}"
else
    RANGE="HEAD"
    HEADER="## All Changes"
fi

# Collect commits
collect_commits() {
    local pattern="$1"
    if [ -n "$SINCE_TAG" ]; then
        git log "$RANGE" --pretty=format:"%s (%h)" --grep="^${pattern}" 2>/dev/null || true
    else
        git log --pretty=format:"%s (%h)" --grep="^${pattern}" 2>/dev/null || true
    fi
}

generate() {
    echo "# Changelog"
    echo ""
    echo "$HEADER"
    echo ""
    echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    local has_content=false

    # Features
    local feats
    feats=$(collect_commits "feat")
    if [ -n "$feats" ]; then
        has_content=true
        echo "### Features"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$feats"
        echo ""
    fi

    # Bug Fixes
    local fixes
    fixes=$(collect_commits "fix")
    if [ -n "$fixes" ]; then
        has_content=true
        echo "### Bug Fixes"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$fixes"
        echo ""
    fi

    # Performance
    local perfs
    perfs=$(collect_commits "perf")
    if [ -n "$perfs" ]; then
        has_content=true
        echo "### Performance"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$perfs"
        echo ""
    fi

    # Documentation
    local docs
    docs=$(collect_commits "docs")
    if [ -n "$docs" ]; then
        has_content=true
        echo "### Documentation"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$docs"
        echo ""
    fi

    # CI/CD
    local cis
    cis=$(collect_commits "ci")
    if [ -n "$cis" ]; then
        has_content=true
        echo "### CI/CD"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$cis"
        echo ""
    fi

    # Refactoring
    local refactors
    refactors=$(collect_commits "refactor")
    if [ -n "$refactors" ]; then
        has_content=true
        echo "### Refactoring"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$refactors"
        echo ""
    fi

    # Tests
    local tests
    tests=$(collect_commits "test")
    if [ -n "$tests" ]; then
        has_content=true
        echo "### Tests"
        echo ""
        while IFS= read -r line; do
            echo "- ${line}"
        done <<< "$tests"
        echo ""
    fi

    if [ "$has_content" = false ]; then
        echo "No categorized changes found."
        echo ""
        echo "### All Commits"
        echo ""
        if [ -n "$SINCE_TAG" ]; then
            git log "$RANGE" --pretty=format:"- %s (%h)" 2>/dev/null || true
        else
            git log --pretty=format:"- %s (%h)" -20 2>/dev/null || true
        fi
        echo ""
    fi
}

if [ -n "$OUTPUT" ]; then
    generate > "$OUTPUT"
    echo "Changelog written to $OUTPUT"
else
    generate
fi
