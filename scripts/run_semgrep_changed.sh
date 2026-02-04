#!/usr/bin/env bash
set -euo pipefail

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep is required but was not found in PATH" >&2
    exit 2
fi

SCHEMA_FLAGS=(
    --config p/c
    --config p/security-audit
    --metrics=off
    --error
)

if [[ "${SCAN_ALL:-0}" == "1" ]]; then
    echo "Running semgrep against src/, tests/, and bpf/."
    semgrep "${SCHEMA_FLAGS[@]}" src tests bpf
    exit 0
fi

mapfile -t changed_files < <(scripts/changed_c_family_files.sh)
if [[ "${#changed_files[@]}" -eq 0 ]]; then
    echo "No changed C/C++ files detected; skipping semgrep."
    exit 0
fi

echo "Running semgrep on ${#changed_files[@]} changed file(s)"
semgrep "${SCHEMA_FLAGS[@]}" "${changed_files[@]}"
