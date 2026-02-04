#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build-clang-tidy}"

if ! command -v clang-tidy >/dev/null 2>&1; then
    echo "clang-tidy is required but was not found in PATH" >&2
    exit 2
fi

if [[ ! -f "${BUILD_DIR}/compile_commands.json" ]]; then
    echo "Missing ${BUILD_DIR}/compile_commands.json; run CMake configure first" >&2
    exit 2
fi

if command -v rg >/dev/null 2>&1; then
    mapfile -t changed_files < <(scripts/changed_c_family_files.sh | rg -N '\.(cc|cpp)$')
else
    mapfile -t changed_files < <(scripts/changed_c_family_files.sh | { grep -E '\.(cc|cpp)$' || true; })
fi

if [[ "${#changed_files[@]}" -eq 0 ]]; then
    echo "No changed C++ translation units detected; skipping clang-tidy."
    exit 0
fi

echo "Running clang-tidy on ${#changed_files[@]} changed file(s)"
clang-tidy -p "${BUILD_DIR}" "${changed_files[@]}"
