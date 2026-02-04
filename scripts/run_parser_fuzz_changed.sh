#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build-fuzz}"
FUZZ_SECONDS="${FUZZ_SECONDS:-120}"

if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "Missing fuzz build directory: ${BUILD_DIR}" >&2
    exit 2
fi

PARSER_FILE_PATTERN='^(src/(policy|network_ops|events|commands_policy|crypto|sha256)\.cpp|tests/fuzz/.*|config/event-schema\.json)$'

mapfile -t changed_files < <(scripts/changed_c_family_files.sh)

# Include non-C/C++ parser-related files that changed C-file helper would skip.
if [[ -n "${BASE_REF:-}" || -n "${DIFF_RANGE:-}" ]]; then
    if [[ -n "${DIFF_RANGE:-}" ]]; then
        diff_range="${DIFF_RANGE}"
    else
        base_ref="${BASE_REF#refs/heads/}"
        if git rev-parse --verify --quiet "origin/${base_ref}" >/dev/null; then
            merge_base="$(git merge-base HEAD "origin/${base_ref}")"
            diff_range="${merge_base}...HEAD"
        elif git rev-parse --verify --quiet "${base_ref}" >/dev/null; then
            merge_base="$(git merge-base HEAD "${base_ref}")"
            diff_range="${merge_base}...HEAD"
        else
            diff_range="HEAD~1...HEAD"
        fi
    fi
    mapfile -t extra_changes < <(git diff --name-only --diff-filter=ACMR "${diff_range}" | sort -u)
    changed_files+=("${extra_changes[@]}")
fi

if [[ ${#changed_files[@]} -eq 0 ]]; then
    echo "No changed files detected for parser fuzz gate."
    exit 0
fi

should_run=0
for file in "${changed_files[@]}"; do
    if [[ "${file}" =~ ${PARSER_FILE_PATTERN} ]]; then
        should_run=1
        break
    fi
done

if [[ ${should_run} -eq 0 ]]; then
    echo "No parser-related changes detected; skipping parser fuzz gate."
    exit 0
fi

targets=(fuzz_policy fuzz_bundle fuzz_network fuzz_path fuzz_event)
echo "Parser-related changes detected; running fuzz targets for ${FUZZ_SECONDS}s each."
for target in "${targets[@]}"; do
    echo "Fuzzing ${target}..."
    "./${BUILD_DIR}/${target}" -max_total_time="${FUZZ_SECONDS}" -print_final_stats=1
done
