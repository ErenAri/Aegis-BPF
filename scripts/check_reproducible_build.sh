#!/usr/bin/env bash
#
# Reproducibility check.
#
# Builds aegisbpf twice from two *different* absolute source paths
# (so the -ffile-prefix-map / -fdebug-prefix-map flags actually have
# work to do), then compares the full output binaries byte-for-byte.
#
# Pass criteria: sha256 of `aegisbpf` is identical across both builds.
#
# We do NOT normalise / strip / dump-section the artefacts: that would
# only verify "the .text section happens to match", which is a weaker
# claim than what reproducible-builds.org actually requires.
#
# Variables you can override:
#   SOURCE_DATE_EPOCH  unix timestamp baked into anything time-aware
#                      (defaults to the latest commit's author time).
#   CMAKE_GENERATOR    defaults to Ninja.
#   KEEP_TMP=1         keep the two scratch source/build trees on
#                      success, for manual diffoscope inspection.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT_DIR}" log -1 --pretty=%ct)}"
export LC_ALL=C
export TZ=UTC
# Strip the umask out of the equation: ar/ranlib otherwise pick up
# different default file modes between hosts.
umask 022

WORK="$(mktemp -d -t aegis-repro-XXXXXX)"
SRC_A="${WORK}/aaaaaa/src"
SRC_B="${WORK}/bbbbbbbbbbbbbb/src"
BUILD_A="${WORK}/aaaaaa/build"
BUILD_B="${WORK}/bbbbbbbbbbbbbb/build"

cleanup() {
    if [[ "${KEEP_TMP:-0}" != "1" ]]; then
        rm -rf "${WORK}"
    else
        echo "KEEP_TMP=1: scratch tree retained at ${WORK}"
    fi
}
trap cleanup EXIT

echo "staging source copies"
mkdir -p "${SRC_A}" "${SRC_B}"
# Copy the working tree (excluding any build dirs and .git) into both
# scratch locations. rsync's --exclude keeps the copies tight.
rsync -a \
    --exclude='/build*' \
    --exclude='/.git' \
    --exclude='/.claude' \
    --exclude='/operator/bin' \
    --exclude='/operator/console-preview' \
    --exclude='/results' \
    --exclude='/evidence' \
    "${ROOT_DIR}/" "${SRC_A}/"
rsync -a \
    --exclude='/build*' \
    --exclude='/.git' \
    --exclude='/.claude' \
    --exclude='/operator/bin' \
    --exclude='/operator/console-preview' \
    --exclude='/results' \
    --exclude='/evidence' \
    "${ROOT_DIR}/" "${SRC_B}/"

configure_and_build() {
    local src="$1"
    local build="$2"
    cmake -S "${src}" -B "${build}" -G "${CMAKE_GENERATOR}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DSKIP_BPF_BUILD=ON \
        -DAEGIS_BPF_OBJ_DEFINE_PATH=/opt/aegisbpf/aegis.bpf.o \
        -DAEGIS_REPRODUCIBLE_BUILD=ON
    cmake --build "${build}" -j"$(nproc)" --target aegisbpf
}

echo "build A (source: ${SRC_A})"
configure_and_build "${SRC_A}" "${BUILD_A}"
echo "build B (source: ${SRC_B})"
configure_and_build "${SRC_B}" "${BUILD_B}"

BIN_A="${BUILD_A}/aegisbpf"
BIN_B="${BUILD_B}/aegisbpf"
if [[ ! -f "${BIN_A}" || ! -f "${BIN_B}" ]]; then
    echo "missing build outputs for reproducibility check" >&2
    exit 1
fi

SHA_A="$(sha256sum "${BIN_A}" | awk '{print $1}')"
SHA_B="$(sha256sum "${BIN_B}" | awk '{print $1}')"

echo "sha256 build A: ${SHA_A}  ${BIN_A}"
echo "sha256 build B: ${SHA_B}  ${BIN_B}"

if [[ "${SHA_A}" != "${SHA_B}" ]]; then
    echo "reproducibility check FAILED: aegisbpf binaries differ" >&2
    if command -v diffoscope >/dev/null 2>&1; then
        echo "running diffoscope for diagnostics..." >&2
        diffoscope "${BIN_A}" "${BIN_B}" || true
    else
        echo "(install diffoscope for a structured diff)" >&2
    fi
    KEEP_TMP=1
    exit 1
fi

echo "reproducibility check PASSED: aegisbpf is byte-identical across builds"
