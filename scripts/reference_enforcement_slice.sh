#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"
PRESERVE_TMP_ON_FAIL="${PRESERVE_TMP_ON_FAIL:-0}"
SUMMARY_OUT="${SUMMARY_OUT:-}"

declare -i TOTAL_CHECKS=0
declare -i PASSED_CHECKS=0
declare -i FAILED_CHECKS=0
declare -i SKIPPED_CHECKS=0

AGENT_PID=""
TMP_DIR=""
LOG_FILE=""

cleanup() {
    local exit_code=$?
    if [[ -n "${AGENT_PID}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
        wait "${AGENT_PID}" 2>/dev/null || true
        AGENT_PID=""
    fi
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        if [[ "${PRESERVE_TMP_ON_FAIL}" == "1" && ${exit_code} -ne 0 ]]; then
            echo "Preserving failed run artifacts at ${TMP_DIR}" >&2
        else
            rm -rf "${TMP_DIR}"
        fi
    fi
}
trap cleanup EXIT

pass() {
    local label="$1"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    echo "[PASS] ${label}"
}

fail() {
    local label="$1"
    local detail="$2"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    echo "[FAIL] ${label}: ${detail}" >&2
}

run_expect_success() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "${label}"
    else
        fail "${label}" "command failed unexpectedly"
    fi
}

run_expect_blocked() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "${label}" "command succeeded (expected block)"
    else
        pass "${label}"
    fi
}

require_prereqs() {
    if [[ $EUID -ne 0 ]]; then
        echo "Must run as root (BPF LSM enforcement tests)." >&2
        exit 1
    fi

    if [[ ! -x "${BIN}" ]]; then
        echo "Agent binary not found at ${BIN}. Build first." >&2
        exit 1
    fi

    if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
        echo "cgroup v2 is required at /sys/fs/cgroup." >&2
        exit 1
    fi

    if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
        echo "BPF LSM is not enabled; this suite requires enforce-capable kernel." >&2
        exit 1
    fi
}

start_agent() {
    LOG_FILE="${TMP_DIR}/agent.log"
    "${BIN}" run --enforce --enforce-signal=none >"${LOG_FILE}" 2>&1 &
    AGENT_PID=$!
    sleep 1
    if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
        echo "Agent failed to start. Log:" >&2
        cat "${LOG_FILE}" >&2 || true
        exit 1
    fi
}

stop_agent() {
    if [[ -n "${AGENT_PID}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
        wait "${AGENT_PID}" 2>/dev/null || true
        AGENT_PID=""
    fi
}

main() {
    require_prereqs

    TMP_DIR="$(mktemp -d)" || { echo "Failed to create temp directory" >&2; exit 1; }
    echo "Running reference enforcement slice using ${BIN}"
    echo "Workspace: ${TMP_DIR}"

    local target="${TMP_DIR}/reference_target.sh"
    local benign="${TMP_DIR}/benign.txt"
    local symlink_path="${TMP_DIR}/reference_target.symlink"
    local hardlink_path="${TMP_DIR}/reference_target.hardlink"

    printf '#!/bin/sh\necho reference\n' >"${target}"
    chmod +x "${target}"
    printf 'benign\n' >"${benign}"
    ln -sf "${target}" "${symlink_path}"
    ln "${target}" "${hardlink_path}"

    local inode
    inode="$(stat -c %i "${target}")"

    start_agent

    if ! "${BIN}" block add "${target}" >/dev/null 2>&1; then
        echo "Failed to add block rule for ${target}" >&2
        exit 1
    fi

    run_expect_blocked "reference: cat direct" cat "${target}"
    run_expect_blocked "reference: exec direct" "${target}"
    run_expect_blocked "reference: cat symlink" cat "${symlink_path}"
    run_expect_blocked "reference: cat hardlink" cat "${hardlink_path}"
    run_expect_success "reference: cat benign" cat "${benign}"

    run_expect_success "reference: expected action logged" grep -q "\"action\":\"BLOCK\"" "${LOG_FILE}"
    run_expect_success "reference: inode logged" grep -q "\"ino\":${inode}" "${LOG_FILE}"

    "${BIN}" block del "${target}" >/dev/null 2>&1 || true
    stop_agent

    if [[ -n "${SUMMARY_OUT}" ]]; then
        cat >"${SUMMARY_OUT}" <<EOF
{
  "total_checks": ${TOTAL_CHECKS},
  "passed_checks": ${PASSED_CHECKS},
  "failed_checks": ${FAILED_CHECKS},
  "skipped_checks": ${SKIPPED_CHECKS},
  "reference_slice_passed": $( [[ ${FAILED_CHECKS} -eq 0 ]] && echo true || echo false )
}
EOF
    fi

    echo
    echo "Reference slice summary: passed=${PASSED_CHECKS} failed=${FAILED_CHECKS} total=${TOTAL_CHECKS}"
    if ((FAILED_CHECKS > 0)); then
        exit 1
    fi
}

main "$@"
