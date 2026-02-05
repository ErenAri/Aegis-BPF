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

skip() {
    local label="$1"
    local detail="$2"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
    echo "[SKIP] ${label}: ${detail}"
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
    local enforce_signal="$1"
    LOG_FILE="${TMP_DIR}/agent-${enforce_signal}.log"
    "${BIN}" run --enforce --enforce-signal="${enforce_signal}" >"${LOG_FILE}" 2>&1 &
    AGENT_PID=$!
    sleep 1
    if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
        echo "Agent failed to start for signal=${enforce_signal}. Log:" >&2
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

expected_action_for_signal() {
    case "$1" in
    none)
        echo "BLOCK"
        ;;
    term)
        echo "TERM"
        ;;
    int)
        echo "INT"
        ;;
    *)
        echo "Unsupported enforce signal: $1" >&2
        exit 1
        ;;
    esac
}

run_signal_suite() {
    local signal="$1"
    local expected_action="$2"
    local scenario_dir="${TMP_DIR}/${signal}"
    local target="${scenario_dir}/target.txt"
    local symlink_path="${scenario_dir}/target.symlink"
    local hardlink_path="${scenario_dir}/target.hardlink"
    local cross_hardlink_path="${scenario_dir}/hardlinks/target.cross.hardlink"
    local swap_symlink_path="${scenario_dir}/target.swap.symlink"
    local benign_target="${scenario_dir}/benign.txt"
    local renamed_path="${scenario_dir}/target.renamed"
    local bind_alias_path="${scenario_dir}/target.bind"

    mkdir -p "${scenario_dir}"
    mkdir -p "${scenario_dir}/subdir"
    mkdir -p "${scenario_dir}/hardlinks"
    printf 'signal=%s\n' "${signal}" >"${target}"
    printf 'benign=%s\n' "${signal}" >"${benign_target}"
    ln -sf "${target}" "${symlink_path}"
    ln "${target}" "${hardlink_path}"
    ln "${target}" "${cross_hardlink_path}"
    ln -sf "${benign_target}" "${swap_symlink_path}"
    touch "${bind_alias_path}"

    local inode
    inode="$(stat -c %i "${target}")"

    start_agent "${signal}"

    if ! "${BIN}" block add "${target}" >/dev/null 2>&1; then
        echo "Failed to add block rule for ${target}" >&2
        exit 1
    fi

    # 10 blocked-open assertions per signal mode.
    run_expect_blocked "${signal}: cat direct" cat "${target}"
    run_expect_blocked "${signal}: head direct" head -c 1 "${target}"
    run_expect_blocked "${signal}: tail direct" tail -c 1 "${target}"
    run_expect_blocked "${signal}: dd direct" dd if="${target}" of=/dev/null bs=1 count=1 status=none
    run_expect_blocked "${signal}: grep direct" grep -m1 . "${target}"
    run_expect_blocked "${signal}: python direct" python3 -c "import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()" "${target}"
    run_expect_blocked "${signal}: cat symlink" cat "${symlink_path}"
    run_expect_blocked "${signal}: head symlink" head -c 1 "${symlink_path}"
    run_expect_blocked "${signal}: cat hardlink" cat "${hardlink_path}"
    run_expect_blocked "${signal}: dd hardlink" dd if="${hardlink_path}" of=/dev/null bs=1 count=1 status=none
    run_expect_blocked "${signal}: cat cross-dir hardlink" cat "${cross_hardlink_path}"
    run_expect_success "${signal}: cat benign symlink before swap" cat "${swap_symlink_path}"
    ln -sf "${target}" "${swap_symlink_path}"
    run_expect_blocked "${signal}: cat symlink after swap" cat "${swap_symlink_path}"
    run_expect_blocked "${signal}: cat traversal" cat "${scenario_dir}/subdir/../target.txt"

    # Rename should not bypass inode-based enforcement.
    mv "${target}" "${renamed_path}"
    run_expect_blocked "${signal}: cat renamed" cat "${renamed_path}"
    run_expect_blocked "${signal}: head renamed" head -c 1 "${renamed_path}"
    local renamed_inode
    renamed_inode="$(stat -c %i "${renamed_path}")"
    if [[ "${renamed_inode}" == "${inode}" ]]; then
        pass "${signal}: inode stable across rename"
    else
        fail "${signal}: inode stable across rename" "expected ${inode}, got ${renamed_inode}"
    fi
    mv "${renamed_path}" "${target}"

    local bind_mounted=0
    if mount --bind "${target}" "${bind_alias_path}" >/dev/null 2>&1; then
        bind_mounted=1
        run_expect_blocked "${signal}: cat bind" cat "${bind_alias_path}"
        run_expect_blocked "${signal}: head bind" head -c 1 "${bind_alias_path}"
        local bind_inode
        bind_inode="$(stat -c %i "${bind_alias_path}")"
        if [[ "${bind_inode}" == "${inode}" ]]; then
            pass "${signal}: inode stable across bind mount alias"
        else
            fail "${signal}: inode stable across bind mount alias" \
                 "expected ${inode}, got ${bind_inode}"
        fi
    else
        skip "${signal}: bind mount alias checks" "mount --bind unavailable in this environment"
        skip "${signal}: bind mount alias checks" "mount --bind unavailable in this environment"
        skip "${signal}: bind mount alias checks" "mount --bind unavailable in this environment"
    fi

    sleep 1
    run_expect_success "${signal}: expected action logged" grep -q "\"action\":\"${expected_action}\"" "${LOG_FILE}"
    run_expect_success "${signal}: inode logged" grep -q "\"ino\":${inode}" "${LOG_FILE}"

    if [[ "${bind_mounted}" -eq 1 ]]; then
        if ! umount "${bind_alias_path}" >/dev/null 2>&1; then
            fail "${signal}: unmount bind alias" "failed to unmount ${bind_alias_path}"
        fi
    fi

    "${BIN}" block del "${target}" >/dev/null 2>&1 || true
    stop_agent
}

main() {
    require_prereqs

    TMP_DIR="$(mktemp -d /tmp/aegisbpf_e2e_matrix.XXXXXX)"
    echo "Running kernel enforcement matrix using ${BIN}"
    echo "Workspace: ${TMP_DIR}"

    local signal
    for signal in none term int; do
        run_signal_suite "${signal}" "$(expected_action_for_signal "${signal}")"
    done

    if [[ -n "${SUMMARY_OUT}" ]]; then
        local os_id="unknown"
        local os_version="unknown"
        local kernel_rel="unknown"
        local fs_type="unknown"
        if [[ -r /etc/os-release ]]; then
            # shellcheck disable=SC1091
            . /etc/os-release
            os_id="${ID:-unknown}"
            os_version="${VERSION_ID:-unknown}"
        fi
        kernel_rel="$(uname -r 2>/dev/null || echo unknown)"
        fs_type="$(stat -f -c %T "${TMP_DIR}" 2>/dev/null || echo unknown)"
        cat >"${SUMMARY_OUT}" <<EOF
{
  "total_checks": ${TOTAL_CHECKS},
  "passed_checks": ${PASSED_CHECKS},
  "failed_checks": ${FAILED_CHECKS},
  "skipped_checks": ${SKIPPED_CHECKS},
  "kernel_release": "${kernel_rel}",
  "os_id": "${os_id}",
  "os_version": "${os_version}",
  "workspace_fs": "${fs_type}"
}
EOF
    fi

    echo
    echo "E2E matrix summary: passed=${PASSED_CHECKS} failed=${FAILED_CHECKS} skipped=${SKIPPED_CHECKS} total=${TOTAL_CHECKS}"
    if ((FAILED_CHECKS > 0)); then
        exit 1
    fi
}

main "$@"
