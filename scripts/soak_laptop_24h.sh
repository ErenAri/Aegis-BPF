#!/usr/bin/env bash
# Laptop-local 24h soak wrapper for AegisBPF.
# Designed to run inside a tmux session under `systemd-inhibit` so a
# 24-hour run survives lid-close / idle suspend on an i9-13900H-class
# workstation.
#
# Output: evidence/soak-24h-laptop/ (relative to REPO_ROOT).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/evidence/soak-24h-laptop"
mkdir -p "${OUT_DIR}"

AEGIS_BIN="${AEGIS_BIN:-${REPO_ROOT}/build/aegisbpf}"
export AEGIS_BIN

export SOAK_MODE="${SOAK_MODE:-audit}"
export SOAK_NET_WORKLOAD="${SOAK_NET_WORKLOAD:-1}"
export DURATION_SECONDS="${DURATION_SECONDS:-86400}"
export WORKERS="${WORKERS:-16}"
export POLL_SECONDS="${POLL_SECONDS:-5}"
export MAX_RINGBUF_DROPS="${MAX_RINGBUF_DROPS:-2000}"
export MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-131072}"
export MAX_EVENT_DROP_RATIO_PCT="${MAX_EVENT_DROP_RATIO_PCT:-0.1}"
export MIN_TOTAL_DECISIONS="${MIN_TOTAL_DECISIONS:-100}"
export OUT_JSON="${OUT_DIR}/soak_summary.json"

START_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
echo "${START_UTC}" > "${OUT_DIR}/start_utc.txt"

echo "=== AegisBPF laptop soak ==="
echo "commit     $(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
echo "host       $(uname -n)"
echo "kernel     $(uname -r)"
echo "lsm        $(cat /sys/kernel/security/lsm)"
echo "duration   ${DURATION_SECONDS}s"
echo "workers    ${WORKERS}"
echo "mode       ${SOAK_MODE}"
echo "net        ${SOAK_NET_WORKLOAD}"
echo "out        ${OUT_DIR}"
echo "start      ${START_UTC}"
echo "============================"

cd "${REPO_ROOT}"

# Run the underlying reliability harness, tee log.
{
  "${REPO_ROOT}/scripts/soak_reliability.sh"
} 2>&1 | tee "${OUT_DIR}/soak.log"
SOAK_EXIT=${PIPESTATUS[0]}

FINISH_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
echo "${FINISH_UTC}" > "${OUT_DIR}/finish_utc.txt"
echo "${SOAK_EXIT}" > "${OUT_DIR}/exit_code.txt"

free -m > "${OUT_DIR}/memory-end.txt" || true

echo "=== Soak finished at ${FINISH_UTC} (exit ${SOAK_EXIT}) ==="
exit "${SOAK_EXIT}"
