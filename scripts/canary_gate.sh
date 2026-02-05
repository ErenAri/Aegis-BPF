#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AEGIS_BIN="${AEGIS_BIN:-${ROOT_DIR}/build/aegisbpf}"
PHASE="${PHASE:-audit}" # audit|enforce
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/artifacts/canary}"
DURATION_SECONDS="${DURATION_SECONDS:-300}"
MAX_RINGBUF_DROPS="${MAX_RINGBUF_DROPS:-100}"
MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-65536}"
MAX_EVENT_DROP_RATIO_PCT="${MAX_EVENT_DROP_RATIO_PCT:-0.1}"
MIN_TOTAL_DECISIONS="${MIN_TOTAL_DECISIONS:-100}"
ENFORCE_SIGNAL="${ENFORCE_SIGNAL:-term}"
ALLOW_SIGKILL_CANARY="${ALLOW_SIGKILL_CANARY:-0}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "canary_gate.sh must run as root" >&2
    exit 1
fi

if [[ ! -x "${AEGIS_BIN}" ]]; then
    echo "aegisbpf binary not found or not executable: ${AEGIS_BIN}" >&2
    exit 1
fi

if [[ "${PHASE}" != "audit" && "${PHASE}" != "enforce" ]]; then
    echo "PHASE must be 'audit' or 'enforce' (got: ${PHASE})" >&2
    exit 1
fi

if [[ "${PHASE}" == "enforce" && "${ENFORCE_SIGNAL}" == "kill" && "${ALLOW_SIGKILL_CANARY}" != "1" ]]; then
    echo "Refusing ENFORCE_SIGNAL=kill for canary without ALLOW_SIGKILL_CANARY=1" >&2
    echo "Use ENFORCE_SIGNAL=term for staged canary validation." >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${OUT_DIR}/canary-${PHASE}-${TIMESTAMP}.log"
SOAK_SUMMARY="${OUT_DIR}/soak-${PHASE}-${TIMESTAMP}.json"

exec > >(tee "${REPORT}") 2>&1

echo "=== AegisBPF Canary Gate ==="
echo "phase=${PHASE}"
echo "timestamp=${TIMESTAMP}"
echo "binary=${AEGIS_BIN}"
echo "out_dir=${OUT_DIR}"
echo

echo "[1/5] Environment verification"
"${ROOT_DIR}/scripts/verify_env.sh" --strict

echo
echo "[2/5] Health snapshot"
"${AEGIS_BIN}" health --json | tee "${OUT_DIR}/health-${PHASE}-${TIMESTAMP}.json"
"${AEGIS_BIN}" metrics >"${OUT_DIR}/metrics-before-${PHASE}-${TIMESTAMP}.prom" 2>/dev/null || true

echo
echo "[3/5] Smoke validation"
if [[ "${PHASE}" == "audit" ]]; then
    BIN="${AEGIS_BIN}" "${ROOT_DIR}/scripts/smoke_audit.sh"
else
    BIN="${AEGIS_BIN}" ENFORCE_SIGNAL="${ENFORCE_SIGNAL}" "${ROOT_DIR}/scripts/smoke_enforce.sh"
fi

echo
echo "[4/5] Soak reliability"
AEGIS_BIN="${AEGIS_BIN}" \
DURATION_SECONDS="${DURATION_SECONDS}" \
MAX_RINGBUF_DROPS="${MAX_RINGBUF_DROPS}" \
MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB}" \
MAX_EVENT_DROP_RATIO_PCT="${MAX_EVENT_DROP_RATIO_PCT}" \
MIN_TOTAL_DECISIONS="${MIN_TOTAL_DECISIONS}" \
SOAK_SUMMARY_OUT="${SOAK_SUMMARY}" \
"${ROOT_DIR}/scripts/soak_reliability.sh"

echo
echo "[5/5] Post-run metrics snapshot"
"${AEGIS_BIN}" metrics >"${OUT_DIR}/metrics-after-${PHASE}-${TIMESTAMP}.prom" 2>/dev/null || true
"${AEGIS_BIN}" health --json >"${OUT_DIR}/health-after-${PHASE}-${TIMESTAMP}.json" 2>/dev/null || true

echo
echo "Canary gate passed."
echo "Report: ${REPORT}"
