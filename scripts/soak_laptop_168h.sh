#!/usr/bin/env bash
# Laptop-local 168h ENFORCE-mode soak wrapper for AegisBPF.
#
# Runs the hardened reliability harness in --enforce mode for 7 days with an
# in-band enforcement canary: a dedicated throwaway file is denied and a read
# of it MUST fail on every poll (any success = a missed enforcement decision =
# soak fails). Unlike the 24h audit wrapper, this overrides SOAK_BLOCK_PATH to
# a private canary file so enforce mode never denies a system path (e.g.
# /etc/hosts) host-wide.
#
# Meant to run under `systemd-inhibit` + `setsid` (as root) so a 7-day run
# survives lid-close / idle suspend / this shell exiting.
#
# Output: evidence/soak-168h-laptop/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/evidence/soak-168h-laptop"
mkdir -p "${OUT_DIR}"

# Dedicated enforce canary (NOT a system file). Denying reads of this is inert.
CANARY="${SOAK_BLOCK_PATH:-/var/tmp/aegis-soak-canary}"
printf 'aegisbpf enforce soak canary\n' > "${CANARY}"
chmod 0644 "${CANARY}"

export AEGIS_BIN="${AEGIS_BIN:-${REPO_ROOT}/build/aegisbpf}"
export SOAK_MODE="enforce"
export SOAK_ENFORCE_SIGNAL="${SOAK_ENFORCE_SIGNAL:-none}"   # EPERM only, no signal to readers
export SOAK_BLOCK_PATH="${CANARY}"
export SOAK_NET_WORKLOAD="${SOAK_NET_WORKLOAD:-1}"
export DURATION_SECONDS="${DURATION_SECONDS:-604800}"       # 168h
export WORKERS="${WORKERS:-16}"
export POLL_SECONDS="${POLL_SECONDS:-10}"
# Telemetry-drop gates are intentionally neutralized: the workers read the
# canary in a tight loop (millions/sec), which saturates the ringbuf by design.
# Under this synthetic hammer, dropped *telemetry* events are expected and the
# ENFORCEMENT decision (-EPERM) is decoupled from event emission — proven
# independently in evidence/backpressure-saturation-laptop/. Over 168h the
# cumulative drop counter is astronomically large and meaningless as a gate.
# This soak is gated on what matters: enforcement-canary misses (must be 0),
# RSS growth (must stay within budget), and daemon survival.
export MAX_RINGBUF_DROPS="${MAX_RINGBUF_DROPS:-100000000000}"   # effectively off (see note above)
export MAX_EVENT_DROP_RATIO_PCT="${MAX_EVENT_DROP_RATIO_PCT:-100}"  # effectively off (see note above)
export MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-131072}"         # 128 MiB budget over 7 days — REAL gate
export MIN_TOTAL_DECISIONS="${MIN_TOTAL_DECISIONS:-1000}"
export OUT_JSON="${OUT_DIR}/soak_summary.json"

START_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
echo "${START_UTC}" > "${OUT_DIR}/start_utc.txt"
git -C "${REPO_ROOT}" rev-parse HEAD > "${OUT_DIR}/commit.txt"
"${AEGIS_BIN}" --version > "${OUT_DIR}/version.txt" 2>&1 || true
uname -a > "${OUT_DIR}/kernel.txt"
cat /sys/kernel/security/lsm > "${OUT_DIR}/lsm.txt" 2>/dev/null || true
lscpu > "${OUT_DIR}/cpu.txt" 2>/dev/null || true
cat /etc/os-release > "${OUT_DIR}/os-release.txt" 2>/dev/null || true
free -m > "${OUT_DIR}/memory-start.txt" || true

echo "=== AegisBPF laptop 168h ENFORCE soak ==="
echo "commit    $(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
echo "version   $(cat "${OUT_DIR}/version.txt")"
echo "kernel    $(uname -r)"
echo "lsm       $(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "canary    ${CANARY}  (enforce-signal=${SOAK_ENFORCE_SIGNAL})"
echo "duration  ${DURATION_SECONDS}s (168h)  workers ${WORKERS}  net ${SOAK_NET_WORKLOAD}"
echo "out       ${OUT_DIR}"
echo "start     ${START_UTC}"
echo "=========================================="

cd "${REPO_ROOT}"
{ "${REPO_ROOT}/scripts/soak_reliability.sh"; } 2>&1 | tee "${OUT_DIR}/soak.log"
SOAK_EXIT=${PIPESTATUS[0]}

FINISH_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
echo "${FINISH_UTC}" > "${OUT_DIR}/finish_utc.txt"
echo "${SOAK_EXIT}" > "${OUT_DIR}/exit_code.txt"
free -m > "${OUT_DIR}/memory-end.txt" || true
rm -f "${CANARY}" || true
echo "=== 168h soak finished at ${FINISH_UTC} (exit ${SOAK_EXIT}) ==="
exit "${SOAK_EXIT}"
