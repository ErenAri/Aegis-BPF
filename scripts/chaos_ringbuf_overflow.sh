#!/usr/bin/env bash
set -euo pipefail

AEGIS_BIN="${AEGIS_BIN:-./build/aegisbpf}"
RINGBUF_BYTES="${RINGBUF_BYTES:-4096}"
EVENT_SAMPLE_RATE="${EVENT_SAMPLE_RATE:-1}"
WORKERS="${WORKERS:-8}"
DURATION_SECONDS="${DURATION_SECONDS:-10}"
TARGET_DROPS="${TARGET_DROPS:-1}"
OUT_JSON="${OUT_JSON:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "chaos_ringbuf_overflow.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "${AEGIS_BIN}" ]]; then
  echo "aegisbpf binary not found or not executable: ${AEGIS_BIN}" >&2
  exit 1
fi

for var in RINGBUF_BYTES EVENT_SAMPLE_RATE WORKERS DURATION_SECONDS TARGET_DROPS; do
  if ! [[ "${!var}" =~ ^[0-9]+$ ]]; then
    echo "${var} must be numeric" >&2
    exit 1
  fi
done

LOG_DIR="$(mktemp -d /tmp/aegisbpf-chaos-XXXXXX)"
DAEMON_LOG="${LOG_DIR}/daemon.log"
WORKER_PIDS=()
DAEMON_PID=""

cleanup() {
  set +e
  for wp in "${WORKER_PIDS[@]:-}"; do
    kill "${wp}" >/dev/null 2>&1
  done
  if [[ -n "${DAEMON_PID}" ]]; then
    kill -INT "${DAEMON_PID}" >/dev/null 2>&1
    wait "${DAEMON_PID}" >/dev/null 2>&1
  fi
  rm -rf "${LOG_DIR}"
  set -e
}
trap cleanup EXIT

echo "starting daemon (ringbuf=${RINGBUF_BYTES} bytes, sample_rate=${EVENT_SAMPLE_RATE})"
"${AEGIS_BIN}" run --audit --ringbuf-bytes="${RINGBUF_BYTES}" \
  --event-sample-rate="${EVENT_SAMPLE_RATE}" >"${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
sleep 1

if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
  echo "daemon failed to start" >&2
  cat "${DAEMON_LOG}" >&2 || true
  exit 1
fi

# Ensure high-volume events by denying a hot path (audit mode still emits events).
"${AEGIS_BIN}" block add /etc/hosts >/dev/null 2>&1 || true

for _ in $(seq 1 "${WORKERS}"); do
  (
    while kill -0 "${DAEMON_PID}" >/dev/null 2>&1; do
      cat /etc/hosts >/dev/null 2>&1 || true
    done
  ) &
  WORKER_PIDS+=("$!")
done

MAX_DROPS=0
END_TS=$((SECONDS + DURATION_SECONDS))

while [[ ${SECONDS} -lt ${END_TS} ]]; do
  if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    echo "daemon exited during chaos run" >&2
    cat "${DAEMON_LOG}" >&2 || true
    exit 1
  fi

  METRICS="$("${AEGIS_BIN}" metrics 2>/dev/null || true)"
  DROPS="$(awk '$1=="aegisbpf_ringbuf_drops_total" {print $2; exit}' <<<"${METRICS}")"
  DROPS="${DROPS:-0}"
  if [[ "${DROPS}" =~ ^[0-9]+$ && "${DROPS}" -gt "${MAX_DROPS}" ]]; then
    MAX_DROPS="${DROPS}"
  fi
  if [[ "${MAX_DROPS}" -ge "${TARGET_DROPS}" ]]; then
    break
  fi
  sleep 1
done

PASS=0
if [[ "${MAX_DROPS}" -ge "${TARGET_DROPS}" ]]; then
  PASS=1
fi

echo "max ringbuf drops observed: ${MAX_DROPS} (target >= ${TARGET_DROPS})"

if [[ -n "${OUT_JSON}" ]]; then
  python3 - <<PY
import json

payload = {
    "ringbuf_bytes": int("${RINGBUF_BYTES}"),
    "event_sample_rate": int("${EVENT_SAMPLE_RATE}"),
    "workers": int("${WORKERS}"),
    "duration_seconds": int("${DURATION_SECONDS}"),
    "target_drops": int("${TARGET_DROPS}"),
    "max_drops": int("${MAX_DROPS}"),
    "pass": bool(int("${PASS}")),
}
with open("${OUT_JSON}", "w", encoding="utf-8") as f:
    json.dump(payload, f, separators=(",", ":"))
PY
fi

if [[ "${PASS}" -ne 1 ]]; then
  echo "ringbuf drop target not reached (no overflow observed)" >&2
  exit 1
fi

echo "chaos ringbuf overflow checks passed"
