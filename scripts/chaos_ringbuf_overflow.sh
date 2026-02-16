#!/usr/bin/env bash
set -euo pipefail

AEGIS_BIN="${AEGIS_BIN:-./build/aegisbpf}"
RINGBUF_BYTES="${RINGBUF_BYTES:-4096}"
EVENT_SAMPLE_RATE="${EVENT_SAMPLE_RATE:-1}"
WORKERS="${WORKERS:-8}"
DURATION_SECONDS="${DURATION_SECONDS:-10}"
TARGET_DROPS="${TARGET_DROPS:-1}"
FORCE_CONSUMER_PAUSE="${FORCE_CONSUMER_PAUSE:-1}"
PAUSE_SECONDS="${PAUSE_SECONDS:-2}"
CHAOS_BLOCK_PATH="${CHAOS_BLOCK_PATH:-/etc/hosts}"
OUT_JSON="${OUT_JSON:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "chaos_ringbuf_overflow.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "${AEGIS_BIN}" ]]; then
  echo "aegisbpf binary not found or not executable: ${AEGIS_BIN}" >&2
  exit 1
fi

for var in RINGBUF_BYTES EVENT_SAMPLE_RATE WORKERS DURATION_SECONDS TARGET_DROPS FORCE_CONSUMER_PAUSE PAUSE_SECONDS; do
  if ! [[ "${!var}" =~ ^[0-9]+$ ]]; then
    echo "${var} must be numeric" >&2
    exit 1
  fi
done

if [[ -z "${CHAOS_BLOCK_PATH}" || "${CHAOS_BLOCK_PATH}" != /* ]]; then
  echo "CHAOS_BLOCK_PATH must be an absolute path" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d)" || { echo "Failed to create temp directory" >&2; exit 1; }
DAEMON_LOG="${LOG_DIR}/daemon.log"
WORKER_PIDS=()
DAEMON_PID=""
BLOCK_RULE_ADDED=0

cleanup() {
  set +e
  for wp in "${WORKER_PIDS[@]:-}"; do
    kill "${wp}" >/dev/null 2>&1
  done
  if [[ "${BLOCK_RULE_ADDED}" -eq 1 ]]; then
    "${AEGIS_BIN}" block del "${CHAOS_BLOCK_PATH}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${DAEMON_PID}" ]]; then
    kill -INT "${DAEMON_PID}" >/dev/null 2>&1
    wait "${DAEMON_PID}" >/dev/null 2>&1
  fi
  rm -rf "${LOG_DIR}"
  set -e
}
trap cleanup EXIT

read_metric_sum() {
  local metric="$1"
  local metrics_text="$2"
  awk -v metric="${metric}" '
    $1 == metric || index($1, metric "{") == 1 { sum += $2 }
    END { printf "%.0f\n", sum + 0 }
  ' <<<"${metrics_text}"
}

read_totals() {
  local metrics
  metrics="$("${AEGIS_BIN}" metrics 2>/dev/null || true)"
  local file_drops net_drops file_blocks net_connect net_bind
  file_drops="$(read_metric_sum "aegisbpf_ringbuf_drops_total" "${metrics}")"
  net_drops="$(read_metric_sum "aegisbpf_net_ringbuf_drops_total" "${metrics}")"
  file_blocks="$(read_metric_sum "aegisbpf_blocks_total" "${metrics}")"
  net_connect="$(read_metric_sum "aegisbpf_net_connect_blocks_total" "${metrics}")"
  net_bind="$(read_metric_sum "aegisbpf_net_bind_blocks_total" "${metrics}")"

  FILE_DROPS="${file_drops:-0}"
  NET_DROPS="${net_drops:-0}"
  TOTAL_DROPS=$((FILE_DROPS + NET_DROPS))
  TOTAL_DECISIONS=$((file_blocks + net_connect + net_bind))
}

force_consumer_pause() {
  local seconds="$1"
  if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    return 1
  fi
  kill -STOP "${DAEMON_PID}" >/dev/null 2>&1 || return 1
  sleep "${seconds}"
  kill -CONT "${DAEMON_PID}" >/dev/null 2>&1 || true
  # Give the daemon a moment to recover and flush any pending user-space work.
  sleep 1
}

echo "preparing deny rule for chaos traffic: ${CHAOS_BLOCK_PATH}"
if "${AEGIS_BIN}" block add "${CHAOS_BLOCK_PATH}" >/dev/null 2>&1; then
  BLOCK_RULE_ADDED=1
else
  echo "failed to add deny rule for chaos traffic: ${CHAOS_BLOCK_PATH}" >&2
  exit 1
fi

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

for _ in $(seq 1 "${WORKERS}"); do
  (
    while kill -0 "${DAEMON_PID}" >/dev/null 2>&1; do
      cat /etc/hosts >/dev/null 2>&1 || true
    done
  ) &
  WORKER_PIDS+=("$!")
done

MAX_DROPS=0
MAX_FILE_DROPS=0
MAX_NET_DROPS=0
MAX_TOTAL_DECISIONS=0
END_TS=$((SECONDS + DURATION_SECONDS))

if [[ "${FORCE_CONSUMER_PAUSE}" -eq 1 ]]; then
  echo "forcing temporary daemon pause to create ringbuf pressure (${PAUSE_SECONDS}s)"
  if ! force_consumer_pause "${PAUSE_SECONDS}"; then
    echo "[!] failed to pause/resume daemon for overflow pressure test" >&2
  fi
fi

while [[ ${SECONDS} -lt ${END_TS} ]]; do
  if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    echo "daemon exited during chaos run" >&2
    cat "${DAEMON_LOG}" >&2 || true
    exit 1
  fi

  read_totals
  if [[ "${TOTAL_DROPS}" =~ ^[0-9]+$ && "${TOTAL_DROPS}" -gt "${MAX_DROPS}" ]]; then
    MAX_DROPS="${TOTAL_DROPS}"
  fi
  if [[ "${FILE_DROPS}" =~ ^[0-9]+$ && "${FILE_DROPS}" -gt "${MAX_FILE_DROPS}" ]]; then
    MAX_FILE_DROPS="${FILE_DROPS}"
  fi
  if [[ "${NET_DROPS}" =~ ^[0-9]+$ && "${NET_DROPS}" -gt "${MAX_NET_DROPS}" ]]; then
    MAX_NET_DROPS="${NET_DROPS}"
  fi
  if [[ "${TOTAL_DECISIONS}" =~ ^[0-9]+$ && "${TOTAL_DECISIONS}" -gt "${MAX_TOTAL_DECISIONS}" ]]; then
    MAX_TOTAL_DECISIONS="${TOTAL_DECISIONS}"
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

echo "max ringbuf drops observed: ${MAX_DROPS} (file=${MAX_FILE_DROPS}, net=${MAX_NET_DROPS}; target >= ${TARGET_DROPS})"
echo "max decision events observed: ${MAX_TOTAL_DECISIONS}"

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
    "max_file_drops": int("${MAX_FILE_DROPS}"),
    "max_net_drops": int("${MAX_NET_DROPS}"),
    "max_decisions": int("${MAX_TOTAL_DECISIONS}"),
    "force_consumer_pause": bool(int("${FORCE_CONSUMER_PAUSE}")),
    "pause_seconds": int("${PAUSE_SECONDS}"),
    "pass": bool(int("${PASS}")),
}
with open("${OUT_JSON}", "w", encoding="utf-8") as f:
    json.dump(payload, f, separators=(",", ":"))
PY
fi

if [[ "${PASS}" -ne 1 ]]; then
  echo "ringbuf drop target not reached (no overflow observed)" >&2
  echo "recent daemon log:" >&2
  tail -n 80 "${DAEMON_LOG}" >&2 || true
  exit 1
fi

echo "chaos ringbuf overflow checks passed"
