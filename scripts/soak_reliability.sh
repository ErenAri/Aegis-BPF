#!/usr/bin/env bash
set -euo pipefail

AEGIS_BIN="${AEGIS_BIN:-./build/aegisbpf}"
DURATION_SECONDS="${DURATION_SECONDS:-300}"
WORKERS="${WORKERS:-4}"
POLL_SECONDS="${POLL_SECONDS:-5}"
MAX_RINGBUF_DROPS="${MAX_RINGBUF_DROPS:-1000}"
MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-65536}"
RINGBUF_BYTES="${RINGBUF_BYTES:-16777216}"
MAX_EVENT_DROP_RATIO_PCT="${MAX_EVENT_DROP_RATIO_PCT:-0.1}"
MIN_TOTAL_DECISIONS="${MIN_TOTAL_DECISIONS:-100}"
SOAK_GENERATE_BLOCK_EVENTS="${SOAK_GENERATE_BLOCK_EVENTS:-1}"
SOAK_BLOCK_PATH="${SOAK_BLOCK_PATH:-/etc/hosts}"
SOAK_SUMMARY_OUT="${SOAK_SUMMARY_OUT:-}"
OUT_JSON="${OUT_JSON:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "soak_reliability.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "${AEGIS_BIN}" ]]; then
  echo "aegisbpf binary not found or not executable: ${AEGIS_BIN}" >&2
  exit 1
fi

if ! [[ "${DURATION_SECONDS}" =~ ^[0-9]+$ && "${POLL_SECONDS}" =~ ^[0-9]+$ && "${WORKERS}" =~ ^[0-9]+$ ]]; then
  echo "DURATION_SECONDS, POLL_SECONDS, and WORKERS must be numeric" >&2
  exit 1
fi

if ! [[ "${MAX_RINGBUF_DROPS}" =~ ^[0-9]+$ && "${MAX_RSS_GROWTH_KB}" =~ ^[0-9]+$ ]]; then
  echo "MAX_RINGBUF_DROPS and MAX_RSS_GROWTH_KB must be numeric" >&2
  exit 1
fi

if ! [[ "${MAX_EVENT_DROP_RATIO_PCT}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "MAX_EVENT_DROP_RATIO_PCT must be numeric (for example 0.1)" >&2
  exit 1
fi

if ! [[ "${MIN_TOTAL_DECISIONS}" =~ ^[0-9]+$ ]]; then
  echo "MIN_TOTAL_DECISIONS must be numeric" >&2
  exit 1
fi

if [[ "${SOAK_GENERATE_BLOCK_EVENTS}" != "0" && "${SOAK_GENERATE_BLOCK_EVENTS}" != "1" ]]; then
  echo "SOAK_GENERATE_BLOCK_EVENTS must be 0 or 1" >&2
  exit 1
fi

if [[ -z "${SOAK_BLOCK_PATH}" || "${SOAK_BLOCK_PATH}" != /* ]]; then
  echo "SOAK_BLOCK_PATH must be an absolute path" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d)" || { echo "Failed to create temp directory" >&2; exit 1; }
DAEMON_LOG="${LOG_DIR}/daemon.log"
WORKLOAD_LOG="${LOG_DIR}/workload.log"
WORKER_PIDS=()
DAEMON_PID=""
BLOCK_RULE_ADDED=0

cleanup() {
  set +e
  for wp in "${WORKER_PIDS[@]:-}"; do
    kill "${wp}" >/dev/null 2>&1
  done
  if [[ "${BLOCK_RULE_ADDED}" == "1" ]]; then
    "${AEGIS_BIN}" block del "${SOAK_BLOCK_PATH}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${DAEMON_PID}" ]]; then
    kill -INT "${DAEMON_PID}" >/dev/null 2>&1
    wait "${DAEMON_PID}" >/dev/null 2>&1
  fi
  set -e
}
trap cleanup EXIT

echo "starting daemon for soak test (duration=${DURATION_SECONDS}s workers=${WORKERS})"
if [[ "${SOAK_GENERATE_BLOCK_EVENTS}" == "1" ]]; then
  # Pre-seed the deny rule before daemon startup so audit-mode hook optimization
  # does not skip file hooks due an empty-policy hint.
  if "${AEGIS_BIN}" block add "${SOAK_BLOCK_PATH}" >/dev/null 2>&1; then
    BLOCK_RULE_ADDED=1
    echo "preloaded temporary soak block rule: ${SOAK_BLOCK_PATH}"
  else
    echo "failed to preload temporary soak block rule: ${SOAK_BLOCK_PATH}" >&2
    exit 1
  fi
fi

"${AEGIS_BIN}" run --audit --ringbuf-bytes="${RINGBUF_BYTES}" >"${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
sleep 2

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
  ) >>"${WORKLOAD_LOG}" 2>&1 &
  WORKER_PIDS+=("$!")
done

read_rss_kb() {
  awk '/VmRSS:/ { print $2; found=1 } END { if (!found) print 0 }' "/proc/${DAEMON_PID}/status"
}

read_metric_sum() {
  local metric="$1"
  local metrics_text="$2"
  awk -v metric="${metric}" '
    $1 == metric || index($1, metric "{") == 1 { sum += $2 }
    END { printf "%.0f\n", sum + 0 }
  ' <<<"${metrics_text}"
}

calc_drop_ratio_pct() {
  local total_drops="$1"
  local total_decisions="$2"
  python3 - "${total_drops}" "${total_decisions}" <<'PY'
import sys

drops = float(sys.argv[1])
decisions = float(sys.argv[2])
total = drops + decisions
ratio = 0.0 if total <= 0 else (drops * 100.0 / total)
print(f"{ratio:.6f}")
PY
}

float_gt() {
  local left="$1"
  local right="$2"
  python3 - "${left}" "${right}" <<'PY'
import sys

sys.exit(0 if float(sys.argv[1]) > float(sys.argv[2]) else 1)
PY
}

INITIAL_RSS="$(read_rss_kb)"
MAX_RSS="${INITIAL_RSS}"
MAX_DROPS=0
MAX_FILE_DROPS=0
MAX_NET_DROPS=0
MAX_TOTAL_DECISIONS=0
MAX_TOTAL_EVENTS=0
MAX_DROP_RATIO_PCT="0.000000"
END_TS=$((SECONDS + DURATION_SECONDS))

echo "initial RSS: ${INITIAL_RSS} kB"

while [[ ${SECONDS} -lt ${END_TS} ]]; do
  if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    echo "daemon exited early during soak" >&2
    cat "${DAEMON_LOG}" >&2 || true
    exit 1
  fi

  RSS="$(read_rss_kb)"
  if [[ "${RSS}" -gt "${MAX_RSS}" ]]; then
    MAX_RSS="${RSS}"
  fi

  METRICS="$("${AEGIS_BIN}" metrics 2>/dev/null || true)"
  FILE_BLOCKS="$(read_metric_sum "aegisbpf_blocks_total" "${METRICS}")"
  NET_CONNECT_BLOCKS="$(read_metric_sum "aegisbpf_net_connect_blocks_total" "${METRICS}")"
  NET_BIND_BLOCKS="$(read_metric_sum "aegisbpf_net_bind_blocks_total" "${METRICS}")"
  FILE_DROPS="$(read_metric_sum "aegisbpf_ringbuf_drops_total" "${METRICS}")"
  NET_DROPS="$(read_metric_sum "aegisbpf_net_ringbuf_drops_total" "${METRICS}")"
  TOTAL_DECISIONS=$((FILE_BLOCKS + NET_CONNECT_BLOCKS + NET_BIND_BLOCKS))
  TOTAL_DROPS=$((FILE_DROPS + NET_DROPS))
  TOTAL_EVENTS=$((TOTAL_DECISIONS + TOTAL_DROPS))

  if [[ "${TOTAL_DROPS}" -gt "${MAX_DROPS}" ]]; then
    MAX_DROPS="${TOTAL_DROPS}"
  fi
  if [[ "${FILE_DROPS}" -gt "${MAX_FILE_DROPS}" ]]; then
    MAX_FILE_DROPS="${FILE_DROPS}"
  fi
  if [[ "${NET_DROPS}" -gt "${MAX_NET_DROPS}" ]]; then
    MAX_NET_DROPS="${NET_DROPS}"
  fi
  if [[ "${TOTAL_DECISIONS}" -gt "${MAX_TOTAL_DECISIONS}" ]]; then
    MAX_TOTAL_DECISIONS="${TOTAL_DECISIONS}"
  fi
  if [[ "${TOTAL_EVENTS}" -gt "${MAX_TOTAL_EVENTS}" ]]; then
    MAX_TOTAL_EVENTS="${TOTAL_EVENTS}"
  fi

  DROP_RATIO_PCT="$(calc_drop_ratio_pct "${TOTAL_DROPS}" "${TOTAL_DECISIONS}")"
  if float_gt "${DROP_RATIO_PCT}" "${MAX_DROP_RATIO_PCT}"; then
    MAX_DROP_RATIO_PCT="${DROP_RATIO_PCT}"
  fi

  sleep "${POLL_SECONDS}"
done

RSS_GROWTH=$((MAX_RSS - INITIAL_RSS))

echo "max RSS: ${MAX_RSS} kB (growth=${RSS_GROWTH} kB)"
echo "max ringbuf drops: ${MAX_DROPS} (file=${MAX_FILE_DROPS}, net=${MAX_NET_DROPS})"
echo "max observed decision events: ${MAX_TOTAL_DECISIONS}"
echo "max observed total events (decisions + drops): ${MAX_TOTAL_EVENTS}"
echo "max observed drop ratio: ${MAX_DROP_RATIO_PCT}% (target <= ${MAX_EVENT_DROP_RATIO_PCT}%)"

if [[ -n "${OUT_JSON}" ]]; then
  python3 - <<PY
import json

payload = {
    "duration_seconds": int("${DURATION_SECONDS}"),
    "workers": int("${WORKERS}"),
    "poll_seconds": int("${POLL_SECONDS}"),
    "ringbuf_bytes": int("${RINGBUF_BYTES}"),
    "initial_rss_kb": int("${INITIAL_RSS}"),
    "max_rss_kb": int("${MAX_RSS}"),
    "rss_growth_kb": int("${RSS_GROWTH}"),
    "max_ringbuf_drops_total": int("${MAX_DROPS}"),
    "max_ringbuf_drops_file": int("${MAX_FILE_DROPS}"),
    "max_ringbuf_drops_net": int("${MAX_NET_DROPS}"),
    "max_decision_events": int("${MAX_TOTAL_DECISIONS}"),
    "max_total_events": int("${MAX_TOTAL_EVENTS}"),
    "max_drop_ratio_pct": float("${MAX_DROP_RATIO_PCT}"),
    "max_allowed_drops": int("${MAX_RINGBUF_DROPS}"),
    "max_allowed_rss_growth_kb": int("${MAX_RSS_GROWTH_KB}"),
    "max_allowed_drop_ratio_pct": float("${MAX_EVENT_DROP_RATIO_PCT}"),
    "min_total_decisions": int("${MIN_TOTAL_DECISIONS}"),
    "pass": (${RSS_GROWTH} <= ${MAX_RSS_GROWTH_KB}
             and ${MAX_DROPS} <= ${MAX_RINGBUF_DROPS}
             and ${MAX_TOTAL_DECISIONS} >= ${MIN_TOTAL_DECISIONS}
             and float("${MAX_DROP_RATIO_PCT}") <= float("${MAX_EVENT_DROP_RATIO_PCT}")),
}
with open("${OUT_JSON}", "w", encoding="utf-8") as f:
    json.dump(payload, f, separators=(",", ":"))
PY
fi

if [[ "${RSS_GROWTH}" -gt "${MAX_RSS_GROWTH_KB}" ]]; then
  echo "RSS growth exceeded threshold (${RSS_GROWTH} > ${MAX_RSS_GROWTH_KB})" >&2
  exit 1
fi

if [[ "${MAX_DROPS}" -gt "${MAX_RINGBUF_DROPS}" ]]; then
  echo "ringbuf drops exceeded threshold (${MAX_DROPS} > ${MAX_RINGBUF_DROPS})" >&2
  exit 1
fi

if [[ "${MAX_TOTAL_DECISIONS}" -lt "${MIN_TOTAL_DECISIONS}" ]]; then
  echo "insufficient decision-event volume (${MAX_TOTAL_DECISIONS} < ${MIN_TOTAL_DECISIONS})" >&2
  exit 1
fi

if float_gt "${MAX_DROP_RATIO_PCT}" "${MAX_EVENT_DROP_RATIO_PCT}"; then
  echo "event drop ratio exceeded threshold (${MAX_DROP_RATIO_PCT}% > ${MAX_EVENT_DROP_RATIO_PCT}%)" >&2
  exit 1
fi

if [[ -n "${SOAK_SUMMARY_OUT}" ]]; then
  python3 - "${SOAK_SUMMARY_OUT}" \
    "${INITIAL_RSS}" "${MAX_RSS}" "${RSS_GROWTH}" \
    "${MAX_DROPS}" "${MAX_FILE_DROPS}" "${MAX_NET_DROPS}" \
    "${MAX_TOTAL_DECISIONS}" "${MAX_TOTAL_EVENTS}" \
    "${MAX_DROP_RATIO_PCT}" "${MAX_EVENT_DROP_RATIO_PCT}" <<'PY'
import json
import pathlib
import sys

out_path = pathlib.Path(sys.argv[1])
payload = {
    "initial_rss_kb": int(sys.argv[2]),
    "max_rss_kb": int(sys.argv[3]),
    "rss_growth_kb": int(sys.argv[4]),
    "max_ringbuf_drops_total": int(sys.argv[5]),
    "max_ringbuf_drops_file": int(sys.argv[6]),
    "max_ringbuf_drops_net": int(sys.argv[7]),
    "max_decision_events": int(sys.argv[8]),
    "max_total_events": int(sys.argv[9]),
    "max_drop_ratio_pct": float(sys.argv[10]),
    "drop_ratio_target_pct": float(sys.argv[11]),
}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

echo "soak reliability checks passed"
