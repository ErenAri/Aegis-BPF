#!/usr/bin/env bash
set -euo pipefail

BIN="${AEGIS_BIN:-./build/aegisbpf}"
AGENT_LOG="${AEGIS_DEMO_AGENT_LOG:-/tmp/aegisbpf-demo-net-agent.log}"
AGENT_PID=""
TARGET_IP="${AEGIS_DEMO_IP:-1.1.1.1}"
TARGET_PORT="${AEGIS_DEMO_PORT:-80}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "run as root: sudo $0" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  "${BIN}" network deny del --ip "${TARGET_IP}" >/dev/null 2>&1 || true
  if [[ -n "${AGENT_PID}" ]]; then
    kill "${AGENT_PID}" >/dev/null 2>&1 || true
    wait "${AGENT_PID}" >/dev/null 2>&1 || true
  fi
}

require_root
trap cleanup EXIT

if [[ ! -x "${BIN}" ]]; then
  echo "missing executable: ${BIN}" >&2
  exit 1
fi

if curl -m 3 "http://${TARGET_IP}:${TARGET_PORT}" >/dev/null 2>&1; then
  echo "baseline: network reachable"
else
  echo "baseline: network unreachable (still proceeding)"
fi

"${BIN}" run --enforce --enforce-signal=none --log=stdout --log-format=json >"${AGENT_LOG}" 2>&1 &
AGENT_PID="$!"
sleep 2

"${BIN}" network deny add --ip "${TARGET_IP}"

if curl -m 3 "http://${TARGET_IP}:${TARGET_PORT}" >/dev/null 2>&1; then
  echo "failure: network was not blocked" >&2
  exit 1
fi

echo "success: network blocked by AegisBPF"
echo "agent log: ${AGENT_LOG}"
