#!/usr/bin/env bash
set -euo pipefail

BIN="${AEGIS_BIN:-./build/aegisbpf}"
TARGET="${AEGIS_DEMO_TARGET:-/tmp/aegisbpf-demo-secret}"
AGENT_LOG="${AEGIS_DEMO_AGENT_LOG:-/tmp/aegisbpf-demo-file-agent.log}"
AGENT_PID=""

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "run as root: sudo $0" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  "${BIN}" block del "${TARGET}" >/dev/null 2>&1 || true
  if [[ -n "${AGENT_PID}" ]]; then
    kill "${AGENT_PID}" >/dev/null 2>&1 || true
    wait "${AGENT_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${TARGET}"
}

require_root
trap cleanup EXIT

if [[ ! -x "${BIN}" ]]; then
  echo "missing executable: ${BIN}" >&2
  echo "build first: cmake -B build -G Ninja && cmake --build build" >&2
  exit 1
fi

echo "demo-secret" > "${TARGET}"
chmod 600 "${TARGET}"

cat "${TARGET}" >/dev/null

echo "baseline: read succeeded"

"${BIN}" run --enforce --enforce-signal=none --log=stdout --log-format=json >"${AGENT_LOG}" 2>&1 &
AGENT_PID="$!"
sleep 2

"${BIN}" block add "${TARGET}"

if cat "${TARGET}" >/dev/null 2>&1; then
  echo "failure: read was not blocked" >&2
  echo "agent log: ${AGENT_LOG}" >&2
  exit 1
fi

echo "success: read was blocked by AegisBPF"
echo "agent log: ${AGENT_LOG}"
