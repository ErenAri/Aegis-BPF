#!/usr/bin/env bash
set -euo pipefail

BIN="${AEGIS_BIN:-./build/aegisbpf}"
TARGET="${AEGIS_DEMO_TARGET:-/tmp/aegisbpf-demo-breakglass}"
AGENT_LOG="${AEGIS_DEMO_AGENT_LOG:-/tmp/aegisbpf-demo-breakglass.log}"
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
  "${BIN}" emergency-enable --reason "cleanup" >/dev/null 2>&1 || true
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
  exit 1
fi

echo "secret" > "${TARGET}"
chmod 600 "${TARGET}"

"${BIN}" run --enforce --enforce-signal=none --log=stdout --log-format=json >"${AGENT_LOG}" 2>&1 &
AGENT_PID="$!"
sleep 2

"${BIN}" block add "${TARGET}"

if cat "${TARGET}" >/dev/null 2>&1; then
  echo "failure: initial block failed" >&2
  exit 1
fi

echo "blocked as expected"

"${BIN}" emergency-disable --reason "demo"
sleep 1

if cat "${TARGET}" >/dev/null 2>&1; then
  echo "success: breakglass restored access"
else
  echo "failure: breakglass did not restore access" >&2
  exit 1
fi

echo "agent log: ${AGENT_LOG}"
