#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
    fi
    rm -f "${TMPFILE:-}" "${LOGFILE:-}"
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root (needs BPF LSM + cgroup v2)" >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "Agent binary not found at $BIN. Build first (cmake --build build)." >&2
    exit 1
fi

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    echo "cgroup v2 is required at /sys/fs/cgroup" >&2
    exit 1
fi

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM is not enabled (missing \"bpf\" in /sys/kernel/security/lsm)" >&2
    exit 1
fi

TMPFILE=$(mktemp)
LOGFILE=$(mktemp)

echo "[*] Starting agent..."
"$BIN" run >"$LOGFILE" 2>&1 &
AGENT_PID=$!
sleep 1
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "[!] Agent failed to start; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi

echo "[*] Blocking $TMPFILE"
"$BIN" block add "$TMPFILE"

echo "[*] Attempting access (should be killed/EPERM)..."
set +e
cat "$TMPFILE" >/dev/null 2>&1
status=$?
set -e

if [[ $status -eq 0 ]]; then
    echo "[!] Expected block or kill but cat succeeded" >&2
    exit 1
else
    echo "[+] Access blocked as expected (status $status)"
fi

echo "[*] Stats after attempt:"
"$BIN" stats || true

echo "[*] Done. Agent log at $LOGFILE"
