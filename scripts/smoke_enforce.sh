#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"
ENFORCE_SIGNAL="${ENFORCE_SIGNAL:-term}"

case "${ENFORCE_SIGNAL}" in
term)
    EXPECTED_ACTION="TERM"
    ;;
kill)
    EXPECTED_ACTION="KILL"
    ;;
int)
    EXPECTED_ACTION="INT"
    ;;
none)
    EXPECTED_ACTION="BLOCK"
    ;;
*)
    echo "Unsupported ENFORCE_SIGNAL: ${ENFORCE_SIGNAL} (expected one of: term, kill, int, none)" >&2
    exit 1
    ;;
esac

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
    echo "BPF LSM is not enabled; enforce smoke test is not applicable." >&2
    exit 0
fi

TMPFILE=$(mktemp)
LOGFILE=$(mktemp)
INO=$(stat -c %i "$TMPFILE")

echo "[*] Starting agent (enforce mode)..."
"$BIN" run --enforce --enforce-signal="${ENFORCE_SIGNAL}" >"$LOGFILE" 2>&1 &
AGENT_PID=$!
echo "[*] Agent PID: $AGENT_PID"
sleep 2
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "[!] Agent failed to start; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi
echo "[*] Agent is running"

echo "[*] Blocking $TMPFILE (enforce expected)"
# Add timeout to prevent indefinite hangs
if command -v timeout >/dev/null 2>&1; then
    timeout 30 "$BIN" block add "$TMPFILE" || {
        echo "[!] block add command timed out or failed (exit code: $?)" >&2
        exit 1
    }
else
    "$BIN" block add "$TMPFILE" || {
        echo "[!] block add command failed (exit code: $?)" >&2
        exit 1
    }
fi

echo "[*] Attempting access (should be blocked)..."
set +e
cat "$TMPFILE" >/dev/null 2>&1
status=$?
set -e
if [[ $status -eq 0 ]]; then
    echo "[!] Expected enforce block but cat succeeded" >&2
    exit 1
fi

sleep 1
if ! grep -q "\"action\":\"${EXPECTED_ACTION}\"" "$LOGFILE"; then
    echo "[!] Expected ${EXPECTED_ACTION} event but none found; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi
if ! grep -q "\"ino\":$INO" "$LOGFILE"; then
    echo "[!] Expected inode $INO in block event; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi

echo "[*] Stats after attempt:"
"$BIN" stats || true

echo "[+] Enforce smoke test passed. Agent log at $LOGFILE"
