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
    echo "Must run as root (needs BPF + cgroup v2)" >&2
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

if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM is enabled; audit fallback test is not applicable." >&2
    exit 0
fi

TMPFILE=$(mktemp)
LOGFILE=$(mktemp)

echo "[*] Starting agent (tracepoint fallback)..."
"$BIN" run --enforce >"$LOGFILE" 2>&1 &
AGENT_PID=$!
sleep 1
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "[!] Agent failed to start; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi

echo "[*] Blocking $TMPFILE (audit-only expected)"
"$BIN" block add "$TMPFILE"

echo "[*] Attempting access (should be allowed but audited)..."
set +e
cat "$TMPFILE" >/dev/null 2>&1
status=$?
set -e
if [[ $status -ne 0 ]]; then
    echo "[!] Expected audit-only access but cat failed (status $status)" >&2
    exit 1
fi

sleep 1
if ! grep -q "\"action\":\"AUDIT\"" "$LOGFILE"; then
    echo "[!] Expected AUDIT event but none found; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi
if ! grep -q "\"path\":\"$TMPFILE\"" "$LOGFILE"; then
    echo "[!] Expected path $TMPFILE in audit event; log follows:" >&2
    cat "$LOGFILE" >&2
    exit 1
fi

echo "[*] Stats after attempt:"
"$BIN" stats || true

echo "[+] Audit fallback smoke test passed. Agent log at $LOGFILE"
