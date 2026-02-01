#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"
FILE="${FILE:-/etc/hosts}"
ITERATIONS="${ITERATIONS:-200000}"
WITH_AGENT="${WITH_AGENT:-0}"
FORMAT="${FORMAT:-text}"
OUT="${OUT:-}"

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
    fi
    rm -f "${LOGFILE:-}"
}
trap cleanup EXIT

if [[ ! -r "$FILE" ]]; then
    echo "File not readable: $FILE" >&2
    exit 1
fi

if [[ "$WITH_AGENT" -eq 1 ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "WITH_AGENT=1 requires root (BPF + cgroup access)." >&2
        exit 1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet aegisbpf.service; then
            echo "aegisbpf.service is active; stop it before WITH_AGENT=1." >&2
            exit 1
        fi
    fi
    if [[ ! -x "$BIN" ]]; then
        echo "Agent binary not found at $BIN. Build first (cmake --build build)." >&2
        exit 1
    fi
    LOGFILE=$(mktemp)
    "$BIN" run --audit >"$LOGFILE" 2>&1 &
    AGENT_PID=$!
    sleep 1
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        echo "Agent failed to start; log follows:" >&2
        cat "$LOGFILE" >&2
        exit 1
    fi
fi

python3 - <<PY
import os
import json
import time

path = "$FILE"
iterations = int("$ITERATIONS")
with_agent = int("$WITH_AGENT") == 1
fmt = os.environ.get("FORMAT", "text").lower()
out_path = os.environ.get("OUT", "")

start = time.perf_counter()
for _ in range(iterations):
    fd = os.open(path, os.O_RDONLY)
    os.read(fd, 1)
    os.close(fd)
end = time.perf_counter()

elapsed = end - start
us_per_op = (elapsed / iterations) * 1e6
payload = {
    "iterations": iterations,
    "seconds": round(elapsed, 6),
    "us_per_op": round(us_per_op, 2),
    "file": path,
    "with_agent": with_agent,
}
if fmt == "json":
    text = json.dumps(payload, separators=(",", ":"))
else:
    text = f"iterations={iterations}\nseconds={elapsed:.6f}\nus_per_op={us_per_op:.2f}"

if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text + "\n")
print(text)
PY
