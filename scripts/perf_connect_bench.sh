#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"
ITERATIONS="${ITERATIONS:-50000}"
WITH_AGENT="${WITH_AGENT:-0}"
FORMAT="${FORMAT:-text}"
OUT="${OUT:-}"
HOST="${HOST:-127.0.0.1}"

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
    fi
    rm -f "${LOGFILE:-}"
}
trap cleanup EXIT

if [[ "${WITH_AGENT}" -eq 1 ]]; then
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
import json
import math
import os
import socket
import time

host = os.environ.get("HOST", "127.0.0.1")
port = int(os.environ.get("PORT", "9"))
iterations = int(os.environ.get("ITERATIONS", "50000"))
with_agent = int(os.environ.get("WITH_AGENT", "0")) == 1
fmt = os.environ.get("FORMAT", "text").lower()
out_path = os.environ.get("OUT", "")

# Use UDP connect() to benchmark connect syscall overhead without accept-thread noise.
for _ in range(1024):
    warm = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    warm.connect((host, port))
    warm.close()

samples_ns = []
start_total = time.perf_counter()
for _ in range(iterations):
    start = time.perf_counter_ns()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.connect((host, port))
    client.close()
    end = time.perf_counter_ns()
    samples_ns.append(end - start)
end_total = time.perf_counter()

samples_ns.sort()

def percentile(sorted_samples, p):
    if not sorted_samples:
        return 0.0
    idx = (len(sorted_samples) - 1) * p
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return sorted_samples[lo] / 1000.0
    frac = idx - lo
    return (sorted_samples[lo] + (sorted_samples[hi] - sorted_samples[lo]) * frac) / 1000.0

elapsed = end_total - start_total
us_per_op = (elapsed / iterations) * 1e6 if iterations else 0.0
payload = {
    "iterations": iterations,
    "seconds": round(elapsed, 6),
    "us_per_op": round(us_per_op, 2),
    "p50_us": round(percentile(samples_ns, 0.50), 2),
    "p95_us": round(percentile(samples_ns, 0.95), 2),
    "p99_us": round(percentile(samples_ns, 0.99), 2),
    "host": host,
    "port": port,
    "protocol": "udp",
    "with_agent": with_agent,
}

if fmt == "json":
    text = json.dumps(payload, separators=(",", ":"))
else:
    text = (
        f"iterations={iterations}\\n"
        f"seconds={elapsed:.6f}\\n"
        f"us_per_op={us_per_op:.2f}\\n"
        f"p50_us={payload['p50_us']:.2f}\\n"
        f"p95_us={payload['p95_us']:.2f}\\n"
        f"p99_us={payload['p99_us']:.2f}"
    )

if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text + "\\n")
print(text)
PY
