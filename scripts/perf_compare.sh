#!/usr/bin/env bash
set -euo pipefail

FILE="${FILE:-/etc/hosts}"
ITERATIONS="${ITERATIONS:-200000}"
MAX_PCT="${MAX_PCT:-10}"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root to benchmark with the agent." >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet aegisbpf.service; then
        echo "aegisbpf.service is active; stop it before running perf_compare." >&2
        exit 1
    fi
fi

baseline=$(ITERATIONS="$ITERATIONS" FILE="$FILE" scripts/perf_open_bench.sh | awk -F= '/^us_per_op=/{print $2}')
with_agent=$(WITH_AGENT=1 ITERATIONS="$ITERATIONS" FILE="$FILE" scripts/perf_open_bench.sh | awk -F= '/^us_per_op=/{print $2}')

python3 - <<PY
import os

baseline = float("$baseline")
with_agent = float("$with_agent")
delta = with_agent - baseline
pct = (delta / baseline) * 100 if baseline else 0.0

print(f"baseline_us_per_op={baseline:.2f}")
print(f"with_agent_us_per_op={with_agent:.2f}")
print(f"delta_us_per_op={delta:.2f}")
print(f"delta_pct={pct:.2f}")

max_pct = float("$MAX_PCT" or 0)
if max_pct > 0 and pct > max_pct:
    raise SystemExit(1)
PY
