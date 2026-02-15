#!/usr/bin/env bash
set -euo pipefail

FILE="${FILE:-/etc/hosts}"
ITERATIONS="${ITERATIONS:-200000}"
MAX_PCT="${MAX_PCT:-10}"
REPEATS="${REPEATS:-3}"
BIN="${BIN:-./build/aegisbpf}"
OUT_JSON="${OUT_JSON:-}"

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

# Keep self-hosted runs isolated from stale pinned rules.
"$BIN" block clear >/dev/null 2>&1 || true
"$BIN" network deny clear >/dev/null 2>&1 || true

if ! [[ "$REPEATS" =~ ^[0-9]+$ ]] || [[ "$REPEATS" -lt 1 ]]; then
    echo "REPEATS must be a positive integer (got: $REPEATS)" >&2
    exit 1
fi

median() {
    printf '%s\n' "$@" | sort -n | awk '
        { a[NR] = $1 }
        END {
            n = NR
            if (n == 0) exit 1
            if (n % 2 == 1) {
                print a[(n + 1) / 2]
            } else {
                print (a[n / 2] + a[(n / 2) + 1]) / 2
            }
        }
    '
}

run_open_bench() {
    local with_agent_flag="$1"
    if [[ "$with_agent_flag" -eq 1 ]]; then
        WITH_AGENT=1 BIN="$BIN" ITERATIONS="$ITERATIONS" FILE="$FILE" scripts/perf_open_bench.sh | awk -F= '/^us_per_op=/{print $2}'
    else
        BIN="$BIN" ITERATIONS="$ITERATIONS" FILE="$FILE" scripts/perf_open_bench.sh | awk -F= '/^us_per_op=/{print $2}'
    fi
}

baseline_samples=()
with_agent_samples=()
for ((i = 0; i < REPEATS; ++i)); do
    baseline_samples+=("$(run_open_bench 0)")
    with_agent_samples+=("$(run_open_bench 1)")
done

baseline=$(median "${baseline_samples[@]}")
with_agent=$(median "${with_agent_samples[@]}")

python3 - <<PY
import os
import json

baseline = float("$baseline")
with_agent = float("$with_agent")
delta = with_agent - baseline
pct = (delta / baseline) * 100 if baseline else 0.0

print(f"baseline_us_per_op={baseline:.2f}")
print(f"with_agent_us_per_op={with_agent:.2f}")
print(f"delta_us_per_op={delta:.2f}")
print(f"delta_pct={pct:.2f}")
print(f"repeats={int('$REPEATS')}")

max_pct = float("$MAX_PCT" or 0)
passed = (max_pct <= 0) or (pct <= max_pct)

out_json = os.environ.get("OUT_JSON", "")
if out_json:
    os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
    payload = {
        "baseline_us_per_op": round(baseline, 2),
        "with_agent_us_per_op": round(with_agent, 2),
        "delta_us_per_op": round(delta, 2),
        "delta_pct": round(pct, 2),
        "max_allowed_pct": round(max_pct, 2),
        "pass": passed,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))

if max_pct > 0 and pct > max_pct:
    raise SystemExit(1)
PY
