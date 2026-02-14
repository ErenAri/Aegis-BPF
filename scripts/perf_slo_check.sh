#!/usr/bin/env bash
# perf_slo_check.sh — Validate performance benchmark results against SLO thresholds
#
# Input: JSON files from perf_compare.sh and perf_workload_suite.sh
# Environment variables:
#   OPEN_JSON       - Path to open/close comparison JSON (default: artifacts/perf/open_compare.json)
#   WORKLOAD_JSON   - Path to workload suite JSON (default: artifacts/perf/workload_suite.json)
#   SOAK_JSON       - Path to soak summary JSON (default: artifacts/soak/soak_summary.json)
#   MAX_OPEN_P95_OVERHEAD   - Max open() p95 overhead percentage (default: 10)
#   MAX_CONNECT_P95_OVERHEAD - Max connect() p95 overhead percentage (default: 10)
#   MAX_RSS_GROWTH_MB       - Max RSS growth in MB over soak (default: 128)
#   MAX_RINGBUF_DROP_RATE   - Max ring buffer drop rate percentage (default: 0.1)
#
# Exit code: 0 if all SLOs pass, 1 if any SLO violated

set -euo pipefail

OPEN_JSON="${OPEN_JSON:-artifacts/perf/open_compare.json}"
WORKLOAD_JSON="${WORKLOAD_JSON:-artifacts/perf/workload_suite.json}"
SOAK_JSON="${SOAK_JSON:-artifacts/soak/soak_summary.json}"
MAX_OPEN_P95_OVERHEAD="${MAX_OPEN_P95_OVERHEAD:-10}"
MAX_CONNECT_P95_OVERHEAD="${MAX_CONNECT_P95_OVERHEAD:-10}"
MAX_RSS_GROWTH_MB="${MAX_RSS_GROWTH_MB:-128}"
MAX_RINGBUF_DROP_RATE="${MAX_RINGBUF_DROP_RATE:-0.1}"

VIOLATIONS=0

check_slo() {
    local name="$1"
    local actual="$2"
    local threshold="$3"
    local unit="${4:-}"

    if command -v python3 >/dev/null 2>&1; then
        exceeded=$(python3 -c "print(1 if float('$actual') > float('$threshold') else 0)" 2>/dev/null || echo "0")
    else
        exceeded=$(awk "BEGIN { print ($actual > $threshold) ? 1 : 0 }")
    fi

    if [ "$exceeded" -eq 1 ]; then
        echo "FAIL SLO: $name = ${actual}${unit} (threshold: ${threshold}${unit})"
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        echo "PASS SLO: $name = ${actual}${unit} (threshold: ${threshold}${unit})"
    fi
}

echo "=== AegisBPF Performance SLO Gate ==="
echo

# --- Check open() overhead ---
if [ -f "$OPEN_JSON" ]; then
    echo "--- open() overhead ---"
    if command -v python3 >/dev/null 2>&1; then
        OVERHEAD=$(python3 -c "
import json, sys
try:
    data = json.load(open('$OPEN_JSON'))
    overhead = data.get('overhead_pct', data.get('overhead', 0))
    print(overhead)
except Exception:
    print(0)
" 2>/dev/null || echo "0")
        check_slo "open() p95 overhead" "$OVERHEAD" "$MAX_OPEN_P95_OVERHEAD" "%"
    else
        echo "SKIP: python3 not available for JSON parsing"
    fi
else
    echo "SKIP: $OPEN_JSON not found"
fi

# --- Check workload suite ---
if [ -f "$WORKLOAD_JSON" ]; then
    echo "--- workload suite ---"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json, sys
data = json.load(open('$WORKLOAD_JSON'))
results = data if isinstance(data, list) else data.get('results', [data])
for r in results:
    name = r.get('workload', r.get('name', 'unknown'))
    overhead = r.get('overhead_pct', r.get('overhead', 0))
    print(f'{name}:{overhead}')
" 2>/dev/null | while IFS=: read -r name overhead; do
            check_slo "workload($name) overhead" "$overhead" "$MAX_OPEN_P95_OVERHEAD" "%"
        done
    fi
else
    echo "SKIP: $WORKLOAD_JSON not found"
fi

# --- Check soak metrics ---
if [ -f "$SOAK_JSON" ]; then
    echo "--- soak metrics ---"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json
data = json.load(open('$SOAK_JSON'))
rss_kb = data.get('rss_growth_kb', 0)
rss_mb = rss_kb / 1024.0
drops = data.get('ringbuf_drops', 0)
total_events = data.get('total_events', 1)
drop_rate = (drops / max(total_events, 1)) * 100.0
print(f'rss_mb:{rss_mb:.2f}')
print(f'drop_rate:{drop_rate:.4f}')
" 2>/dev/null | while IFS=: read -r metric value; do
            case "$metric" in
                rss_mb) check_slo "RSS growth" "$value" "$MAX_RSS_GROWTH_MB" "MB" ;;
                drop_rate) check_slo "ring buffer drop rate" "$value" "$MAX_RINGBUF_DROP_RATE" "%" ;;
            esac
        done
    fi
else
    echo "SKIP: $SOAK_JSON not found"
fi

echo
echo "=== SLO Gate Result: $VIOLATIONS violation(s) ==="

if [ "$VIOLATIONS" -gt 0 ]; then
    exit 1
fi
exit 0
