#!/bin/bash
# BPF security agent comparison benchmark.
#
# Runs a synthetic workload under: no agent (baseline), AegisBPF mainline,
# aegis-next prototype, Tetragon, Falco, and Tracee (if installed).
# Collects wall-clock time, CPU overhead, and memory usage.
#
# Must run as root (BPF agents need CAP_BPF/CAP_SYS_ADMIN).
#
# Usage: sudo ./compare.sh [iterations] [workers]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKLOAD="$SCRIPT_DIR/workload.sh"
ITERATIONS=${1:-500}
WORKERS=${2:-4}
RESULTS_DIR="${SCRIPT_DIR}/../../results/bench-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$RESULTS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[bench]${NC} $*"; }
warn() { echo -e "${YELLOW}[bench]${NC} $*"; }
err() { echo -e "${RED}[bench]${NC} $*" >&2; }

# Detect available agents
TETRAGON_BIN=$(which tetragon 2>/dev/null || true)
FALCO_BIN=$(which falco 2>/dev/null || true)
TRACEE_BIN=""
[[ -x /tmp/dist/tracee-static ]] && TRACEE_BIN="/tmp/dist/tracee-static"
AEGIS_BIN=$(find /home -name aegisbpf -not -path "*/prototype/*" -type f -executable 2>/dev/null | head -1 || true)
AEGIS_NEXT_BIN=$(find /home -path "*/build*/prototype/aegisbpf-next" -type f -executable 2>/dev/null | head -1 || true)

log "Benchmark configuration:"
log "  iterations: $ITERATIONS, workers: $WORKERS"
log "  results:    $RESULTS_DIR"
log "  agents:"
log "    tetragon: ${TETRAGON_BIN:-NOT FOUND}"
log "    falco:    ${FALCO_BIN:-NOT FOUND}"
log "    tracee:   ${TRACEE_BIN:-NOT FOUND}"
log "    aegisbpf: ${AEGIS_BIN:-NOT FOUND}"
log "    aegis-next: ${AEGIS_NEXT_BIN:-NOT FOUND}"

# Measure CPU/memory of a background process
measure_agent() {
    local pid=$1
    local name=$2
    local outfile="$RESULTS_DIR/${name}_resources.txt"

    # Sample 3 times over 6 seconds
    for i in 1 2 3; do
        if kill -0 "$pid" 2>/dev/null; then
            ps -p "$pid" -o pid,rss,%cpu,%mem,vsz --no-headers >> "$outfile" 2>/dev/null || true
        fi
        sleep 2
    done
}

# Run workload and capture timing
run_workload() {
    local name=$1
    local outfile="$RESULTS_DIR/${name}_workload.txt"
    bash "$WORKLOAD" "$ITERATIONS" "$WORKERS" > "$outfile" 2>&1
    cat "$outfile" >&2  # show output on stderr (not captured by caller)
    grep "RESULT_MS=" "$outfile" | tail -1 | cut -d= -f2
}

# Kill agent and clean up
stop_agent() {
    local pid=$1
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        sleep 1
    fi
}

# ---- benchmark runs ----

declare -A RESULTS

# 1. Baseline (no agent)
log ""
log "=== BASELINE (no agent) ==="
RESULTS[baseline]=$(run_workload baseline)
log "  elapsed: ${RESULTS[baseline]}ms"

# 2. Tetragon
if [[ -n "$TETRAGON_BIN" ]]; then
    log ""
    log "=== TETRAGON ==="
    mkdir -p /var/run/tetragon
    $TETRAGON_BIN --export-filename="$RESULTS_DIR/tetragon_events.jsonl" \
        --log-level=error \
        --enable-process-cred=false \
        --enable-process-ns=false \
        >"$RESULTS_DIR/tetragon_stdout.txt" 2>&1 &
    TETRAGON_PID=$!
    sleep 3  # let it initialize

    if kill -0 "$TETRAGON_PID" 2>/dev/null; then
        measure_agent "$TETRAGON_PID" "tetragon" &
        RESULTS[tetragon]=$(run_workload tetragon)
        log "  elapsed: ${RESULTS[tetragon]}ms"
        stop_agent "$TETRAGON_PID"
    else
        warn "  tetragon failed to start"
        RESULTS[tetragon]="FAILED"
    fi
else
    warn "tetragon not found, skipping"
fi

# 3. Falco
if [[ -n "$FALCO_BIN" ]]; then
    log ""
    log "=== FALCO ==="
    $FALCO_BIN \
        -o "json_output=true" \
        -o "log_level=error" \
        >"$RESULTS_DIR/falco_stdout.txt" 2>&1 &
    FALCO_PID=$!
    sleep 5  # falco takes longer to init

    if kill -0 "$FALCO_PID" 2>/dev/null; then
        measure_agent "$FALCO_PID" "falco" &
        RESULTS[falco]=$(run_workload falco)
        log "  elapsed: ${RESULTS[falco]}ms"
        stop_agent "$FALCO_PID"
    else
        warn "  falco failed to start (check logs)"
        RESULTS[falco]="FAILED"
    fi
else
    warn "falco not found, skipping"
fi

# 4. Tracee
if [[ -n "$TRACEE_BIN" ]]; then
    log ""
    log "=== TRACEE ==="
    $TRACEE_BIN \
        -o json \
        -o option:parse-arguments \
        >"$RESULTS_DIR/tracee_events.jsonl" 2>"$RESULTS_DIR/tracee_stderr.txt" &
    TRACEE_PID=$!
    sleep 5

    if kill -0 "$TRACEE_PID" 2>/dev/null; then
        measure_agent "$TRACEE_PID" "tracee" &
        RESULTS[tracee]=$(run_workload tracee)
        log "  elapsed: ${RESULTS[tracee]}ms"
        stop_agent "$TRACEE_PID"
    else
        warn "  tracee failed to start"
        RESULTS[tracee]="FAILED"
    fi
else
    warn "tracee not found, skipping"
fi

# 5. AegisBPF mainline
if [[ -n "$AEGIS_BIN" ]]; then
    log ""
    log "=== AEGISBPF (mainline) ==="
    warn "  mainline requires policy config, skipping automated bench"
    RESULTS[aegisbpf]="SKIP"
else
    warn "aegisbpf mainline not found, skipping"
fi

# 6. aegis-next prototype
# (requires root + kernel 6.9, and may fail on BPF load — that's OK)
if [[ -n "$AEGIS_NEXT_BIN" ]]; then
    log ""
    log "=== AEGIS-NEXT (prototype) ==="
    $AEGIS_NEXT_BIN attach >"$RESULTS_DIR/aegis_next_stdout.txt" 2>&1 &
    NEXT_PID=$!
    sleep 3

    if kill -0 "$NEXT_PID" 2>/dev/null; then
        measure_agent "$NEXT_PID" "aegis_next" &
        RESULTS[aegis_next]=$(run_workload aegis_next)
        log "  elapsed: ${RESULTS[aegis_next]}ms"
        stop_agent "$NEXT_PID"
    else
        warn "  aegis-next failed to start (check kernel >= 6.9 + BPF LSM)"
        RESULTS[aegis_next]="FAILED"
    fi
else
    warn "aegis-next binary not found, skipping"
fi

# ---- summary ----

log ""
log "================================================================"
log "  BENCHMARK SUMMARY"
log "  workload: ${ITERATIONS} iters x ${WORKERS} workers"
log "  kernel:   $(uname -r)"
log "================================================================"

printf "%-20s %10s %10s\n" "AGENT" "TIME(ms)" "OVERHEAD"
printf "%-20s %10s %10s\n" "----" "--------" "--------"

BASELINE_MS=${RESULTS[baseline]:-0}

for agent in baseline tetragon falco tracee aegisbpf aegis_next; do
    ms=${RESULTS[$agent]:-N/A}
    if [[ "$ms" =~ ^[0-9]+$ ]] && [[ "$BASELINE_MS" =~ ^[0-9]+$ ]] && [[ "$BASELINE_MS" -gt 0 ]]; then
        overhead=$(( (ms - BASELINE_MS) * 100 / BASELINE_MS ))
        printf "%-20s %10s %9s%%\n" "$agent" "$ms" "$overhead"
    else
        printf "%-20s %10s %10s\n" "$agent" "$ms" "-"
    fi
done

# Resource usage summary
log ""
log "Resource usage (peak RSS from 3 samples):"
for agent in tetragon falco tracee aegis_next; do
    rfile="$RESULTS_DIR/${agent}_resources.txt"
    if [[ -f "$rfile" ]] && [[ -s "$rfile" ]]; then
        peak_rss=$(awk '{print $2}' "$rfile" | sort -n | tail -1)
        avg_cpu=$(awk '{sum+=$3; n++} END {if(n>0) printf "%.1f", sum/n; else print "N/A"}' "$rfile")
        printf "  %-18s RSS: %6s KB  CPU: %s%%\n" "$agent" "$peak_rss" "$avg_cpu"
    fi
done

# Save summary as JSON
cat > "$RESULTS_DIR/summary.json" << JSONEOF
{
  "kernel": "$(uname -r)",
  "iterations": $ITERATIONS,
  "workers": $WORKERS,
  "timestamp": "$(date -Iseconds)",
  "results": {
$(for agent in baseline tetragon falco tracee aegis_next; do
    ms=${RESULTS[$agent]:-null}
    [[ "$ms" == "FAILED" || "$ms" == "SKIP" || "$ms" == "N/A" ]] && ms="null"
    echo "    \"$agent\": $ms,"
done)
    "_end": null
  }
}
JSONEOF

log ""
log "Full results saved to: $RESULTS_DIR"
