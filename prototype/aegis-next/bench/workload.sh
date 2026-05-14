#!/bin/bash
# Synthetic workload generator for BPF agent benchmarking.
# Produces a controlled mix of exec, file-open, and connect events.
#
# Usage: ./workload.sh [iterations] [parallel_workers]
#   Default: 500 iterations, 4 workers

set -euo pipefail

ITERATIONS=${1:-500}
WORKERS=${2:-4}
TMPDIR=$(mktemp -d /tmp/aegis-bench.XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "workload: ${ITERATIONS} iterations x ${WORKERS} workers"
echo "  tmpdir: $TMPDIR"

# --- workload functions ---

do_exec_storm() {
    local n=$1
    for ((i = 0; i < n; i++)); do
        /bin/true
    done
}

do_file_storm() {
    local n=$1
    local dir=$2
    for ((i = 0; i < n; i++)); do
        echo "x" > "${dir}/f${i}"
    done
    rm -f "${dir}"/f*
}

do_connect_storm() {
    local n=$1
    for ((i = 0; i < n; i++)); do
        # Connect to localhost:1 (will fail immediately — ECONNREFUSED)
        # but the connect() syscall still fires. Use /dev/tcp directly.
        (echo > /dev/tcp/127.0.0.1/1) 2>/dev/null || true
    done
}

export -f do_exec_storm do_file_storm do_connect_storm

# --- run workload ---

START_NS=$(date +%s%N)

for ((w = 0; w < WORKERS; w++)); do
    mkdir -p "$TMPDIR/w${w}"
    (
        do_exec_storm "$ITERATIONS"
        do_file_storm "$ITERATIONS" "$TMPDIR/w${w}"
        do_connect_storm "$((ITERATIONS / 10))"
    ) &
done

wait

END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
TOTAL_OPS=$(( WORKERS * (ITERATIONS + ITERATIONS + ITERATIONS / 10) ))

echo "workload complete: ${TOTAL_OPS} ops in ${ELAPSED_MS}ms"
echo "  throughput: $(( TOTAL_OPS * 1000 / (ELAPSED_MS + 1) )) ops/sec"
echo "RESULT_MS=${ELAPSED_MS}"
echo "RESULT_OPS=${TOTAL_OPS}"
