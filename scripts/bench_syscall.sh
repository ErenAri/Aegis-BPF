#!/usr/bin/env bash
# bench_syscall.sh — reproducible syscall-level benchmark runner.
#
# Builds (if needed) and runs the aegisbpf_bench_syscall target which measures
# open() and connect() latency with and without BPF LSM hooks attached.
#
# Requires:
#   - Root (for BPF loading)
#   - Built BPF object (aegis.bpf.o)
#   - Google Benchmark library
#
# Usage:
#   sudo scripts/bench_syscall.sh              # text output
#   sudo scripts/bench_syscall.sh --json       # JSON output
#   sudo scripts/bench_syscall.sh --out results.json  # save to file
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${PROJECT_DIR}/build}"

FORMAT="console"
OUT=""
MIN_TIME="1.0"
REPETITIONS="5"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)       FORMAT="json"; shift ;;
        --out)        OUT="$2"; shift 2 ;;
        --min-time)   MIN_TIME="$2"; shift 2 ;;
        --reps)       REPETITIONS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--json] [--out FILE] [--min-time SECS] [--reps N]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Error: syscall benchmarks require root (BPF loading)." >&2
    exit 1
fi

# Ensure aegisbpf is not already running.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet aegisbpf.service 2>/dev/null; then
        echo "Error: aegisbpf.service is active. Stop it before benchmarking." >&2
        exit 1
    fi
fi

BENCH_BIN="${BUILD_DIR}/aegisbpf_bench_syscall"

if [[ ! -x "$BENCH_BIN" ]]; then
    echo "Benchmark binary not found at ${BENCH_BIN}."
    echo "Building..."
    cmake --build "$BUILD_DIR" --target aegisbpf_bench_syscall
fi

BENCH_ARGS=(
    "--benchmark_min_time=${MIN_TIME}"
    "--benchmark_repetitions=${REPETITIONS}"
    "--benchmark_report_aggregates_only=true"
)

if [[ "$FORMAT" == "json" ]]; then
    BENCH_ARGS+=("--benchmark_format=json")
fi

if [[ -n "$OUT" ]]; then
    BENCH_ARGS+=("--benchmark_out=${OUT}" "--benchmark_out_format=json")
fi

echo "Running syscall benchmarks..."
echo "  binary:      ${BENCH_BIN}"
echo "  min_time:    ${MIN_TIME}s"
echo "  repetitions: ${REPETITIONS}"
echo "  format:      ${FORMAT}"
[[ -n "$OUT" ]] && echo "  output:      ${OUT}"
echo ""

exec "$BENCH_BIN" "${BENCH_ARGS[@]}"
